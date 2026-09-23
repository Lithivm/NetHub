package config

import (
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	"nethub/internal/secret"
	"nethub/internal/upstream"
)

// 上游凭据的加密保管（A18，见 internal/secret 的说明）。
//
// 配置里的形态：
//
//	chains:
//	  - name: 主链路
//	    forward: socks5+tls://1.2.3.4:10080      # 不含口令
//	    secret: chain-主链路                       # 口令在 secrets.dat（DPAPI 加密）
//
// 为什么这么设计：config.yaml 要能被人手工看/改/diff，所以不能整文件加密；
// 但口令留纯文本就等于"文件被拷走＝口令泄漏"。折中就是把口令挪到一个纯文本看不见的地方，
// 而**导出配置时再还原成明文** —— 于是"一个文件导入即开箱即用"的体验不受影响。

var (
	secretMu    sync.Mutex
	secretStore *secret.Store
	secretDir   string
)

// Secrets 取本配置目录下的凭据保险箱（惰性加载，加载失败返回 nil + 记下错误）。
func (c *Config) Secrets() *secret.Store {
	dir := c.dir()
	if dir == "" {
		return nil
	}
	secretMu.Lock()
	defer secretMu.Unlock()
	if secretStore != nil && secretDir == dir {
		return secretStore
	}
	s, err := secret.Load(dir)
	if err != nil {
		// 失败时把缓存整体清掉：否则 secretDir 会被改成新目录，而 secretStore
		// 还是上一个目录的箱子 —— 下一次访问就会串用别的目录的口令。
		secretStore, secretDir = nil, ""
		return nil
	}
	secretStore, secretDir = s, dir
	return s
}

// dir 配置所在目录（历史遗留的 secrets.dat 跟配置放一起）。
func (c *Config) dir() string {
	if c.path == "" {
		return ""
	}
	d := filepath.Dir(c.path)
	if d == "." {
		return ""
	}
	return d
}

// publicURL 去掉凭据、保留协议与地址（可被 upstream.Parse 解析）。
func publicURL(up *upstream.Upstream) string {
	scheme := up.Protocol
	switch {
	case up.Protocol == "http" && up.TLS:
		scheme = "https"
	case up.TLS:
		scheme += "+tls"
	}
	return scheme + "://" + up.Addr
}

// UpstreamsResolved 把历史遗留的 secret: 引用还原成带凭据的上游 URL。
//
// 【现在只为了读老配置】新版不再加密：口令就是明文写在 forward 里（与 gost 脚本一致），
// 下一次保存会被 flattenSecrets 摊平成明文，之后这个函数就走直通分支了。
// 没有 secret 的链就是原样。
func (c *Config) UpstreamsResolved(ch Chain) []string {
	raws := ch.Upstreams()
	if ch.Secret == "" || len(raws) == 0 {
		return raws
	}
	store := c.Secrets()
	if store == nil {
		return raws // 保险箱打不开：只能拿没凭据的（会认证失败，日志里能看出来）
	}
	cred := store.Get(ch.Secret)
	if cred == "" {
		return raws
	}
	user, pass := cred, ""
	if i := strings.Index(cred, ":"); i >= 0 {
		user, pass = cred[:i], cred[i+1:]
	}
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		up, err := upstream.Parse(raw)
		if err != nil {
			out = append(out, raw)
			continue
		}
		out = append(out, withCreds(up, user, pass))
	}
	return out
}

// withCreds 把用户名口令塞回 URL（用 net/url 保证特殊字符被转义）。
func withCreds(up *upstream.Upstream, user, pass string) string {
	u := &url.URL{Scheme: up.Protocol, Host: up.Addr}
	if up.TLS && up.Protocol != "http" {
		u.Scheme = up.Protocol + "+tls"
	}
	if up.Protocol == "http" && up.TLS {
		u.Scheme = "https"
	}
	if pass == "" {
		u.User = url.User(user)
	} else {
		u.User = url.UserPassword(user, pass)
	}
	return u.String()
}

// flattenSecrets 把保险箱里的口令搬回配置字段（明文），并清掉 secret 引用。
//
// 落盘前调用：这样"以前加过密"的配置下一次保存就变成和 gost 脚本一样的明文，
// 之后 secrets.dat 也不再需要（没有引用了就删掉它）。
func (c *Config) flattenSecrets() int {
	if c.Secrets() == nil {
		return 0 // 保险箱打不开（或没装）：保持原样，别把口令弄丢
	}
	n := 0
	for i := range c.Chains {
		ch := &c.Chains[i]
		if ch.Secret == "" {
			continue
		}
		raws := c.UpstreamsResolved(*ch)
		if len(raws) == 0 {
			continue
		}
		hasCred := false
		for _, r := range raws {
			if strings.Contains(r, "@") || strings.Contains(r, "auth=") {
				hasCred = true
			}
		}
		if !hasCred {
			continue // 解出来还是没凭据 → 不动，免得把 secret 引用丢掉
		}
		if len(raws) == 1 {
			ch.Forwards, ch.Forward = nil, raws[0]
		} else {
			ch.Forwards, ch.Forward = raws, ""
		}
		ch.Secret = ""
		n++
	}
	return n
}

// LegacySecretWarning 老配置里还有 secret: 引用、但保险箱打不开/不在了 —— 这条链路必然认证失败。
//
// 为什么要专门喊一声：加密保存已经取消（口令就是明文）。如果谁手里还留着旧版配置，
// 而 secrets.dat 丢了，现象是"链路上游明明填了、却报认证被拒"，很难一眼看出原因。
// 这里在载入时就把话说明白。返回涉及的链名。
func (c *Config) LegacySecretWarning() []string {
	var out []string
	for _, ch := range c.Chains {
		if ch.Secret == "" {
			continue
		}
		if len(c.UpstreamsResolved(ch)) == 0 {
			continue
		}
		// 解出来有没有凭据？没有就是解不开
		hasCred := false
		for _, u := range c.UpstreamsResolved(ch) {
			if strings.Contains(u, "@") || strings.Contains(u, "auth=") {
				hasCred = true
			}
		}
		if !hasCred {
			out = append(out, ch.Name+"（引用 "+ch.Secret+"）")
		}
	}
	return out
}
