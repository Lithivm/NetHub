package config

import (
	"fmt"
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
	secretErr   error
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
	secretDir, secretErr = dir, err
	if err != nil {
		return nil
	}
	secretStore = s
	return s
}

// SecretsError 保险箱加载失败的原因（界面显示用）。
func (c *Config) SecretsError() string {
	c.Secrets()
	secretMu.Lock()
	defer secretMu.Unlock()
	if secretErr == nil {
		return ""
	}
	return secretErr.Error()
}

// SecretsPath 保险箱文件路径。
func (c *Config) SecretsPath() string {
	if s := c.Secrets(); s != nil {
		return s.Path()
	}
	return ""
}

// dir 配置所在目录（保险箱跟配置放一起）。
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

// SealEnabled 凭据是否加密保存（默认开：没写就是开）。
func (c *Config) SealEnabled() bool {
	if c.Tuning.Secrets == nil {
		return true
	}
	return *c.Tuning.Secrets
}

// sealLocked 把明文口令挪进保险箱，配置里只留 secret: 引用。
// 只在"单上游 + 有凭据"时做（多上游的每条口令要多个名字，先不引入这份复杂度）。
// 返回改动过的链数量。
func (c *Config) sealLocked() (int, error) {
	if !c.SealEnabled() {
		return 0, nil
	}
	store := c.Secrets()
	if store == nil {
		return 0, fmt.Errorf("凭据保险箱不可用：%s", c.SecretsError())
	}
	changed := 0
	for i := range c.Chains {
		ch := &c.Chains[i]
		// 多上游不处理（保持明文），免得多出口场景配不明白
		if len(ch.Forwards) > 1 {
			continue
		}
		raw := ch.Forward
		if raw == "" && len(ch.Forwards) == 1 {
			raw = ch.Forwards[0]
		}
		if strings.TrimSpace(raw) == "" {
			continue
		}
		up, err := upstream.Parse(raw)
		if err != nil {
			continue // 解析不了就交给校验去报错
		}
		if up.Creds.User == "" && up.Creds.Pass == "" {
			continue // 没凭据，无需处理
		}
		name := "chain-" + ch.Name
		if strings.TrimSpace(ch.Name) == "" {
			name = fmt.Sprintf("chain-%d", i+1)
		}
		if err := store.Put(name, up.Creds.User+":"+up.Creds.Pass); err != nil {
			return changed, fmt.Errorf("写凭据保险箱失败：%w", err)
		}
		pub := publicURL(up)
		ch.Forward, ch.Forwards, ch.Secret = pub, nil, name
		changed++
	}
	return changed, nil
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

// UpstreamsResolved 把 secret: 引用还原成带凭据的上游 URL（引擎拨号/探测用）。
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

// SecretNames 当前配置里用到的凭据名字（界面显示"已加密"用）。
func (c *Config) SecretNames() []string {
	var out []string
	for _, ch := range c.Chains {
		if ch.Secret != "" {
			out = append(out, ch.Secret)
		}
	}
	return out
}

// ExportPlain 导出一份"带明文凭据"的配置（给人拿到新机器上一键导入用）。
// 与 SaveAs 的区别：这里会把 secret: 引用还原成明文口令。
func (c *Config) ExportPlain(path string) error {
	cp := *c
	cp.Chains = make([]Chain, len(c.Chains))
	for i, ch := range c.Chains {
		n := ch
		if ch.Secret != "" {
			if raws := c.UpstreamsResolved(ch); len(raws) > 0 {
				n.Forward = raws[0]
				if len(raws) > 1 {
					n.Forwards = raws
					n.Forward = ""
				}
			}
			n.Secret = ""
		}
		cp.Chains[i] = n
	}
	cp.path = path
	return cp.writeTo(path, false) // 导出件不加密：新机器直接导入就能用
}

// PendingPlaintext 还有几条链的口令是明文写在配置里的（保存一次就会被封存）。
// 界面用它把状态说准：开关是"开"、但文件里还是明文时，必须让人看出来。
func (c *Config) PendingPlaintext() int {
	n := 0
	for _, ch := range c.Chains {
		if ch.Secret != "" {
			continue
		}
		raws := ch.Upstreams()
		if len(raws) != 1 {
			continue // 多上游不做封存（见 sealLocked 的说明）
		}
		up, err := upstream.Parse(raws[0])
		if err == nil && (up.Creds.User != "" || up.Creds.Pass != "") {
			n++
		}
	}
	return n
}
