package config

import (
	"nethub/internal/fakeip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"nethub/internal/upstream"
)

// ───────── 配置导出（无凭据版）─────────
//
// 与"打码"（gostbat.Redact 把口令换成 ***）不同：这里要的是**能导入**，
// 所以是把用户名/口令**剔除**掉 —— 打码后的 auth= 不是合法 base64，导入会直接校验失败。

// stripCreds 去掉上游 URL 里的凭据，保留协议与地址（结果仍可被 upstream.Parse 解析）。
func stripCreds(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	up, err := upstream.Parse(raw)
	if err != nil {
		// 解析不了也不能原样返回 —— 这个函数存在的唯一理由就是“无凭据版”。
		// 用兜底抹掉 userinfo 与 ?auth=，避免把 user:pass@ 带进导出文件。
		return redactUserinfo(raw)
	}
	if up.Creds.User == "" && up.Creds.Pass == "" {
		return raw
	}
	switch {
	case up.Protocol == "http" && up.TLS:
		return "https://" + up.Addr
	default:
		// SchemeTag 自带传输后缀（+tls / +ws / +wss）—— 写丢传输层的话，
		// “导出无凭据”再导回来就连不上了。
		return up.SchemeTag() + "://" + up.Addr
	}
}

// redactUserinfo 解析失败时的兜底脱敏：去掉 ?auth=，抹掉 scheme://userinfo@ 里的 userinfo。
// 宁可把地址弄得不完整（导入时校验会报），也不能把口令泄进“无凭据版”。
func redactUserinfo(raw string) string {
	s := raw
	if i := strings.Index(s, "?"); i >= 0 {
		base, q := s[:i], s[i+1:]
		kept := make([]string, 0, 2)
		for _, kv := range strings.Split(q, "&") {
			k, _, _ := strings.Cut(kv, "=")
			if k == "auth" {
				continue
			}
			kept = append(kept, kv)
		}
		s = base
		if len(kept) > 0 {
			s += "?" + strings.Join(kept, "&")
		}
	}
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			if cut := strings.IndexAny(rest, "/?#"); cut < 0 || at < cut {
				s = s[:i+3] + rest[at+1:]
			}
		}
	}
	return s
}

// SaveAsRedacted 导出一份"无凭据但可导入"的配置。
func (c *Config) SaveAsRedacted(path string) error {
	snapshot := c.Snapshot()
	cp := snapshot.config()
	cp.Chains = make([]Chain, len(snapshot.Chains))
	for i, ch := range snapshot.Chains {
		n := ch
		n.Forward = stripCreds(ch.Forward)
		if len(ch.Forwards) > 0 {
			n.Forwards = make([]string, 0, len(ch.Forwards))
			for _, f := range ch.Forwards {
				n.Forwards = append(n.Forwards, stripCreds(f))
			}
		}
		// 历史遗留的 secret: 引用也要清掉：导出文件不会带 secrets.dat，
		// 留个悬空引用只会在目标机器上报“解不开”。
		n.Secret = ""
		cp.Chains[i] = n
	}
	b, err := yaml.Marshal(&cp)
	if err != nil {
		return err
	}
	header := "# NetHub 配置（无凭据版）\n" +
		"# 上游地址里的用户名/口令已剔除 —— 这个文件**可以直接导入**，导入后请补上口令。\n" +
		"# 生成时间：" + time.Now().Format("2006-01-02 15:04:05") + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(header), b...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// BackupNow 立刻备份当前配置（导入/回滚前用）。
func (c *Config) BackupNow() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backupLocked()
}

// CountDirectEnabled 是否把直连流量也纳入统计（默认关）。
//
// 关（默认）：直连网段不进内核过滤器 —— 一个包都不碰，统计里只看到它的 SYN。
// 开：直连网段也装进过滤器，我们不改包、只数双向字节（换来一点每包开销）。
// 需要在「连接」页勾选，改完要重启服务（过滤器在启动时装配）。
func (c *Config) CountDirectEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Tuning.CountDirect
}

// BuiltinDirectEnabled 是否启用“内置直连端口”（默认开）。
//
// 现在内置的是 TCP 7680（Windows 更新传递优化）：客户内网里这些连接不该走隧道。
// 以前靠配置里写一条 direct 规则实现；现在内置，规则列表里少一条噪音。
func (c *Config) BuiltinDirectEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.Tuning.BuiltinDirectDisabled
}

// QuicBlockEnabled 是否阻断 QUIC（UDP 443，默认开）。见 Tuning.QuicBlockDisabled。
func (c *Config) QuicBlockEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.Tuning.QuicBlockDisabled
}

// TLSSniffEnabled 是否只读嗅探 TLS SNI / HTTP Host（默认开）。
// 注意：即使开着，没有通配域名规则时也不会开第二只句柄（一分钱不花）。
func (c *Config) TLSSniffEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.Tuning.TLSSniffDisabled
}

// DNSTakeoverEnabled 是否开启 DNS 接管（发假 IP）。默认开，只有通配域名规则时才生效。
func (c *Config) DNSTakeoverEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.Tuning.DNSTakeoverDisabled
}

// DNSBlackboxEnabled 是否开 DNS 黑匣子（排查用，默认关）。
func (c *Config) DNSBlackboxEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Tuning.DNSBlackbox
}

// FakeIPRangeOr 假 IP 段（未配则用 fakeip 包的默认值）。
func (c *Config) FakeIPRangeOr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if s := strings.TrimSpace(c.Tuning.FakeIPRange); s != "" {
		return s
	}
	return fakeip.DefaultRange
}

// ProbeNetsParsed 已删除（随“先接后判”一起去掉）：域名通配的名字来源现在
// 只有两条只读通道（明文 DNS 嗅探 + TLS SNI/HTTP Host 嗅探），不再揣测。

// EnabledRoutes 只返回启用的规则（引擎、界面统计用）。
//
// 注意：真正的"停用"效果发生在 app.toRules（停用规则根本不进规则集与内核过滤器），
// 这个函数是给需要显式过滤的调用方用的（比如规则模拟器、体检）。
func (c *Config) EnabledRoutes() []Route {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Route, 0, len(c.Routes))
	for _, r := range c.Routes {
		if r.IsEnabled() {
			out = append(out, r)
		}
	}
	return out
}
