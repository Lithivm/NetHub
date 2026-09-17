package webui

import "testing"

// 这些验证向量**全部来自真实 WinINET 的观测**（PowerShell 调
// [System.Net.WebRequest]::GetSystemWebProxy().GetProxy(url)），不是我自己推的规则。
//
// 观测 1（Clash 默认绕过列表：含 10.* 与 172.16.*–172.31.*，无内网域名）：
//
//	http://10.0.0.10/  -> DIRECT     （10.0.* 命中）
//	http://10.0.1.10/  -> DIRECT     （10.* 命中）
//	http://app.example.com/  -> 走代理      （无条目命中）
//	https://chatgpt.com/  -> 走代理      （无条目命中）
//
// 观测 2（用户在 Clash 里追加 4 个内网域名后）：
//
//	http://app.example.com/       -> DIRECT
//	http://opm.example.com/        -> DIRECT
//	http://site-b.example.com/    -> DIRECT
//	http://site-c.example.com/  -> DIRECT
//	https://chatgpt.com/       -> 走代理  （未受影响）
const clashDefaults = "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;" +
	"172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;" +
	"172.28.*;172.29.*;10.0.*;172.31.*;<local>"

const withDomains = clashDefaults + ";app.example.com;opm.example.com;site-b.example.com;site-c.example.com"

func TestProxyBypassHitGroundTruth(t *testing.T) {
	cases := []struct {
		name string
		list string
		host string
		want bool
	}{
		// 观测 1：默认列表
		{"默认列表 IP 172.30", clashDefaults, "10.0.0.10", true},
		{"默认列表 IP 10.x", clashDefaults, "10.0.1.10", true},
		{"默认列表 域名未覆盖", clashDefaults, "app.example.com", false},
		{"默认列表 公网", clashDefaults, "chatgpt.com", false},

		// 观测 2：追加域名后
		{"追加后 app.example.com", withDomains, "app.example.com", true},
		{"追加后 opm.example.com", withDomains, "opm.example.com", true},
		{"追加后 site-b.example.com", withDomains, "site-b.example.com", true},
		{"追加后 site-c.example.com", withDomains, "site-c.example.com", true},
		{"追加后 公网仍走代理", withDomains, "chatgpt.com", false},
		{"追加后 别的内网域名仍走代理", withDomains, "other.example.com", false},

		// 边界：大小写、空格、<local>、通配
		{"大小写不敏感", withDomains, "APP.EXAMPLE.COM", true},
		{"带空格", "a.com; b.com ", "b.com", true},
		{"<local> 匹配无点名", clashDefaults, "intranet", true},
		{"<local> 不匹配域名", clashDefaults, "app.example.com", false},
		{"通配后缀", "*.corp.local", "a.corp.local", true},
		{"通配后缀 不匹配裸域", "*.corp.local", "corp.local", false},
		{"空列表", "", "app.example.com", false},
	}
	for _, c := range cases {
		if got := proxyBypassHit(c.host, c.list); got != c.want {
			t.Errorf("%s: proxyBypassHit(%q) = %v, want %v", c.name, c.host, got, c.want)
		}
	}
}

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		ent, s string
		want   bool
	}{
		{"10.*", "10.0.1.10", true},
		{"10.*", "11.10.10.1", false},
		{"10.0.*", "10.0.0.10", true},
		{"app.example.com", "app.example.com", true},
		{"app.example.com", "xapp.example.com", false},
		{"*example.com", "app.example.com", true},
		{"*", "anything", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
	}
	for _, c := range cases {
		if got := wildcardMatch(c.ent, c.s); got != c.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", c.ent, c.s, got, c.want)
		}
	}
}
