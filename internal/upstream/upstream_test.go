package upstream

import (
	"strings"
	"testing"
	"time"
)

func TestParseSchemes(t *testing.T) {
	cases := []struct {
		raw      string
		protocol string
		tls      bool
		user     string
		pass     string
		addr     string
	}{
		{"socks5+tls://1.2.3.4:10080?auth=dXNlcjpwYXNz", "socks5", true, "user", "pass", "1.2.3.4:10080"},
		{"socks5://1.2.3.4:1080", "socks5", false, "", "", "1.2.3.4:1080"},
		{"socks5h://1.2.3.4:1080", "socks5", false, "", "", "1.2.3.4:1080"},
		{"socks://1.2.3.4:1080", "socks5", false, "", "", "1.2.3.4:1080"},
		{"socks4://1.2.3.4:1080", "socks4", false, "", "", "1.2.3.4:1080"},
		{"socks4a://1.2.3.4:1080", "socks4a", false, "", "", "1.2.3.4:1080"},
		{"http://proxy:8080", "http", false, "", "", "proxy:8080"},
		{"https://proxy:8443", "http", true, "", "", "proxy:8443"},
		{"http://u:p@proxy:8080", "http", false, "u", "p", "proxy:8080"},
		{"socks5+tls://u:p@1.2.3.4:443", "socks5", true, "u", "p", "1.2.3.4:443"},
	}
	for _, c := range cases {
		up, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%s: 解析失败 %v", c.raw, err)
			continue
		}
		if up.Protocol != c.protocol || up.TLS != c.tls || up.Addr != c.addr {
			t.Errorf("%s: 得到 %s tls=%v addr=%s，期望 %s tls=%v addr=%s",
				c.raw, up.Protocol, up.TLS, up.Addr, c.protocol, c.tls, c.addr)
		}
		if up.Creds.User != c.user || up.Creds.Pass != c.pass {
			t.Errorf("%s: 凭据得到 %q/%q，期望 %q/%q", c.raw, up.Creds.User, up.Creds.Pass, c.user, c.pass)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, bad := range []string{
		"", "relay+tls://1.2.3.4:5678", "quic://1.2.3.4:5678", "ss://1.2.3.4:8388",
		"socks5+tls://noport", "http://",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q 应该被拒绝，但解析通过了", bad)
		}
	}
}

func TestStringHidesCreds(t *testing.T) {
	up, _ := Parse("socks5+tls://203.0.113.10:10080?auth=dXNlcjpwYXNz")
	s := up.String()
	if s == "" || strings.Contains(s, "user") || strings.Contains(s, "pass") || strings.Contains(s, "dXNlc") {
		t.Errorf("String() 泄漏了凭据: %q", s)
	}
}

// Probe 只测到代理这一段：死端口要快速失败（不碰任何业务目标）。
func TestProbeDeadUpstream(t *testing.T) {
	u, err := Parse("socks5://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Probe(2 * time.Second); err == nil {
		t.Error("127.0.0.1:1 应该探测失败")
	}
}
