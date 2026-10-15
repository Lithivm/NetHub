package webui

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// pickProxyURL 是"按协议挑代理"的全部逻辑，现场机器上 ProxyServer 的写法五花八门，
// 逐条钉住（写错了不是报错、而是"悄悄直连"，最难查）。
func TestPickProxyURL(t *testing.T) {
	cases := []struct {
		name   string
		server string
		scheme string
		want   string // 空 = 直连（nil）
	}{
		{"裸地址：所有协议都用它", "127.0.0.1:7897", "https", "http://127.0.0.1:7897"},
		{"裸地址 http", "127.0.0.1:7897", "http", "http://127.0.0.1:7897"},
		{"https 没写就借 http 那条（Clash Verge 的形态）", "http=127.0.0.1:7897", "https", "http://127.0.0.1:7897"},
		{"按协议各写各的", "http=1.2.3.4:8080;https=5.6.7.8:8443", "https", "http://5.6.7.8:8443"},
		{"https 那条是空值 → 退回 http", "http=1.2.3.4:8080;https=", "https", "http://1.2.3.4:8080"},
		{"socks 项变 socks5://", "socks=127.0.0.1:1080", "https", "socks5://127.0.0.1:1080"},
		{"http 项是空值 → socks 兜底", "http=;socks=127.0.0.1:1080", "https", "socks5://127.0.0.1:1080"},
		{"值本身带 scheme 时原样用", "https://127.0.0.1:7897", "https", "https://127.0.0.1:7897"},
		{"不认识的协议当没有（宁可直连也不塞坏 URL）", "ftp=1.2.3.4:21", "https", ""},
		{"值是垃圾当没有", "http=::::", "https", ""},
		{"端口不是数字当没有", "http=127.0.0.1:abc", "https", ""},
		{"IPv6 代理地址能用", "http=[::1]:7897", "https", "http://[::1]:7897"},
		{"空值当没有", "", "https", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pickProxyURL(c.server, c.scheme)
			if c.want == "" {
				if got != nil {
					t.Fatalf("想要直连(nil)，得到 %s", got)
				}
				return
			}
			if got == nil || got.String() != c.want {
				t.Fatalf("想要 %s，得到 %v", c.want, got)
			}
		})
	}
}

// scrubProxyURL：这一行会进界面文案与日志，代理 URL 允许带凭据 —— 必须抹掉。
func TestScrubProxyURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://127.0.0.1:7897", "http://127.0.0.1:7897"},
		{"http://user:pass@127.0.0.1:7897", "http://127.0.0.1:7897"},
		{"socks5://u@10.0.0.1:1080", "socks5://10.0.0.1:1080"},
		{"127.0.0.1:7897", "127.0.0.1:7897"},
	}
	for _, c := range cases {
		if got := scrubProxyURL(c.in); got != c.want {
			t.Errorf("scrubProxyURL(%q) = %q，想要 %q", c.in, got, c.want)
		}
	}
}

// 环境变量优先于系统设置：显式配置压过机器设置（也方便排查时临时覆盖）。
func TestEnvProxySet(t *testing.T) {
	keys := []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"}
	for _, k := range keys {
		t.Setenv(k, "")
	}
	if envProxySet() {
		t.Fatal("全空时不该认为设了代理")
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7897")
	if !envProxySet() {
		t.Fatal("设了 HTTPS_PROXY 就该认为设了代理")
	}
}

// 走过系统代理这条路不等于"内网交给代理"：命中绕过列表的目标必须直连。
// 这里用注入的配置验逻辑，不读注册表（读注册表那份在 TestSystemProxyLive 里）。
func TestSystemProxyFuncBypass(t *testing.T) {
	pm := ProxyMode{Mode: "system", Enable: true, Server: "127.0.0.1:7897",
		BypassRaw: "localhost;127.*;192.168.*;10.*;<local>"}
	server, bypass := pm.Server, pm.BypassRaw
	pf := func(req *http.Request) (*url.URL, error) {
		if proxyBypassHit(req.URL.Hostname(), bypass) {
			return nil, nil
		}
		return pickProxyURL(server, req.URL.Scheme), nil
	}
	// 公网目标 → 走代理
	req, _ := http.NewRequest("GET", "https://api.github.com/", nil)
	if u, _ := pf(req); u == nil || u.String() != "http://127.0.0.1:7897" {
		t.Fatalf("公网目标没走代理：%v", u)
	}
	// 绕过列表里的（环回、内网段、简单主机名）→ 直连
	for _, raw := range []string{"http://127.0.0.1:9090/", "http://10.10.10.1/", "http://hisbox/"} {
		r, _ := http.NewRequest("GET", raw, nil)
		if u, _ := pf(r); u != nil {
			t.Errorf("%s 命中绕过列表，却仍被推给代理 %s", raw, u)
		}
	}
}

// TestSystemProxyLive 只在本机**真的**开着系统代理时断言：
// 那份设置会被接到"要出公网的请求"上，且绕过列表里的目标仍是直连。
// 没开（或走的是环境变量/PAC）就跳过 —— 机器设置不能当测试前提。
func TestSystemProxyLive(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			t.Skip("本机设了代理环境变量，走的是环境变量那条路")
		}
	}
	pm := readProxyMode()
	if !pm.WouldProxy() {
		t.Skipf("本机没开（可用的）系统代理：mode=%s enable=%v server=%q", pm.Mode, pm.Enable, pm.Server)
	}
	pf := systemProxyFunc()
	if pf == nil {
		t.Fatal("本机开着系统代理，systemProxyFunc 却返回 nil —— 更新请求会直连，等于一键更新不可用")
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/Lithivm/NetHub/releases/latest", nil)
	got, err := pf(req)
	if err != nil || got == nil {
		t.Fatalf("github.com 没被交给系统代理：url=%v err=%v", got, err)
	}
	t.Logf("本机系统代理 %q → github.com 走 %s", pm.Server, got)

	if proxyBypassHit("127.0.0.1", pm.BypassRaw) {
		r, _ := http.NewRequest("GET", "http://127.0.0.1:9090/", nil)
		if u, _ := pf(r); u != nil {
			t.Fatalf("绕过列表含环回，环回目标却仍被推给代理 %s", u)
		}
	}
}
