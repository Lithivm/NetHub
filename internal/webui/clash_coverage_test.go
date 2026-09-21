package webui

import (
	"testing"

	"nethub/internal/config"
)

// 没开系统代理（没装 Clash、或装了没开）→ 必须判定为 OK。
//
// 这条对应一个很容易踩的坑：本机压根没有 Clash，却因为“目标不在绕过列表里”
// 而报错/挂红条 —— 那是把“检测不到”当成了“有问题”。
func TestCoverageNoSystemProxyIsOK(t *testing.T) {
	cfg := &config.Config{
		Chains: []config.Chain{{Name: "etyy", Forward: "socks5://127.0.0.1:1080"}},
		Routes: []config.Route{{Name: "内网", Targets: []string{"172.30.4.0/24"}, Chain: "etyy"}},
	}
	c := coverageFor(cfg, ProxyMode{Mode: "none"})
	if !c.OK {
		t.Errorf("没有系统代理时应判定 OK，得到 %+v", c)
	}
	if len(c.Checked) != 0 || len(c.Missed) != 0 {
		t.Errorf("没有系统代理时不该去做覆盖检查，得到 %+v", c)
	}
}

// 开了系统代理且内网网段不在绕过列表里 → 报出漏掉的目标（红线）。
// 停用的规则不参与：那些环境现在不由我们接管。
func TestCoverageWithSystemProxy(t *testing.T) {
	cfg := &config.Config{
		Chains: []config.Chain{{Name: "etyy", Forward: "socks5://127.0.0.1:1080"},
			{Name: "xaby", Forward: "socks5://127.0.0.1:1081"}},
		Hosts: config.HostsCfg{Entries: []string{"172.30.4.217 main.his.com"}},
		Routes: []config.Route{
			{Name: "内网", Targets: []string{"172.30.4.0/24"}, Chain: "etyy"},
			{Name: "停用的环境", Targets: []string{"219.145.88.134/32"}, Chain: "xaby", Enabled: boolPtr(false)},
		},
	}
	pm := ProxyMode{Mode: "system", Server: "127.0.0.1:7890", BypassRaw: "localhost;127.*;10.*;172.16.*"}
	c := coverageFor(cfg, pm)
	if c.OK {
		t.Fatalf("172.30.4.0/24 不在绕过列表里（只绕过了 172.16.*），应报漏掉: %+v", c)
	}
	var hasDomain bool
	for _, m := range c.Missed {
		// hosts 条目的名字不会产生 DNS 查询（系统直接查文件），所以报的是它的 **IP**：
		// 真正该进绕过列表的也是这个 IP。
		if m == "172.30.4.217" {
			hasDomain = true
		}
		if m == "219.145.88.134" {
			t.Error("停用规则的目标不该进检查（会把同事的停用环境误报成红线）")
		}
		if m == "main.his.com" {
			t.Error("hosts 条目应报 IP（它不走 DNS），不该报域名")
		}
	}
	if !hasDomain {
		t.Error("hosts 条目对应的 IP 要进检查")
	}

	// 绕过列表补上（含网段）→ 恢复 OK
	pm.BypassRaw = "localhost;127.*;10.*;172.16.*;172.30.*"
	if c2 := coverageFor(cfg, pm); !c2.OK {
		t.Errorf("绕过列表覆盖后应 OK，得到 %+v", c2)
	}
}

func boolPtr(b bool) *bool { return &b }
