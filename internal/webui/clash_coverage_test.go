package webui

import (
	"testing"
	"time"

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
	pm := ProxyMode{Mode: "system", Enable: true, Server: "127.0.0.1:7890", BypassRaw: "localhost;127.*;10.*;172.16.*"}
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

// 把「看着像风险、其实不是」的几种状态都钉住（2026-10-14 用户报“判定太宽松、有短暂误报”）：
//   - ProxyEnable=1 但没有代理服务器地址：系统不会转发任何请求；
//   - PAC 模式：绕过列表根本不参与判定（拿它算“缺条目”必然是假的）；
//   - Mode 说是 system 但 Enable=false（注册表被写坏/半写）：一样不算。
//
// 它们都必须是 OK + 一句说明，不能挂红线。
func TestCoverageDoesNotAlarmOnFalseSignals(t *testing.T) {
	cfg := &config.Config{
		Chains: []config.Chain{{Name: "etyy", Forward: "socks5://127.0.0.1:1080"}},
		Routes: []config.Route{{Name: "内网", Targets: []string{"172.30.4.0/24"}, Chain: "etyy"}},
	}
	cases := []struct {
		name string
		pm   ProxyMode
	}{
		{"没开系统代理", ProxyMode{Mode: "none"}},
		{"开了开关但没代理地址", ProxyMode{Mode: "system", Enable: true, Server: ""}},
		{"代理地址只有空白", ProxyMode{Mode: "system", Enable: true, Server: "   "}},
		{"PAC 模式", ProxyMode{Mode: "pac", PacURL: "http://x/proxy.pac"}},
		{"Mode 是 system 但没使能", ProxyMode{Mode: "system", Server: "127.0.0.1:7890"}},
	}
	for _, tc := range cases {
		c := coverageFor(cfg, tc.pm)
		if !c.OK {
			t.Errorf("%s：不该报风险，得到 %+v", tc.name, c)
		}
		if len(c.Missed) != 0 {
			t.Errorf("%s：不该算出漏掉的目标，得到 %+v", tc.name, c)
		}
		if tc.pm.Mode != "none" && c.Note == "" {
			t.Errorf("%s：没做判定就得说明原因（Note 空着，界面看着像“算过且没问题”）", tc.name)
		}
	}
}

// 真的缺条目时，**连读两次都缺**才算数。
//
// 对应现场：代理工具重写系统代理时先写 ProxyEnable、后写 ProxyOverride，
// 中间那一小段读到的是“代理开着、绕过列表还没写” —— 一次采样就报警 = 一闪一闪的假警报。
func TestConfirmedCoverageFiltersTransient(t *testing.T) {
	cfg := &config.Config{
		Chains: []config.Chain{{Name: "etyy", Forward: "socks5://127.0.0.1:1080"}},
		// hosts 条目非空才不会被 real hosts 文件干扰（hostsEntriesFrom 在配置为空时会去读系统 hosts）
		Hosts:  config.HostsCfg{Entries: []string{"172.30.4.217 main.his.com"}},
		Routes: []config.Route{{Name: "内网", Targets: []string{"172.30.4.0/24"}, Chain: "etyy"}},
	}
	none := func(time.Duration) {}
	missing := ProxyMode{Mode: "system", Enable: true, Server: "127.0.0.1:7890", BypassRaw: "localhost"}
	covered := ProxyMode{Mode: "system", Enable: true, Server: "127.0.0.1:7890", BypassRaw: "localhost;172.30.*"}

	// 第一次缺、第二次（确认时）已经好了 → 判定 OK（那次是竞态窗口）
	reads := []ProxyMode{missing, covered}
	i := 0
	read := func() ProxyMode {
		m := reads[i]
		if i < len(reads)-1 {
			i++
		}
		return m
	}
	if c := confirmedCoverage(cfg, read, none); !c.OK {
		t.Errorf("短暂的窗口期不该被判成风险，得到 %+v", c)
	}

	// 两次都缺 → 算数，并且把漏掉的目标报出来
	always := func() ProxyMode { return missing }
	c := confirmedCoverage(cfg, always, none)
	if c.OK || len(c.Missed) == 0 {
		t.Errorf("持续缺条目必须报出来，得到 %+v", c)
	}

	// 本来就是好的 → 一次就读完（不去等确认窗口）
	waited := false
	wait := func(time.Duration) { waited = true }
	if c := confirmedCoverage(cfg, func() ProxyMode { return covered }, wait); !c.OK {
		t.Errorf("覆盖正常时应 OK，得到 %+v", c)
	}
	if waited {
		t.Error("覆盖正常时不该去等确认窗口（每一轮都白等 3 秒）")
	}
}
