package webui

import (
	"strings"
	"testing"

	"nethub/internal/config"
	"nethub/internal/rules"
)

// 批量模拟：三类结论要分得清（走隧道 / 直连 / 未命中），网段要抽样，
// 端口没填时要说清楚“这只看了目标”。
func TestSimulateTargets(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	cfg.Routes = []config.Route{
		{Name: "业务A", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a", Ports: []string{"443", "80"}},
		{Name: "本机直连", Targets: []string{"172.22.224.0/20"}, Chain: config.DirectChain},
		{Name: "禁访问", Targets: []string{"10.9.9.0/24"}, Chain: config.BlockChain},
	}
	rs := rules.New()
	if err := rs.Load([]rules.Route{
		{Name: "业务A", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a", Ports: []string{"443", "80"}},
		{Name: "本机直连", Targets: []string{"172.22.224.0/20"}, Chain: config.DirectChain, Action: rules.ActionDirect},
		{Name: "禁访问", Targets: []string{"10.9.9.0/24"}, Chain: config.BlockChain, Action: rules.ActionBlock},
	}); err != nil {
		t.Fatal(err)
	}
	b.a.Rules = rs

	v := b.SimulateTargets(`
		10.0.0.5:443          # 走隧道
		172.22.224.10         # 直连
		10.9.9.9:22           # 阻断
		192.168.1.1           # 没规则命中
		10.0.0.0/24:443       # 网段 + 端口
		乱写的东西
	`)
	byInput := map[string]SimRow{}
	for _, r := range v.Rows {
		byInput[r.Input] = r
	}
	check := func(in, wantAction, wantChain string) {
		t.Helper()
		r, ok := byInput[in]
		if !ok {
			t.Fatalf("没模拟 %s：%+v", in, v.Rows)
		}
		if !r.OK || !strings.Contains(r.Action, wantAction) || r.Chain != wantChain {
			t.Errorf("%s 期望 %s/%s，得到 ok=%v action=%q chain=%q err=%q", in, wantAction, wantChain, r.OK, r.Action, r.Chain, r.Err)
		}
	}
	check("10.0.0.5:443", "链 proxy-a", "proxy-a")
	check("172.22.224.10", "直连", config.DirectChain)
	check("10.9.9.9:22", "阻断", config.BlockChain)
	check("192.168.1.1", "未命中", "")
	if r := byInput["10.0.0.0/24:443"]; !r.OK || !strings.Contains(r.Action, "proxy-a") || !strings.Contains(r.Note, "抽样") {
		t.Errorf("带端口的网段应抽样后给结论：%+v", r)
	}
	if r := byInput["乱写的东西"]; r.OK || r.Err == "" {
		t.Errorf("非法输入应报错：%+v", r)
	}

	// 没填端口 + 规则限定端口 → 必须提示“只看目标”
	if r := byInput["172.22.224.10"]; r.OK && r.Note != "" && strings.Contains(r.Note, "端口") {
		// 直连规则没端口条件，这里不该有提示
		t.Errorf("无端口条件的规则不该给端口提示：%+v", r)
	}
	rs2 := rules.New()
	if err := rs2.Load([]rules.Route{{Name: "只走443", Targets: []string{"10.1.0.0/16"}, Chain: "proxy-a", Ports: []string{"443"}}}); err != nil {
		t.Fatal(err)
	}
	b.a.Rules = rs2
	cfg.Routes = []config.Route{{Name: "只走443", Targets: []string{"10.1.0.0/16"}, Chain: "proxy-a", Ports: []string{"443"}}}
	v2 := b.SimulateTargets("10.1.2.3")
	if len(v2.Rows) != 1 || !strings.Contains(v2.Rows[0].Note, "只看目标") {
		t.Errorf("未填端口应提示端口条件没算进来：%+v", v2.Rows)
	}

	// 汇总要能一眼看懂
	if !strings.Contains(v.Summary, "共 6 项") {
		t.Errorf("汇总缺项数：%q", v.Summary)
	}
}
