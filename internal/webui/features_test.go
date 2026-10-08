package webui

import (
	"encoding/json"
	"strings"
	"testing"

	"nethub/internal/config"
	"nethub/internal/rules"
)

// 新加的一批“界面按钮背后”的方法：至少保证接线对（前端字段名/签名与后端一致）。
// 这些方法一旦字段名写错，界面点了才炸 —— 所以在这里先炸。
func TestFeatureWiring(t *testing.T) {
	b, cfg := newRoutesBackend(t)

	// 两条规则：一条宽（走链）、一条窄（直连）+ 一条完全被覆盖的（影子）
	if err := b.AddRoute("窄段直连", "10.0.0.5", "direct", "", ""); err != nil {
		t.Fatal(err)
	}
	// 顺序：窄的在前（最具体优先）
	if err := b.AddRoute("宽段", "10.0.0.0/24", "proxy-a", "", ""); err != nil {
		t.Fatal(err)
	}
	// 被完全覆盖的规则 **存不进去**（程序会拒绝），所以影子目标只可能来自手写配置 ——
	// 这里直接改内存里的规则来模拟那种配置。
	cfg.Routes = append(cfg.Routes, config.Route{Name: "被覆盖", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-b"})

	// 规则层：Explain 要能区分“命中”与“被抢先”
	rs := rules.New()
	if err := rs.Load([]rules.Route{
		{Name: "窄段直连", Targets: []string{"10.0.0.5"}, Chain: "direct", Action: rules.ActionDirect},
		{Name: "宽段", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a"},
		{Name: "被覆盖", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-b"},
	}); err != nil {
		t.Fatal(err)
	}
	b.a.Rules = rs

	// 视图里的影子目标
	vs := b.GetRoutes()
	if len(vs) != 3 || len(vs[2].Shadowed) != 1 {
		t.Fatalf("影子目标没标出来: %+v", vs)
	}

	// 命中窄规则（直连）
	v, err := b.ExplainTarget("10.0.0.5", "")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Matched || v.RuleIndex != 0 || !strings.Contains(v.Action, "直连") || !v.PortIgnored {
		t.Errorf("解释结果不对: %+v", v)
	}
	if len(v.Shadowed) != 2 {
		t.Errorf("应指出被抢先的规则: %+v", v.Shadowed)
	}
	// 走链的那条要带上链路健康
	if v2, err := b.ExplainTarget("10.0.0.9", "5432"); err != nil || !v2.Matched || v2.Chain != "proxy-a" {
		t.Errorf("解释结果不对: %+v %v", v2, err)
	}
	// 不命中
	if v3, _ := b.ExplainTarget("8.8.8.8", ""); v3.Matched {
		t.Errorf("公网地址不该命中: %+v", v3)
	}
	// 非法输入要报错而不是 panic
	if _, err := b.ExplainTarget("不是IP", ""); err == nil {
		t.Error("非法 IP 应报错")
	}
	if _, err := b.ExplainTarget("10.0.0.5", "99999"); err == nil {
		t.Error("非法端口应报错")
	}

	// 体检报告
	if rep := b.PrecheckConfig(); len(rep) == 0 {
		t.Error("体检不该是空报告")
	}

	// 排序：已经有序时返回 changed=false（不是错误）
	if _, err := b.SortRoutes(); err != nil {
		t.Errorf("排序失败: %v", err)
	}
	if changed, err := b.SortRoutes(); err != nil {
		t.Errorf("再次排序不该出错: %v", err)
	} else if changed {
		t.Error("第二次排序应该返回 changed=false（已经有序）")
	}
	if list := b.ListBackups(); len(list) == 0 {
		t.Error("保存过配置后应有备份")
	}

	// 连接/巡检快照（引擎为空也不该炸）
	if list := b.GetConns(); list.List == nil && list.Total != 0 {
		t.Errorf("连接快照异常: %+v", list)
	}
	_ = b.GetTargetHealth()
	_ = b.GetChainHealth()

	// 服务状态（未安装）
	if st := b.GetService(); st.State == "" {
		t.Error("服务状态不该为空")
	}

	// 接管状态卡（诊断页）：引擎没在跑时也要能取，而且应当直接说“没在跑”，
	// 不能满屏 0 让人以为“一切正常、只是没流量”。
	rt := b.GetRuntimeStatus()
	if rt.Running {
		t.Error("测试环境里引擎不该是运行中")
	}
	if len(rt.Warnings) == 0 || rt.Warnings[0].Kind != "engine.stopped" {
		t.Errorf("引擎没在跑时必须有一条 engine.stopped 提示，得到 %+v", rt.Warnings)
	}
	// 折叠区（按需取原文）也不能炸
	if d := b.GetKernelDetail(); d.Filter != "" && d.Ranges == nil {
		t.Errorf("覆盖区间清单不该是 nil：%+v", d)
	}

	// 前端是按这些 JSON 键取值的：标签写错 = 界面上那一格永远是空的，而编译期看不出来
	buf, err := json.Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"running"`, `"uptime"`, `"kernel"`, `"ranges"`, `"peers"`, `"quicBlock"`,
		`"names"`, `"newestSec"`, `"fakeCap"`, `"wildcards"`, `"takeover"`,
		`"conns"`, `"perChain"`, `"procUnknown"`, `"procPorts"`,
		`"rules"`, `"shadowed"`, `"warnings"`, `"severity"`,
	} {
		if !strings.Contains(string(buf), key) {
			t.Errorf("接管状态的 JSON 里缺键 %s —— 前端那一格会是空的", key)
		}
	}
}
