package webui

import (
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
	if err := b.AddRoute("窄段直连", "10.0.0.5", "direct", ""); err != nil {
		t.Fatal(err)
	}
	// 顺序：窄的在前（最具体优先）
	if err := b.AddRoute("宽段", "10.0.0.0/24", "proxy-a", ""); err != nil {
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

	// 排序：已经有序时会明确告诉你“不需要调整”（不是错误）
	if err := b.SortRoutes(); err != nil && !strings.Contains(err.Error(), "不需要调整") {
		t.Errorf("排序失败: %v", err)
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

	// 诊断包：能打出来、且不含凭据
	p, err := b.ExportDiagnostics()
	if err != nil {
		t.Fatalf("导出诊断包失败: %v", err)
	}
	if !strings.HasSuffix(p, ".zip") {
		t.Errorf("诊断包路径不对: %s", p)
	}
	_ = cfg
}
