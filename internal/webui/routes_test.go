package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nethub/internal/app"
	"nethub/internal/config"
	"nethub/internal/logbus"
)

// newRoutesBackend 造一个"够规则增改查用"的后端：配置落 t.TempDir()。
// 不碰 hosts、不起驱动、不建托盘 —— 这些接口只需要 a.Cfg 和 SaveConfig。
func newRoutesBackend(t *testing.T) (*Backend, *config.Config) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	seed := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n" +
		"  - name: proxy-b\n    forward: socks5://127.0.0.1:1081\n" +
		"routes: []\n"
	if err := os.WriteFile(p, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return &Backend{a: app.New(cfg, logbus.New(200))}, cfg
}

// 一次填多个目标 = **一条**规则（对齐 Proxifier：一个动作挂一组目标），不是多条。
func TestAddRouteMultiTarget(t *testing.T) {
	b, cfg := newRoutesBackend(t)

	if err := b.AddRoute("内网主体链路", "10.1.1.1, 10.1.1.2\n10.2.0.0/24\n10.0.0.0/24", "proxy-a", "", ""); err != nil {
		t.Fatalf("AddRoute 失败: %v", err)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("应该是 1 条规则（含 4 个目标），实际 %d 条", len(cfg.Routes))
	}
	r := cfg.Routes[0]
	if r.Name != "内网主体链路" || r.Chain != "proxy-a" {
		t.Errorf("名字/链不对: %+v", r)
	}
	want := "10.1.1.1/32,10.1.1.2/32,10.2.0.0/24,10.0.0.0/24"
	if got := strings.Join(r.Targets, ","); got != want {
		t.Errorf("目标 = %q，期望 %q", got, want)
	}

	// 真落盘了：重新读一遍还是同一条多目标规则
	re, err := config.Load(cfg.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(re.Routes) != 1 || strings.Join(re.Routes[0].Targets, ",") != want {
		t.Errorf("落盘后 = %+v", re.Routes)
	}

	// 界面上看到的也是一行
	vs := b.GetRoutes()
	if len(vs) != 1 {
		t.Fatalf("GetRoutes 返回 %d 行，期望 1 行", len(vs))
	}
	if vs[0].Name != "内网主体链路" || len(vs[0].Targets) != 4 || vs[0].Chain != "proxy-a" {
		t.Errorf("RouteView = %+v", vs[0])
	}
}

// 编辑规则同样是"改这一组目标"。
func TestUpdateRouteMultiTarget(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	if err := b.AddRoute("", "10.1.1.1", "proxy-a", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateRoute(0, "改过名", "10.1.1.1\n10.1.1.2\n10.9.9.0/24", "proxy-b", "", ""); err != nil {
		t.Fatalf("UpdateRoute 失败: %v", err)
	}
	r := cfg.Routes[0]
	if r.Name != "改过名" || r.Chain != "proxy-b" {
		t.Errorf("名字/链没更新: %+v", r)
	}
	if got := strings.Join(r.Targets, ","); got != "10.1.1.1/32,10.1.1.2/32,10.9.9.0/24" {
		t.Errorf("目标 = %q", got)
	}
}

// 空目标 / 非法目标 / 跨规则重复：都要报错，且配置一点都不能变。
func TestAddRouteRejects(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	if err := b.AddRoute("已存在", "10.9.9.9", "proxy-a", "", ""); err != nil {
		t.Fatal(err)
	}
	before := len(cfg.Routes)

	cases := []struct {
		name, targets, chain, want string
	}{
		{"空目标", "   \n ,、", "proxy-a", "至少要填一个目标"},
		{"非法目标", "10.1.1.1 abc", "proxy-a", `"abc"`},
		{"与已有规则重复", "10.1.1.1 10.9.9.9", "proxy-a", "已在第 1 条规则"},
		{"引用了不存在的链", "10.1.1.1", "no-such-chain", "不存在的链"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := b.AddRoute("", c.targets, c.chain, "", "")
			if err == nil {
				t.Fatalf("应该报错（含 %q）", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误 %q 里没有 %q", err, c.want)
			}
			if len(cfg.Routes) != before {
				t.Errorf("失败的添加不该改配置：%d → %d", before, len(cfg.Routes))
			}
		})
	}
}

// 目标列/回执里的摘要：目标多了要能看出还有几个。
func TestTargetsSummary(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	if err := b.AddRoute("业务系统", "10.1.1.1 10.1.1.2 10.1.1.3 10.1.1.4 10.1.1.5", "proxy-a", "", ""); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes[0].Targets) != 5 {
		t.Fatalf("目标数 = %d", len(cfg.Routes[0].Targets))
	}
	if got := cfg.Routes[0].Label(); !strings.Contains(got, "业务系统：") {
		t.Errorf("Label = %q", got)
	}
}

// 前端下拉里的「直连（不走代理）」：后端收的就是保留链名 direct，
// 视图要带 direct 标记 + 一句说明，且不需要先建链。
func TestAddDirectRoute(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	if err := b.AddRoute("本机网段直连", "192.168.1.0/24 10.0.0.102", "direct", "", ""); err != nil {
		t.Fatalf("加直连规则不该要求先建链: %v", err)
	}
	vs := b.GetRoutes()
	if len(vs) != 1 || !vs[0].Direct || vs[0].Chain != "direct" {
		t.Fatalf("视图没带 direct 标记: %+v", vs)
	}
	if vs[0].Note == "" {
		t.Error("直连规则的说明不该是空的")
	}
	if len(cfg.Routes[0].Targets) != 2 {
		t.Errorf("目标数 = %d", len(cfg.Routes[0].Targets))
	}

	// 直连和隧道规则共存，互不影响
	if err := b.AddRoute("HIS 主链路", "10.0.0.0/24", "proxy-a", "", ""); err != nil {
		t.Fatal(err)
	}
	vs = b.GetRoutes()
	if vs[1].Direct || vs[1].Chain != "proxy-a" || vs[1].Note != "" {
		t.Errorf("普通规则被污染了: %+v", vs[1])
	}

	// 链名 direct 是保留名（避免“到底走代理还是直连”含糊）
	if err := b.AddChain(ChainInput{Name: "direct", Forward: "socks5://127.0.0.1:1080"}); err == nil {
		t.Error("链名 direct 应该被拒绝")
	}
}

// 规则开关：切换 + 编辑规则内容时不能把停用状态弄丢。
func TestRouteEnableSwitch(t *testing.T) {
	b, _ := newRoutesBackend(t)
	if err := b.AddRoute("环境A", "172.30.4.0/24", "proxy-a", "", ""); err != nil {
		t.Fatalf("加规则失败: %v", err)
	}
	if !b.GetRoutes()[0].Enabled {
		t.Error("新加的规则默认应为启用")
	}

	// 停用
	if err := b.SetRouteEnabled(0, false); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if b.GetRoutes()[0].Enabled {
		t.Fatal("停用后状态应为 false")
	}

	// 停用状态下编辑内容（改名字）→ 不能被重新启用
	if err := b.SaveRoute(0, RouteInput{Name: "环境A-改名", Targets: "172.30.4.0/24", Chain: "proxy-a"}); err != nil {
		t.Fatalf("编辑失败: %v", err)
	}
	r := b.GetRoutes()[0]
	if r.Enabled {
		t.Error("编辑停用的规则不该把它重新启用")
	}
	if r.Name != "环境A-改名" {
		t.Errorf("改名没生效: %q", r.Name)
	}

	// 停用状态下可以加一条同目标规则（多环境共存），启用状态下不行
	r2 := RouteInput{Name: "环境B", Targets: "172.30.4.0/24", Chain: "proxy-a"}
	if err := b.SaveRoute(-1, r2); err != nil {
		t.Fatalf("停用着第一条时，加同目标规则应允许: %v", err)
	}
	// 停用第一条 → 第二条能启用
	if err := b.SetRouteEnabled(0, false); err != nil {
		t.Fatal(err)
	}
	if err := b.SetRouteEnabled(1, true); err != nil {
		t.Fatalf("第二条启用应成功: %v", err)
	}
	// 现在两条都启用 → 第二条启用时目标已被第一条占着？第一条是停用的 → 仍可
	if err := b.SetRouteEnabled(0, true); err == nil {
		t.Error("两条都启用且目标相同时，第二条启用应报冲突")
	}
}
