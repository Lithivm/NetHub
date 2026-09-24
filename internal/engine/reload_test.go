package engine

import (
	"net"
	"strings"
	"testing"

	"nethub/internal/config"
	"nethub/internal/fakeip"
	"nethub/internal/rules"
)

// buildMainFilter 是「启动」与「热重载」共用的装配路径，假 IP 段一定不能漏：
// 漏了的表现是“DNS 接管之后应用连假 IP 连不上”（包根本不在过滤器里）。
func TestBuildMainFilterIncludesFakeRange(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "内网", Targets: []string{"10.1.0.0/24"}, Chain: "etyy"}}); err != nil {
		t.Fatal(err)
	}
	e := newRulesEngine(&config.Config{}, rs)

	f, n := e.buildMainFilter(rs, 13001)
	if f == "" || n != 1 {
		t.Fatalf("应得 1 段区间与非空过滤器，得到 n=%d filter=%q", n, f)
	}
	if !strings.Contains(f, "10.1.0.0") || !strings.Contains(f, "tcp.SrcPort == 13001") {
		t.Fatalf("过滤器缺内容: %s", f)
	}

	// 装上假 IP 池之后，整段假 IP 必须进过滤器
	pool, err := fakeip.NewPool("198.19.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	e.fake = pool
	f2, n2 := e.buildMainFilter(rs, 13001)
	if n2 != 2 || !strings.Contains(f2, "198.19.0.0") || !strings.Contains(f2, "198.19.255.255") {
		t.Fatalf("假 IP 段没并进过滤器: n=%d filter=%s", n2, f2)
	}
}

// 没有需要拦截的规则（只填了直连）→ 空过滤器，调用方据此报“无事可做”。
func TestBuildMainFilterEmptyWhenOnlyDirect(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "直连", Targets: []string{"192.168.0.0/24"}, Chain: "direct", Action: rules.ActionDirect}}); err != nil {
		t.Fatal(err)
	}
	e := newRulesEngine(&config.Config{}, rs)
	if f, n := e.buildMainFilter(rs, 13001); f != "" || n != 0 {
		t.Fatalf("只填直连时不该有过滤器：n=%d filter=%q", n, f)
	}
}

// 热重载：引擎没在跑 → 明确报 ErrNotRunning（调用方要说“已落盘，但运行实例没应用”）。
func TestReloadRulesNotRunning(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "内网", Targets: []string{"10.1.0.0/24"}, Chain: "etyy"}}); err != nil {
		t.Fatal(err)
	}
	e := newRulesEngine(&config.Config{}, rs)
	if err := e.ReloadRules(rs); err != ErrNotRunning {
		t.Fatalf("应报 ErrNotRunning，得到 %v", err)
	}
	if err := e.ReloadRules(nil); err == nil {
		t.Fatal("nil 规则集应报错")
	}
}

// 热重载必须把**学到的名字**继承给新规则集：否则通配规则“忘掉”已观察到的名字，
// 表现为“刚还好好的，保存一次规则后不通了”。
func TestReloadRulesInheritsLearnedNames(t *testing.T) {
	old := rules.New()
	if err := old.Load([]rules.Route{{Name: "通配", Targets: []string{"*.his.com"}, Chain: "etyy"}}); err != nil {
		t.Fatal(err)
	}
	e := newRulesEngine(&config.Config{}, old)
	e.relay = "127.0.0.1:13001"
	// 模拟“已经通过 DNS 嗅探学到了这个内网域名”
	e.names.Set("main.his.com", []string{"10.100.100.99"}, 0)
	e.applyHostIPs()
	if n := len(old.WildcardRanges(false)); n != 1 {
		t.Fatalf("前置条件：旧规则集应已覆盖学到的 IP，得到 %d 段", n)
	}

	// 让“过滤器没变”走不碰驱动的分支（真机换句柄另有端到端验证）。
	filter, _ := e.buildMainFilter(old, 13001)
	e.mainFilter, e.run = filter, true

	ns := rules.New()
	// 新规则集：同样只覆盖 *.his.com，只把链换一条 —— 过滤器字符串不变
	if err := ns.Load([]rules.Route{{Name: "通配", Targets: []string{"*.his.com"}, Chain: "sjy"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.ReloadRules(ns); err != nil {
		t.Fatalf("热重载失败: %v", err)
	}
	if e.ruleSet() != ns {
		t.Fatal("规则集没有换成新的")
	}
	rs := ns.WildcardRanges(false)
	if len(rs) != 1 || rs[0].First != rules.IP2U(net.ParseIP("10.100.100.99").To4()) {
		t.Fatalf("新规则集没继承学到过的 IP：%+v", rs)
	}
}
