package engine

import (
	"net"
	"testing"
	"time"

	"nethub/internal/config"
	"nethub/internal/dnsmap"
	"nethub/internal/rules"
)

// 域名规则的解析接线：解析成功 → 规则能匹配、过滤器包含那些 IP；
// 解析失败 → 什么都不匹配（**不能**退化成拦全部流量）。
func TestResolveHostTargets(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{
		{Name: "按域名", Targets: []string{"main.his.com"}, Chain: "tun"},
		{Name: "按网段", Targets: []string{"10.0.0.0/8"}, Chain: "tun"},
	}); err != nil {
		t.Fatalf("载入规则失败: %v", err)
	}
	e := newTestEngine()
	e.rules.Store(rs)
	e.cfg = &config.Config{}
	e.names = dnsmap.NewWithLookup(func(host string) ([]string, error) {
		if host == "main.his.com" {
			return []string{"172.30.4.217"}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})

	e.resolveHostTargets(false)
	if _, _, ok := rs.MatchProc(net.ParseIP("172.30.4.217"), 443, ""); !ok {
		t.Fatal("解析成功后域名规则应该能命中")
	}
	var hasIP bool
	for _, rg := range rs.FilterRanges(false) {
		if rg.First == rules.IP2U(net.ParseIP("172.30.4.217").To4()) && rg.Last == rg.First {
			hasIP = true
		}
		if rg.First == 0 && rg.Last == 0xFFFFFFFF {
			t.Fatal("域名规则绝不能退化成拦全部流量")
		}
	}
	if !hasIP {
		t.Error("过滤器要包含域名解析出的 IP（否则包到不了我们手上）")
	}
	// 界面上能查到解析状态
	hs := e.HostResolves()
	if len(hs) != 1 || hs[0].Host != "main.his.com" || len(hs[0].IPs) != 1 {
		t.Errorf("HostResolves 不对: %+v", hs)
	}
	if name := e.NameForIP(net.ParseIP("172.30.4.217")); name != "main.his.com" {
		t.Errorf("NameForIP = %q", name)
	}
}

// 解析不到的域名：不崩、不拦全部、状态里记得住失败原因。
func TestResolveHostTargetsUnresolved(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "解析不到", Targets: []string{"nope.his.com"}, Chain: "tun"}}); err != nil {
		t.Fatalf("载入规则失败: %v", err)
	}
	e := newTestEngine()
	e.rules.Store(rs)
	e.cfg = &config.Config{}
	e.names = dnsmap.NewWithLookup(func(string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	})
	e.resolveHostTargets(false)

	for _, rg := range rs.FilterRanges(false) {
		if rg.First == 0 && rg.Last == 0xFFFFFFFF {
			t.Fatal("解析不到时绝不能拦全部流量")
		}
	}
	st := e.HostResolves()
	if len(st) != 1 || !st[0].Failed {
		t.Errorf("失败状态应记下来: %+v", st)
	}
}

// 巡检状态：点了「立即巡检」要立刻看得出“正在巡”，巡完（无论成败）必须清掉。
//
// 清不掉比不显示更糟：界面会永远停在“巡检中”，用户一直等一个不会来的结果
// （与探测那边同一个道理，见 probe_state_test.go）。
func TestTargetProbeState(t *testing.T) {
	e := newTestEngine()
	e.cfg = &config.Config{}

	if e.TargetsProbing() {
		t.Fatal("刚建好的引擎不该在巡检")
	}
	if n := e.ProbeTargetsAsync(); n != 0 {
		t.Fatalf("没有最近访问过的目标时，这一轮应巡 0 个，实际 %d", n)
	}
	// 备的是一次**空轮**（没有目标）：计数也应当先标上再清掉
	if !e.TargetsProbing() {
		t.Error("按钮点下去的那一刻就该是“正在巡检”（否则界面点完没反应）")
	}
	if e.TargetProbeCount() != 0 {
		t.Errorf("这一轮目标数 = %d，期望 0", e.TargetProbeCount())
	}
	deadline := time.Now().Add(2 * time.Second)
	for e.TargetsProbing() {
		if time.Now().After(deadline) {
			t.Fatal("巡检结束后状态没清掉 —— 界面会永远显示“巡检中”")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 同步入口（自动巡检走它）也要有同样的状态语义
	e.beginTargetRound(3)
	if !e.TargetsProbing() || e.TargetProbeCount() != 3 {
		t.Errorf("整轮标记没生效：probing=%v count=%d", e.TargetsProbing(), e.TargetProbeCount())
	}
	// 计数可重入：自动轮与手动轮会叠在一起
	e.beginTargetRound(3)
	e.endTargetRound()
	if !e.TargetsProbing() {
		t.Error("两轮叠加时，结束一轮不该认为巡完了")
	}
	e.endTargetRound()
	if e.TargetsProbing() {
		t.Error("两轮都结束后应清掉")
	}
}
