package engine

import (
	"net"
	"testing"

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
	e.rules = rs
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
	e.rules = rs
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
