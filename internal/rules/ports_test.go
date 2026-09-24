package rules

import (
	"net"
	"testing"
)

// 端口条件：规则带 ports 时要求“目标命中 **且** 端口命中”。
// 与直连规则组合就能表达“这个网段走隧道，但某端口直连”。
func TestPortMatch(t *testing.T) {
	s := New()
	err := s.Load([]Route{
		{Name: "排除更新端口", Targets: []string{"10.0.0.0/24"}, Ports: []string{"7680"}, Chain: "direct", Action: ActionDirect},
		{Name: "HIS 主链路", Targets: []string{"10.0.0.0/24"}, Ports: []string{"443", "5432", "8000-9000"}, Chain: "proxy-a"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, act, ok := s.Match(net.ParseIP("10.0.0.102"), 7680); !ok || act != ActionDirect {
		t.Errorf("7680 应命中直连，得到 act=%v ok=%v", act, ok)
	}
	for _, port := range []uint16{443, 5432, 8000, 9000} {
		if chain, act, ok := s.Match(net.ParseIP("10.0.0.5"), port); !ok || act != ActionChain || chain != "proxy-a" {
			t.Errorf("端口 %d 应命中隧道，得到 chain=%q act=%v ok=%v", port, chain, act, ok)
		}
	}
	// 9001 不在 8000-9000 里，两条规则都不命中
	if _, _, ok := s.Match(net.ParseIP("10.0.0.5"), 9001); ok {
		t.Error("8000-9000 之外的端口不该命中")
	}
	if _, _, ok := s.Match(net.ParseIP("10.0.0.5"), 80); ok {
		t.Error("没写 80 就不该命中")
	}

	// 过滤器里只应该有隧道那条（带端口条件）；直连那条不进过滤器
	rs := s.FilterRanges(false)
	if len(rs) != 1 {
		t.Fatalf("期望只合并出 1 段隧道区间，得到 %+v", rs)
	}
	if len(rs[0].Ports) != 3 {
		t.Errorf("端口条件应跟到区间上: %+v", rs[0].Ports)
	}
	if rs[0].Ports[0].First != 443 || rs[0].Ports[2].First != 8000 || rs[0].Ports[2].Last != 9000 {
		t.Errorf("端口区间解析不对: %+v", rs[0].Ports)
	}
}

// 端口写法：区间两端相等时收敛成单端口；写反了自动换。
func TestPortRangeParse(t *testing.T) {
	cases := []struct {
		in          string
		first, last uint16
		wantErr     bool
	}{
		{in: "443", first: 443, last: 443},
		{in: "8000-9000", first: 8000, last: 9000},
		{in: "9000-8000", first: 8000, last: 9000},
		{in: "8000~9000", first: 8000, last: 9000},
		{in: "0", wantErr: true},
		{in: "70000", wantErr: true},
		{in: "abc", wantErr: true},
	}
	for _, tc := range cases {
		got, err := parsePortRange(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parsePortRange(%q) 应该报错", tc.in)
			}
			continue
		}
		if err != nil || got.first != tc.first || got.last != tc.last {
			t.Errorf("parsePortRange(%q) = %+v, %v", tc.in, got, err)
		}
	}
}

// A15：只有 includeDirect=true 时才把直连网段装进过滤器（默认不装 = 零开销）。
func TestFilterRangesIncludeDirect(t *testing.T) {
	s := New()
	if err := s.Load([]Route{
		{Name: "隧道", Targets: []string{"10.1.0.0/24"}, Chain: "a"},
		{Name: "直连", Targets: []string{"192.168.0.0/24"}, Chain: "direct", Action: ActionDirect},
	}); err != nil {
		t.Fatal(err)
	}
	if rs := s.FilterRanges(false); len(rs) != 1 {
		t.Errorf("默认不该把直连网段装进过滤器：%v", rs)
	}
	if rs := s.FilterRanges(true); len(rs) != 2 {
		t.Errorf("开了直连统计后应装进去：%v", rs)
	}
}

// RangesForPort：给 UDP（QUIC 443）拼过滤器时，只留「端口条件覆盖 443」或「没写端口」
// 的区间，并且**丢掉端口约束**后合并 —— 只走 8080 的目标不该在 UDP 侧被拦。
func TestRangesForPort(t *testing.T) {
	rng := func(a, b string, ports ...PortRange) Range {
		return Range{First: IP2U(net.ParseIP(a).To4()), Last: IP2U(net.ParseIP(b).To4()), Ports: ports}
	}
	rs := []Range{
		rng("10.0.0.0", "10.0.0.255"),                        // 没写端口 → 覆盖
		rng("10.0.1.0", "10.0.1.255", PortRange{443, 443}),   // 正好 443 → 覆盖，且与上段相邻应合并
		rng("10.0.2.0", "10.0.2.255", PortRange{8080, 8080}), // 只走 8080 → 不覆盖
		rng("10.0.3.0", "10.0.3.255", PortRange{1, 65535}),   // 全端口 → 覆盖
		rng("10.0.4.0", "10.0.4.255", PortRange{400, 500}),   // 区间含 443 → 覆盖
	}
	got := RangesForPort(rs, 443)
	if len(got) != 2 {
		t.Fatalf("应得 2 段（相邻段合并后），得到 %d 段: %+v", len(got), got)
	}
	// 10.0.0.0/24 与 10.0.1.0/24（仅 443）相邻 → 合并；10.0.3.0/24（全端口）与
	// 10.0.4.0/24（端口 400-500）相邻 → 合并；只走 8080 的 10.0.2.0/24 被丢掉。
	want := [][2]string{{"10.0.0.0", "10.0.1.255"}, {"10.0.3.0", "10.0.4.255"}}
	for i, w := range want {
		if got[i].First != IP2U(net.ParseIP(w[0]).To4()) || got[i].Last != IP2U(net.ParseIP(w[1]).To4()) {
			t.Errorf("第 %d 段 = %s~%s，期望 %s~%s", i+1,
				U2IP(got[i].First), U2IP(got[i].Last), w[0], w[1])
		}
		if len(got[i].Ports) != 0 {
			t.Errorf("第 %d 段不该带端口条件：%+v", i+1, got[i].Ports)
		}
	}
	// 空输入不能报错、不能返回 nil 长度异常
	if out := RangesForPort(nil, 443); len(out) != 0 {
		t.Errorf("空输入应返回空：%v", out)
	}
	// 只在 443 上写明的规则，在别的端口上不该出现（否则 QUIC 之外也会被拦）
	only443 := []Range{rng("10.0.2.0", "10.0.2.255", PortRange{443, 443})}
	if out := RangesForPort(only443, 8080); len(out) != 0 {
		t.Errorf("非 443 端口不该带出只写了 443 的区间：%+v", out)
	}
	if out := RangesForPort(only443, 443); len(out) != 1 {
		t.Errorf("443 上应带出该区间：%+v", out)
	}
}
