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
	rs := s.FilterRanges()
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
