package engine

import (
	"net"
	"strings"
	"testing"

	"nethub/internal/rules"
)

// buildFilter 是直接喂给内核的字符串，写错了就拦不住或被全拦，单独测一下。
func TestBuildFilter(t *testing.T) {
	// 1) 不带端口：一段区间
	got := buildFilter([]rules.Range{
		{First: rules.IP2U(net.ParseIP("10.0.0.0")), Last: rules.IP2U(net.ParseIP("10.0.0.255"))},
	}, 55043)
	want := "(outbound and tcp and ((ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.0.0.255)))" +
		" or (outbound and tcp and tcp.SrcPort == 55043)"
	if got != want {
		t.Errorf("不带端口时过滤器不对:\n got %s\nwant %s", got, want)
	}

	// 2) 带端口：端口条件要写在同一个括号里（and 优先级）
	got = buildFilter([]rules.Range{
		{First: rules.IP2U(net.ParseIP("10.0.0.0")), Last: rules.IP2U(net.ParseIP("10.0.0.255")),
			Ports: []rules.PortRange{{First: 443, Last: 443}, {First: 8000, Last: 9000}}},
	}, 1234)
	if !strings.Contains(got, "ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.0.0.255 and (tcp.DstPort == 443 or (tcp.DstPort >= 8000 and tcp.DstPort <= 9000))") {
		t.Errorf("带端口的过滤器不对: %s", got)
	}
	if !strings.HasSuffix(got, " or (outbound and tcp and tcp.SrcPort == 1234)") {
		t.Errorf("return 方向的条件不该丢: %s", got)
	}
}
