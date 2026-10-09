package netx

import (
	"net/netip"
	"strings"
	"testing"
)

// IP 区间 → 一批 CIDR，条数要是**最少**的（对齐的起点要并成大块）。
func TestRangeToCIDRs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{name: "末段（不含 .0，所以是 8 条而不是并成 /24）", in: "10.1.1.1-10.1.1.255",
			want: []string{"10.1.1.1/32", "10.1.1.2/31", "10.1.1.4/30", "10.1.1.8/29",
				"10.1.1.16/28", "10.1.1.32/27", "10.1.1.64/26", "10.1.1.128/25"}},
		{name: "整段（含 .0）并成一条", in: "10.1.1.0-10.1.1.255", want: []string{"10.1.1.0/24"}},
		{name: "单个地址", in: "10.1.1.1-10.1.1.1", want: []string{"10.1.1.1/32"}},
		{name: "段内不带对齐", in: "10.0.5.1-10.0.5.30",
			want: []string{"10.0.5.1/32", "10.0.5.2/31", "10.0.5.4/30", "10.0.5.8/29",
				"10.0.5.16/29", "10.0.5.24/30", "10.0.5.28/31", "10.0.5.30/32"}},
		{name: "跨段", in: "10.0.0.250-10.0.1.5",
			want: []string{"10.0.0.250/31", "10.0.0.252/30", "10.0.1.0/30", "10.0.1.4/31"}},
		{name: "整个 /8", in: "10.0.0.0-10.255.255.255", want: []string{"10.0.0.0/8"}},
		{name: "写反了自动换序", in: "10.1.1.255-10.1.1.1",
			want: []string{"10.1.1.1/32", "10.1.1.2/31", "10.1.1.4/30", "10.1.1.8/29",
				"10.1.1.16/28", "10.1.1.32/27", "10.1.1.64/26", "10.1.1.128/25"}},
		{name: "横线两侧带空格", in: "10.1.1.0 - 10.1.1.255", want: []string{"10.1.1.0/24"}},
		{name: "en dash（文档自动排版常见）", in: "10.1.1.0–10.1.1.255", want: []string{"10.1.1.0/24"}},
		{name: "两端都对齐", in: "10.2.0.0-10.2.3.255", want: []string{"10.2.0.0/22"}},
		{name: "极值：整个 v4 空间", in: "0.0.0.0-255.255.255.255", want: []string{"0.0.0.0/0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := RangeToCIDRs(c.in)
			if err != nil {
				t.Fatalf("不该报错，却得到 %v", err)
			}
			if strings.Join(got, " ") != strings.Join(c.want, " ") {
				t.Fatalf("%s → %v，期望 %v", c.in, got, c.want)
			}
		})
	}
}

// 展开必须**不重不漏**：每条 CIDR 的地址数加起来要正好等于区间长度。
func TestRangeToCIDRsCoversExactly(t *testing.T) {
	for _, in := range []string{
		"10.1.1.0-10.1.1.255",
		"10.0.5.1-10.0.5.30",
		"10.0.0.250-10.0.1.5",
		"0.0.0.1-255.255.255.254", // 不做位运算上限保护就会在这里溢出
		"172.16.0.7-172.31.255.9",
	} {
		got, err := RangeToCIDRs(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		// 一个连续区间最多展开成 64 条（首尾各自最多 32 条）——条数不失控是这条的硬保证
		if len(got) > 64 {
			t.Errorf("%s 展开出 %d 条，超过一个连续区间的上限 64", in, len(got))
		}
		total := 0
		for _, c := range got {
			total += 1 << (32 - maskLen(t, c))
		}
		lo, hi, _ := splitRange(in)
		want := int(beUint32(parseIPv4(hi).As4())) - int(beUint32(parseIPv4(lo).As4())) + 1
		if total != want {
			t.Errorf("%s 覆盖 %d 个地址，期望 %d（不重不漏）", in, total, want)
		}
	}
}

// 域名/通配/畸形写法都不能被当成区间 —— 尤其 **带横线的域名**（main-1.his.com）。
func TestIsIPRange(t *testing.T) {
	for _, s := range []string{
		"main-1.his.com",             // 带横线的域名（最常见）
		"a1.b2-c3.d4.com",            // 横线在中间
		"10.1.1.1",                   // 单地址，不是区间
		"10.1.1.0/24",                // CIDR
		"10.100.100.*",               // IP 通配
		"10.1.1.1-",                  // 只有一侧
		"-10.1.1.1",                  // 只有一侧
		"10.1.1.1-abc",               // 一侧不是 IP
		"abc-10.1.1.1",               // 一侧不是 IP
		"10.1.1.1-10.1.1.300",        // 越界的八位组
		"10.1.1.1-10.1.1.1-10.1.1.1", // 多个横线
	} {
		if IsIPRange(s) {
			t.Errorf("%q 不该被当成 IP 区间", s)
		}
		if _, err := RangeToCIDRs(s); err == nil {
			t.Errorf("%q 展开应该报错", s)
		}
	}
	for _, s := range []string{"10.1.1.1-10.1.1.255", "0.0.0.0-255.255.255.255",
		"10.1.1.1 - 10.1.1.255", "10.1.1.0–10.1.1.255"} {
		if !IsIPRange(s) {
			t.Errorf("%q 应该被识别为 IP 区间", s)
		}
	}
	// 空格只在两侧都是 IPv4 时才算区间的一部分（否则 "main-1.his.com" 那种会被误拆）
	if !IsRangeDash("-") || !IsRangeDash(" – ") || IsRangeDash("10.1.1.1") {
		t.Error("IsRangeDash 只该认单独一根横线")
	}
	if !IsIPv4Literal("10.1.1.1") || IsIPv4Literal("10.0.0.0/24") || IsIPv4Literal("main.his.com") {
		t.Error("IsIPv4Literal 只该认不带掩码的 IPv4")
	}
}

func maskLen(t *testing.T, cidr string) int {
	t.Helper()
	i := strings.IndexByte(cidr, '/')
	if i < 0 {
		t.Fatalf("%q 不是 CIDR", cidr)
	}
	n := 0
	for _, c := range cidr[i+1:] {
		if c < '0' || c > '9' {
			t.Fatalf("%q 的掩码不是数字", cidr)
		}
		n = n*10 + int(c-'0')
	}
	_ = netip.Addr{}
	return n
}
