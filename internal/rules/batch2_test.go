package rules

import (
	"net"
	"testing"
)

// 回归：通配匹配不能出现“前缀与后缀重复消费同一段字符”的假阳性。
func TestMatchAppNameWildcardNoFalsePositive(t *testing.T) {
	cases := []struct {
		cond, name string
		want       bool
	}{
		{"ab*bc", "abc", false}, // * 不能既满足前缀又满足后缀
		{"aa*a", "aa", false},
		{"ab*bc", "abbc", true},
		{"ab*", "abc", true},
		{"*bc", "abc", true},
		{"*.exe", "chrome.exe", true},
		{"*weixin*", "weixin.exe", true},
		{"chrome.exe", "chrome.exe", true},
		{"chrome.exe", "edge.exe", false},
	}
	for _, c := range cases {
		if got := MatchAppName(c.cond, c.name); got != c.want {
			t.Errorf("MatchAppName(%q, %q) = %v，期望 %v", c.cond, c.name, got, c.want)
		}
	}
}

// 回归：本机网段条件当前不满足的规则，其网段**仍然要**进内核过滤器。
// 静态过滤器只在启动装配，而本机网段会随换网变化；A16 的“换到公司网才生效”
// 依赖“包一直能到用户态、由 Match 的 active() 动态判断”。若建过滤器时就排除，
// 换网后规则会静默失效。
func TestFilterRangesKeepsLocalNetRules(t *testing.T) {
	s := New()
	if err := s.Load([]Route{{
		Name: "仅公司网", Chain: "proxy", Targets: []string{"10.0.0.0/24"},
		LocalNets: []string{"192.168.1.0/24"},
	}}); err != nil {
		t.Fatal(err)
	}
	s.SetLocalIPs([]net.IP{net.ParseIP("172.16.0.1")}) // 当前不在公司网
	if got := s.FilterRanges(false); len(got) == 0 {
		t.Fatal("带本机网段条件的规则必须始终进过滤器（换网后才能生效）")
	}
	s.SetLocalIPs([]net.IP{net.ParseIP("192.168.1.5")}) // 在公司网
	if got := s.FilterRanges(false); len(got) == 0 {
		t.Fatal("生效的规则应当进过滤器")
	}
}

// 回归：区间合并时 Last+1 在 uint32 上会回绕（0.0.0.0/0 时 Last==0xFFFFFFFF）。
func TestMergeRangesHandlesUint32Wrap(t *testing.T) {
	out := mergeRanges([]Range{
		{First: 0, Last: 0xFFFFFFFF},
		{First: 5, Last: 5},
	})
	if len(out) != 1 {
		t.Fatalf("回绕导致区间没合并：%+v", out)
	}
}

// 回归：v4-mapped 的 CIDR（掩码 16 字节）必须被 parseTarget 拒绝，
// 否则规则会静默不生效，甚至把过滤器掩码算成 0（拦掉整个 IPv4）。
func TestLoadRejectsV4MappedCIDR(t *testing.T) {
	s := New()
	err := s.Load([]Route{{Name: "bad", Chain: "proxy", Targets: []string{"::ffff:10.0.0.0/104"}}})
	if err == nil {
		t.Fatal("v4-mapped CIDR 应当被拒绝")
	}
	// 正常 IPv4 仍要能通过
	if err := s.Load([]Route{{Name: "ok", Chain: "proxy", Targets: []string{"10.0.0.0/24"}}}); err != nil {
		t.Fatalf("正常 IPv4 不该失败: %v", err)
	}
}
