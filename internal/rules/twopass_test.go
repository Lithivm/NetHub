package rules

import (
	"net"
	"testing"
)

// 这批规则复刻现场那次事故：
//
//	第 1 条 etyy：172.30.4.0/24 + main.*.com
//	第 2 条 sjy ：10.100.100.0/24 + opm.*.com
//
// main.wbzxyy.com 在 hosts 里指向 10.100.100.99。旧实现里 "main.*.com" 和 IP 同层比，
// 抢在第 2 条前面 → 走 etyy（而 etyy 到不了 10.100.100.99）。新语义：显式 IP 优先，
// 名字只在 IP 定不出来时兜底。
func twoPassSet(t *testing.T) *Set {
	t.Helper()
	s := New()
	if err := s.Load([]Route{
		{Name: "etyy", Chain: "etyy", Targets: []string{"172.30.4.0/24", "main.*.com"}},
		{Name: "sjy", Chain: "sjy", Targets: []string{"10.100.100.0/24", "opm.*.com"}},
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMatchNameIPBeatsWildcard(t *testing.T) {
	s := twoPassSet(t)

	cases := []struct {
		name string
		ip   string
		want string
		why  string
	}{
		{"main.wbzxyy.com", "10.100.100.99", "sjy", "IP 命中 10.100.100.0/24，不该被前面 main.*.com 抢走"},
		{"main.his.com", "172.30.4.217", "etyy", "IP 命中 172.30.4.0/24"},
		{"", "10.100.100.5", "sjy", "没有名字也要能按 IP 匹配"},
		{"main.xatlgcyy.com", "10.100.100.99", "sjy", "同上"},
		// 假 IP 阶段：IP 不在任何网段里 → 名字兜底命中 main.*.com（handleConn 拿到真实 IP 后会再修正）
		{"main.wbzxyy.com", "198.19.0.2", "etyy", "IP 定不出来时名字兜底"},
	}
	for _, c := range cases {
		chain, _, ok := s.MatchName(c.name, net.ParseIP(c.ip), 443, "")
		if !ok || chain != c.want {
			t.Errorf("MatchName(name=%q ip=%s) = %q ok=%v，期望 %q（%s）", c.name, c.ip, chain, ok, c.want, c.why)
		}
	}
}

// 回归：**域名通配不能丢**。名字对应的 IP 不在任何显式网段里时，通配规则必须按名字命中。
func TestWildcardStillMatchesWhenNoIPRuleHits(t *testing.T) {
	s := New()
	if err := s.Load([]Route{
		{Name: "内网段", Chain: "sjy", Targets: []string{"10.100.100.0/24"}},
		{Name: "通配", Chain: "etyy", Targets: []string{"main.*.com"}},
	}); err != nil {
		t.Fatal(err)
	}
	// 公网 IP（不在任何网段）→ 只能靠通配
	chain, _, ok := s.MatchName("main.wbzxyy.com", net.ParseIP("203.0.113.9"), 443, "")
	if !ok || chain != "etyy" {
		t.Fatalf("通配没兜底：chain=%q ok=%v", chain, ok)
	}
	// 具体域名：按名字匹配（不需要能反查出 IP）
	s2 := New()
	if err := s2.Load([]Route{{Name: "具体域名", Chain: "etyy", Targets: []string{"main.his.com"}}}); err != nil {
		t.Fatal(err)
	}
	chain, _, ok = s2.MatchName("main.his.com", net.ParseIP("203.0.113.9"), 443, "")
	if !ok || chain != "etyy" {
		t.Fatalf("具体域名按名字匹配失败：chain=%q ok=%v", chain, ok)
	}
	// 名字对不上就不该命中
	if _, _, ok := s2.MatchName("other.his.com", net.ParseIP("203.0.113.9"), 443, ""); ok {
		t.Fatal("名字对不上却命中了")
	}
}

// 回归：通配规则“学到的 IP”（hostIPs）仍能在第二遍按 IP 命中（DoH/自带解析器场景：
// 名字拿不到，但学到的 IP 要能接管）。
func TestWildcardHostIPFallback(t *testing.T) {
	s := New()
	if err := s.Load([]Route{{Name: "通配", Chain: "etyy", Targets: []string{"main.*.com"}}}); err != nil {
		t.Fatal(err)
	}
	s.SetHostIPs(map[string][]*net.IPNet{
		"main.wbzxyy.com": {{IP: net.ParseIP("203.0.113.9").To4(), Mask: net.CIDRMask(32, 32)}},
	})
	chain, _, ok := s.MatchName("", net.ParseIP("203.0.113.9"), 443, "")
	if !ok || chain != "etyy" {
		t.Fatalf("学到的 IP 没能在第二遍命中通配规则：chain=%q ok=%v", chain, ok)
	}
}
