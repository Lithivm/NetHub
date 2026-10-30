package rules

import (
	"net"
	"testing"
)

func parseIPOrNil(s string) net.IP {
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

// ExplainName：带名字的判定。
//
// 为什么它必须存在：Explain 只能靠 hostIPs（域名→IP 的产物）反查，
// 一个还没被观测过的名字在模拟里就不会命中通配规则，而引擎实际会命中。
func TestExplainName(t *testing.T) {
	s := New()
	if err := s.Load([]Route{
		{Name: "通配", Targets: []string{"*.example.com"}, Chain: "a", Ports: []string{"443"}},
		{Name: "具体", Targets: []string{"db.example.com"}, Chain: "b"},
		{Name: "网段", Targets: []string{"10.0.0.0/24"}, Chain: "c"},
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		why        string
		name       string
		ip         string
		port       uint16
		ignorePort bool
		want       int // -1 = 不命中
	}{
		{"名字命中通配，IP 为本机解析不到（nil）", "main.example.com", "", 443, false, 0},
		{"端口不符 → 通配不命中", "main.example.com", "", 80, false, -1},
		{"无关的名字", "other.test", "", 443, false, -1},
		// 宽通配在前，具体域名也归它管（自上而下、命中即止）——这是规则顺序的语义，不是 bug
		{"具体域名落在通配里", "db.example.com", "", 0, true, 0},
		{"显式 IP 走第一遍", "main.example.com", "10.0.0.7", 0, true, 2},
		{"空名字空 IP → 无从判定", "", "", 0, true, -1},
	}
	for _, c := range cases {
		idx, _, ok := s.ExplainName(c.name, parseIPOrNil(c.ip), c.port, c.ignorePort)
		if c.want < 0 {
			if ok {
				t.Errorf("%s：期望不命中，得到第 %d 条", c.why, idx)
			}
			continue
		}
		if !ok || idx != c.want {
			t.Errorf("%s：期望第 %d 条，得到 idx=%d ok=%v", c.why, c.want, idx, ok)
		}
	}

	// 被前面规则遮住的也要能说出来（界面显示“被抢先”）
	_, shadowed, _ := s.ExplainName("db.example.com", nil, 0, true)
	if len(shadowed) != 1 || shadowed[0] != 1 {
		t.Errorf("db.example.com 应命中第 1 条并遮住第 2 条：shadowed=%v", shadowed)
	}
	if err := s.Load([]Route{
		{Name: "宽通配", Targets: []string{"*.example.com"}, Chain: "a"},
		{Name: "窄通配", Targets: []string{"*.sub.example.com"}, Chain: "b"},
	}); err != nil {
		t.Fatal(err)
	}
	idx, shadowed, ok := s.ExplainName("x.sub.example.com", nil, 0, true)
	if !ok || idx != 0 || len(shadowed) != 1 || shadowed[0] != 1 {
		t.Errorf("宽通配应命中并遮住窄通配：idx=%d shadowed=%v ok=%v", idx, shadowed, ok)
	}
}
