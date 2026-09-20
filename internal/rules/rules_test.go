package rules

import (
	"net"
	"testing"
)

// 直连规则（ActionDirect）：命中时 Match 要报告动作，且它的目标**不进**内核过滤器
// ——不进过滤器的含义是"这些包在驱动层就被放行，一次用户态都不用来"。
func TestDirectRoute(t *testing.T) {
	s := New()
	err := s.Load([]Route{
		{Name: "本机网段直连", Targets: []string{"192.168.1.0/24"}, Chain: "direct", Action: ActionDirect},
		{Name: "HIS 主链路", Targets: []string{"10.0.0.0/24", "172.16.0.0/24"}, Chain: "proxy-a"},
		{Name: "邻居机器直连", Targets: []string{"10.0.0.102"}, Chain: "direct", Action: ActionDirect},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 一个和隧道网段不重叠的直连目标：命中且是直连
	if _, act, ok := s.Match(net.ParseIP("192.168.1.42"), 443); !ok || act != ActionDirect {
		t.Errorf("本机网段应命中直连，得到 act=%v ok=%v", act, ok)
	}
	// 10.0.0.102 同时落在直连规则和隧道网段里：规则自上而下，先命中的赢
	if chain, act, ok := s.Match(net.ParseIP("10.0.0.102"), 443); !ok || act != ActionChain || chain != "proxy-a" {
		t.Errorf("直连规则在隧道规则后面时应该走隧道，得到 chain=%q act=%v ok=%v", chain, act, ok)
	}
	// 隧道网段里的普通地址照旧走隧道
	if chain, act, ok := s.Match(net.ParseIP("172.16.0.9"), 443); !ok || act != ActionChain || chain != "proxy-a" {
		t.Errorf("隧道网段应命中隧道，得到 chain=%q act=%v ok=%v", chain, act, ok)
	}
	// 没命中的公网地址：不拦截
	if _, _, ok := s.Match(net.ParseIP("8.8.8.8"), 443); ok {
		t.Error("公网地址不该命中任何规则")
	}

	// 过滤器只装需要接管的网段：本机网段不进去（零成本放行），隧道网段要在
	rs := s.FilterRanges()
	has := func(ip string) bool {
		u := IP2U(net.ParseIP(ip))
		for _, r := range rs {
			if u >= r.First && u <= r.Last {
				return true
			}
		}
		return false
	}
	if has("192.168.1.42") {
		t.Error("直连规则的目标不该进 WinDivert 过滤器")
	}
	if !has("10.0.0.5") || !has("172.16.0.9") {
		t.Error("隧道网段必须进过滤器")
	}
}

// 阻断规则（ActionBlock）**要**进过滤器：不接管就没法丢包。
func TestBlockRoute(t *testing.T) {
	s := New()
	err := s.Load([]Route{
		{Name: "拉黑扫描源", Targets: []string{"10.9.9.9"}, Chain: "block", Action: ActionBlock},
		{Name: "HIS 主链路", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, act, ok := s.Match(net.ParseIP("10.9.9.9"), 22); !ok || act != ActionBlock {
		t.Errorf("应命中阻断，得到 act=%v ok=%v", act, ok)
	}
	if _, act, ok := s.Match(net.ParseIP("10.0.0.1"), 443); !ok || act != ActionChain {
		t.Errorf("隧道规则不该被影响，得到 act=%v ok=%v", act, ok)
	}
	u := IP2U(net.ParseIP("10.9.9.9"))
	found := false
	for _, r := range s.FilterRanges() {
		if u >= r.First && u <= r.Last {
			found = true
		}
	}
	if !found {
		t.Error("阻断目标必须进过滤器，否则丢不掉")
	}
}

// 反过来排（直连在前、隧道在后）：同一个地址就该直连 —— 这也是用户
// "把本地网段放最上面"的用法。
func TestDirectBeforeTunnel(t *testing.T) {
	s := New()
	if err := s.Load([]Route{
		{Name: "邻居机器直连", Targets: []string{"10.0.0.102"}, Chain: "direct", Action: ActionDirect},
		{Name: "HIS 主链路", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, act, ok := s.Match(net.ParseIP("10.0.0.102"), 443); !ok || act != ActionDirect {
		t.Errorf("直连在前时应直连，得到 act=%v ok=%v", act, ok)
	}
	if chain, act, ok := s.Match(net.ParseIP("10.0.0.5"), 443); !ok || act != ActionChain || chain != "proxy-a" {
		t.Errorf("同网段其它地址仍走隧道，得到 chain=%q act=%v ok=%v", chain, act, ok)
	}
	// 10.0.0.102 被直连规则先命中，但 10.0.0.0/24 整体仍在过滤器里
	//（过滤器是"可能被接管"的粗筛，精确顺序由引擎判定）
	if rs := s.FilterRanges(); len(rs) != 1 {
		t.Errorf("期望只合并出一段，得到 %+v", rs)
	}
}

// 全是直连规则时，过滤器为空 —— 引擎据此提示"没有需要拦截的规则"。
func TestOnlyDirectRoutes(t *testing.T) {
	s := New()
	if err := s.Load([]Route{
		{Targets: []string{"192.168.0.0/16"}, Chain: "direct", Action: ActionDirect},
	}); err != nil {
		t.Fatal(err)
	}
	if rs := s.FilterRanges(); len(rs) != 0 {
		t.Errorf("只有直连规则时过滤器应为空，得到 %+v", rs)
	}
}
