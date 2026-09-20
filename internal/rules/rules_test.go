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
	rs := s.FilterRanges(false)
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
	for _, r := range s.FilterRanges(false) {
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
	if rs := s.FilterRanges(false); len(rs) != 1 {
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
	if rs := s.FilterRanges(false); len(rs) != 0 {
		t.Errorf("只有直连规则时过滤器应为空，得到 %+v", rs)
	}
}

// ───────── 进程条件（A20）─────────

func TestMatchAppName(t *testing.T) {
	cases := []struct {
		cond, name string
		want       bool
	}{
		{"chrome.exe", "chrome.exe", true},
		{"CHROME.EXE", "chrome.exe", true},
		{"chrome.exe", "msedge.exe", false},
		{"*weixin*", "weixin.exe", true},
		{"*weixin*", "wxwork.exe", false},
		{"*.exe", "gost.exe", true},
		{`C:\Tools\gost.exe`, "gost.exe", true},
		{"gost.exe", `C:\Tools\gost.exe`, true},
		{"gost.exe", "", false},   // 进程未知 → 不命中（fail-open）
		{"gost.exe", "?", false},  // 查不到时的占位
		{"", "chrome.exe", false}, // 空条件不命中
		{"*", "anything.exe", true},
		{"java*", "javaw.exe", true},
		{"javaw.exe", "java.exe", false},
	}
	for _, c := range cases {
		if got := MatchAppName(c.cond, c.name); got != c.want {
			t.Errorf("MatchAppName(%q,%q)=%v 期望 %v", c.cond, c.name, got, c.want)
		}
	}
}

func TestMatchWild(t *testing.T) {
	yes := [][2]string{{"a*c", "abc"}, {"*b*", "xby"}, {"a*b*c", "a11b22c"}, {"*", "x"}, {"abc", "abc"}}
	no := [][2]string{{"a*c", "abx"}, {"a*b*c", "a11b22"}, {"abc", "abd"}, {"x*", "yx"}}
	for _, p := range yes {
		if !matchWild(p[0], p[1]) {
			t.Errorf("matchWild(%q,%q) 应为真", p[0], p[1])
		}
	}
	for _, p := range no {
		if matchWild(p[0], p[1]) {
			t.Errorf("matchWild(%q,%q) 应为假", p[0], p[1])
		}
	}
}

// 进程条件与目标条件是 AND；只填进程 = 该进程所有连接。
func TestMatchProcSemantics(t *testing.T) {
	s := New()
	err := s.Load([]Route{
		{Name: "只按进程", Chain: "tun", Apps: []string{"must-via.exe"}},
		{Name: "进程+目标", Targets: []string{"10.0.0.0/8"}, Chain: "tun2", Apps: []string{"app.exe"}},
		{Name: "只按目标", Targets: []string{"172.16.0.0/12"}, Chain: "tun3"},
	})
	if err != nil {
		t.Fatalf("载入失败: %v", err)
	}
	if !s.NeedsProc() {
		t.Fatal("有进程条件，NeedsProc 应为 true")
	}

	// 只按进程：任何目标都命中
	if chain, _, ok := s.MatchProc(parseIP4("8.8.8.8"), 443, "must-via.exe"); !ok || chain != "tun" {
		t.Errorf("只按进程的规则应命中任意目标，得到 %q %v", chain, ok)
	}
	// 进程对但规则不是这条 → 不命中（8.8.8.8 不在 10/8，也不在 172.16/12）
	if _, _, ok := s.MatchProc(parseIP4("8.8.8.8"), 443, "app.exe"); ok {
		t.Error("app.exe 连 8.8.8.8 不该命中任何规则")
	}
	// 进程+目标：两个都要对
	if chain, _, ok := s.MatchProc(parseIP4("10.1.2.3"), 80, "app.exe"); !ok || chain != "tun2" {
		t.Errorf("进程+目标都命中时应收 tun2，得到 %q %v", chain, ok)
	}
	if _, _, ok := s.MatchProc(parseIP4("10.1.2.3"), 80, "other.exe"); ok {
		t.Error("目标对但进程不对，不该命中 tun2")
	}
	// 进程未知（"" 或 "?"）→ 带进程条件的规则一律不命中（fail-open），但纯目标规则照常命中
	if _, _, ok := s.MatchProc(parseIP4("172.16.1.1"), 8080, ""); !ok {
		t.Error("进程未知时，纯目标规则仍应命中（fail-open 不能误伤）")
	}
	if _, _, ok := s.MatchProc(parseIP4("10.1.2.3"), 80, "?"); ok {
		t.Error("进程未知时，带进程条件的规则不该命中")
	}
}

// 只按进程的规则：过滤器必须拦全部（目标提前不可知）。
func TestFilterRangesAppsOnly(t *testing.T) {
	s := New()
	if err := s.Load([]Route{{Name: "全拦", Chain: "tun", Apps: []string{"x.exe"}}}); err != nil {
		t.Fatalf("载入失败: %v", err)
	}
	rs := s.FilterRanges(false)
	if len(rs) != 1 || rs[0].First != 0 || rs[0].Last != 0xFFFFFFFF {
		t.Fatalf("只按进程的规则应拦 0.0.0.0/0，得到 %+v", rs)
	}
	// 带目标 + 进程条件时，只拦那些目标
	s2 := New()
	if err := s2.Load([]Route{{Name: "窄", Targets: []string{"10.0.0.0/8"}, Chain: "tun", Apps: []string{"x.exe"}}}); err != nil {
		t.Fatalf("载入失败: %v", err)
	}
	rs2 := s2.FilterRanges(false)
	if len(rs2) != 1 || rs2[0].First != IP2U(net.ParseIP("10.0.0.0").To4()) {
		t.Fatalf("带目标的进程规则应只拦 10.0.0.0/8，得到 %+v", rs2)
	}
}

// 没有进程条件时 NeedsProc=false（引擎据此完全不查 TCP 表）。
func TestNeedsProcFalse(t *testing.T) {
	s := New()
	if err := s.Load([]Route{{Targets: []string{"10.0.0.0/8"}, Chain: "tun"}}); err != nil {
		t.Fatalf("载入失败: %v", err)
	}
	if s.NeedsProc() {
		t.Error("没有进程条件时 NeedsProc 应为 false")
	}
}

func parseIP4(s string) net.IP { return net.ParseIP(s).To4() }

// 域名目标：解析出来的 IP 参与匹配，过滤器也要把它包含进去。
func TestHostnameTarget(t *testing.T) {
	s := New()
	if err := s.Load([]Route{
		{Name: "按域名", Targets: []string{"main.his.com"}, Chain: "tun"},
		{Name: "按网段", Targets: []string{"10.0.0.0/8"}, Chain: "tun"},
	}); err != nil {
		t.Fatalf("载入失败（域名目标应该被接受）: %v", err)
	}
	if got := s.HostTargets(); len(got) != 1 || got[0] != "main.his.com" {
		t.Fatalf("HostTargets = %v", got)
	}
	// 解析之前：域名那条不匹配任何东西（也不该崩）
	if _, _, ok := s.Match(net.ParseIP("172.30.4.217"), 443); ok {
		t.Error("还没解析时不该命中域名规则")
	}
	// 过滤器：解析前不该出现域名那个 IP（而**不能**退化成拦全部）
	for _, rg := range s.FilterRanges(false) {
		if rg.First == 0 && rg.Last == 0xFFFFFFFF {
			t.Fatalf("解析不出来时不该拦全部流量（性能地雷）: %+v", rg)
		}
		if rg.First <= IP2U(net.ParseIP("172.30.4.217").To4()) && IP2U(net.ParseIP("172.30.4.217").To4()) <= rg.Last {
			t.Errorf("解析前不该包含域名那个 IP: %+v", rg)
		}
	}

	// 引擎解析完之后填进来 → 匹配与过滤器都要生效
	s.SetHostIPs(map[string][]*net.IPNet{
		"main.his.com": {{IP: net.ParseIP("172.30.4.217").To4(), Mask: net.CIDRMask(32, 32)}},
	})
	if chain, _, ok := s.Match(net.ParseIP("172.30.4.217"), 443); !ok || chain != "tun" {
		t.Errorf("解析后应命中域名规则，得到 %q ok=%v", chain, ok)
	}
	var hasHostIP bool
	for _, rg := range s.FilterRanges(false) {
		if rg.First == IP2U(net.ParseIP("172.30.4.217").To4()) && rg.Last == rg.First {
			hasHostIP = true
		}
	}
	if !hasHostIP {
		t.Error("过滤器要包含域名解析出的 IP（否则包根本到不了我们手上）")
	}
	// 通配域名：明确拒绝，并把替代方案说出来
	if err := New().Load([]Route{{Targets: []string{"main.*.com"}, Chain: "tun"}}); err == nil {
		t.Error("通配域名暂时应被拒绝")
	}
}

// IP 通配（Proxifier 写法）在规则层也要能生效：整段命中、段外不命中、
// 并且进内核过滤器的区间覆盖整个 /24（否则包根本到不了用户态）。
func TestRouteIPWildcard(t *testing.T) {
	rs := New()
	if err := rs.Load([]Route{
		{Name: "通配", Targets: []string{"10.100.100.*"}, Chain: "tun"},
	}); err != nil {
		t.Fatalf("载入规则失败: %v（通配写法在规则层也该认）", err)
	}
	for _, ip := range []string{"10.100.100.1", "10.100.100.99", "10.100.100.254"} {
		if _, _, ok := rs.Match(net.ParseIP(ip).To4(), 80); !ok {
			t.Errorf("%s 应该命中通配规则", ip)
		}
	}
	for _, ip := range []string{"10.100.101.1", "10.100.99.254", "10.100.100.0"} {
		_, _, ok := rs.Match(net.ParseIP(ip).To4(), 80)
		if ip == "10.100.100.0" {
			// .0 属于该网段（是否真的用得上无所谓，匹配语义要一致）
			if !ok {
				t.Errorf("%s 在 10.100.100.0/24 内，应该命中", ip)
			}
			continue
		}
		if ok {
			t.Errorf("%s 不在网段内，不该命中", ip)
		}
	}
	// 过滤器：必须把整个 /24 拦进来
	var found bool
	for _, r := range rs.FilterRanges(false) {
		if r.First == IP2U(net.ParseIP("10.100.100.0").To4()) && r.Last == IP2U(net.ParseIP("10.100.100.255").To4()) {
			found = true
		}
	}
	if !found {
		t.Errorf("过滤器应覆盖 10.100.100.0/24，实际 %+v", rs.FilterRanges(false))
	}
}
