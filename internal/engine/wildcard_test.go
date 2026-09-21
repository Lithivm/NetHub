package engine

import (
	"net"
	"strings"
	"testing"
	"time"

	"nethub/internal/config"
	"nethub/internal/dnsmap"
	"nethub/internal/logbus"
	"nethub/internal/rules"
)

// mkUDPDNS 造一个"IPv4 + UDP(源端口 53) + DNS 应答"的完整包。
// 用真实报文而不是直接调 dnssniff：验证从 IP 头里取负载那一步也对。
func mkUDPDNS(t *testing.T, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	total := 20 + 8 + len(payload)
	pkt[2], pkt[3] = byte(total>>8), byte(total)
	pkt[9] = 17                               // UDP
	copy(pkt[12:16], []byte{192, 168, 1, 1})  // 假装的 DNS 服务器
	copy(pkt[16:20], []byte{192, 168, 1, 42}) // 本机
	pkt[20], pkt[21] = 0, 53                  // sport = 53
	pkt[22], pkt[23] = 0xd4, 0x31             // dport
	ul := 8 + len(payload)
	pkt[24], pkt[25] = byte(ul>>8), byte(ul) // UDP 长度
	copy(pkt[28:], payload)
	return pkt
}

// mkTCPDNS 同上，但走 TCP（带 20 字节 TCP 头，data offset=5）。
func mkTCPDNS(payload []byte) []byte {
	pkt := make([]byte, 20+20+len(payload))
	pkt[0] = 0x45
	total := 20 + 20 + len(payload)
	pkt[2], pkt[3] = byte(total>>8), byte(total)
	pkt[9] = 6 // TCP
	copy(pkt[12:16], []byte{192, 168, 1, 1})
	copy(pkt[16:20], []byte{192, 168, 1, 42})
	pkt[20], pkt[21] = 0, 53
	pkt[22], pkt[23] = 0xd4, 0x31
	pkt[32] = 0x50 // data offset = 5
	copy(pkt[40:], payload)
	return pkt
}

// dnsAnswer 拼一个最小的 DNS 应答：一个问题 + 一条 A 记录（名字用压缩指针）。
func dnsAnswer(qname, ip string, ttl uint32) []byte {
	enc := func(n string) []byte {
		var b []byte
		start := 0
		for i := 0; i <= len(n); i++ {
			if i == len(n) || n[i] == '.' {
				if i > start {
					b = append(b, byte(i-start))
					b = append(b, n[start:i]...)
				}
				start = i + 1
			}
		}
		return append(b, 0)
	}
	b := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	b = append(b, enc(qname)...)
	b = append(b, 0, 1, 0, 1) // QTYPE=A QCLASS=IN
	b = append(b, 0xc0, 12)   // 名字用压缩指针指回问题名
	hdr := []byte{0, 1, 0, 1} // TYPE=A CLASS=IN
	hdr = append(hdr, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
	hdr = append(hdr, 0, 4) // RDLENGTH
	b = append(b, hdr...)
	ipv4 := net.ParseIP(ip).To4()
	return append(b, ipv4...)
}

func TestDNSPayloadExtraction(t *testing.T) {
	body := dnsAnswer("a.his.com", "10.20.30.40", 60)
	udp := mkUDPDNS(t, body)
	if got := dnsPayload(udp); len(got) != len(body) {
		t.Errorf("UDP 负载长度 = %d，期望 %d", len(got), len(body))
	}
	tcp := mkTCPDNS(body)
	if got := dnsPayload(tcp); len(got) != len(body) {
		t.Errorf("TCP 负载长度 = %d，期望 %d", len(got), len(body))
	}
	// 不是 DNS 的包（TCP 443、没有负载）→ nil，不能把别的流量当 DNS 解析
	if got := dnsPayload(mkPkt(1500)); got != nil {
		t.Errorf("TCP 443 的包不该被当成 DNS，得到 %d 字节", len(got))
	}
	// 截断的 UDP 长度字段不能让我们越界
	bad := mkUDPDNS(t, body)
	bad[24], bad[25] = 0xff, 0xff
	if got := dnsPayload(bad); len(got) != len(bad)-28 {
		t.Errorf("UDP 长度字段过大时应退化成“到包尾”，得到 %d", len(got))
	}
}

// 端到端：观察到 DNS 应答 → 名字表学到 → 通配规则命中 → 过滤器区间跟着出来。
func TestWildcardLearnedFromDNS(t *testing.T) {
	rs := rules.New()
	err := rs.Load([]rules.Route{
		{Name: "按域名走", Targets: []string{"*.his.com"}, Chain: "etyy"},
		{Name: "另一网段", Targets: []string{"10.9.9.0/24"}, Chain: "direct", Action: rules.ActionDirect},
	})
	if err != nil {
		t.Fatalf("载入通配规则失败: %v", err)
	}
	if !rs.HasWildcards() {
		t.Fatal("HasWildcards 应该是 true")
	}

	e := &Engine{
		bus:      logbus.New(50),
		cfg:      &config.Config{},
		rules:    rs,
		names:    dnsmap.New(),
		dynDirty: make(chan struct{}, 1),
	}
	// 把节流窗口“提前用完”，让 learnDNS 只置脏标记、不真的去开 WinDivert 句柄
	// （测试进程里不该动驱动；动态过滤器的热替换靠真机验证）。
	e.dynLast.Store(time.Now().UnixMilli())

	e.learnDNS(mkUDPDNS(t, dnsAnswer("opm.his.com", "10.20.30.40", 60)))

	if ips := e.names.IPsFor("opm.his.com"); len(ips) != 1 || ips[0] != "10.20.30.40" {
		t.Fatalf("DNS 应答没被学进名字表: %v", ips)
	}
	if got := e.names.NamesFor(net.ParseIP("10.20.30.40")); len(got) != 1 || got[0] != "opm.his.com" {
		t.Fatalf("IP → 名字 反查不对: %v", got)
	}

	// 规则层：这个名字要命中通配规则（拿到链名）。
	//
	// 注意语义：学到的 IP 会被填进 hostIPs（所以“这个 IP 属于通配覆盖范围”本身
	// 就是命中依据）—— 因此这里换个名字也照样命中。名字匹配（MatchesName）真正
	// 起作用的是**包先到、hostIPs 还没填上**那一瞬，以及只有一个裸名字可用时。
	ip := net.ParseIP("10.20.30.40")
	if chain, act, hit := rs.MatchName("opm.his.com", ip, 443, ""); !hit || chain != "etyy" || act != rules.ActionChain {
		t.Errorf("通配规则应该命中 etyy，得到 chain=%q act=%v hit=%v", chain, act, hit)
	}
	if chain, _, hit := rs.MatchName("a.his.com", ip, 443, ""); !hit || chain != "etyy" {
		t.Errorf("同一 IP 的其它 his.com 名字也该命中，得到 %q hit=%v", chain, hit)
	}

	// 另一台还没学到的 IP：靠**名字**命中，而不是靠 IP
	other := net.ParseIP("10.99.99.99")
	if chain, _, hit := rs.MatchName("a.his.com", other, 443, ""); !hit || chain != "etyy" {
		t.Errorf("名字命中不依赖 IP 是否已学到，得到 %q hit=%v", chain, hit)
	}
	if _, _, hit := rs.MatchName("a.hisXcom", other, 443, ""); hit {
		t.Error("相似但不同的名字不该命中")
	}
	// 没有名字（没观察到 DNS）+ IP 不在覆盖范围内 → 不命中：
	// 这正是为什么要看 DNS，而不是把通配规则退化成“拦全部”。
	if _, _, hit := rs.MatchName("", other, 443, ""); hit {
		t.Error("不知道名字且 IP 未覆盖时，通配规则不该命中")
	}

	// 过滤器区间：通配规则学到的 IP 要能被塞进动态过滤器（否则包根本到不了我们）
	wr := rs.WildcardRanges(false)
	if len(wr) != 1 {
		t.Fatalf("应该有一条通配区间，得到 %+v", wr)
	}
	f := buildFilter(wr, 55043)
	if !contains(f, "10.20.30.40") {
		t.Errorf("过滤器串里应该有学到的 IP: %s", f)
	}
	// 直连规则的目标不进过滤器
	if contains(f, "10.9.9.0") {
		t.Errorf("直连规则不该进过滤器: %s", f)
	}
	// 具体的、非通配的区间也不该出现在动态过滤器里（它们在启动时的静态过滤器里）
	if got := rs.WildcardRanges(true); len(got) != 1 {
		t.Errorf("只该有通配那一条，得到 %+v", got)
	}
}

// 观察到的名字过期后：不再作为匹配依据，动态过滤器也该收回去。
func TestWildcardPruneOnExpiry(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "w", Targets: []string{"*.his.com"}, Chain: "etyy"}}); err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		bus:      logbus.New(50),
		cfg:      &config.Config{},
		rules:    rs,
		names:    dnsmap.New(),
		dynDirty: make(chan struct{}, 1),
	}
	e.dynLast.Store(time.Now().UnixMilli())
	e.learnDNS(mkUDPDNS(t, dnsAnswer("a.his.com", "10.1.1.1", 1))) // TTL 1 秒
	if n := len(rs.WildcardRanges(false)); n != 1 {
		t.Fatalf("学到之后应该有一条区间，得到 %d", n)
	}
	time.Sleep(1100 * time.Millisecond)
	e.pruneNames()
	if n := len(rs.WildcardRanges(false)); n != 0 {
		t.Errorf("过期后区间应该被收回，得到 %d", n)
	}
	// 名字表（反查）里也要清掉：包里拿不到名字，名字匹配就不会发生
	if got := e.names.NamesFor(net.ParseIP("10.1.1.1")); len(got) != 0 {
		t.Errorf("过期后反查应该为空，得到 %v", got)
	}
	if _, _, hit := rs.MatchName("", net.ParseIP("10.1.1.1"), 443, ""); hit {
		t.Error("过期后不该再命中")
	}
}

// WildcardStats 是界面上“通配域名现在覆盖到哪些 IP”的数据源。
func TestWildcardStats(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "w", Targets: []string{"*.his.com"}, Chain: "etyy"}}); err != nil {
		t.Fatal(err)
	}
	e := &Engine{bus: logbus.New(50), cfg: &config.Config{}, rules: rs,
		names: dnsmap.New(), dynDirty: make(chan struct{}, 1)}
	e.dynLast.Store(time.Now().UnixMilli())
	e.learnDNS(mkUDPDNS(t, dnsAnswer("a.his.com", "10.1.1.1", 60)))
	e.learnDNS(mkUDPDNS(t, dnsAnswer("b.his.com", "10.1.1.2", 60)))

	st := e.WildcardStats()
	if len(st) != 1 || st[0].Pattern != "*.his.com" {
		t.Fatalf("通配状态不对: %+v", st)
	}
	if len(st[0].IPs) != 2 {
		t.Errorf("应该覆盖 2 个 IP，得到 %v", st[0].IPs)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
