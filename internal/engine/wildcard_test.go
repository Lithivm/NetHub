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
	"nethub/internal/tlsname"
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

// mkTCPData 造一个 TCP 包，带任意负载（SNI 嗅探用）。
func mkTCPData(payload []byte, dport uint16) []byte {
	pkt := make([]byte, 20+20+len(payload))
	pkt[0] = 0x45
	total := 20 + 20 + len(payload)
	pkt[2], pkt[3] = byte(total>>8), byte(total)
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 168, 1, 42})
	copy(pkt[16:20], []byte{203, 0, 113, 9})
	pkt[20], pkt[21] = 0xd4, 0x31
	pkt[22], pkt[23] = byte(dport>>8), byte(dport)
	pkt[32] = 0x50
	copy(pkt[40:], payload)
	return pkt
}

// 从 TLS 握手里学名字 —— 这条路的目的是：就算应用用了加密 DNS（DoH/DoT），
// 只要它走 TLS，我们仍能从明文 SNI 里知道它要去哪个域名。
func TestLearnFromHandshake(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "w", Targets: []string{"*.his.com"}, Chain: "etyy"}}); err != nil {
		t.Fatal(err)
	}
	e := &Engine{bus: logbus.New(50), cfg: &config.Config{}, rules: rs,
		names: dnsmap.New(), dynDirty: make(chan struct{}, 1)}
	e.dynLast.Store(time.Now().UnixMilli())

	// 负载要从 IP 头里取得出来（这条路径与真机完全一致）
	hello := append([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}, make([]byte, 40)...)
	if got := tcpPayload(mkTCPData(hello, 443)); len(got) != len(hello) {
		t.Fatalf("TCP 负载取错了：%d != %d", len(got), len(hello))
	}
	// DNS 那段不该把非 53 端口的 TCP 当 DNS
	if got := dnsPayload(mkTCPData(hello, 443)); got != nil {
		t.Errorf("443 的 TCP 不该被当成 DNS（源端口不是 53），得到 %d 字节", len(got))
	}

	e.learnFromHandshake(tlsname.Result{Name: "db.his.com", Kind: "tls"}, net.ParseIP("10.5.5.5"))
	if ips := e.names.IPsFor("db.his.com"); len(ips) != 1 || ips[0] != "10.5.5.5" {
		t.Fatalf("握手学到的名字没进名字表: %v", ips)
	}
	if chain, _, hit := rs.MatchName("", net.ParseIP("10.5.5.5"), 443, ""); !hit || chain != "etyy" {
		t.Errorf("握手学到的 IP 应该被通配规则覆盖，得到 %q hit=%v", chain, hit)
	}
	if n := len(rs.WildcardRanges(false)); n != 1 {
		t.Errorf("动态过滤器区间应该跟着出来，得到 %d", n)
	}

	// ECH：真名看不见，但公开名也要记上（并会打一条警告），不能崩
	e.learnFromHandshake(tlsname.Result{Name: "public.example", ECH: true, Kind: "tls"}, net.ParseIP("10.6.6.6"))
	if ips := e.names.IPsFor("public.example"); len(ips) != 1 {
		t.Errorf("ECH 的公开名也该记上: %v", ips)
	}
	// 空名字 / nil IP 直接忽略，不写脏数据
	e.learnFromHandshake(tlsname.Result{Name: "", Kind: "tls"}, net.ParseIP("10.7.7.7"))
	e.learnFromHandshake(tlsname.Result{Name: "x.his.com", Kind: "tls"}, nil)
	if got := e.names.IPsFor("x.his.com"); len(got) != 0 {
		t.Errorf("空数据不该写进表: %v", got)
	}
}

// 嗅探端口白名单：只在这些端口上只读嗅探（代价与覆盖面都要能说清）。
func TestSNISniffFilterPorts(t *testing.T) {
	f := sniSniffFilter()
	for _, p := range []string{"443", "8443", "9443", "6443", "4443", "10443", "80", "8080"} {
		if !strings.Contains(f, "tcp.DstPort == "+p) {
			t.Errorf("过滤器里应该有端口 %s: %s", p, f)
		}
	}
	if !strings.HasPrefix(f, "outbound and tcp and ip.Length < 1400 and (") {
		t.Errorf("只该看出方向的 TCP: %s", f)
	}
	if strings.Contains(f, "inbound") {
		t.Errorf("不该包含入方向（SNI 是客户端先发的）: %s", f)
	}
}

// 先接后判：从连接的**前几个字节**里认出域名，并决定走哪条链。
func clientHelloBytes(name string) []byte {
	exts := sniExtBytes(name)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func sniExtBytes(name string) []byte {
	inner := []byte{0, byte(len(name) >> 8), byte(len(name))}
	inner = append(inner, name...)
	list := append([]byte{byte(len(inner) >> 8), byte(len(inner))}, inner...)
	return append([]byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}, list...)
}

func TestDecideProbeFromPipe(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "w", Targets: []string{"*.his.com"}, Chain: "etyy"}}); err != nil {
		t.Fatal(err)
	}
	e := &Engine{bus: logbus.New(50), rules: rs,
		cfg:   &config.Config{Chains: []config.Chain{{Name: "etyy", Forward: "socks5://127.0.0.1:1080"}}},
		names: dnsmap.New(), dynDirty: make(chan struct{}, 1)}
	st := &connState{dst: net.ParseIP("10.20.30.40"), dport: 443}

	// 客户端先写一段 ClientHello，再写一点“后续数据”（模拟真实应用）
	hello := clientHelloBytes("db.his.com")
	c, s := net.Pipe()
	go func() {
		_, _ = s.Write(hello)
		_, _ = s.Write([]byte("AFTER"))
		time.Sleep(50 * time.Millisecond)
		_ = s.Close()
	}()
	chain, peeked, res, tunnel := e.decideProbe(c, st)
	if !tunnel || chain != "etyy" || res.Name != "db.his.com" {
		t.Fatalf("先接后判没认出域名: chain=%q tunnel=%v res=%+v", chain, tunnel, res)
	}
	// 读走的字节必须一个不少地留着（要原样补给下游）
	if !strings.HasPrefix(string(peeked), string(hello)) {
		t.Errorf("读走的数据不完整: %d 字节", len(peeked))
	}
	_ = c.Close()

	// 不是 TLS/HTTP（比如直接是个二进制协议）→ 不接管，但已读字节照样还回来
	c2, s2 := net.Pipe()
	go func() { _, _ = s2.Write([]byte("XYZ123")); time.Sleep(30 * time.Millisecond); _ = s2.Close() }()
	chain2, peeked2, _, tunnel2 := e.decideProbe(c2, &connState{dst: net.ParseIP("10.9.9.9"), dport: 443})
	if tunnel2 || chain2 != "" {
		t.Errorf("认不出的协议不该接管: chain=%q tunnel=%v", chain2, tunnel2)
	}
	if string(peeked2) != "XYZ123" {
		t.Errorf("读走的字节要原样保留，得到 %q", peeked2)
	}
	_ = c2.Close()
}

// 名字命中哪条链：通配/具体域名才算；直连与不存在的链都回空（走直连回退）。
func TestChainForName(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{
		{Name: "w", Targets: []string{"*.his.com"}, Chain: "etyy"},
		{Name: "d", Targets: []string{"*.direct.com"}, Chain: "direct", Action: rules.ActionDirect},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Chains: []config.Chain{{Name: "etyy", Forward: "socks5://127.0.0.1:1080"}}}
	e := &Engine{bus: logbus.New(50), cfg: cfg, rules: rs, names: dnsmap.New()}
	st := &connState{dst: net.ParseIP("10.1.1.1"), dport: 443}

	if got := e.chainForName("a.his.com", st); got != "etyy" {
		t.Errorf("通配命中应返回 etyy，得到 %q", got)
	}
	if got := e.chainForName("a.direct.com", st); got != "" {
		t.Errorf("直连规则不该走链，得到 %q", got)
	}
	if got := e.chainForName("a.other.com", st); got != "" {
		t.Errorf("没命中应返回空，得到 %q", got)
	}
	if got := e.chainForName("", st); got != "" {
		t.Errorf("空名字应返回空，得到 %q", got)
	}
}

// 先接后判的过滤器：只管内网目标、常见 TLS 端口、且排除主过滤器已覆盖的范围与 relay 自己。
func TestProbeFilter(t *testing.T) {
	rs := []rules.Range{{First: 0x0A000001, Last: 0x0A0000FF}} // 10.0.0.1-255
	f := probeFilter(rs, nil, nets("10.0.0.0/8"), 55043)
	for _, want := range []string{"outbound and tcp", "tcp.DstPort == 443", "tcp.DstPort == 80",
		"tcp.SrcPort != 55043",
		// “不在主过滤器区间内”用等价写法（WinDivert 不认 not）
		"ip.DstAddr < 10.0.0.1 or ip.DstAddr > 10.0.0.255"} {
		if !strings.Contains(f, want) {
			t.Errorf("过滤器里应该有 %q：%s", want, f)
		}
	}
	// 已经学到的通配 IP 也要排除（否则它们永远过不了快路径）
	f3 := probeFilter(rs, []rules.Range{{First: 0x0A0A0A01, Last: 0x0A0A0A01}}, nets("10.0.0.0/8"), 55043)
	if !strings.Contains(f3, "ip.DstAddr < 10.10.10.1 or ip.DstAddr > 10.10.10.1") {
		t.Errorf("学到的通配 IP 应被排除：%s", f3)
	}
	if strings.Contains(f, "inbound") {
		t.Errorf("先接后判只看出方向: %s", f)
	}
	if strings.Contains(f, " not ") {
		t.Errorf("WinDivert 不认 not，不能用它: %s", f)
	}
	// 主过滤器为空时不能拼出残缺表达式
	f2 := probeFilter(nil, nil, nets("10.0.0.0/8"), 55043)
	if strings.Contains(f2, "and and") || strings.HasSuffix(f2, "and ") {
		t.Errorf("空区间不该拼出残缺表达式: %s", f2)
	}
}

func nets(cidrs ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}
