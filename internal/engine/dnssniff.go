package engine

import (
	"net"
	"nethub/internal/dnsmap"
	"nethub/internal/dnssniff"
	"sort"
	"strings"
	"time"

	"github.com/imgk/divert-go"
)

// ───────────────────────── 域名通配：只读嗅探 DNS ─────────────────────────

// dnsSniffFilter 只读嗅探用的过滤器：只关心 DNS **应答**（源端口 53），UDP 与 TCP 都要。
//
// 用 sniff + recv-only：包照常交给系统与应用，我们只看一份拷贝 —— 这一步出
// 任何问题最多是“没看见”，绝不会把全机 DNS 弄坏（这是选这个方案的前提）。
const dnsSniffFilter = "(inbound and udp and udp.SrcPort == 53) or (inbound and tcp and tcp.SrcPort == 53)" +
	" or (outbound and udp and udp.DstPort == 53)"

// dnsLoop 读 DNS 应答 → 学“名字 ↔ IP” → 按需重建动态过滤器。
func (e *Engine) dnsLoop() {
	defer e.wg.Done()

	h, err := divert.Open(dnsSniffFilter, divert.LayerNetwork, divert.PriorityHighest, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Warn("域名通配：无法只读嗅探 DNS（%v）—— 通配域名只能匹配已经观察到的名字", err)
		return
	}
	defer h.Close()
	if !e.trackSniff(h) {
		return // 已经在停止：直接退出（defer 会关 h）
	}
	e.bus.Debug("dns.sniff: started mode=read-only scope=answers+queries")

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	for {
		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("域名通配：DNS 嗅探中断: %v（通配域名将不再学到新 IP）", err)
				return
			}
		}
		pkt := buf[:n]
		// 出方向的查询：DNS 接管（开了才有动作）—— 命中通配规则的名字塞一条假 IP 应答
		if e.fake != nil && e.takeoverQuery(pkt, addr) {
			continue
		}
		// 入方向的应答：学“名字 → IP”
		e.learnDNS(pkt)
	}
}

// takeoverQuery 处理一条**出方向** DNS 查询：命中通配规则就额外塞一条假 IP 应答。
//
// 返回 true 表示“这是查询，已处理”（不必再当应答解析）。
//
// 注意：这是**只读**句柄，我们从头到尾**不消费**这个包 —— 原查询照常发出去，
// 我们只是多塞一条应答。真应答先到的话，应用就用真 IP，而那条路我们能靠
// “名字→IP”嗅探照常接管（两条路都能到，不会因此失效）。
func (e *Engine) takeoverQuery(pkt []byte, addr *divert.Address) bool {
	info, payload, ok := udpPayload(pkt)
	if !ok {
		return false
	}
	// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
	// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
	if info.sport >= dnsProbePortLo && info.sport <= dnsProbePortHi {
		return true
	}
	q, okq := dnssniff.ParseQuery(payload)
	if !okq {
		return false
	}
	// verbose 档：DNS **请求**（Proxifier 把 DNS requests 归 Verbose）。
	// 只在这儿记：查询本来就是在这里被解析的（没开 DNS 接管时不解析，也就不记）。
	// 只看得到自己发出去的查询 —— 走 DoH 的应用不经这里（那类靠 sni.sniff 学名字）。
	e.bus.Detail("dns.query: name=%s type=%s from=%s:%d", q.Name, dnsTypeName(q.Type), info.src, info.sport)
	// 黑匣子：这是“到底谁弄坏的”唯一的原始事实
	if e.dnsBox != nil {
		e.dnsBox.Writef("查询  %s:%d → %s:%d  id=%#04x %s 类型 %d",
			info.src, info.sport, info.dst, info.dport, q.ID, q.Name, q.Type)
	}
	if !e.ruleSet().WildcardMatch(q.Name) {
		return true // 不命中：什么都不做（原查询照常）
	}
	var ansIP net.IP
	switch q.Type {
	case 1:
		ansIP = e.fake.Assign(q.Name, dnsFakeTTL)
		if ansIP == nil {
			e.bus.Throttle("dns.takeover.poolfull", time.Minute,
				"DNS 接管：假 IP 池已满，本次不接管（1 分钟内的重复不再逐条记）")
			return true
		}
	case 28:
		ansIP = nil // AAAA：答“没有这条记录”，否则应用可能走 IPv6 绕过我们
	default:
		// 其余类型（TXT / SRV / MX / **HTTPS-SVCB** …）也一律答“没有这条记录”，
		// **不放原查询出去**。
		//
		// 为什么（2026-09-28 复核发现的一个真泄漏面）：HTTPS/SVCB 记录里能带
		// `ipv4hint` / `ipv6hint`（RFC 9460）—— 应用拿到它就能直连真实 IP，绕过我们。
		// 原来这里 `return true` 让原查询照常发出去，等于把“本该走链”的名字的真实地址
		// 漏给了应用。Proxifier 对同一件事有个专门的开关「block non A/AAAA DNS queries」。
		//
		// 影响面只限**命中通配规则**的名字（不命中的在上面就 return 了），
		// 而这些名字本来就要接管，应用连它们靠的是 A/AAAA。
		ansIP = nil
		e.bus.Detail("dns.takeover: name=%s qtype=%s answer=NOERROR/empty（防空地址从 SVCB/HTTPS 的 ipv4hint 漏出去）",
			q.Name, dnsTypeName(q.Type))
	}
	resp := buildDNSResponse(pkt, info, q, ansIP)
	if resp == nil {
		return true
	}
	inj := e.injectorHandle()
	if inj == nil {
		return true
	}
	addr.Flags &^= 0x02 // 清掉 Outbound：回包是**入方向**的
	divert.CalcChecksums(resp, addr, divert.ChecksumDefault)
	if _, serr := inj.Send(resp, addr); serr != nil {
		e.bus.Throttle("dns.takeover.injectfail", time.Minute,
			"DNS 接管：注入假应答失败: %v（1 分钟内的重复不再逐条记）", serr)
		if e.dnsBox != nil {
			e.dnsBox.Writef("注入失败 %s: %v", q.Name, serr)
		}
		return true
	}
	e.tookOver.Add(1)
	if e.dnsBox != nil {
		e.dnsBox.Writef("已回答 %s → %v（已注入应答）", q.Name, ansIP)
	}
	e.noteTookOver(q.Name, q.Type)
	return true
}

// injectorHandle 取“只塞”那只句柄（过滤器是 false，什么也不匹配）。
func (e *Engine) injectorHandle() *divert.Handle {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.injector
}

// learnDNS 从一条 DNS 报文里学“名字 → IP”，写进名字表。
//
// 为什么全记（不只是能命中通配规则的名字）：同一个 IP 常被多个名字共用，
// 只记能命中的那些会漏掉“先用另一个名字访问过、然后才轮到通配规则”的情况；
// 表本身按 TTL 过期（见 dnsmap.Expired），不会无限长。
func (e *Engine) learnDNS(pkt []byte) {
	payload := dnsPayload(pkt)
	if len(payload) == 0 {
		return
	}
	res, err := dnssniff.Parse(payload)
	if err != nil || len(res.Pairs) == 0 {
		return
	}
	e.dnsSeen.Add(1)
	byName := map[string][]string{}
	ttl := map[string]time.Duration{}
	for _, p := range res.Pairs {
		byName[p.Name] = append(byName[p.Name], p.IP)
		if cur, ok := ttl[p.Name]; !ok || (p.TTL > 0 && p.TTL < cur) {
			ttl[p.Name] = p.TTL
		}
	}
	// 观测到的名字**封顶**存 10 分钟。
	//
	// 直接用报文里的 TTL（公网域名常见几千到 86400 秒）的后果：一天的观测全留着，
	// 而名字表每次写入都要整表重建索引（持写锁、全表 Snapshot），长跑后包处理会被
	// 这些写操作周期性地挡住（审计 P1-6）。
	// 10 分钟足够覆盖“应用刚解析完就要连”这个真正的用途。
	for name, d := range ttl {
		if d <= 0 || d > maxObservedTTL {
			ttl[name] = maxObservedTTL
		}
	}
	changed := false
	for name, ips := range byName {
		before := e.names.IPsFor(name)
		e.names.SetWithTTL(name, ips, dnsmap.PrioObserved, ttl[name])
		e.dnsLearn.Add(1)
		if !sameStrSet(before, e.names.IPsFor(name)) {
			changed = true
			// verbose 档：DNS **应答**里学到的“名字 → IP”（Proxifier 把 DNS requests 归 Verbose）。
			// 只在映射真的变了才写：同一个名字的重复应答不刷屏。
			e.bus.Detail("dns.answer: name=%s ips=%s ttl=%s", name, strings.Join(ips, ","), ttl[name])
		}
	}
	if changed {
		e.applyHostIPs()
		e.onWildcardsChanged()
	}
}

// tcpPayload 从 IP 包里取出 TCP 负载（不做端口判断，调用方自己判）。
func tcpPayload(pkt []byte) []byte {
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok || proto != 6 {
		return nil
	}
	if len(pkt) < ihl+20 {
		return nil
	}
	hdr := int(pkt[ihl+12]>>4) * 4 // data offset
	if hdr < 20 || ihl+hdr > len(pkt) {
		return nil
	}
	return pkt[ihl+hdr:]
}

// dnsPayload 从 IP 包里取出 UDP/TCP 负载（DNS 报文）。取不到返回 nil。
//
// 只认**源端口 53**（应答）：嗅探过滤器只装了这一个条件，这里再守一道，
// 免得把别的 TCP 流量当成 DNS 报文去解析（解析器再怎么健壮也不该被白喂）。
func dnsPayload(pkt []byte) []byte {
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok {
		return nil
	}
	switch proto {
	case 17: // UDP
		if len(pkt) < ihl+8 {
			return nil
		}
		if be16(pkt, ihl) != 53 {
			return nil
		}
		l := int(be16(pkt, ihl+4)) // UDP 长度（含 8 字节头）
		end := ihl + l
		if l < 8 || end > len(pkt) {
			end = len(pkt)
		}
		return pkt[ihl+8 : end]
	case 6: // TCP
		if be16(pkt, ihl) != 53 {
			return nil
		}
		return tcpPayload(pkt)
	}
	return nil
}

// onWildcardsChanged 发现名字表变了：有必要时立刻重建动态过滤器。
//
// 为什么要“立刻”：应用解析完域名后会马上发起连接，而那个包还没进过滤器。
// 这一小段窗口就是能不能拦住首次连接的关键，所以不能等到下一次 tick。
// 但也不能每个 DNS 应答都重建（重建要开新句柄），所以节流 200 ms，
// 节流期间只置脏标记，由 dynFilterLoop 补上。
func (e *Engine) onWildcardsChanged() {
	if !e.ruleSet().HasWildcards() {
		return
	}
	now := time.Now().UnixMilli()
	last := e.dynLast.Load()
	if now-last >= 200 {
		e.dynLast.Store(now)
		e.rebuildDynFilter()
		return
	}
	select {
	case e.dynDirty <- struct{}{}:
	default: // 已经有人置脏了
	}
}

// dynFilterLoop 把节流期间攒下的“脏”补上（最多滞后 200 ms）。
func (e *Engine) dynFilterLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(200 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			select {
			case <-e.dynDirty:
				e.dynLast.Store(time.Now().UnixMilli())
				e.rebuildDynFilter()
			default:
			}
		}
	}
}

// rebuildDynFilter 重建动态过滤器（第二只句柄，只装通配域名当前覆盖到的 IP）。
//
// 热替换的做法：**先开新句柄、再关旧句柄**，中间不丢包（两只都开着的那一瞬，
// 同一个包只会被其中一只收到，两边的处理逻辑完全一样）。
func (e *Engine) rebuildDynFilter() {
	rs := e.ruleSet().WildcardRanges(e.cfg.CountDirectEnabled())
	filter := ""
	if len(rs) > 0 {
		filter = buildFilter(rs, portOf(e.RelayAddr()))
	}

	e.mu.Lock()
	oldH, oldStop, oldFilter := e.dynHandle, e.dynStop, e.dynFilter
	if filter == oldFilter {
		e.mu.Unlock()
		return // 没变化，不要白白换句柄
	}
	if filter == "" {
		e.dynHandle, e.dynStop, e.dynFilter = nil, nil, ""
		e.mu.Unlock()
		if oldH != nil {
			if oldStop != nil {
				close(oldStop)
			}
			oldH.Close()
			e.bus.Debug("wildcard: filter.remove reason=no-matched-ip")
		}
		return
	}

	nh, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		// 把“记住的旧过滤器”清掉：否则下次观测到同一批 IP 时，
		// rebuildDynFilter 会以为“没变”直接返回，这只句柄就永久建立不起来了。
		e.dynFilter = ""
		e.mu.Unlock()
		e.bus.Warn("域名通配：动态过滤器打开失败: %v", err)
		return
	}
	if !e.run {
		// 已经停在停止过程中了：不要把协程加进 WaitGroup（Add 与 Wait 并发是错的）
		e.mu.Unlock()
		nh.Close()
		return
	}
	stop := make(chan struct{})
	e.dynHandle, e.dynStop, e.dynFilter, e.dynAt = nh, stop, filter, time.Now()
	e.wg.Add(1)
	e.mu.Unlock()

	go e.guard("dynPacketLoop", func() { e.packetLoop(nh, stop, loopDyn, -1) })
	if oldH != nil {
		if oldStop != nil {
			close(oldStop)
		}
		oldH.Close()
	}
	e.bus.Debug("wildcard: filter.update ranges=%d filter=%s", len(rs), filter)
}

// WildcardStat 一条通配规则当前的状态（界面/日志看“学到了几个 IP”）。
type WildcardStat struct {
	Pattern  string            `json:"pattern"`
	IPs      []string          `json:"ips"`
	Updated  string            `json:"updated"`
	Takeover bool              `json:"takeover"`
	Names    []string          `json:"names"`
	FakeIPs  map[string]string `json:"fakeIps"`
}

// WildcardStats 通配域名规则当前各覆盖到哪些 IP / 接管过哪些名字。
func (e *Engine) WildcardStats() []WildcardStat {
	var out []WildcardStat
	seen := map[string][]string{}
	for _, r := range e.ruleSet().List() {
		for _, w := range r.WildcardTargets() {
			if _, done := seen[w]; done {
				continue
			}
			var ips []string
			for h, list := range e.names.Snapshot() {
				if dnsmap.MatchWildcard(w, h) {
					ips = append(ips, list...)
				}
			}
			sort.Strings(ips)
			// 接管过哪些名字：假 IP 池里有记录（这是它**真的在干活**的证据）。
			var names []string
			fake := map[string]string{}
			if e.fake != nil {
				for _, n := range e.fake.Names() {
					if !dnsmap.MatchWildcard(w, n) {
						continue
					}
					names = append(names, n)
					if ip, ok := e.fake.IPFor(n); ok {
						fake[n] = ip.String()
					}
				}
			}
			sort.Strings(names)
			seen[w] = ips
			out = append(out, WildcardStat{Pattern: w, IPs: ips, Names: names, FakeIPs: fake,
				Takeover: e.cfg.DNSTakeoverEnabled()})
		}
	}
	if len(out) == 0 {
		return nil
	}
	e.mu.RLock()
	at := e.dynAt
	e.mu.RUnlock()
	age := "—"
	if !at.IsZero() {
		age = humanDur(time.Since(at))
	}
	for i := range out {
		out[i].Updated = age
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pattern < out[j].Pattern })
	return out
}

// DNSStats 只读嗅探的统计（进/出）—— 诊断页用。
func (e *Engine) DNSStats() (seen, learned uint64) {
	return e.dnsSeen.Load(), e.dnsLearn.Load()
}

// closedCh 简单包装：nil 通道永远不关闭。
func closedCh(ch chan struct{}) <-chan struct{} {
	if ch == nil {
		return nil
	}
	return ch
}

// sameStrSet 两个集合是否相等（顺序无关，元素不重复）。
func sameStrSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	return true
}
