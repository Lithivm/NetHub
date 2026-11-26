package engine

import (
	"context"
	"fmt"
	"net"
	"nethub/internal/dnsmap"
	"nethub/internal/dnssniff"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/rules"
)

// 接管查询用的是 dnsLoop 那只**只读嗅探**句柄（dnsSniffFilter 已含
// `outbound and udp and udp.DstPort == 53`）；这里不再单独定义过滤器。
const (
	dnsProbePortLo = 53901
	dnsProbePortHi = 53910
)

// noteTookOver 第一次接管某个名字时说一行，之后静默计数。
func (e *Engine) noteTookOver(name string, qtype uint16) {
	e.mu.Lock()
	if e.tookSeen == nil {
		e.tookSeen = map[string]bool{}
	}
	show := !e.tookSeen[name]
	if show {
		e.tookSeen[name] = true
	}
	e.mu.Unlock()
	if !show {
		return
	}
	ip, _ := e.fake.IPFor(name)
	if ip == nil {
		// 非 A 查询走这条：AAAA（防走 IPv6）或其它类型（防 SVCB/HTTPS 的 ipv4hint 漏地址）。
		// 报**真实的 qtype**，不要写死 AAAA —— 否则现场看到这条会以为只可能是 AAAA。
		//
		// 放在 verbose 档：这是 DNS 请求与应答层面的细节（Proxifier 也是把 DNS requests
		// 归 Verbose）；normal 档只留连接与错误。
		e.bus.Detail("dns.takeover: name=%s qtype=%s answer=NOERROR/empty", name, dnsTypeName(qtype))
		return
	}
	e.bus.Detail("dns.takeover: name=%s fake_ip=%s ttl=%s", name, ip, dnsFakeTTL)
}

// dnsTypeName DNS 查询类型的短名（只列我们日志里会碰到的几种）。
func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 5:
		return "CNAME"
	case 12:
		return "ANY"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS(SVCB)"
	default:
		return fmt.Sprintf("type%d", t)
	}
}

// ───────────────────────── 名字反查：假 IP 优先 ─────────────────────────

// nameOf 这个目标属于哪个域名：先查假 IP 池（DNS 接管发的），再查名字表（嗅探/解析来的）。
func (e *Engine) nameOf(ip net.IP) (string, bool) {
	if e.fake != nil {
		if n, ok := e.fake.NameFor(ip); ok {
			return n, true
		}
	}
	if e.names != nil {
		return e.names.NameFor(ip)
	}
	return "", false
}

// isFakeIP 这个地址是不是我们发的假 IP。
func (e *Engine) isFakeIP(ip net.IP) bool {
	return e.fake != nil && e.fake.Range().Contains(ip)
}

// sweepFakeIP 回收过期的假 IP（一个名字过期后地址还给池子）。
func (e *Engine) sweepFakeIP() {
	if e.fake == nil {
		return
	}
	gone := e.fake.Sweep()
	if len(gone) == 0 {
		return
	}
	e.mu.Lock()
	for _, n := range gone {
		delete(e.tookSeen, n)
	}
	e.mu.Unlock()
	e.bus.Debug("fakeip.recycle: count=%d names=%v", len(gone), gone)
}

// udpPayload 从 IP 包里取出 UDP 负载，并返回地址/端口（DNS 接管要互换它们）。
// udpSrcPort 只取 UDP 源端口（不做分配、不取地址/载荷）。
//
// 为什么单独一个：包循环里拿它排掉“我们自己解析器发的查询”，**每个包都要跑**。
// 用 udpPayload 会把两个地址各 copy 一块新 slice（实测每包两次小分配 → GC 压力），
// 而我们只想要那个端口号。
func udpSrcPort(pkt []byte) (uint16, bool) {
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok || proto != 17 || len(pkt) < ihl+4 {
		return 0, false
	}
	return be16(pkt, ihl), true
}

// udpPayload 一个 UDP 包的地址、端口与载荷。
func udpPayload(pkt []byte) (udpInfo, []byte, bool) {
	var u udpInfo
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok || proto != 17 || len(pkt) < ihl+8 {
		return u, nil, false
	}
	u.src = append(net.IP(nil), pkt[12:16]...)
	u.dst = append(net.IP(nil), pkt[16:20]...)
	u.sport = be16(pkt, ihl)
	u.dport = be16(pkt, ihl+2)
	l := int(be16(pkt, ihl+4)) // UDP 长度（含 8 字节头）
	end := ihl + l
	if l < 8 || end > len(pkt) {
		end = len(pkt)
	}
	return u, pkt[ihl+8 : end], true
}

// udpInfo 一个 UDP 包的地址与端口。
type udpInfo struct {
	src, dst     net.IP
	sport, dport uint16
}

// dnsFakeTTL 我们发出的假 A 记录的 TTL。
//
// maxObservedTTL 观测到的名字最多记住多久（见 dnsLoop 里的封顶）：
// 名字表的真实用途是“应用刚解析完就要连”，10 分钟绰绰有余；
// 用它换掉报文里的原始 TTL，避免长跑后表无限变大、每次写入都重建全表索引。
//
// 短一点有三个好处：① 假 IP 回收得快，池子不易满；
// ② 我们重启后应用缓存里的旧假 IP 很快失效（假 IP 映射不落盘）；
// ③ 名字对应的真实 IP 变化时跟着快。
const dnsFakeTTL = 60 * time.Second

// maxObservedTTL 观测到的名字最多记多久（见 dnsLoop 里的封顶）。
const maxObservedTTL = 10 * time.Minute

// buildDNSResponse 造一条 DNS 应答；ip 为 nil 表示“明确告诉它没有这条记录”
// （用于 AAAA：空 NOERROR，防止应用走 IPv6 绕过我们）。
//
// 实测配方（见 KB 决策/2026-09-21-DNS接管已验证可行.md）—— 缺一个就被静默丢弃：
// 新建缓冲区、问题段逐字节搬、ANCOUNT/NSCOUNT/ARCOUNT 写对（丢掉 EDNS0 OPT）、
// QR=1 且 RD 跟查询一致、RA=1、IP 与 UDP 的地址/端口互换、长度改对。
func buildDNSResponse(pkt []byte, u udpInfo, q dnssniff.Query, ip net.IP) []byte {
	payload, ok := udpPayloadOnly(pkt)
	if !ok || q.QEnd > len(payload) || len(payload) < 12 {
		return nil
	}
	dns := make([]byte, 0, 12+(q.QEnd-12)+16)
	hdr := make([]byte, 12)
	copy(hdr, payload[:12])
	hdr[2] = 0x80 | (payload[2] & 0x01) // QR=1，RD 跟查询一致
	hdr[3] = 0x80                       // RA=1，RCODE=0
	if ip != nil {
		putBE16(hdr, 6, 1) // ANCOUNT=1
	} else {
		putBE16(hdr, 6, 0) // 空应答
	}
	putBE16(hdr, 8, 0)  // NSCOUNT=0
	putBE16(hdr, 10, 0) // ARCOUNT=0（丢掉 EDNS0 OPT，否则计数对不上）
	dns = append(dns, hdr...)
	dns = append(dns, payload[12:q.QEnd]...) // 问题段原样

	if ip != nil {
		ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01} // 名字指针 + TYPE=A + CLASS=IN
		ttl := uint32(dnsFakeTTL / time.Second)
		ans = append(ans, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
		ans = append(ans, 0x00, 0x04)
		ans = append(ans, ip.To4()...)
		dns = append(dns, ans...)
	}

	// 套回 IP + UDP（源/目标互换）
	ipLen := 20 + 8 + len(dns)
	resp := make([]byte, 0, ipLen)
	head := append([]byte{}, pkt[:20]...)
	copy(head[12:16], pkt[16:20]) // 源 = 原目标（DNS 服务器）
	copy(head[16:20], pkt[12:16]) // 目标 = 原来源（本机）
	putBE16(head, 2, uint16(ipLen))
	putBE16(head, 10, 0) // IP 校验和交给 CalcChecksums
	resp = append(resp, head...)
	resp = append(resp, byte(u.dport>>8), byte(u.dport))
	resp = append(resp, byte(u.sport>>8), byte(u.sport))
	ul := 8 + len(dns)
	resp = append(resp, byte(ul>>8), byte(ul), 0, 0)
	return append(resp, dns...)
}

// udpPayloadOnly 只取 UDP 负载（不关心地址）。
func udpPayloadOnly(pkt []byte) ([]byte, bool) {
	_, payload, ok := udpPayload(pkt)
	return payload, ok
}

// realResolver **绕开我们自己**的解析器：用专用源端口发查询。
//
// 为什么需要：DNS 接管会“看”到本机所有出方向 DNS 查询（包括我们自己进程发的）——
// 而拿到假 IP 后我们要把它换回**真实 IP**，如果那次解析也被自己塞了假 IP，
// 就是自己骗自己、跳进死循环。所以自己的查询从一个专用端口段发，并在过滤器里排除。
//
// 服务器地址仍然由系统配置决定（Go 的 Resolver 会把服务器地址传进来）。
func (e *Engine) realResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// 端口被占就往后找一个
			for p := dnsProbePortLo; p <= dnsProbePortHi; p++ {
				d := net.Dialer{
					Timeout:   3 * time.Second,
					LocalAddr: &net.UDPAddr{Port: p},
				}
				c, err := d.DialContext(ctx, "udp", address)
				if err == nil {
					return c, nil
				}
			}
			return nil, fmt.Errorf("DNS 探针端口 %d-%d 都被占用", dnsProbePortLo, dnsProbePortHi)
		},
	}
}

// resolveReal 把一个域名在本机解析成**真实 IP**（绕开我们自己的假 IP）。
//
// 拿到后调用方应该把它记进名字表（见 noteRealIP）—— 假 IP 只是为了让包能被拦到，
// 真实 IP 才是“这个名字现在实际用哪个地址”，它同时也是界面统计的数据源。
func (e *Engine) resolveReal(name string) net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := e.realResolver().LookupIP(ctx, "ip4", name)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			return v4
		}
	}
	return nil
}

// noteRealIP 记下“我们代理自己解出来的真实 IP”（DNS 接管路径专用）。
//
// 优先级用 PrioObserved（和嗅到的 DNS 应答同级）：dnsmap 是“只升不降”，所以
// 配置里 hosts/域名规则写死的映射（PrioRule）不会被这里覆盖 —— 那是用户明写的意图。
// TTL 与假 IP 同寿命（dnsFakeTTL）：过期自然回收，不会长期留着旧 IP。
func (e *Engine) noteRealIP(name string, ip net.IP) {
	v4 := ip.To4()
	if v4 == nil || e.names == nil {
		return
	}
	before := e.names.IPsFor(name)
	e.names.SetWithTTL(name, []string{v4.String()}, dnsmap.PrioObserved, dnsFakeTTL)
	if !sameStrSet(before, e.names.IPsFor(name)) {
		// 通了新 IP → 让内核过滤器把目标换进来（否则包到不了我们手里）
		e.applyHostIPs()
		e.onWildcardsChanged()
	}
}

// dnsCanaries 自检用的“不相干名字”（不属于任何通配规则，必须能解析出**真实 IP**）。
//
// 为什么需要：透明拦截工具最不该做的事是“一开就让人上不了网”。DNS 接管只应该
// 改变命中通配规则的名字，其余必须照常 —— 这一条不能靠“我觉得对”，要能验、
// 而且要能自己说出来。
var dnsCanaries = []string{"www.baidu.com", "www.qq.com"}

const (
	// dnsSelfCheckRetry 自检失败后的复测间隔（瞬时抖动与真故障的分界）。
	dnsSelfCheckRetry = 20 * time.Second
	// dnsSelfCheckQuiet 本机网络刚变化后多久之内根本不查（见 netChangedWithin）。
	dnsSelfCheckQuiet = 30 * time.Second
)

// dnsCanaryProbe 一条 canary 名字的探测结果。
type dnsCanaryProbe struct {
	Name       string
	IPs        []net.IP
	Err        error
	Answerable bool // 这个名字命中通配规则（本来就归我们答）—— 那它就不是“不相干名字”了
	Fake       bool // 解出来的是我们发的假 IP
}

// ok 这条 canary 的表现算“照常”吗。
//
// 两种都算：解出了真实 IP；或者它本来就命中通配规则 —— 那种情况下被答成假 IP 是
// 用户明写的意图，不是故障（自检的前提“它不属于任何通配规则”在这个名字上不成立）。
func (p dnsCanaryProbe) ok() bool {
	if p.Err != nil || len(p.IPs) == 0 {
		return false
	}
	return !p.Fake || p.Answerable
}

// why 这条 canary 为什么算失败（人话，直接进日志）。
func (p dnsCanaryProbe) why() string {
	if p.Fake && !p.Answerable {
		return fmt.Sprintf("%s 被答成了我们自己的假 IP（%v）", p.Name, p.IPs)
	}
	return fmt.Sprintf("%s 解不出（%v）", p.Name, p.Err)
}

// probeDNSCanaries 用**系统解析器**（应用走的那条路）解一遍所有 canary。
//
// 解名与判据分开：解名是这条路径，判据是纯函数（judgeDNSProbe）—— 这样“什么情况下
// 才该报那条 ERROR”能逐条钉在用例里，不用真去动本机 DNS。
func probeDNSCanaries(lookup func(string) ([]net.IP, error), isFake func(net.IP) bool, answerable func(string) bool) []dnsCanaryProbe {
	out := make([]dnsCanaryProbe, 0, len(dnsCanaries))
	for _, name := range dnsCanaries {
		p := dnsCanaryProbe{Name: name, Answerable: answerable(name)}
		p.IPs, p.Err = lookup(name)
		for _, ip := range p.IPs {
			if isFake(ip) {
				p.Fake = true
			}
		}
		out = append(out, p)
	}
	return out
}

// dnsProbeAnyOK 这一轮里有没有“照常”的 canary（至少一个就算通过，与原来的口径一致）。
func dnsProbeAnyOK(list []dnsCanaryProbe) bool {
	for _, p := range list {
		if p.ok() {
			return true
		}
	}
	return false
}

// dnsProbeReasons 这一轮里失败的那几条的原因。
func dnsProbeReasons(list []dnsCanaryProbe) []string {
	var out []string
	for _, p := range list {
		if !p.ok() {
			out = append(out, p.why())
		}
	}
	return out
}

// dnsProbeVerdict 复测之后的结论。
type dnsProbeVerdict int

const (
	dnsProbeOK   dnsProbeVerdict = iota // 照常
	dnsProbeEnv                         // 本机 DNS 整体不可用，但**不是我们干的**
	dnsProbeOurs                        // 我们有份 → 该大声报
)

// judgeDNSProbe 复测仍失败时下结论：这次解不出来，跟我们有没有关系？（纯函数）
//
// 为什么要归因，而不是“解不出来就报”：探针走的是**系统解析器**，所以
// “本机 DNS 整体不可用”与“我们把别的名字答坏了”在这一层长得一模一样。
// 2026-10-16 08:58 就是这个坑：机器从睡眠唤醒、物理网卡还没起来
// （事件日志：08:58:57 唤醒，08:59:07 网卡才有地址），系统解析器必然解不出 ——
// Windows 自己的时间服务在同一秒也在报 WSAHOST_NOT_FOUND。那天自检刷了一条
// “我们把 DNS 弄坏了”的 ERROR。
//
// 归因是**结构性**的，不是猜：我们往网上发 DNS 应答的唯一入口是 takeoverQuery，
// 而它被 WildcardMatch 挡着（不命中就一个包都不发；注入句柄还是 filter=false，
// 只塞不拦）—— 于是“本轮 tookOver 没涨”= 我们一个应答都没发过 = 与我们无关。
//
// 反过来，只要这轮我们发过应答、或者 canary（本不该被我们答的名字）被答成了假 IP，
// 就照旧大声报 —— 那才是这个自检要抓的东西。
func judgeDNSProbe(second []dnsCanaryProbe, injected bool) (dnsProbeVerdict, []string) {
	bad := dnsProbeReasons(second)
	if len(bad) == 0 {
		return dnsProbeOK, nil
	}
	for _, p := range second {
		if p.Fake && !p.Answerable {
			return dnsProbeOurs, bad // 明证：不相干的名字被我们答了
		}
	}
	if injected {
		return dnsProbeOurs, bad // 这轮我们发过应答 → 不能排除自己
	}
	return dnsProbeEnv, bad
}

// dnsTakeoverSelfCheck 验“除指定域名外的解析照常吗”。
//
// **只报警，不自己关**：这个功能就是干这个的，一有问题就自废就没意义了。
// （唯一会自动退让的情形是“本机还有别的程序也在拦 DNS”导致的乒乓，那是真打架，
// 见 dnsTakeoverLoop 里的检测。）
//
// 三层判据：
//
//	① 至少一个 canary 照常 → 通过（verbose 一行，normal 档什么都不写）。
//	② 失败**先不下结论**：唤醒/换网那几秒本来就会解不出来，等 dnsSelfCheckRetry
//	   再解一遍；复测通过只写 verbose。
//	③ 复测仍失败才**归因**（judgeDNSProbe）：不是我们干的 → verbose 说清；
//	   有我们的份 → ERROR，原文照旧。
func (e *Engine) dnsTakeoverSelfCheck() {
	before := e.tookOver.Load()
	lookup := func(name string) ([]net.IP, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return net.DefaultResolver.LookupIP(ctx, "ip4", name)
	}
	probe := func() []dnsCanaryProbe {
		return probeDNSCanaries(lookup,
			func(ip net.IP) bool { return e.isFakeIP(ip) },
			func(name string) bool { return e.ruleSet().WildcardMatch(name) })
	}

	first := probe()
	if dnsProbeAnyOK(first) {
		// 自检通过属于“一切都好”的自证行 → verbose 档（失败仍是 Error，两档都看得见）。
		e.bus.Detail("dns.selftest: ok canaries=%v", dnsCanaries)
		return
	}
	// ② 复测：给“瞬时不可用”一次自己好的机会（别再让唤醒那几秒制造假警报）。
	retry := e.dnsRetry
	if retry <= 0 {
		retry = dnsSelfCheckRetry
	}
	select {
	case <-e.done:
		return
	case <-time.After(retry):
	}
	second := probe()
	verdict, bad := judgeDNSProbe(second, e.tookOver.Load() != before)
	switch verdict {
	case dnsProbeOK:
		// 第一轮失败、复测通过 —— “早上报一次、再查就好了”这种现场材料必须留得下（verbose），
		// 否则下次还得靠猜。
		e.bus.Detail("dns.selftest: 复测通过（第一轮：%v）—— 瞬时不可用，与 DNS 接管无关", dnsProbeReasons(first))
		return
	case dnsProbeEnv:
		e.bus.Detail("dns.selftest: 本机 DNS 此刻整体不可用（%v）—— 本轮我们没有注入过任何应答，"+
			"与本机 DNS 接管无关（刚唤醒/刚换网/现场网络不通时都这样）", bad)
		return
	}
	e.bus.Error("dns.selftest: failed bad=%d total=%d detail=%v", len(bad), len(dnsCanaries), bad)
	e.bus.Error("  —— 注意：DNS 接管只应该改变**命中通配规则**的名字，其余必须照常。" +
		"这条已经影响别的名字了，请把上面几行日志发回来（功能不会自动关闭，但这个问题得查）")
}

// dnsTakeoverGuard 起来后马上自检一次，之后每 10 分钟复查（环境会变）。
func (e *Engine) dnsTakeoverGuard() {
	defer e.wg.Done()
	// 稍微等一下再查：启动瞬间本地 DNS 栈可能还在忙
	select {
	case <-e.done:
		return
	case <-time.After(3 * time.Second):
	}
	e.dnsTakeoverSelfCheck()
	tk := time.NewTicker(10 * time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			if !e.dnsTakeoverRunning() {
				continue
			}
			// ③ 本机网络刚变过（唤醒/插拔网线/换 Wi-Fi）：那几秒里 DNS 本来就不可用，
			// 现在查是白查 —— 让给下一轮（2026-10-16 早上那次误报正好落在这个窗口里：
			// 08:58:57 唤醒，08:59:07 网卡才有地址，自检在 08:58:58 就跑了）。
			if e.netChangedWithin(dnsSelfCheckQuiet) {
				e.bus.Detail("dns.selftest: 跳过本轮（本机网络刚变化，等它稳下来）")
				continue
			}
			e.dnsTakeoverSelfCheck()
		}
	}
}

// netChangedWithin 本机网络在 d 之内刚变化过吗（唤醒/换网/插拔网线）。
//
// 时刻来自 localNetLoop 的采样（它每 10 秒看一眼本机非回环地址），只看**真变了**的
// 那一次；引擎启动后的首次采样不算（见那里的注释）。
func (e *Engine) netChangedWithin(d time.Duration) bool {
	at := e.netChangedAt.Load()
	if at == 0 {
		return false
	}
	return time.Since(time.Unix(0, at)) < d
}

// dnsTakeoverRunning DNS 接管句柄还在不在。
func (e *Engine) dnsTakeoverRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.injector != nil
}

// noticeSeen 直连/阻断日志去重用的一条记录。
type noticeSeen struct {
	key  string // 动作 + 目标
	last time.Time
}

// noteAction 同一动作在同一条连接上（同一源端口 + 同一目标）只报一行。
// 源端口被系统复用给另一个目标时，目标变了就再报一行。
func (e *Engine) noteAction(kind string, sport uint16, dst net.IP, dport uint16, note string) {
	e.noticeTick(sport, kind, dst, dport)
	e.bus.Throttle(fmt.Sprintf("action:%s:%s:%d", kind, dst, dport), time.Minute,
		"[%s] %s:%d  %s", kind, dst, dport, note)
}

// noteActionDetail 同 noteAction，但归到“详细日志”（内置直连那类刷屏项用它）。
func (e *Engine) noteActionDetail(kind string, sport uint16, dst net.IP, dport uint16, note string) {
	e.noticeTick(sport, kind, dst, dport)
	if e.bus.Verbose() {
		e.bus.Throttle(fmt.Sprintf("action:%s:%s:%d", kind, dst, dport), time.Minute,
			"[%s] %s:%d  %s", kind, dst, dport, note)
	}
}

// noticeTick 记下“这个源端口最后是什么动作/目标”（连接表与排查用）。
func (e *Engine) noticeTick(sport uint16, kind string, dst net.IP, dport uint16) {
	key := kind + " " + fmt.Sprintf("%s:%d", dst, dport)
	e.mu.Lock()
	if e.notices == nil {
		e.notices = map[uint16]noticeSeen{}
	}
	e.notices[sport] = noticeSeen{key: key, last: time.Now()}
	e.mu.Unlock()
}

// procLookupTries / procRetryEvery 一条连接最多查几次进程表、每次至少隔多久
// （见 connState.procTries）：新连接的头几拍常查不到（表还没刷新到它），
// 所以按时间间隔给它几次机会；短连接只试一次，长会话会被后续包补上。
const (
	procLookupTries = 5
	procRetryEvery  = 200 * time.Millisecond
)

// flowProc 这条连接的进程名 / PID。
//
// 三层次序：① 连接上已经查到过 → 用缓存的；② 试够了还没查到
// → 不再每包重查；③ 查一次表（常见情况只是内存里 map 命中）。
// flowProc 这条连接的进程名 / PID。
//
// 三层次序：① 连接上已经查到过 → 用缓存的；② 这个连接查过一次没查到
// （受保护进程/已消失）→ 不再每包重查；③ 查一次表（常见情况只是内存里 map 命中）。
//
// 为什么现在**总是查**（不再要求“规则里写了进程条件”）：
//   - 后台每 500ms 刷表这件事本来就在跑（resolver 在 New() 里建、Start() 里启），
//     省掉的只是一个 map 查找（实测命中 ~0.1µs，见 local/procbench）；
//   - 换来的是日志与连接列表里都有进程名（实测以前几乎全是 proc=unknown），
//     而“到底是谁在连这个地址”正是现场第一个要问的问题。
func (e *Engine) flowProc(sport uint16) (string, uint32) {
	if e.proc == nil {
		return "", 0
	}
	if st := e.flow(sport); st != nil {
		if st.procName != "" {
			return st.procName, st.pid
		}
		if st.procTries.Load() >= procLookupTries {
			return "", 0 // 试够了还查不到（受保护进程/已消失），别每个包都再查
		}
		now := time.Now().UnixNano()
		if now < st.procNext.Load() {
			return "", 0 // 距上次尝试太近：等下一个包再来
		}
		st.procNext.Store(now + int64(procRetryEvery))
		st.procTries.Add(1)
	}
	name, pid, _ := e.proc.ByPort(sport)
	if name == "" {
		// 只在详细日志里说：查不出进程名到底是“表里没这个端口”还是“打不开这个进程”。
		// 这两个在包路径上完全看不出区别（都表现为 proc=unknown）。
		e.bus.Debug("proc.lookup: port=%d result=unknown pid=%d", sport, pid)
	}
	return name, pid
}

// ProcStats 进程解析器缓存规模（诊断页用）。
func (e *Engine) ProcStats() (ports, pids int) {
	if e.proc == nil {
		return 0, 0
	}
	return e.proc.Stats()
}

// ProcPath 某个 PID 的完整路径（界面看“到底是谁”时用）。
func (e *Engine) ProcPath(pid uint32) string {
	if e.proc == nil {
		return ""
	}
	return e.proc.FullPath(pid)
}

// connWho 拼连接级日志里的“谁”：`curl.exe (12376)`。
//
// 对齐 Proxifier 的写法（`iexplore.exe (2972) - proxifier.com:80 open`）。
// 进程查不到时写“未知进程” —— 宁可说不知道，也不要留空让人以为是空字符串。
func connWho(procName string, pid uint32) string {
	if procName == "" {
		return "未知进程"
	}
	if pid == 0 { // PID 0 是空闲进程，永远不拥有 TCP 连接，打出来只会骗人
		return procName
	}
	return fmt.Sprintf("%s (%d)", procName, pid)
}

// connTarget 拼连接级日志里的“目标”：名字已知就写 `名字(IP):端口`。
//
// 为什么要名字：现场是运维在看日志，`192.0.2.217:80` 认不出是哪个业务，
// `main.example.com` 一眼就懂。Proxifier 每条连接都带 hostname，正是这个道理。
func (e *Engine) connTarget(ip net.IP, dport uint16) string {
	if n, ok := e.nameOf(ip); ok && n != "" && n != ip.String() {
		return fmt.Sprintf("%s(%s):%d", n, ip, dport)
	}
	return fmt.Sprintf("%s:%d", ip, dport)
}

// connTargetDial 同 connTarget，但假 IP 只写名字。
//
// 假 IP（198.19.x.x）是我们自己发的临时地址，写进日志只会让现场去查一个不存在的地址；
// 名字才是应用真正要连的东西。名字没登记时（重启前发的旧应答）老实标出来。
func (e *Engine) connTargetDial(orig, dial net.IP, dport uint16) string {
	if e.isFakeIP(orig) {
		if n, ok := e.nameOf(orig); ok && n != "" {
			return fmt.Sprintf("%s:%d", n, dport)
		}
		return fmt.Sprintf("%s:%d（假 IP 未登记）", orig, dport)
	}
	return e.connTarget(dial, dport)
}

// ruleSuffix 给“直连/阻断”那类行内日志补上规则序号（有就补）。
func ruleSuffix(ruleNo int, ruleName string) string {
	if ruleNo <= 0 {
		return ""
	}
	if ruleName == "" {
		return fmt.Sprintf("（规则 %d）", ruleNo)
	}
	return fmt.Sprintf("（规则 %d %s）", ruleNo, ruleName)
}

// hitText “命中第 N 条规则「名字」”；ruleNo<=0 = 没有规则命中。
func hitText(ruleNo int, ruleName string) string {
	switch {
	case ruleNo <= 0:
		return "没有规则命中"
	case ruleName == "":
		return fmt.Sprintf("命中第 %d 条规则", ruleNo)
	default:
		return fmt.Sprintf("命中第 %d 条规则「%s」", ruleNo, ruleName)
	}
}

// routeMatchLog 记一行“这条连接为什么这么走”（verbose 档）。
//
// 对齐 Proxifier 的规则处理消息（Verbose 档才输出）：
//
//	[02.01 11:18:37] iexplore.exe (2972) - proxifier.com:80 matching Default rule : using Failover proxy chain
//
// 为什么要它：normal 档只记“连接开/关”，而“这个目标为什么没走隧道 / 怎么走了这条链”
// 以前在日志里根本无处可查（只能猜或去翻配置）。
//
// 去重按**五元组的源端口 + 目标**：一条连接一行（Proxifier 就是每条连接一行），
// 而 SYN 重传（同源端口、同目标）在 1 分钟内塌成一行 —— 吞掉的条数由 Throttle 自己补出来。
func (e *Engine) routeMatchLog(sport uint16, dst net.IP, dport uint16, procName string, pid uint32, verdict string) {
	if !e.bus.Verbose() {
		return
	}
	who := "proc=unknown"
	if procName != "" {
		who = fmt.Sprintf("proc=%s pid=%d", procName, pid)
	}
	e.bus.Throttle(fmt.Sprintf("route:%d:%s:%d", sport, dst, dport), time.Minute,
		"route.match: %s target=%s:%d → %s", who, dst, dport, verdict)
}

// isSyn 只看 SYN（不带 ACK）—— 新连接的第一个包。
func isSyn(flags byte) bool { return flags&0x02 != 0 && flags&0x10 == 0 }

// builtinDirectPort 内置直连端口：Windows 更新传递优化（Delivery Optimization）。
// 这些连接在客户内网里应直连，不该进隧道 —— 以前靠配置里写 direct 规则，现在内置。
const builtinDirectPort = 7680

// rewriteOutbound 把应用发往内网目标的包改成"发给本机 relay"。
func (e *Engine) rewriteOutbound(h *divert.Handle, pkt []byte, addr *divert.Address, t int,
	src, dst net.IP, sport, dport uint16, flags byte, chain string, relayIP net.IP, relayPort uint16,
	ruleNo int, ruleName, procName string, pid uint32) {

	if isSyn(flags) {
		// A14：新建连接时判一次环（目标=上游自己 / 源=目标 / 同目标疯狂重连）
		e.checkLoop(src, dst, dport, chain)
		// A19：抓包写“改写前”的形态（目标还是内网地址）——拿 Wireshark 看就是一段正常会话
		e.cap.note(pkt)
		e.mu.Lock()
		_, existed := e.conns[sport]
		_, isSelf := e.selfPorts[sport]
		st := &connState{
			dst: dst, dport: dport,
			app: append(net.IP(nil), src...), appPort: sport,
			chain: chain, action: rules.ActionChain, start: time.Now(),
			ruleNo: ruleNo, ruleName: ruleName,
			procName: procName, pid: pid,
			self:    isSelf,
			counted: !isSelf, // 紧接着（!existed 时）会 statActive++
		}
		// 调用方刚刚查过一次进程表（flowProc）：不额外标记，
		// 让后续几个包还有机会补上（新连接的第一拍常查不到，见 procTries）。
		st.touch()
		e.conns[sport] = st
		if !existed {
			if !isSelf {
				e.statTotal++
				e.statActive++
				e.statPerRule[chain]++
			}
		}
		e.mu.Unlock()
		if !existed {
			// 目标是假 IP 时，日志里要看到**域名**（否则只能看到一个 198.19.x.x 莫明其妙）
			if e.isFakeIP(dst) {
				if n, ok := e.nameOf(dst); ok {
					st.fakeName = n
				}
			}
			e.routeMatchLog(sport, dst, dport, procName, pid, hitText(ruleNo, ruleName)+" → 走链 "+chain)
			// 对齐 Proxifier 的 open 行：谁 → 哪 → 走哪条链。
			// 规则明细在 verbose 的 route.match 里，normal 这一行不重复写一遍。
			e.connInfo(st.self, "open: %s → %s via %s",
				connWho(procName, pid), e.connTargetDial(dst, dst, dport), chain)
		}
	} else if st := e.flow(sport); st != nil {
		st.touch()
	}

	// 目标 → relay；源也改成 relay 的 IP（关键！否则环回口丢包）
	copy(pkt[offDstIP:offDstIP+4], relayIP)
	putBE16(pkt, t+offDstPort, relayPort)
	copy(pkt[offSrcIP:offSrcIP+4], relayIP)

	if flags&0x04 != 0 { // RST：应用主动断了，标结束（条目留着给界面看）
		if st := e.flow(sport); st != nil {
			e.finish(st)
		}
	}

	divert.CalcChecksums(pkt, addr, divert.ChecksumDefault)
	if _, err := h.Send(pkt, addr); err != nil {
		e.bus.Throttle("inject.fail", time.Minute, "注入失败: %v（1 分钟内的重复不再逐条记）", err)
	}
}

// rewriteInbound 把 relay 回来的包改回"来自真正的内网目标"。
func (e *Engine) rewriteInbound(h *divert.Handle, pkt []byte, addr *divert.Address, t int, dport uint16) {
	st := e.flow(dport) // dport = 应用的源端口
	if st == nil {
		_, _ = h.Send(pkt, addr)
		return
	}
	st.touch()
	copy(pkt[offSrcIP:offSrcIP+4], st.dst.To4()) // 源 = 应用实际连的那个地址（假 IP 场景就是假 IP）
	putBE16(pkt, t+offSrcPort, st.dport)
	copy(pkt[offDstIP:offDstIP+4], st.app.To4())
	putBE16(pkt, t+offDstPort, st.appPort)
	divert.CalcChecksums(pkt, addr, divert.ChecksumDefault)
	// A19：入方向写“改写后”的形态（看起来就是从内网目标回来的）
	e.cap.note(pkt)
	if _, err := h.Send(pkt, addr); err != nil {
		e.bus.Throttle("inject.fail", time.Minute, "注入失败: %v（1 分钟内的重复不再逐条记）", err)
	}
}

// flow 按源端口取连接状态（读锁：每个包都要走，不能和写路径抢）。
func (e *Engine) flow(sport uint16) *connState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.conns[sport]
}

// passCount 直连/阻断包的一次记账：找出这条连接，按方向累加字节。
//
// **回包不能拿源端口查表**：出方向的包源端口 = 应用端口（连接表的 key），
// 而回包的源端口是**对端端口**（例如 127.0.0.1:7897）—— 用它查表永远查不到，
// 下行就一个字节都不记。这就是以前“直连只能统计出方向”的成因。
// 环回直连的回包也会被内核过滤器当 outbound 交给我们（实测日志里 `[直连] 127.0.0.1:51028`
// 的 dport 就是应用端口），所以它本来就到了我们手上，只是账没记对。
// 回包只能按 dport（= 应用端口）反查，并要求 st.dport 正好是本包的源端口 ——
// 两个端口严丝合缝才算同一条连接，否则出方向的包在连接表刚被回收时会串到别人头上。
// 真网段直连的回包是 inbound，压根不进过滤器（见 buildFilter），那种目标仍然只有出方向。
func (e *Engine) passCount(sport, dport uint16, n int, act rules.Action, fin bool) {
	st, inbound := e.flow(sport), false
	if st == nil {
		if back := e.flow(dport); back != nil && back.dport == sport && back.action == rules.ActionDirect {
			st, inbound = back, true
		}
	}
	if st == nil {
		return
	}
	st.touch()
	st.packets.Add(1)
	if act == rules.ActionDirect {
		if inbound {
			st.down.Add(uint64(n))
			e.dirDown.Add(uint64(n)) // 顶栏流量图的直连口径
		} else {
			st.up.Add(uint64(n))
			e.dirUp.Add(uint64(n)) // 同上：直连口径
		}
	}
	if !inbound && fin { // 回包的 FIN 不重复收尾（它和出方向那条 FIN 是同一个连接）
		e.finish(st)
	}
}

// passThrough 处理直连与阻断：计数 + 必要时记一行日志（去重）。
// 直连的包原样放回内核转发；阻断的包丢掉，并在 SYN 上回一个 RST。
func (e *Engine) passThrough(h *divert.Handle, pkt []byte, addr *divert.Address, t int,
	src, dst net.IP, sport, dport uint16, flags byte, act rules.Action, ruleNo int, ruleName, procName string, pid uint32, detail bool) {

	if isSyn(flags) {
		e.mu.Lock()
		if _, ok := e.conns[sport]; !ok {
			st := &connState{dst: dst, dport: dport, app: append(net.IP(nil), src...),
				appPort: sport, action: act, start: time.Now(),
				ruleNo: ruleNo, ruleName: ruleName, procName: procName, pid: pid,
				// 规则路径的直连目标只在开了“直连统计”时才进过滤器（内置直连 7680
				// 走 detail=true 另一条路，它一直在）
				statsOnly: act == rules.ActionDirect && !detail}
			st.touch()
			e.conns[sport] = st
		}
		e.mu.Unlock()
		if act == rules.ActionDirect {
			if detail {
				e.noteActionDetail("直连", sport, dst, dport, "不走代理"+ruleSuffix(ruleNo, ruleName))
			} else {
				e.noteAction("直连", sport, dst, dport, "不走代理"+ruleSuffix(ruleNo, ruleName))
			}
		} else {
			e.noteAction("阻断", sport, dst, dport, "已丢弃"+ruleSuffix(ruleNo, ruleName))
		}
		verdict := hitText(ruleNo, ruleName) + " → 直连（不走代理）"
		switch {
		case detail:
			// 内置直连（7680）：ruleNo 也是 0，但那不是“没有规则命中”
			verdict = fmt.Sprintf("内置直连（dport=%d，Windows 更新传递优化）→ 直连（不走代理）", builtinDirectPort)
		case act == rules.ActionBlock:
			verdict = hitText(ruleNo, ruleName) + " → 阻断（丢包）"
		}
		e.routeMatchLog(sport, dst, dport, procName, pid, verdict)
	}

	e.passCount(sport, dport, len(pkt), act, flags&0x05 != 0) // FIN 或 RST 就在这一下里收尾

	if act == rules.ActionBlock {
		if isSyn(flags) {
			e.sendReset(h, pkt, addr, t, src, dst, sport, dport)
		}
		return // 阻断：包丢掉
	}
	// A19：直连的包原样写进抓包（能证实“这个目标确实没走隧道”）
	e.cap.note(pkt)
	_, _ = h.Send(pkt, addr)
}

// ── 速率采样 ──
//
// 为什么速率要在引擎侧算、而不是界面拿两次快照自己做差：
//   - 界面的轮询**只在「连接」页可见时**跑（1.5 秒一次）。切到别的页再回来做差，
