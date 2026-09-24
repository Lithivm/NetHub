package engine

import (
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/imgk/divert-go"
)

// QUIC（HTTP/3）走 UDP 443。我们不做 UDP 中继，所以这类包以前是**静默漏出**的：
// 目标虽然配了“走隧道”，浏览器一上来先试 QUIC，走的是直连（不经过我们、日志里一个字都没有），
// 要是那条路不通，应用还得自己等超时（实测好几秒）才回落 TCP。
//
// 现在的做法：把“该走链的目标”的 UDP 443 也装进内核过滤器（见 buildMainFilter），
// **拦到就丢掉并记一行日志** —— 它再也不会直连出去；TCP 那条路仍然是我们接管的。
//
// 关于回 ICMP 端口不可达（想让应用立刻回落 TCP、而不是自己等超时）：
// 这是**尽力而为**，没有当成承诺。实测（本机 Windows 11）：
//   - 回环目标（应用连本机地址）能收到，应用立刻报“连接被拒” → 按预期回落；
//   - 源地址不在本机所在子网时（内网 10.x、假 IP 198.19.x、甚至公网 219.x），
//     ICMP 在 WinDivert 层看得见、**应用却收不到** —— 系统在接口/WFP 层把它丢了。
//     三种注入方式都试过：用收到包的句柄回注、清 Outbound 位、换 filter=false 的
//     注入句柄（DNS 塞假应答用的那只）、把地址标成 Loopback —— 都一样。
//
// 所以：**丢掉包本身**才是这个功能真正兑现的东西；ICMP 只当运气好时的加速。
// 不影响正确性：应用自己的 QUIC 超时到了照样回落 TCP（浏览器还会并行跑 TCP 竞速）。
const (
	// quicPort QUIC 固定用的 UDP 端口。
	quicPort = 443
	// icmpHdrLen ICMP 头长度（type/code/checksum/4 字节其余）。
	icmpHdrLen = 8
	// icmpUnreachablePort ICMP type 3（目的不可达）code 3（端口不可达）。
	icmpUnreachablePort = 3
)

// buildICMPUnreachable 构造「目的端口不可达」的 ICMP 报文（源 = 原目标，目标 = 应用）。
//
// RFC 792 要求 ICMP 差错报文把**原数据报的 IP 头 + 至少前 8 字节传输层头**带回去 ——
// 少了这段，应用内核认不出这个差错属于哪个 socket，也就不会把它当成连接错误
// （表现就是回了个没用的包、应用照样等超时）。所以内嵌部分整段照抄原包。
func buildICMPUnreachable(pkt []byte, t int, src, dst net.IP) ([]byte, bool) {
	s4, d4 := src.To4(), dst.To4()
	if s4 == nil || d4 == nil || t < tcpHdrMin || len(pkt) < t+icmpHdrLen {
		return nil, false
	}
	inner := t + icmpHdrLen // 内嵌：原 IP 头 + 前 8 字节
	total := tcpHdrMin + icmpHdrLen + inner
	out := make([]byte, total)

	// 外层 IP 头：源/目标互换（看起来就是目标回给应用的），总长按实际写
	out[0] = 0x45 // IPv4, 首部 20 字节
	putBE16(out, ipOffTotalLen, uint16(total))
	out[8] = 64 // TTL
	out[offProto] = 1
	copy(out[offSrcIP:offSrcIP+4], d4) // 源 = 原目标
	copy(out[offDstIP:offDstIP+4], s4) // 目标 = 应用

	// ICMP 头 + 内嵌原数据报
	out[tcpHdrMin] = icmpUnreachablePort
	out[tcpHdrMin+1] = icmpUnreachablePort
	copy(out[tcpHdrMin+icmpHdrLen:], pkt[:inner])

	// 校验和自己算（不交给 WinDivert 的助手）。
	//
	// 为什么不用 divert.CalcChecksums：它的 ICMP 分支在我们这条路径上没被验证过，
	// 而且“算错了”的表现极难查 —— 包能抓得到、但内核默默丢弃（校验和错），
	// 应用看不到任何错误，看起来就像“这个功能根本没生效”（实测就这么绕过一圈）。
	// 自己算成纯 Go 的十几行，还能在单测里断言校验和正确。
	putBE16(out, tcpHdrMin+2, 0)
	putBE16(out, tcpHdrMin+2, checksum(out[tcpHdrMin:]))
	putBE16(out, 10, 0)
	putBE16(out, 10, checksum(out[:tcpHdrMin]))
	return out, true
}

// checksum 标准的 16 位反码和（IP / ICMP / TCP / UDP 都用它）。
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// blockQUIC 丢掉一个 QUIC 包（可选地回一个 ICMP 端口不可达，见文件头说明）。
//
// 只在“这个目标本该走我们”的时候才会被调用 —— UDP 443 只有落在规则网段里
// 才会进过滤器（直连的不进来，见 buildMainFilter）。
func (e *Engine) blockQUIC(h *divert.Handle, pkt []byte, addr *divert.Address, src, dst net.IP, ihl int) {
	if len(pkt) < ihl+icmpHdrLen {
		_, _ = h.Send(pkt, addr) // 头都不全，别乱动，原样放回
		return
	}
	dport := be16(pkt, ihl+offDstPort)
	if dport != quicPort {
		_, _ = h.Send(pkt, addr) // 不是 QUIC（防御性：理论上到不了这里）
		return
	}
	e.cap.note(pkt) // A19：抓包里能看到“这个 QUIC 被我们拦了”
	e.quicBlocked.Add(1)
	// 顺手回一个 ICMP 端口不可达（尽力而为：能落到应用就加速回落，落不到也不影响“已拦住”）。
	if icmp, ok := buildICMPUnreachable(pkt, ihl, src, dst); ok {
		// 注入姿势：拷一份地址、清 Outbound 位（bit1 = 0x02）—— 这是“回给应用”的包
		// 该有的方向（和 DNS 接管塞假应答同一套路）；从收到包的那只句柄回注则只在
		// WinDivert 层可见、应用一个字节都收不到。
		// addr 是循环里复用的接收地址，注入前拷一份改，别把接收状态改了。
		na := *addr
		na.Flags &^= 0x02
		sh := h
		if inj := e.injectorHandle(); inj != nil {
			sh = inj
		}
		if _, err := sh.Send(icmp, &na); err != nil {
			e.bus.Warn("quic.block: target=%s:%d icmp.inject.fail: %v", dst, dport, err)
		}
	}
	e.logQUICBlock(dst, dport)
}

// logQUICBlock 记一行“这个目标的 QUIC 被拦了”。
//
// 每个目标 60 秒最多一行：一次网页浏览能刷出几十上百个 QUIC 包，逐个记会把日志淹掉，
// 而现场需要的是“哪些目标在被拦”这个事实，不是包数（包数在 total 里累计）。
func (e *Engine) logQUICBlock(dst net.IP, dport uint16) {
	key := dst.String() + ":" + strconv.Itoa(int(dport))
	// “最近被拦的目标”给界面用（跟去重无关：它回答的是“到底拦了什么”）
	e.mu.Lock()
	e.quicNotices[key] = time.Now()
	e.mu.Unlock()
	// 日志：同一目标 60 秒最多一行；被吞掉的条数由总线补 `suppressed:` 行
	// （journald 的做法 —— 不补就等于日志在骗人：看起来只发生过一次）。
	e.bus.Throttle("quic.block:"+key, time.Minute,
		"quic.block: target=%s action=drop icmp=best-effort total=%d", key, e.quicBlocked.Load())
}

// prunquicNotices 清掉过期的 QUIC 日志去重记录（janitor 调）。
func (e *Engine) pruneQUICNotices() {
	cut := time.Now().Add(-10 * time.Minute)
	e.mu.Lock()
	for k, t := range e.quicNotices {
		if t.Before(cut) {
			delete(e.quicNotices, k)
		}
	}
	e.mu.Unlock()
}

// noteOnce 同一件事在窗口内只允许记一次；返回 true = 这次该记。
//
// 用于“重复出现但每次都没有新信息”的日志：同一个域名又用了 ECH、同一条上游又抖了一下……
// 这类东西第一次说有用（告诉现场“有这回事”），后面重复只把日志刷成噪声。
// 注意它只做去重，不做降级——该 WARN 的还是 WARN（要降级在调用处决定）。
func (e *Engine) noteOnce(key string, window time.Duration) bool {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.onceAt == nil {
		e.onceAt = map[string]time.Time{}
	}
	if last, seen := e.onceAt[key]; seen && now.Sub(last) < window {
		return false
	}
	e.onceAt[key] = now
	return true
}

// pruneOnce 清掉过期的去重记录（janitor 调）。
func (e *Engine) pruneOnce() {
	cut := time.Now().Add(-30 * time.Minute)
	e.mu.Lock()
	for k, t := range e.onceAt {
		if t.Before(cut) {
			delete(e.onceAt, k)
		}
	}
	e.mu.Unlock()
}

// QUICBlocked 累计拦了多少个 QUIC 包（界面/排查用）。
func (e *Engine) QUICBlocked() uint64 { return e.quicBlocked.Load() }

// QUICStats 累计拦下的包数 + **最近**被拦的目标（最多 5 个，新的在前）。
//
// 为什么要“最近”：光看包数回答不了现场那句“到底拦了什么、是不是我的业务”。
// 数据来自日志去重表（每个目标头一次被拦就记下时间，10 分钟没再见到就清掉）——
// 所以它说的是“这段时间谁在被拦”，不是“历史上出现过的所有目标”。
func (e *Engine) QUICStats() (uint64, []string) {
	type hit struct {
		target string
		at     time.Time
	}
	e.mu.Lock()
	hits := make([]hit, 0, len(e.quicNotices))
	for k, t := range e.quicNotices {
		hits = append(hits, hit{k, t})
	}
	e.mu.Unlock()
	sort.Slice(hits, func(i, j int) bool { return hits[i].at.After(hits[j].at) })
	const max = 5
	if len(hits) > max {
		hits = hits[:max]
	}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.target)
	}
	return e.quicBlocked.Load(), out
}
