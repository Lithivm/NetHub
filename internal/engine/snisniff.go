package engine

import (
	"fmt"
	"net"
	"nethub/internal/dnsmap"
	"nethub/internal/tlsname"
	"strings"
	"time"

	"github.com/imgk/divert-go"
)

// ───────────────────── 名字的第二个来源：TLS SNI / HTTP Host ─────────────────────

// sniSniffPorts 只读嗅探的端口：TLS 常见端口 + 明文 HTTP 常见端口。
//
// 为什么要端口白名单：嗅探的代价是“这些包的负载都拷一份到用户态”，
// 范围越小越好；而握手只发生在连接最开始，常见的就这几类端口。
// 内网服务端口不在表里的，可以用通配域名 + 明文 DNS 拿到（不依赖 SNI）。
var sniSniffPorts = []uint16{443, 8443, 9443, 6443, 4443, 10443, 80, 8080, 853} // 853=DoT

// sniSniffFilter 拼出方向 TCP 的嗅探过滤器（只读，不改任何包）。
//
// 加 `ip.Length < 1400` 是为了**开销**，不是为了省事：嗅探的代价在“每个匹配的包
// 都要拷一份到用户态”，而大包体量最大。实测 30MB 下载（全部经 Clash 的 443）
// 开销约 0.7s CPU；加上长度条件后大块数据包直接不进内核过滤，代价降到零头。
//
// 代价：极端大的 ClientHello（≥1400 字节，比如带 ECH 配置的）会被漏掉 ——
// 而 ECH 的名字本来我们也看不到（真名被加密），漏了不亏。
func sniSniffFilter() string {
	var c string
	for i, p := range sniSniffPorts {
		if i > 0 {
			c += " or "
		}
		c += fmt.Sprintf("tcp.DstPort == %d", p)
	}
	return "outbound and tcp and ip.Length < 1400 and (" + c + ")"
}

// sniBuf 一条连接攒起来的“开头几个字节”（连接只靠源端口区分，与拦截路径一致）。
type sniBuf struct {
	dst  net.IP
	data []byte
	at   time.Time
	done bool // 已经得出结论（学到了名字，或者判定不是我们要的）
}

// sniLoop 只读嗅探 TLS ClientHello / 明文 HTTP 请求，从中读出目标域名。
//
// 为什么要有它：名字原本靠“看明文 DNS 应答”学；一旦应用用了加密 DNS
// （DoH/DoT）或自带解析器，DNS 层就什么都看不见了。但握手是明文的 ——
// SNI 里还有名字。这就是“防患于未然”的那一半。
func (e *Engine) sniLoop() {
	defer e.wg.Done()

	filter := sniSniffFilter()
	h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityHighest, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Warn("TLS 嗅探：无法启动（%v）—— 加密 DNS 环境下通配域名将学不到名字", err)
		return
	}
	defer h.Close()
	if !e.trackSniff(h) {
		return // 已经在停止：直接退出（defer 会关 h）
	}
	e.bus.Debug("sni.sniff: started mode=read-only ports=%d filter=%s", len(sniSniffPorts), filter)

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	flows := map[uint16]*sniBuf{}
	tk := time.NewTicker(10 * time.Second)
	defer tk.Stop()

	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			// 定期把所有攒着的、没结论的连接丢掉（长连接 + 大流量不能无限攒）
			for k, f := range flows {
				if time.Since(f.at) > 20*time.Second || len(f.data) > 8192 {
					delete(flows, k)
				}
			}
			if len(flows) > 2048 { // 更硬的上限：宁可漏学，不能吃内存
				flows = map[uint16]*sniBuf{}
			}
		default:
		}

		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("TLS 嗅探中断: %v（通配域名将只能靠明文 DNS）", err)
				return
			}
		}
		pkt := buf[:n]

		// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
		// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
		if info, _, ok := udpPayload(pkt); ok && info.sport >= dnsProbePortLo && info.sport <= dnsProbePortHi {
			continue
		}
		src, dst, _, proto, ok := parseIPv4(pkt)
		if !ok || proto != 6 {
			continue
		}
		t := 20
		if _, _, ihl, _, ok2 := parseIPv4(pkt); ok2 {
			t = ihl
		}
		sport := be16(pkt, t+offSrcPort)
		payload := tcpPayload(pkt)
		if len(payload) == 0 {
			continue
		}
		_ = src

		f := flows[sport]
		if f == nil {
			// 只关心“第一条数据”的样子：不像 TLS/HTTP 就不管它（后面也别攒）
			if !tlsname.LooksLikeTLS(payload) && !tlsname.LooksLikeHTTP(payload) {
				continue
			}
			f = &sniBuf{dst: dst, at: time.Now()}
			flows[sport] = f
		}
		if f.done || len(f.data) > 8192 {
			delete(flows, sport)
			continue
		}
		f.data = append(f.data, payload...)
		f.at = time.Now()

		// TLS 要看整条记录；HTTP 只要够一个请求头（通常第一段就够）
		if tlsname.LooksLikeTLS(f.data) && !tlsname.Complete(f.data) {
			continue
		}
		res, okr := tlsname.Name(f.data)
		if !okr {
			// 已经有结论了：不是 TLS 也不是 HTTP（或者没 SNI/Host）→ 别死等
			if len(f.data) > 512 {
				f.done = true
				delete(flows, sport)
			}
			continue
		}
		f.done = true
		delete(flows, sport)
		e.learnFromHandshake(res, dst)
	}
}

// learnFromHandshake 从握手里学到的名字 → 名字表（与 DNS 观察走同一条流水线）。
func (e *Engine) learnFromHandshake(res tlsname.Result, dst net.IP) {
	if res.Name == "" || dst == nil {
		return
	}
	if res.ECH {
		// ECH：SNI 里只是“公开名”，真名被加密了 —— 坦诚地说出来，别让人以为通了。
		// 但同一个域名每次握手都重复说一遍没意义（实测 22 分钟里刷了十几行）：
		// 它是个**稳定属性**，不是“刚发生的事故” —— 每个名字 10 分钟说一次、且降到 INFO。
		if e.noteOnce("ech:"+res.Name, 10*time.Minute) {
			e.bus.Detail("TLS 嗅探：%s 用了 ECH（加密的 ClientHello）—— 真实目标名看不见，"+
				"通配域名对它无效（具体域名规则不受影响）", res.Name)
		}
		e.names.Set(res.Name, []string{dst.String()}, dnsmap.PrioObserved)
		return
	}
	before := e.names.IPsFor(res.Name)
	_, wasKnown := e.names.NameFor(dst)
	e.names.Set(res.Name, []string{dst.String()}, dnsmap.PrioObserved)
	e.sniLearn.Add(1)
	if len(before) == 0 && !wasKnown {
		// 这个名字从未在明文 DNS 里出现过 → 基本可以确定这台机器上有人用了
		// 加密 DNS 或自带解析器的客户端。这条日志的价值：让“为什么通配能/不能生效”有据可查。
		e.bus.Detail("sni.learn: name=%s ip=%s dns_seen=false", res.Name, dst)
	}
	e.applyHostIPs()
	e.onWildcardsChanged()
}

// dohHosts 已知的加密 DNS（DoH/DoT）服务名。只用于**报信**，不参与任何匹配。
var dohHosts = []string{
	"dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one",
	"mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
	"doh.pub", "dns.pub", "doh.360.cn", "dns.alidns.com", "doh.alidns.com",
	"dns.quad9.net", "doh.opendns.com", "dns.nextdns.io", "doh.dns.sb",
	"doh.cleanbrowsing.org", "dns.adguard.com",
}

// isDoHEndpoint 这个域名是不是已知的加密 DNS 端点。
func isDoHEndpoint(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, h := range dohHosts {
		if name == h {
			return true
		}
	}
	return false
}

// noteDoH 第一次看到加密 DNS 端点时报一条（同一个端点只报一次，否则刷屏）。
func (e *Engine) noteDoH(name string, dst net.IP) {
	e.mu.Lock()
	if e.dohSeen == nil {
		e.dohSeen = map[string]bool{}
	}
	show := !e.dohSeen[name]
	if show {
		e.dohSeen[name] = true
	}
	e.mu.Unlock()
	if !show {
		return
	}
	e.bus.Warn("doh.detect: host=%s ip=%s impact=first-connect-may-miss", name, dst)
	e.bus.Warn("  影响：这些名字只能从 TLS 握手看到，**首次连接**可能来不及进过滤器（重试起生效）。" +
		"要首次就生效，需打开 DNS 接管或改用明文 DNS")
}
