package webui

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nethub/internal/config"
	"nethub/internal/dnsmap"
)

// 「上客户现场之前，把服务器清单糊进来一次验完规则」——
// 单独查一个 IP 在路由规则页已经有了（ExplainTarget，带链/巡检细节）；
// 这里做的是**批量**：一次给几十个 IP/网段/URL，直接告诉每一条走哪条链、
// 哪个是直连、哪个根本没被拦到。现场再一条条试太慢，配错了也看不出来。
//
// 输入除了 IP/CIDR，还接受**浏览器地址栏里的那种写法**（`http://main.example.com/`、
// 裸域名 `main.example.com`）。模拟的落点是「浏览器最终会发出的那几条 TCP 连接」：
// 一条输入可能展开成多行（http/https 两个端口 × 多个解析地址），因为浏览器真的会
// 同时连其中几条（Happy Eyeballs），而它们可能命中不同规则 —— 那正是要暴露的坑。
//
// 刻意不模拟的东西都写在 Hints 里（重定向、TLS、HSTS 预载表、浏览器内部 DNS 缓存）。

// SimRow 一行模拟结果 = 一条**实际会发生的连接**（不是一条输入）。
type SimRow struct {
	Input string `json:"input"` // 原始输入（同一输入的多个连接会重复）
	// Host 这条连接的目标：IP（正常情形）；本机解析不到时是域名本身。
	Host string `json:"host,omitempty"`
	// Port 目标端口；0 = 未指定（只看目标，不参与端口条件判断）。
	Port int `json:"port,omitempty"`
	// Source 这个目标是怎么定出来的：直接输入 / hosts 条目 / 本机解析 / 仅域名。
	Source string `json:"source,omitempty"`

	OK     bool   `json:"ok"`
	Err    string `json:"err,omitempty"`
	Rule   string `json:"rule,omitempty"` // 命中的规则名
	RuleNo int    `json:"ruleNo"`         // 命中规则序号（1 起；0=没命中）
	Action string `json:"action,omitempty"`
	Chain  string `json:"chain,omitempty"`
	Note   string `json:"note,omitempty"` // 来源、端口限定、抽样之类的说明
}

// SimCount 按处理方式分组计数（保序，方便前端直接渲染）。
type SimCount struct {
	Action string `json:"action"`
	N      int    `json:"n"`
}

// SimView 一次模拟的完整结果。
type SimView struct {
	Rows    []SimRow   `json:"rows"`
	Counts  []SimCount `json:"counts"`
	Summary string     `json:"summary"`
	// Hints 这次模拟用到的**全局假设**（浏览器行为、我们做不到的部分）。
	// 放在这里而不是每行重复：这些前提跟具体某一条目标无关。
	Hints []string `json:"hints,omitempty"`
}

// 一次最多模拟多少条（防止有人糊进来一整份 IP 表把界面卡住）。
const simMax = 512

// 网段抽样点数：网段不大就全查，大网段按 16 点均匀抽样。
const simSample = 16

// simResolveTimeout 域名解析超时。模拟是**交互操作**，宁可给出"没解析到"
// 也不能让界面转圈几十秒（系统解析器在 DNS 不通时默认会等很久）。
const simResolveTimeout = 2 * time.Second

// SimulateTargets 解析用户粘进来的清单，逐条给出「浏览器会连到哪、然后怎么走」。
//
// 支持：单行一个，也支持逗号/空格/分号分隔；支持 # 注释；
// 每条可以是 IP、IP:端口、网段、网段:端口、域名、域名:端口、URL。
func (b *Backend) SimulateTargets(text string) SimView {
	tokens := parseSimInput(text)
	v := SimView{Rows: make([]SimRow, 0, len(tokens))}

	dropped := 0
	for i, tk := range tokens {
		if len(v.Rows) >= simMax {
			dropped += len(tokens) - i
			break
		}
		got := b.simOne(tk)
		if left := simMax - len(v.Rows); len(got) > left {
			dropped++ // 这一项只展开了一部分
			got = got[:left]
		}
		v.Rows = append(v.Rows, got...)
	}

	order := []string{}
	counts := map[string]int{}
	for _, row := range v.Rows {
		key := row.Action
		if !row.OK {
			key = "无法解析"
		}
		if _, seen := counts[key]; !seen {
			order = append(order, key)
		}
		counts[key]++
	}
	for _, k := range order {
		v.Counts = append(v.Counts, SimCount{Action: k, N: counts[k]})
	}

	parts := make([]string, 0, len(v.Counts))
	for _, c := range v.Counts {
		parts = append(parts, fmt.Sprintf("%s %d", c.Action, c.N))
	}
	v.Summary = fmt.Sprintf("共 %d 项输入、%d 条连接：%s", len(tokens), len(v.Rows), strings.Join(parts, "，"))
	if dropped > 0 {
		v.Summary += fmt.Sprintf("；另有 %d 项/条超出单次上限（%d）没有模拟", dropped, simMax)
	}
	v.Hints = b.simHints(v.Rows)
	return v
}

// simHints 这次结果用到了哪些前提。只列**实际出现**的，别每次糊一屏。
func (b *Backend) simHints(rows []SimRow) []string {
	out := []string{"不跟重定向、不做 TLS 握手 —— 这里判的是浏览器发出的第一条连接"}
	needDNS, need443, needNoScheme, needNameOnly := false, false, false, false
	for _, r := range rows {
		switch {
		case r.Source == "本机解析" || r.Source == "hosts 条目":
			needDNS = true
		case strings.HasPrefix(r.Source, "仅域名"):
			needNameOnly = true
		}
		if r.Port == 443 {
			need443 = true
		}
		if strings.Contains(r.Note, "未写协议") {
			needNoScheme = true
		}
	}
	if needDNS || needNameOnly {
		out = append(out, "名字按「先查 hosts、再查本机 DNS」解析；本工具只做 IPv4（AAAA 会被答空，所以浏览器不会走 IPv6）")
	}
	if needNameOnly {
		out = append(out, "本机解析不到的名字按**域名规则**判定 —— 实际连接时由上游解析真实地址，这正是内网域名的常态")
	}
	if needNoScheme {
		out = append(out, "未写协议时，浏览器先试 http 还是 https 取决于它的 HTTPS-First 与 HSTS，我们不去猜 —— 两个端口都列出来了")
	}
	if need443 {
		out = append(out, "浏览器可能先试 QUIC（UDP 443），它会被拦下并回落到这里列的 TCP 连接（除非该规则勾了「不拦 QUIC」）")
	}
	if b.a.Rules.NeedsProc() {
		out = append(out, "有规则带**进程条件**：模拟没有进程，这些规则不参与判定（真实连接可能命中它们）")
	}
	return out
}

// parseSimInput 把糊进来的文本切成条目：按行、逗号、分号、空白切，支持 # 注释。
func parseSimInput(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		for _, tk := range strings.FieldsFunc(line, func(r rune) bool {
			switch r {
			case ',', '，', ';', '；', '\t', '\r', ' ':
				return true
			}
			return false
		}) {
			tk = strings.TrimSpace(tk)
			if tk == "" || seen[tk] {
				continue
			}
			seen[tk] = true
			out = append(out, tk)
		}
	}
	return out
}

// simOne 模拟一条输入，返回它可能展开出的**多条连接**。
func (b *Backend) simOne(tok string) []SimRow {
	// ① URL（带 scheme://）—— 按浏览器语义取主机与端口
	if i := strings.Index(tok, "://"); i > 0 {
		return b.simURL(tok)
	}
	host, port, hasPort, err := splitSimTarget(tok)
	if err != nil {
		return []SimRow{{Input: tok, Err: err.Error()}}
	}
	switch {
	case strings.Contains(host, "/"):
		return b.simCIDR(tok, host, port, hasPort)
	case net.ParseIP(host) != nil:
		return b.simIP(tok, host, port, hasPort)
	case dnsmap.IsHostname(host):
		return b.simDomain(tok, host, port, hasPort, "")
	default:
		// 剩下的是区间 / IP 通配（Proxifier 的写法）：交给**配置层同一套归一化**。
		// 为什么不自写一个解析：规则保存时走的就是 NormalizeTargetExpr，模拟必须和它
		// 对同一个写法得出同一个目标；而且它报错会指明是哪一侧写坏了（10.1.1.0-10.1.1.300），
		// 比这里再编一句“无法识别”有用得多。
		exprs, err := config.NormalizeTargetExpr(host)
		if err != nil || len(exprs) == 0 {
			msg := "无法识别：要 IP、网段、IP 区间（10.1.1.1-10.1.1.255）、IP 通配（198.51.100.*）、域名或 URL"
			if err != nil {
				msg = "无法识别：" + err.Error()
			}
			return []SimRow{{Input: tok, Err: msg}}
		}
		return b.simExprs(tok, exprs, port, hasPort)
	}
}

// simURL 模拟一条 URL：host + 端口按浏览器的规则确定。
func (b *Backend) simURL(tok string) []SimRow {
	u, err := url.Parse(tok)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return []SimRow{{Input: tok, Err: "不是合法的 URL"}}
	}
	host := u.Hostname()
	if host == "" {
		return []SimRow{{Input: tok, Err: "URL 里没有主机名"}}
	}
	var port uint16
	hasPort := false
	if ps := u.Port(); ps != "" {
		n, e := strconv.Atoi(ps)
		if e != nil || n < 1 || n > 65535 {
			return []SimRow{{Input: tok, Err: fmt.Sprintf("端口要在 1-65535：%q", ps)}}
		}
		port, hasPort = uint16(n), true
	}
	scheme := strings.ToLower(u.Scheme)
	if ip := net.ParseIP(host); ip != nil {
		return b.simIP(tok, host, port, hasPort, scheme)
	}
	if !dnsmap.IsHostname(host) {
		return []SimRow{{Input: tok, Err: fmt.Sprintf("URL 里的主机名不像域名：%q", host)}}
	}
	return b.simDomain(tok, host, port, hasPort, scheme)
}

// simExprs 模拟一条“会展开成多个目标”的写法（IP 区间）。
//
// 区间展开后的每个网段各自抽样、各自判定 —— 一个区间跨到两条规则上是常见的，
// 合成一句结论就把最关键的信息抹掉了。
func (b *Backend) simExprs(tok string, exprs []string, port uint16, hasPort bool) []SimRow {
	out := make([]SimRow, 0, len(exprs))
	for idx, e := range exprs {
		rows := b.simCIDR(tok, e, port, hasPort)
		if len(exprs) > 1 {
			for i := range rows {
				rows[i].Note = joinNote(fmt.Sprintf("这一行是区间展开后的第 %d/%d 个网段（各自独立判定）", idx+1, len(exprs)), rows[i].Note)
			}
		}
		out = append(out, rows...)
	}
	return out
}

// simCIDR 网段：抽样若干点，全一致算一个结论；不一致就把分界说出来。
func (b *Backend) simCIDR(tok, host string, port uint16, hasPort bool) []SimRow {
	_, ipnet, err := net.ParseCIDR(host)
	if err != nil {
		return []SimRow{{Input: tok, Err: "不是合法的网段（如 10.0.0.0/24）"}}
	}
	// 本工具只处理 IPv4：IPv6 网段（fe80::/10）能 ParseCIDR 成功，
	// 但后面按 4 字节解析会直接 panic，所以必须在这里拦下。
	if ipnet.IP.To4() == nil {
		return []SimRow{{Input: tok, Err: "只支持 IPv4 网段（本工具不处理 IPv6）"}}
	}
	ips := sampleCIDR(ipnet, simSample)
	if len(ips) == 0 {
		return []SimRow{{Input: tok, Err: "这个网段取不出可用地址"}}
	}
	first := b.simEval(ips[0], port, !hasPort)
	row := SimRow{
		Input: tok, Host: host, Port: int(port), Source: "直接输入", OK: true,
		Rule: first.rule, RuleNo: first.ruleNo, Action: first.action, Chain: first.chain,
	}
	sampleNote := fmt.Sprintf("网段抽样 %d 点", len(ips))
	for _, ip := range ips[1:] {
		got := b.simEval(ip, port, !hasPort)
		if got.action != first.action || got.rule != first.rule || got.chain != first.chain {
			row.Note = fmt.Sprintf("⚠ 网段内不一致：%s → %s%s，%s → %s%s；请拆开写",
				ips[0], first.action, ruleSuffix(first.rule), ip, got.action, ruleSuffix(got.rule))
			sampleNote = ""
			break
		}
	}
	if sampleNote != "" {
		row.Note = sampleNote
	}
	row.Note = joinNote(row.Note, portNote(b, first.ruleNo, hasPort))
	return []SimRow{row}
}

// simIP 模拟直接给的 IP：保持原来的语义 —— 没写端口就是「只看目标」。
// scheme 非空时（URL 里写的是 IP）按浏览器的默认端口走。
func (b *Backend) simIP(tok, host string, port uint16, hasPort bool, scheme ...string) []SimRow {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return []SimRow{{Input: tok, Err: "不是合法的 IPv4 地址（本工具只处理 IPv4）"}}
	}
	s := ""
	if len(scheme) > 0 {
		s = scheme[0]
	}
	// 裸 IP（没有协议、没写端口）**不走浏览器语义**：它不是“在地址栏输入地址”，
	// 保持原来的“只看目标”—— 否则每个 IP 都会被凭空展开成 80/443 两条。
	var ports []uint16
	var portNoteText string
	if s == "" && !hasPort {
		ports = []uint16{0}
	} else {
		ports, portNoteText = simPorts(port, hasPort, s)
	}
	out := make([]SimRow, 0, len(ports))
	for _, p := range ports {
		got := b.simEval(ip, p, p == 0)
		row := SimRow{
			Input: tok, Host: ip.String(), Port: int(p), Source: "直接输入", OK: true,
			Rule: got.rule, RuleNo: got.ruleNo, Action: got.action, Chain: got.chain,
		}
		row.Note = joinNote(portNoteText, portNote(b, got.ruleNo, p != 0))
		out = append(out, row)
	}
	return out
}

// simDomain 模拟域名：先解析成 IP（hosts → 本机 DNS），再逐个 IP × 端口判定。
// 解析不到时**仍按名字判**——内网域名在本机解不出来是常态，那正是最该回答的问题。
func (b *Backend) simDomain(tok, name string, port uint16, hasPort bool, scheme string) []SimRow {
	ips, src := b.resolveSimName(name)
	ports, portNoteText := simPorts(port, hasPort, scheme)

	if len(ips) == 0 {
		out := make([]SimRow, 0, len(ports))
		for _, p := range ports {
			got := b.simEvalName(name, nil, p, p == 0)
			row := SimRow{
				Input: tok, Host: name, Port: int(p), Source: "仅域名", OK: true,
				Rule: got.rule, RuleNo: got.ruleNo, Action: got.action, Chain: got.chain,
			}
			row.Note = joinNote("本机解析不到真实地址 —— 实际连接由上游解析", portNoteText)
			row.Note = joinNote(row.Note, portNote(b, got.ruleNo, p != 0))
			out = append(out, row)
		}
		return out
	}

	out := make([]SimRow, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, p := range ports {
			got := b.simEvalName(name, ip, p, p == 0)
			row := SimRow{
				Input: tok, Host: ip.String(), Port: int(p), Source: src, OK: true,
				Rule: got.rule, RuleNo: got.ruleNo, Action: got.action, Chain: got.chain,
			}
			row.Note = joinNote(portNoteText, portNote(b, got.ruleNo, p != 0))
			out = append(out, row)
		}
	}
	return out
}

// simPorts 决定这条输入会去连哪些端口（浏览器语义）。
//
//	写了端口      → 就那个
//	http/ws       → 80
//	https/wss     → 443
//	没写协议      → 80 和 443 都列（不猜 HTTPS-First/HSTS）
//	其它协议      → 0 = 只看目标
func simPorts(port uint16, hasPort bool, scheme string) ([]uint16, string) {
	if hasPort && port != 0 {
		return []uint16{port}, ""
	}
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return []uint16{80}, ""
	case "https", "wss":
		return []uint16{443}, ""
	case "":
		return []uint16{80, 443}, "未写协议：浏览器先试哪个取决于 HTTPS-First/HSTS"
	default:
		return []uint16{0}, fmt.Sprintf("不认识的协议 %q，按「只看目标」判断", scheme)
	}
}

// resolveSimName 把域名变成「浏览器实际会连的 IP」，返回结果与来源说明。
//
// 顺序必须与系统解析一致：**先 hosts**（应用也是先查 hosts，命中就不发 DNS），
// 再本机 DNS。假 IP 段里的结果要剔除 —— 那是我们 DNS 接管自己发的地址，
// 拿它当目标去判规则，结论必然是错的（它只存在于我们自己的映射里）。
func (b *Backend) resolveSimName(name string) ([]net.IP, string) {
	if ips := hostsIPsFor(b.a.Cfg.HostsCopy().Entries, name); len(ips) > 0 {
		return ips, "hosts 条目"
	}
	fake := fakeRange(b)
	ctx, cancel := context.WithTimeout(context.Background(), simResolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		return nil, ""
	}
	out := make([]net.IP, 0, len(addrs))
	seen := map[string]bool{}
	for _, a := range addrs {
		v4 := a.To4()
		if v4 == nil || seen[v4.String()] {
			continue
		}
		if fake != nil && fake.Contains(v4) {
			continue // 我们自己发的假 IP，不是真实目标
		}
		seen[v4.String()] = true
		out = append(out, v4)
	}
	if len(out) == 0 {
		return nil, ""
	}
	return out, "本机解析"
}

// hostsIPsFor 在 hosts 托管条目里查这个名字（hosts 一行可以有多个域名）。
func hostsIPsFor(entries []string, name string) []net.IP {
	var out []net.IP
	for _, e := range entries {
		f := strings.Fields(strings.TrimSpace(e))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		for _, h := range f[1:] {
			if strings.EqualFold(h, name) {
				out = append(out, ip.To4())
				break
			}
		}
	}
	return out
}

// fakeRange 配置里的假 IP 段（解析失败返回 nil —— 那只是"没这条约束"）。
func fakeRange(b *Backend) *net.IPNet {
	_, n, err := net.ParseCIDR(b.a.Cfg.FakeIPRangeOr())
	if err != nil {
		return nil
	}
	return n
}

type simVerdict struct {
	rule   string
	ruleNo int
	action string
	chain  string
}

// simEval 就是「这个 IP 会被怎么处理」：命中哪条规则、动作是什么。
func (b *Backend) simEval(ip net.IP, port uint16, ignorePort bool) simVerdict {
	return b.simEvalName("", ip, port, ignorePort)
}

// simEvalName 同上，但带上域名 —— 域名/通配规则靠名字命中（见 rules.ExplainName）。
func (b *Backend) simEvalName(name string, ip net.IP, port uint16, ignorePort bool) simVerdict {
	idx, _, ok := b.a.Rules.ExplainName(name, ip, port, ignorePort)
	routes := b.a.Cfg.RoutesSnapshot()
	if !ok || idx < 0 || idx >= len(routes) {
		return simVerdict{action: "未命中（不拦截）"}
	}
	r := routes[idx]
	return simVerdict{rule: r.Name, ruleNo: idx + 1, action: r.ActionText(), chain: r.Chain}
}

// portNote：没填端口、但命中的规则带端口条件时，把这件事说清楚（别让人误以为结论确定）。
func portNote(b *Backend, ruleNo int, hasPort bool) string {
	routes := b.a.Cfg.RoutesSnapshot()
	if hasPort || ruleNo <= 0 || ruleNo > len(routes) {
		return ""
	}
	if p := routes[ruleNo-1].Ports; len(p) > 0 {
		return "该规则限定端口 " + strings.Join(p, ",") + "；未填端口时按「只看目标」判断"
	}
	return ""
}

func ruleSuffix(name string) string {
	if name == "" {
		return ""
	}
	return "「" + name + "」"
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "；" + b
	}
}

// splitSimTarget 拆出 host 与可选端口。网段带端口写成 10.0.0.0/24:443。
func splitSimTarget(tok string) (host string, port uint16, hasPort bool, err error) {
	if i := strings.LastIndex(tok, ":"); i >= 0 {
		host, p := tok[:i], tok[i+1:]
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", 0, false, fmt.Errorf("端口要在 1-65535：%q", p)
		}
		if host == "" {
			return "", 0, false, fmt.Errorf("缺少地址：%q", tok)
		}
		return host, uint16(n), true, nil
	}
	return tok, 0, false, nil
}

// sampleCIDR 在一个网段里取最多 max 个代表性地址（首、尾，中间均匀取样）。
func sampleCIDR(n *net.IPNet, max int) []net.IP {
	if n == nil || n.IP.To4() == nil {
		return nil // 只处理 IPv4（调用方已拦，这里再兜一道）
	}
	if max < 2 {
		max = 2 // 下面有 max-1 做除数
	}
	base := binary.BigEndian.Uint32(n.IP.To4())
	ones, bits := n.Mask.Size()
	if ones < 0 || bits != 32 || ones > bits {
		return nil
	}
	size := uint64(1) << uint(bits-ones)
	if size == 0 {
		return nil
	}
	if size <= uint64(max) {
		out := make([]net.IP, 0, size)
		for i := uint64(0); i < size; i++ {
			out = append(out, u32ip(base+uint32(i)))
		}
		return out
	}
	out := make([]net.IP, 0, max)
	step := (size - 1) / uint64(max-1)
	for i := uint64(0); i < uint64(max); i++ {
		off := i * step
		if off > size-1 {
			off = size - 1
		}
		out = append(out, u32ip(base+uint32(off)))
	}
	return out
}

func u32ip(v uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:])
}
