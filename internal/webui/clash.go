// Clash 共存检测。
//
// **红线**：内网目标绝不能被交给 Clash。
//
// 为什么这条是硬红线（而不是"共存体验问题"）：
// 内网域名在公网 DNS 上查不到（实测 223.5.5.5/8.8.8.8/1.1.1.1 均 NXDOMAIN），
// 所以一旦浏览器把域名交给 Clash，Clash 会用自己的 DNS 去解析它 ——
// 如果它配的是远程 DNS/DoH，这个【内网域名的查询就真的出了内网】。
// 对企业内网安全监控来说这是可被标记的信号（用户明确说可能导致封号）。
// 而这一步我们拦不住：那时命中内核过滤器的只是"浏览器 → 127.0.0.1:7897"这条环回连接。
//
// 所以本文件的任务是：
//
//	① 确定浏览器实际会走哪条路（读注册表 + 匹配绕过列表）
//	② 只对该路做实测（验到 HTTP 层，不靠猜）
//	③ 【持续巡检】绕过覆盖，一旦丢失立即告警，不等用户打开界面
//
// 局限（README 里也写了）：我们没做 loopback 层的流量控制，做不到 100% fail-closed；
// 能保证的是"丢失后尽快发现并告警"。更彻底的一层是让 Clash 自己知道内网域名的 IP
// （mihomo 的 hosts），那样即使被代理也不外泄 —— 但那要改 Clash 配置，不在我们这边。
//
// 踩过的三个坑（免得重犯）：
//  1. 想当然认为 PAC 模式下会走 ProxyOverride 绕过列表 —— 实测完全失效
//  2. 用 .NET 的 System.Net.WebProxy 模拟绕过匹配 —— 它连 "*.example.com" 都解析不了，
//     和 WinINET 是两套实现，据它下结论是错的
//  3. 想用 WinHttpGetProxyForUrl 拿"某个 URL 会不会走代理"——
//     MSDN 要求 dwFlags 必须是 AUTO_DETECT 或 CONFIG_URL（都是自动代理机制），
//     **它根本无法评估静态代理 + 绕过列表**；显式模式下怎么调都报 ERROR_INVALID_PARAMETER
//
// 本文件只读"有效的系统代理设置"（注册表：模式/代理地址/绕过列表），
// **不读任何 Clash 配置文件**（项目红线：节点凭据不能进上下文）。
package webui

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"

	"nethub/internal/app"
	"nethub/internal/config"
	"nethub/internal/socks"
)

// ProxyMode 系统代理模式（只从注册表读，不涉及任何匹配语义）。
type ProxyMode struct {
	Mode        string // none | system | pac
	Server      string // 显式系统代理的地址
	PacURL      string // PAC 地址
	BypassCount int    // 绕过条目数
	BypassRaw   string // 绕过列表原值（用于本地匹配）
}

func readProxyMode() ProxyMode {
	var m ProxyMode
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		m.Mode = "none"
		return m
	}
	defer k.Close()

	if v, _, err := k.GetStringValue("AutoConfigURL"); err == nil && v != "" {
		m.Mode = "pac"
		m.PacURL = v
	}
	// PAC 模式下 ProxyServer 常留着上一次的值，仅作参考
	if s, _, err := k.GetStringValue("ProxyServer"); err == nil {
		m.Server = s
	}
	if en, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && en == 1 {
		if m.Mode == "" {
			m.Mode = "system"
		}
	}
	if m.Mode == "" {
		m.Mode = "none"
	}
	if ov, _, err := k.GetStringValue("ProxyOverride"); err == nil && ov != "" {
		m.BypassRaw = ov
		m.BypassCount = len(strings.FieldsFunc(ov, func(r rune) bool {
			return r == ';' || r == ',' || r == ' ' || r == '\t'
		}))
	}
	return m
}

// ClashItem 一个内网目标的【数据走向 + 判定】。
//
// 语义很关键：不报"直连通不通/代理通不通"（那样总有一格是红的，且无关），
// 而是报【数据会走哪】+【走对了没】。
type ClashItem struct {
	Host string `json:"host"`

	// Path 数据实际会走的路（由系统代理设置 + 绕过列表决定）
	//   "direct" = 直连（= our tunnel）—— 内网唯一正确的走向
	//   "proxy"  = 交给 Clash（代理节点）—— 对内网而言这是错的（红线）
	Path string `json:"path"`

	// Correct 走向对不对：内网必须走直连
	Correct bool `json:"correct"`

	// Reachable 这条走向实测能不能真的到（验到 HTTP 层）
	Reachable bool   `json:"reachable"`
	Kind      string `json:"kind"` // https | http
	Err       string `json:"err"`

	// 失败时补测另一条走向，用于定位（正常时不填）
	AltPath string `json:"altPath"`
	AltOK   bool   `json:"altOk"`
}

// Coverage 绕过覆盖：内网目标（域名 + 网段代表 IP）是否都命中了绕过列表。
// 未覆盖 = 会被交给 Clash = 红线。
type Coverage struct {
	Checked []string `json:"checked"`
	Missed  []string `json:"missed"`
	OK      bool     `json:"ok"`
}

// ClashCheckView 给前端的检测结果。
type ClashCheckView struct {
	Mode    string      `json:"mode"` // none | system | pac
	Server  string      `json:"server"`
	PacURL  string      `json:"pacUrl"`
	Hosts   []ClashItem `json:"hosts"`
	HostsOK int         `json:"hostsOk"` // 走向正确且实测可达的个数

	PublicOK   bool   `json:"publicOk"` // 公网经代理能不能通
	PublicKind string `json:"publicKind"`
	PublicErr  string `json:"publicErr"`

	Coverage Coverage `json:"coverage"`

	// AllCorrect 全部内网目标走向正确且可达
	AllCorrect bool   `json:"allCorrect"`
	Headline   string `json:"headline"`
	Verdict    string `json:"verdict"`
	NeedFix    bool   `json:"needFix"`
	BypassList string `json:"bypassList"`
}

// 探针端口：先试 443(HTTPS)，不行再试 80(明文 HTTP)
const (
	probePortTLS  = 443
	probePortHTTP = 80
)

func probeTimeout() time.Duration { return 5 * time.Second }

// dialFn 建一条到 host:port 的连接（直连 或 经代理）。
type dialFn func(port int) (net.Conn, error)

// probeHost 真实验证"能不能到内网"：
// 光看 TCP/SOCKS 握手成功是不够的 —— 代理完全可以 CONNECT 成功但实际连到了别处
// （实测过：经 Clash 的 CONNECT 成功，但 TLS 握手失败）。
// 所以必须验到应用层：拿不到 HTTP 响应就不算通。
//
// 返回 "https" / "http" 表示通，error 表示不通。
func probeHost(host string, dial dialFn) (string, error) {
	var lastErr error

	// 1) 443 上试 TLS + HTTP
	if c, err := dial(probePortTLS); err == nil {
		if kind, err2 := tryTLSGet(c, host); err2 == nil {
			return kind, nil
		} else {
			lastErr = err2
		}
	} else {
		lastErr = err
	}

	// 2) 80 上试明文 HTTP
	if c, err := dial(probePortHTTP); err == nil {
		if kind, err2 := tryPlainGet(c, host); err2 == nil {
			return kind, nil
		} else if lastErr == nil {
			lastErr = err2
		}
	} else if lastErr == nil {
		lastErr = err
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("没有拿到 HTTP 响应")
	}
	return "", lastErr
}

// tryTLSGet 对连接做 TLS 握手（不校验证书：内网多半是自签），再发一个 HTTP 请求。
func tryTLSGet(c net.Conn, host string) (string, error) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(probeTimeout()))
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err := tc.Handshake(); err != nil {
		return "", fmt.Errorf("TLS 握手失败: %w", err)
	}
	if err := sendGet(tc, host); err != nil {
		return "", err
	}
	if err := readStatusLine(tc); err != nil {
		return "", err
	}
	return "https", nil
}

func tryPlainGet(c net.Conn, host string) (string, error) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(probeTimeout()))
	if err := sendGet(c, host); err != nil {
		return "", err
	}
	if err := readStatusLine(c); err != nil {
		return "", err
	}
	return "http", nil
}

func sendGet(w io.Writer, host string) error {
	req := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: NetHub-check\r\nConnection: close\r\n\r\n"
	_, err := io.WriteString(w, req)
	return err
}

// readStatusLine 读到第一行并要求它是合法的 HTTP 状态行。
func readStatusLine(r io.Reader) error {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("读响应失败: %w", err)
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "HTTP/") {
		return fmt.Errorf("不是 HTTP 响应: %q", firstN(line, 40))
	}
	return nil
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// proxyBypassHit 判断 host 是否命中 WinINET 的 ProxyOverride 绕过列表。
//
// 规则（Windows 文档 + 实测对照）：
//   - 分号分隔；`*` 是通配符；匹配不区分大小写
//   - 普通条目（如 app.example.com）只匹配该主机本身，不匹配子域
//   - `<local>` 匹配不带点的主机名
//
// 为什么这里可以自己实现（前面明明说过不自己实现匹配）：
//   - 前面坑的是 PAC（脚本）和 .NET 那套——那些真的不能推
//   - 静态绕过列表本身是“通配符匹配主机名字符串”这个简单规则，
//     而且我们手上有**真实 WinINET 观测**做验证向量（见 clash_test.go）
//   - 更根本的原因：**系统没有提供任何 API 能问"这个 URL 会不会绕过静态代理"**。
//     WinHttpGetProxyForUrl 只支持 AUTO_DETECT / CONFIG_URL 两条自动代理路径
func proxyBypassHit(host, list string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, raw := range strings.FieldsFunc(list, func(r rune) bool {
		return r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		if entry == "<local>" {
			if !strings.Contains(host, ".") {
				return true
			}
			continue
		}
		if wildcardMatch(entry, host) {
			return true
		}
	}
	return false
}

// wildcardMatch 把 ent 里的 '*' 当任意长度通配符，整体锚定匹配 s。
func wildcardMatch(ent, s string) bool {
	parts := strings.Split(ent, "*")
	if len(parts) == 1 {
		return ent == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		p := parts[i]
		if p == "" {
			continue
		}
		j := strings.Index(s, p)
		if j < 0 {
			return false
		}
		s = s[j+len(p):]
	}
	last := parts[len(parts)-1]
	if last == "" {
		return true
	}
	return strings.HasSuffix(s, last)
}

// clashCoverage 轻量巡检：只读注册表 + 本地匹配，**不发任何网络请求**，
// 所以可以高频跑（后台每 60 秒一次）。
func (b *Backend) clashCoverage() Coverage {
	pm := readProxyMode()
	if pm.Mode == "none" {
		return Coverage{OK: true} // 没开系统代理 = 没有泄漏面
	}
	var c Coverage
	for _, t := range b.clashTargets() {
		c.Checked = append(c.Checked, t)
		if !proxyBypassHit(t, pm.BypassRaw) {
			c.Missed = append(c.Missed, t)
		}
	}
	c.OK = len(c.Missed) == 0
	return c
}

// clashTargets 必须保证不被交给 Clash 的内网目标：
//   - hosts 里的内网域名（按域名访问时才会踩到 DNS 那道坎）
//   - 每条规则网段的代表 IP（按 IP 访问同样不能进 Clash）
func (b *Backend) clashTargets() []string {
	entries := hostsEntriesFrom(b.a.Cfg)

	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, e := range entries {
		f := strings.Fields(e)
		if len(f) >= 2 {
			add(f[1])
		}
	}
	for _, rt := range b.a.Cfg.Routes {
		for _, t := range rt.Targets {
			add(firstUsableHost(t))
		}
	}
	return out
}

// firstUsableHost 把 "10.0.0.0/24" 变成 "10.0.0.1"（网段地址本身不好当探针）。
func firstUsableHost(cidr string) string {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		if p := net.ParseIP(cidr); p != nil {
			return p.String()
		}
		return ""
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return ""
	}
	v := ip.To4()
	if v == nil {
		return ""
	}
	if ones >= 31 {
		return v.String()
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, binary.BigEndian.Uint32(v)+1)
	return net.IP(buf).String()
}

// clashWatch 后台巡检：绕过覆盖丢失就立即告警，不等用户打开界面。
//
// 只读注册表 + 本地匹配，成本极低（每 60 秒一次）；只在状态变化时告警，不刷屏。
func (b *Backend) clashWatch() {
	wasOK := true
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()

	check := func() {
		c := b.clashCoverage()
		if c.OK == wasOK {
			return
		}
		wasOK = c.OK
		if !c.OK {
			b.a.Bus.Error("⚠ 内网目标会被交给 Clash（DNS 外泄风险）：%s", strings.Join(c.Missed, ", "))
			b.a.Bus.Error("  修法：把 %s 加进 Clash Verge 的「绕过地址」（设置 → 系统代理 左侧小齿轮）",
				strings.Join(c.Missed, ";"))
			b.emit("notify", NotifyView{
				Title: "内网可能被 Clash 代理",
				Text:  "以下内网目标不在 Clash 绕过列表里，请尽快处理：" + strings.Join(c.Missed, ";"),
				Kind:  "error",
			})
			if b.tray != nil {
				b.tray.Balloon("内网可能被 Clash 代理",
					"有 DNS 外泄/封号风险，请到「设置 → 与 Clash 共存」查看", app.NotifyError)
			}
		} else {
			b.a.Bus.Info("✓ Clash 绕过覆盖已恢复，内网目标不会再交给代理")
			b.emit("notify", NotifyView{Title: "Clash 绕过已恢复", Text: "内网目标不再经过代理", Kind: "info"})
		}
	}

	check()
	for range tick.C {
		check()
	}
}

// ClashCheck 检测"我们的数据会走哪 + 走得对不对"。纯只读，不改任何设置。
//
// 核心原则：**每个域名只报它实际会走的那条路的结果。**
// 不把那两条路都平铺出来 —— 因为其中一条恒定是红的（Clash 永远解析不了内网域名），
// 而它压根无关紧要（浏览器既然走直连，Clash 能不能到内网就不影响任何事），
// 摆出来只会制造焦虑。路的选择由系统代理设置 + 绕过列表决定。
// 只有在那条路失败时，才补测另一条路用于定位。
func (b *Backend) ClashCheck() ClashCheckView {
	pm := readProxyMode()
	v := ClashCheckView{Mode: pm.Mode, Server: pm.Server, PacURL: pm.PacURL}

	// hosts 条目：配置 → hosts 文件标记区块 → 内置默认
	entries := hostsEntriesFrom(b.a.Cfg)
	hosts := make([]string, 0, len(entries))
	seen := map[string]bool{}
	for _, e := range entries {
		f := strings.Fields(e)
		if len(f) < 2 || seen[f[1]] {
			continue
		}
		seen[f[1]] = true
		hosts = append(hosts, f[1])
	}

	proxyAddr := pm.Server
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:7897" // Clash 的常见混合端口，尽力而为
	}
	proxyActive := pm.Mode != "none"

	// 两条路的探测器
	probeDirect := func(h string) (string, error) {
		return probeHost(h, func(port int) (net.Conn, error) {
			return net.DialTimeout("tcp", net.JoinHostPort(h, fmt.Sprint(port)), probeTimeout())
		})
	}
	probeViaProxy := func(h string) (string, error) {
		return probeHost(h, func(port int) (net.Conn, error) {
			return socks.DialHost(proxyAddr, h, uint16(port), probeTimeout())
		})
	}

	v.Hosts = make([]ClashItem, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			it := ClashItem{Host: h}

			// ① 数据会走哪：由绕过列表决定。内网的正确走向只有一个 = 直连
			useProxy := proxyActive && !proxyBypassHit(h, pm.BypassRaw)
			it.Correct = !useProxy
			if useProxy {
				it.Path = "proxy"
			} else {
				it.Path = "direct"
			}

			// ② 这条走向实测能不能真的到（走向错了也测，告诉用户“错且不通”还是“错但能通”）
			probe := probeDirect
			if useProxy {
				probe = probeViaProxy
			}
			if kind, err := probe(h); err == nil {
				it.Reachable, it.Kind = true, kind
			} else {
				it.Err = shortErr(err)
			}

			// ③ 不可达时补测另一条走向，用于定位
			if !it.Reachable {
				if useProxy {
					it.AltPath = "direct"
					if _, err := probeDirect(h); err == nil {
						it.AltOK = true
					}
				} else {
					it.AltPath = "proxy"
					if _, err := probeViaProxy(h); err == nil {
						it.AltOK = true
					}
				}
			}
			v.Hosts[i] = it
		}(i, h)
	}

	// 公网：走代理能不能通（这才是"海外"那一半）
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !proxyActive {
			v.PublicOK = true // 没开代理 = 公网直连，不归我们管
			v.PublicKind = "direct"
			return
		}
		if kind, err := probeViaProxy("www.baidu.com"); err == nil {
			v.PublicOK, v.PublicKind = true, kind
		} else {
			v.PublicErr = shortErr(err)
		}
	}()
	wg.Wait()

	for _, it := range v.Hosts {
		if it.Correct && it.Reachable {
			v.HostsOK++
		}
	}

	// ── 结论（语义：走得对不对 优先于 通不通）──
	v.HostsOK = 0
	for _, it := range v.Hosts {
		if it.Correct && it.Reachable {
			v.HostsOK++
		}
	}
	v.AllCorrect = v.HostsOK == len(v.Hosts) && len(v.Hosts) > 0

	// 错向（内网被交给 Clash）= 红线；直连不通 = 我们这一侧的问题
	var misrouted, unreachable []string
	for _, it := range v.Hosts {
		if !it.Correct {
			misrouted = append(misrouted, it.Host)
		} else if !it.Reachable {
			unreachable = append(unreachable, it.Host)
		}
	}
	cov := b.clashCoverage()
	v.Coverage = cov

	switch {
	case len(v.Hosts) == 0:
		v.Headline = "没有内网域名可检"
		v.Verdict = "配置与 hosts 里都没有内网域名。无需处理。"
	case len(misrouted) == 0 && len(unreachable) == 0:
		v.Headline = fmt.Sprintf("✓ 内网 %d/%d 全部走直连（= 我们的隧道）· 公网走 Clash", v.HostsOK, len(v.Hosts))
		v.Verdict = "走向正确：内网数据走我们自己的隧道，不会经过 Clash 代理节点；" +
			"公网走 Clash。你手动配的绕过列表已生效 —— 无需处理。"
	default:
		v.Headline = fmt.Sprintf("✗ 内网 %d/%d 走向正确", v.HostsOK, len(v.Hosts))
	}

	if len(misrouted) > 0 {
		v.NeedFix = true
		v.BypassList = strings.Join(misrouted, ";")
		base := fmt.Sprintf("有 %d 个内网域名会被交给 Clash（红线：Clash 会用自己的 DNS 解析，内网域名可能出内网）：%s。",
			len(misrouted), strings.Join(misrouted, ", "))
		if pm.Mode == "pac" {
			v.Verdict = base + "PAC 模式下绕过列表不生效，建议改用普通系统代理，再按下方内容配绕过。"
		} else {
			v.Verdict = base + "把下方内容加进 Clash Verge 的「绕过地址」（设置 → 系统代理 那一行左侧的小齿轮）。"
		}
	}
	if len(unreachable) > 0 && len(misrouted) == 0 {
		v.Verdict = fmt.Sprintf("走向是对的（都走直连），但有 %d 个内网域名直连也不通：%s ——"+
			"这跟 Clash 无关，是我们这一侧的问题，看运行日志里的引擎/链路状态。",
			len(unreachable), strings.Join(unreachable, ", "))
	}
	if !v.PublicOK && len(v.Hosts) > 0 {
		v.Verdict += "　另外：公网经代理不通（" + v.PublicErr + "），看 Clash 那边。"
	}
	return v
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 90 {
		s = s[:90] + "…"
	}
	return s
}

// PrintClashCheck 命令行诊断入口（nethub.exe -clash-check），不需要管理员权限。
func PrintClashCheck(cfg *config.Config) {
	b := &Backend{a: &app.App{Cfg: cfg}}
	v := b.ClashCheck()

	modeName := map[string]string{
		"none":   "未开启系统代理",
		"system": "普通系统代理",
		"pac":    "PAC（自动配置脚本）",
	}[v.Mode]

	fmt.Println("=== 共存检测：内网数据会走哪 + 走得对不对 ===")
	fmt.Printf("  系统代理: %s", modeName)
	if v.Server != "" {
		fmt.Printf("  %s", v.Server)
	}
	fmt.Println()

	fmt.Println("\n=== 内网：数据会走哪 + 走得对不对 ===")
	fmt.Printf("  %-24s %-22s %s\n", "内网目标", "数据走向", "判定")
	for _, it := range v.Hosts {
		path := "直连（我们的隧道）"
		if it.Path == "proxy" {
			path = "交给 Clash（代理节点）"
		}
		var verdict string
		switch {
		case it.Correct && it.Reachable:
			verdict = "✓ 正确（实测可达 " + it.Kind + "）"
		case it.Correct && !it.Reachable:
			verdict = "✗ 走向对但隧道不通 —— " + it.Err
		case !it.Correct && it.Reachable:
			verdict = "✗ 错误：内网被代理了（虽然能通，但有 DNS 外泄风险）"
		default:
			verdict = "✗ 错误：内网被代理了，且到不了"
			if it.AltPath != "" && it.AltOK {
				verdict += "（直连是通的）"
			}
		}
		fmt.Printf("  %-24s %-22s %s\n", it.Host, path, verdict)
	}
	if len(v.Coverage.Checked) > 0 {
		fmt.Printf("\n  绕过覆盖：%d/%d 命中（含内网网段代表 IP）\n",
			len(v.Coverage.Checked)-len(v.Coverage.Missed), len(v.Coverage.Checked))
		if len(v.Coverage.Missed) > 0 {
			fmt.Printf("  ✗ 未覆盖：%s\n", strings.Join(v.Coverage.Missed, ";"))
		}
	}

	pub := "通(" + v.PublicKind + ")"
	if !v.PublicOK {
		pub = "不通 —— " + v.PublicErr
	}
	fmt.Printf("\n=== 公网（走 Clash）===\n  www.baidu.com  %s\n", pub)

	fmt.Printf("\n=== 总结论 ===\n  %s\n  %s\n", v.Headline, v.Verdict)
	if v.NeedFix {
		fmt.Println("\n  把下面这段填进 Clash Verge 的「绕过地址」：")
		fmt.Println("  【入口】Clash Verge → 设置 → 系统代理 那一行左侧的小齿轮 → 「代理绕过设置」")
		fmt.Println("  【核对】同处的「当前绕过」可确认是否真的写进去了")
		fmt.Printf("  【内容】%s\n", v.BypassList)
		fmt.Println("\n  （为什么不由我们代写：ProxyOverride 由 Clash Verge 自己维护，")
		fmt.Println("    它每次应用系统代理都会重写该值 —— 实测我们的修改 5 秒内就被冲掉了。）")
	}
}
