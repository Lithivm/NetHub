// Clash 共存检测：判断"浏览器那条路"会不会把内网送进 Clash。
//
// 设计原则：**不推断，全部实测。**
//
// 这一路踩了三个坑，都记录在这里免得后人重犯：
//  1. 想当然认为 PAC 模式下会走 ProxyOverride 绕过列表 —— 实测完全失效
//     （ProxyOverride 只在显式系统代理模式下生效）
//  2. 用 .NET 的 System.Net.WebProxy 模拟绕过匹配 —— 它连 "*.example.com" 都解析不了，
//     和 WinINET 是两套实现，据它下结论是错的
//  3. 想用 WinHttpGetProxyForUrl 拿"某个 URL 会不会走代理"——
//     MSDN 要求 dwFlags 必须是 AUTO_DETECT 或 CONFIG_URL（两个都是自动代理机制），
//     **它根本无法评估静态代理 + 绕过列表**；显式模式下怎么调都报 ERROR_INVALID_PARAMETER
//
// 于是改成：对每个内网域名实跑两条路，看哪条能到内网 ——
//
//	直连：系统解析（走 hosts）→ 内网 IP → 被 our WinDivert 接管 → 隧道
//	经代理：把域名交给代理（"让代理自己解析"），看它能不能到
//
// 这两条都是真实连接，不含任何对 Windows 匹配语义的猜测。
//
// 本文件只读"有效的系统代理设置"（注册表：模式/代理地址/绕过条目数），
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

	"netproxy/internal/app"
	"netproxy/internal/config"
	"netproxy/internal/hostsmgr"
	"netproxy/internal/socks"
)

// ProxyMode 系统代理模式（只从注册表读，不涉及任何匹配语义）。
type ProxyMode struct {
	Mode        string // none | system | pac
	Server      string // 显式系统代理的地址
	PacURL      string // PAC 地址
	BypassCount int    // 绕过条目数
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
		m.BypassCount = len(strings.Split(ov, ";"))
	}
	return m
}

// ClashItem 一个内网域名的两条路实测结果。
type ClashItem struct {
	Host       string `json:"host"`
	DirectOK   bool   `json:"directOk"`
	DirectKind string `json:"directKind"` // https | http
	DirectErr  string `json:"directErr"`
	ProxyOK    bool   `json:"proxyOk"`
	ProxyKind  string `json:"proxyKind"`
	ProxyErr   string `json:"proxyErr"`
}

// ClashCheckView 给前端的完整检测结果。
type ClashCheckView struct {
	Mode        string      `json:"mode"` // none | system | pac
	Server      string      `json:"server"`
	PacURL      string      `json:"pacUrl"`
	BypassCount int         `json:"bypassCount"`
	ProxyAddr   string      `json:"proxyAddr"` // 实际用来测"经代理"的地址
	Items       []ClashItem `json:"items"`
	PublicProxy bool        `json:"publicProxy"` // 公网经代理是否可达（确认代理本身是好的）
	PublicKind  string      `json:"publicKind"`
	PublicErr   string      `json:"publicErr"`

	Verdict    string `json:"verdict"`
	NeedFix    bool   `json:"needFix"`
	BypassList string `json:"bypassList"`

	// 隧道自检（与应用/域名无关，证明我们这一侧是好的）
	TunnelTotal int `json:"tunnelTotal"`
	TunnelOK    int `json:"tunnelOk"`
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
	req := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: netproxy-check\r\nConnection: close\r\n\r\n"
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

// ClashCheck 检测内网是否会被送进代理。纯只读，不改任何设置。
func (b *Backend) ClashCheck() ClashCheckView {
	pm := readProxyMode()
	v := ClashCheckView{Mode: pm.Mode, Server: pm.Server, PacURL: pm.PacURL, BypassCount: pm.BypassCount}

	// 要检查的内网域名：配置里的 hosts 条目 → hosts 文件标记区块 → 内置默认
	// （不能只读配置：默认配置的 entries 是空的，那样最关键的域名检查就不会跑）
	entries := b.a.Cfg.Hosts.Entries
	if len(entries) == 0 {
		if block, ok, _, err := hostsmgr.Read(); err == nil && ok {
			entries = block
		}
	}
	if len(entries) == 0 {
		entries = defaultHostsEntries()
	}
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

	// 用来测"经代理"的地址：显式模式用 ProxyServer；PAC 模式下这个值只是参考
	proxyAddr := pm.Server
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:7897" // Clash 的常见混合端口，尽力而为
	}
	v.ProxyAddr = proxyAddr

	// ── 逐域名并发实测两条路 ──
	v.Items = make([]ClashItem, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			it := ClashItem{Host: h}

			// 路 1：直连。用域名 → 系统解析走 hosts → 内网 IP → 被我们接管 → 隧道
			direct := func(port int) (net.Conn, error) {
				return net.DialTimeout("tcp", net.JoinHostPort(h, fmt.Sprint(port)), probeTimeout())
			}
			if kind, err := probeHost(h, direct); err == nil {
				it.DirectOK = true
				it.DirectKind = kind
			} else {
				it.DirectErr = shortErr(err)
			}

			// 路 2：经代理，把域名交给代理去解析（= 浏览器走代理的真实行为）
			viaProxy := func(port int) (net.Conn, error) {
				return socks.DialHost(proxyAddr, h, uint16(port), probeTimeout())
			}
			if kind, err := probeHost(h, viaProxy); err == nil {
				it.ProxyOK = true
				it.ProxyKind = kind
			} else {
				it.ProxyErr = shortErr(err)
			}
			v.Items[i] = it
		}(i, h)
	}

	// 公网对照：代理本身是不是好的
	wg.Add(1)
	go func() {
		defer wg.Done()
		viaProxy := func(port int) (net.Conn, error) {
			return socks.DialHost(proxyAddr, "www.baidu.com", uint16(port), probeTimeout())
		}
		if kind, err := probeHost("www.baidu.com", viaProxy); err == nil {
			v.PublicProxy = true
			v.PublicKind = kind
		} else {
			v.PublicErr = shortErr(err)
		}
	}()
	wg.Wait()

	// ── 我们这一侧的自检：直接测内网 IP（不涉域名/代理）──
	v.TunnelTotal, v.TunnelOK = tunnelProbe(b.a.Cfg.Routes)

	// ── 结论 ──
	var needDomains []string
	anyDirectFail := false
	anyProxyOK := false
	for _, it := range v.Items {
		if !it.DirectOK {
			anyDirectFail = true
		}
		if it.ProxyOK {
			anyProxyOK = true
		}
		if !it.ProxyOK {
			needDomains = append(needDomains, it.Host)
		}
	}
	v.BypassList = strings.Join(needDomains, ";")

	switch {
	case len(v.Items) == 0:
		v.Verdict = "配置里没有内网域名可检（hosts.entries 为空）。"
	case anyDirectFail:
		v.Verdict = "有内网域名【直连也不通】—— 这跟 Clash 无关，是我们这一侧的问题（看运行日志里的引擎/链路状态）。"
	case anyProxyOK:
		v.Verdict = "内网域名经代理也能真正访问到（实测到 HTTP 层），当前配置无需处理。"
	case pm.Mode == "none":
		v.Verdict = "系统代理未开启，浏览器直连，内网正常。"
	default:
		v.NeedFix = len(needDomains) > 0
		if pm.Mode == "pac" {
			v.Verdict = "内网域名经代理到不了（实测到 HTTP 层）。PAC 模式下绕过列表不生效，建议改用普通系统代理，" +
				"并把下面的域名加进 Clash Verge 的「绕过地址」。"
		} else {
			v.Verdict = "内网域名经代理到不了（实测到 HTTP 层），但直连可达。把下面的域名加进 Clash Verge 的「绕过地址」，" +
				"让浏览器访问内网时走直连（= 我们的隧道），公网仍走 Clash。"
		}
	}
	if len(needDomains) == 0 {
		v.NeedFix = false
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

// tunnelProbe 直接按 IP 探测拦截网段，验证"我们这一侧"是好的。
func tunnelProbe(routes []config.Route) (total, ok int) {
	for _, rt := range routes {
		rep := firstUsableHost(rt.Target)
		if rep == "" {
			continue
		}
		for _, port := range []int{443, 80, 5432, 6446, 5000, 9056} {
			total++
			c, err := net.DialTimeout("tcp", net.JoinHostPort(rep, fmt.Sprint(port)), 2500*time.Millisecond)
			if err == nil {
				c.Close()
				ok++
				break // 这个网段通了就够
			}
		}
	}
	return
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

// PrintClashCheck 命令行诊断入口（netproxy.exe -clash-check），不需要管理员权限。
func PrintClashCheck(cfg *config.Config) {
	b := &Backend{a: &app.App{Cfg: cfg}}
	v := b.ClashCheck()

	modeName := map[string]string{
		"none":   "未开启系统代理",
		"system": "普通系统代理",
		"pac":    "PAC（自动配置脚本）",
	}[v.Mode]

	fmt.Println("=== 系统代理 ===")
	fmt.Printf("  模式        : %s\n", modeName)
	if v.Server != "" {
		fmt.Printf("  代理地址    : %s\n", v.Server)
	}
	if v.PacURL != "" {
		fmt.Printf("  PAC 地址    : %s\n", v.PacURL)
	}
	fmt.Printf("  绕过条目数  : %d\n", v.BypassCount)
	fmt.Printf("  实测用代理  : %s\n", v.ProxyAddr)

	fmt.Println("\n=== 内网域名：两条路实测（直连 vs 经代理，都验到 HTTP 层）===")
	fmt.Printf("  %-26s %-16s %s\n", "域名", "直连", "经代理（把域名交给代理解析）")
	for _, it := range v.Items {
		d := "不通"
		if it.DirectOK {
			d = "通(" + it.DirectKind + ")"
		}
		p := "不通"
		if it.ProxyOK {
			p = "通(" + it.ProxyKind + ")"
		}
		fmt.Printf("  %-26s %-16s %s\n", it.Host, d, p)
	}
	if v.PublicProxy {
		fmt.Printf("\n  公网对照 www.baidu.com 经代理: 通(%s) —— 代理本身是好的\n", v.PublicKind)
	} else {
		fmt.Printf("\n  公网对照 www.baidu.com 经代理: 不通（%s）\n", v.PublicErr)
	}

	fmt.Printf("\n=== 我们这一侧（按 IP 直连拦截网段）===\n")
	fmt.Printf("  网段探测: %d/%d 通\n", v.TunnelOK, v.TunnelTotal)

	fmt.Println("\n=== 结论 ===")
	fmt.Printf("  %s\n", v.Verdict)
	if v.NeedFix {
		fmt.Println("\n  把下面这段填进 Clash Verge 的「绕过地址」：")
		fmt.Printf("  %s\n", v.BypassList)
		fmt.Println("\n  （为什么不由我们代写：ProxyOverride 由 Clash Verge 自己维护，")
		fmt.Println("    它每次应用系统代理都会重写该值 —— 实测我们的修改 5 秒内就被冲掉了。）")
	}
}
