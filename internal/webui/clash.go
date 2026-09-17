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

// ClashItem 一个内网域名的【最终结论】（只报实际会走的那条路）。
type ClashItem struct {
	Host string `json:"host"`

	// Path 是浏览器实际会走的路（由系统代理设置 + 绕过列表决定）
	//   "direct" = 直连（解析走 hosts → 内网 IP → 被我们接管）
	//   "proxy"  = 交给代理
	Path string `json:"path"`

	// 只对这个 Path 做实测 —— 不报无关的那一条，避免恒定红列制造焦虑
	OK   bool   `json:"ok"`
	Kind string `json:"kind"` // https | http
	Err  string `json:"err"`

	// 只在这条路失败时才补测另一条，用于定位（正常时不填）
	AltPath string `json:"altPath"`
	AltOK   bool   `json:"altOk"`
	AltErr  string `json:"altErr"`
}

// ClashCheckView 给前端的检测结果：回答"当前共存通不通"。
type ClashCheckView struct {
	Mode    string      `json:"mode"` // none | system | pac
	Server  string      `json:"server"`
	PacURL  string      `json:"pacUrl"`
	Hosts   []ClashItem `json:"hosts"`
	HostsOK int         `json:"hostsOk"`

	PublicOK   bool   `json:"publicOk"` // 公网经代理能不能通
	PublicKind string `json:"publicKind"`
	PublicErr  string `json:"publicErr"`

	// 一句话总结论，前端直接显示
	Headline string `json:"headline"`
	Verdict  string `json:"verdict"`
	NeedFix  bool   `json:"needFix"`

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

// ClashCheck 检测"当前共存通不通"。纯只读，不改任何设置。
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

			// 先确定浏览器会走哪条路
			useProxy := proxyActive && !proxyBypassHit(h, pm.BypassRaw)
			if useProxy {
				it.Path = "proxy"
				if kind, err := probeViaProxy(h); err == nil {
					it.OK, it.Kind = true, kind
				} else {
					it.Err = shortErr(err)
				}
			} else {
				it.Path = "direct"
				if kind, err := probeDirect(h); err == nil {
					it.OK, it.Kind = true, kind
				} else {
					it.Err = shortErr(err)
				}
			}

			// 只在失败时补测另一条路，供定位
			if !it.OK {
				if useProxy {
					it.AltPath = "direct"
					if kind, err := probeDirect(h); err == nil {
						it.AltOK, it.Kind = true, kind
					} else {
						it.AltErr = shortErr(err)
					}
				} else {
					it.AltPath = "proxy"
					if kind, err := probeViaProxy(h); err == nil {
						it.AltOK, it.Kind = true, kind
					} else {
						it.AltErr = shortErr(err)
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
		if it.OK {
			v.HostsOK++
		}
	}

	// ── 结论 ──
	var bad []ClashItem
	for _, it := range v.Hosts {
		if !it.OK {
			bad = append(bad, it)
		}
	}

	v.Headline = fmt.Sprintf("内网 %d/%d 可用 · 公网 %s",
		v.HostsOK, len(v.Hosts), map[bool]string{true: "可用", false: "不可用"}[v.PublicOK])

	var needDomains []string
	switch {
	case len(v.Hosts) == 0 && v.PublicOK:
		v.Verdict = "配置里没有内网域名可检；公网走代理正常。"
	case len(bad) == 0 && v.PublicOK:
		v.Verdict = "内网与海外共存正常：浏览器访问内网走直连（= 我们的隧道），公网走 Clash。无需处理。"
	case len(bad) == 0 && !v.PublicOK:
		v.Verdict = "内网正常，但公网经代理不通（" + v.PublicErr + "）—— 这与 netproxy 无关，看 Clash 那边。"
	case len(bad) > 0 && !v.PublicOK:
		v.Verdict = "内网有域名打不开，且公网经代理也不通 —— 先检查 Clash 是否正常工作。"
	default:
		// 内网有打不开的：区分是“被代理了（可加绕过修复）”还是“我们这一侧的问题”
		fixable := true
		for _, it := range bad {
			if it.Path == "direct" {
				fixable = false // 走直连还不通 = 我们的隧道/解析问题
			}
			if it.Path == "proxy" {
				needDomains = append(needDomains, it.Host)
			}
		}
		v.BypassList = strings.Join(needDomains, ";")
		if fixable && len(needDomains) > 0 {
			v.NeedFix = true
			if pm.Mode == "pac" {
				v.Verdict = "有内网域名被交给了代理而代理到不了。PAC 模式下绕过列表不生效，建议改用普通系统代理，" +
					"再把下面的域名加进 Clash Verge 的「绕过地址」（设置 → 系统代理 左侧小齿轮）。"
			} else {
				v.Verdict = "有内网域名被交给了代理而代理到不了（代理用自己的 DNS，解析不到内网 IP）。" +
					"把下面的域名加进 Clash Verge 的「绕过地址」（设置 → 系统代理 那一行左侧的小齿轮）。"
			}
		} else {
			v.Verdict = "有内网域名【走直连也不通】—— 这跟 Clash 无关，是我们这一侧的问题（看运行日志里的引擎/链路状态）。"
		}
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

// PrintClashCheck 命令行诊断入口（netproxy.exe -clash-check），不需要管理员权限。
func PrintClashCheck(cfg *config.Config) {
	b := &Backend{a: &app.App{Cfg: cfg}}
	v := b.ClashCheck()

	modeName := map[string]string{
		"none":   "未开启系统代理",
		"system": "普通系统代理",
		"pac":    "PAC（自动配置脚本）",
	}[v.Mode]

	fmt.Println("=== 共存检测（只报实际会走的那条路）===")
	fmt.Printf("  系统代理: %s", modeName)
	if v.Server != "" {
		fmt.Printf("  %s", v.Server)
	}
	fmt.Println()

	fmt.Println("\n=== 内网域名 ===")
	fmt.Printf("  %-24s %-10s %s\n", "域名", "走的路", "结果")
	for _, it := range v.Hosts {
		path := "直连"
		if it.Path == "proxy" {
			path = "交给代理"
		}
		res := "通(" + it.Kind + ")"
		if !it.OK {
			res = "不通 —— " + it.Err
			if it.AltPath != "" {
				alt := "直连"
				if it.AltPath == "proxy" {
					alt = "交给代理"
				}
				if it.AltOK {
					res += "（另一条路：" + alt + " 是通的）"
				} else {
					res += "（另一条路：" + alt + " 也不通）"
				}
			}
		}
		fmt.Printf("  %-24s %-10s %s\n", it.Host, path, res)
	}

	pub := "通(" + v.PublicKind + ")"
	if !v.PublicOK {
		pub = "不通 —— " + v.PublicErr
	}
	fmt.Printf("\n=== 公网（经代理）===\n  www.baidu.com  %s\n", pub)

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
