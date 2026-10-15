// 让"要出公网"的请求跟随 Windows 的「系统代理」（Internet 选项 / WinINET）。
//
// 为什么必须有这一层：Go 标准库的 http.ProxyFromEnvironment **只读环境变量**，
// 不读 Windows 的系统代理。实测（本机 Clash Verge 开着系统代理 127.0.0.1:7897）：
// ProxyFromEnvironment 返回 nil —— 于是"一键更新"直连 github.com、10 秒超时，
// 界面上只留一句"网络不通"。而现场机器多半正是"只有 Clash 的【系统代理】能出公网"
// （没开 TUN、也没设环境变量），这一层不补，一键更新在客户那里等于不存在。
//
// 复用 clash.go 那份"有效的系统代理设置"（readProxyMode / WouldProxy / proxyBypassHit）：
// WinINET 的语义只在一处实现，免得两边理解分叉 —— 那里踩过的三个坑（PAC 不可推、
// .NET 的匹配不可信、WinHttpGetProxyForUrl 评估不了静态代理）在这里同样成立。
//
// 边界（别扩大使用范围）：
//   - **只给要出公网的请求用**：一键更新（查版本 / 下包）。
//   - 内网请求（链路探测、自检、上游健康检查、导入配置）绝不能挂上它 ——
//     那正是 clash.go 开头那条红线：内网目标绝不能被交给 Clash 去解析/转发。
//   - 环境变量优先于系统设置：显式配置压过机器设置，也方便排查时临时覆盖。
//
// 不做 PAC：那要跑脚本，而系统没有 API 能问"这个 URL 会不会绕过静态代理"（见 clash.go）。
// PAC 模式下如实说"这次只能直连"，不拿猜的结论冒充结论。
package webui

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// updateClient 生成"要出公网"的 HTTP 客户端（一键更新专用）。
//
// 用 DefaultTransport.Clone() 而不是从零写一个：保留标准库的拨号超时、HTTP/2、
// 连接复用等行为，只把 Proxy 换掉 —— 免得"为了走代理"顺手把别的行为也改了。
func updateClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = systemProxyFunc()
	return &http.Client{Timeout: timeout, Transport: tr}
}

// UpdateProxyNote 一键更新的请求会走哪条网络路径（系统代理 / 直连 / 环境变量）。
//
// 给 -status 与界面文案用：现场排查"更新点了没反应"时，第一句要问的就是这个。
// 只读注册表，不产生任何网络请求。
func UpdateProxyNote() string { return proxyNote() }

// systemProxyFunc 返回给 http.Transport.Proxy 用的函数；返回 nil 表示直连。
//
// 代理设置**在造客户端时读一次**：更新是"用户点按钮 → 立刻发请求"，
// 每次操作都会重新读，不需要在请求途中盯着注册表变。
func systemProxyFunc() func(*http.Request) (*url.URL, error) {
	if envProxySet() {
		// 显式配置的环境变量优先，全部交给标准库（它会处理 NO_PROXY）
		return http.ProxyFromEnvironment
	}
	pm := readProxyMode()
	if !pm.WouldProxy() {
		// 没开系统代理 / 开关开着但地址是空的 / PAC 模式 —— 一律直连
		return nil
	}
	server, bypass := pm.Server, pm.BypassRaw
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, nil
		}
		if proxyBypassHit(req.URL.Hostname(), bypass) {
			return nil, nil // 命中绕过列表 → 直连
		}
		return pickProxyURL(server, req.URL.Scheme), nil
	}
}

// envProxySet 有没有设过代理环境变量（只看在不在，值由标准库去解释）。
func envProxySet() bool {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			return true
		}
	}
	return false
}

// proxyNote 一句话说明"要出公网的请求这次会怎么走" —— 直接进界面文案与日志。
//
// 为什么值得单独写一句：现场失败时，"到底走没走代理"决定了下一步该做什么
// （去 Clash 打开系统代理 / 去查网络 / 手动下包）。含糊的"网络不通"没法行动。
func proxyNote() string {
	if envProxySet() {
		for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"} {
			if v := strings.TrimSpace(os.Getenv(k)); v != "" {
				return "环境变量 " + k + "=" + scrubProxyURL(v)
			}
		}
	}
	pm := readProxyMode()
	switch {
	case pm.Mode == "pac":
		return "系统用的是「自动配置脚本（PAC）」—— 我们不会去跑它，这次只能直连"
	case pm.WouldProxy():
		return "系统代理 " + scrubProxyURL(strings.TrimSpace(pm.Server))
	case pm.Enable:
		return "系统代理开关开着、但没填代理地址（等于直连）"
	default:
		return "直连（系统代理没开，也没有代理环境变量）"
	}
}

// scrubProxyURL 把代理地址印成能给人看的样子，并**抹掉可能带的凭据**
// （这一行会进日志与界面文案；代理 URL 允许写成 http://user:pass@host:port）。
func scrubProxyURL(s string) string {
	i := strings.Index(s, "://")
	if i < 0 {
		return s
	}
	rest := s[i+3:]
	if j := strings.Index(rest, "@"); j >= 0 {
		return s[:i+3] + rest[j+1:]
	}
	return s
}

type proxyCand struct {
	val   string
	socks bool // socks= 那一项要变成 socks5:// 前缀
}

// pickProxyURL 从 Windows 的 ProxyServer 值里挑出该类请求该用的代理；挑不出返回 nil（直连）。
//
// 值的两种写法（Windows 文档 + 实测）：
//
//	127.0.0.1:7897                                   —— 所有协议都用它
//	http=127.0.0.1:7897;https=127.0.0.1:7897;socks=… —— 按协议各写各的
//
// https 没写时借 http 那条：这是 Windows 的常见行为，也是现场 Clash/Verge 的形态
// （只写 http= 一条，https 请求照样走它）。socks 项放最后兜底 —— 有它说明这台机器
// 想让全部流量过 SOCKS。
func pickProxyURL(server, scheme string) *url.URL {
	by, def := parseProxyServer(server)
	var cands []proxyCand
	add := func(v string, socks bool) {
		if strings.TrimSpace(v) != "" {
			cands = append(cands, proxyCand{v, socks})
		}
	}
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "https":
		add(by["https"], false)
		add(by["http"], false)
		add(def, false)
		add(by["socks"], true)
	case "http":
		add(by["http"], false)
		add(def, false)
		add(by["socks"], true)
	default:
		add(by[strings.ToLower(strings.TrimSpace(scheme))], false)
		add(def, false)
		add(by["http"], false)
		add(by["socks"], true)
	}
	for _, c := range cands {
		if u := normalizeProxyURL(c.val, c.socks); u != nil {
			return u
		}
	}
	return nil
}

// parseProxyServer 拆 ProxyServer：返回"按协议名"的映射，与没写协议的兜底那一条。
func parseProxyServer(server string) (map[string]string, string) {
	by := map[string]string{}
	def := ""
	for _, raw := range strings.FieldsFunc(server, func(r rune) bool {
		return r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '|'
	}) {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			if def == "" {
				def = item
			}
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if k != "" && v != "" {
			by[k] = v
		}
	}
	return by, def
}

// normalizeProxyURL 把 "host:port" / "http://host:port" 变成可用的代理 URL。
// 认不出的写法一律返回 nil（宁可直连，也别把坏 URL 塞给 Transport —— 那会变成一个
// 说不清的传输层错误，现场只会看到"下载失败"）。
func normalizeProxyURL(v string, socks bool) *url.URL {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if !strings.Contains(v, "://") {
		// 裸 "host:port"：自己拆，别让 "::::" 这种垃圾被拼成"看起来合法的 URL"
		host, port, err := net.SplitHostPort(v)
		if err != nil || strings.TrimSpace(host) == "" {
			return nil
		}
		if _, err := strconv.Atoi(port); err != nil {
			return nil
		}
		prefix := "http://"
		if socks {
			prefix = "socks5://"
		}
		v = prefix + v
	}
	u, err := url.Parse(v)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	// 主机部分里不该有冒号（IPv6 会写成 [::1]，方括号在）
	if strings.Contains(u.Hostname(), ":") && !strings.Contains(u.Host, "[") {
		return nil
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h", "socks4", "socks4a":
		return u
	}
	return nil
}
