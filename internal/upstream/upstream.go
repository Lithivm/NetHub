// Package upstream 直接实现"到上游代理"的连接 —— 不依赖外部 gost 进程。
//
// 背景：gost 原来只做一件事：在（可选的）TLS 隧道里做一次代理握手再 CONNECT 目标。
//
//	应用 → 我们的 relay → 本地 gost(SOCKS5) → TLS → 上游 SOCKS5 → 目标
//
// 现在直接
//
//	应用 → 我们的 relay → [TLS] → 上游代理协议 → 目标
//
// 好处：少一个外部依赖（不用配 gost.exe、不会版本漂移）、少一跳本地 SOCKS5 握手、
// 没有子进程要托管、日志与超时都归我们控制。
//
// 支持的协议（见 SupportedSchemes）：
//
//	socks5 / socks5h / socks   + tls
//	socks4 / socks4a           + tls
//	http / https（CONNECT 隧道，支持 Basic 认证）
//
// URL 形式与 gost 兼容，旧脚本的 -F 可以直接拿来用：
//
//	socks5+tls://host:port?auth=<base64(user:pass)>     ← 现网两个上游都是这种
//	socks5+tls://user:pass@host:port
//	http://user:pass@proxy:8080
//	https://proxy:8443?auth=<base64>
//	可选参数 secure=true 开启证书校验（默认不校，与 gost 的 socks5+tls 默认行为一致）
//
// 传输层后缀目前支持 `+tls` / `+mtls`（mtls 视同 tls，客户端证书待需要时再加）。
//
// 不做哪些（评估结论）：gost 的 quic/kcp/http2/obfs4 传输是要复刻 gost 自研的
// 多路复用与帧封装，不是"套一层"，成本高且随 gost 版本变；
// forward/direct/remote 是"目标写死在配置里"的端口转发，与我们的动态目标语义不符。
package upstream

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"nethub/internal/socks"
)

// Upstream 一条上游链路。
type Upstream struct {
	Raw      string // 原始 URL（含凭据，不要往日志里打）
	Protocol string // socks5 | socks4 | socks4a | http
	Addr     string // host:port
	TLS      bool   // 是否要在连接上做 TLS（由 +tls / https 决定）
	Creds    socks.Creds

	// Verify 是否校验上游证书。
	// 默认 false —— 与 gost 的 socks5+tls 默认行为一致（它不配 CA 时不校验）。
	// 想开启就在 URL 上加 ?secure=true。
	Verify bool

	// ServerName 校验/SNI 用的主机名
	ServerName string
}

// looksMasked 这串是不是脱敏占位符（`***` / `xxx` / `••••` 这类）。
//
// 只认“全是同一种占位字符且长≥3”—— 避免把短口令（如 `xx`）误判。
func looksMasked(s string) bool {
	s = strings.TrimSpace(s)
	if len([]rune(s)) < 3 {
		return false
	}
	for _, r := range s {
		switch r {
		case '*', 'x', 'X', '•', '·', '▪', '■':
		default:
			return false
		}
	}
	return true
}

// maskOf 报错里指一下是哪一段被抹了。
func maskOf(user, pass string) string {
	switch {
	case looksMasked(user) && looksMasked(pass):
		return "账号与口令都是"
	case looksMasked(pass):
		return "口令是"
	case looksMasked(user):
		return "账号是"
	}
	return "凭据是"
}

// Parse 解析上游 URL。
func Parse(raw string) (*Upstream, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("上游 URL 为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("解析上游 URL 失败: %w", err)
	}
	base, isTLS, known := classify(u.Scheme)
	if !known {
		return nil, fmt.Errorf("不支持的上游协议 %q（当前支持 %s）", u.Scheme, SupportedSchemes())
	}

	up := &Upstream{Raw: raw, Protocol: base, TLS: isTLS}

	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return nil, fmt.Errorf("上游地址必须是 host:port，当前 %q", u.Host)
	}
	up.Addr = net.JoinHostPort(host, port)
	up.ServerName = host

	// 凭据可以写在 userinfo，也可以写在 ?auth=<base64(user:pass)>（gost 的写法）
	if u.User != nil {
		up.Creds.User = u.User.Username()
		if p, ok := u.User.Password(); ok {
			up.Creds.Pass = p
		}
	}
	if a := u.Query().Get("auth"); a != "" {
		dec, err := base64.StdEncoding.DecodeString(a)
		if err != nil {
			dec, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(a, "="))
		}
		if err != nil {
			return nil, fmt.Errorf("auth 参数不是合法的 base64(user:pass)")
		}
		s := string(dec)
		if i := strings.Index(s, ":"); i >= 0 {
			up.Creds.User, up.Creds.Pass = s[:i], s[i+1:]
		} else {
			// 只给了一个值（没有 user:pass 的写法）—— gost 对这种情况的含义是：
			// **整个值就是用户名，口令为空**（服务端通常也只查用户名）。
			//
			// 实测依据（2026-09-21，同事的 snzyy 链 124.115.74.246:10084，
			// auth 解出来是 38 字节二进制、没有冒号）：
			//   空用户 + 整串当口令  → 认证被拒
			//   整串作用户 + 空口令  → 通过（整串同时当口令也通过 → 服务端只查用户名）
			// 所以这里必须跟 gost 一致：User = 整串，Pass = ""。
			// 以前猜成“整串当口令、用户名为空”，等于这类上游根本用不了。
			up.Creds.User, up.Creds.Pass = s, ""
		}
	}
	// 脱敏占位符不能当凭据用。
	//
	// 真实坑：从「导出配置（无凭据）」或文档里拷回来的地址里，口令被抹成 `***` ——
	// 以前它会原样通过校验，运行时才报“认证被拒”，看起来像上游坏了。
	// 这属于“配置一看就是错的”，应该在解析时就挡住、并说清楚怎么改。
	if looksMasked(up.Creds.User) || looksMasked(up.Creds.Pass) {
		return nil, fmt.Errorf("凭据是脱敏占位符（%s）—— 这是「导出配置（无凭据）」或文档里的写法，"+
			"请换成真实用户名/口令；若只是想先占位，把 auth= 整段删掉", maskOf(up.Creds.User, up.Creds.Pass))
	}
	if q := u.Query(); q.Get("secure") == "true" {
		up.Verify = true
	}
	return up, nil
}

// String 只用来打日志：把凭据遮蔽掉。
func (u *Upstream) String() string {
	s := u.Protocol
	if u.TLS {
		s += "+tls"
	}
	auth := ""
	if u.Creds.User != "" || u.Creds.Pass != "" {
		auth = "（带凭据）"
	}
	return s + "://" + u.Addr + auth
}

// Dial 连到 targetIP:port。
// 目标从内核拦截拿到的是 IP，所以不需要（也不应该）让上游去解析域名。
func (u *Upstream) Dial(targetIP net.IP, targetPort uint16, timeout time.Duration) (net.Conn, error) {
	v4 := targetIP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", targetIP)
	}
	switch u.Protocol {
	case "socks5":
		return socks.DialTLS(u.Addr, u.Creds, u.tls(), v4, targetPort, timeout)
	case "socks4", "socks4a":
		// SOCKS4 协议本身没有 TLS；但 gost 允许 "socks4+tls" 这种"TLS 传输 + SOCKS4 协议"
		return socks.DialSOCKS4TLS(u.Addr, u.Creds.User, v4.String(), targetPort, u.tls(), timeout)
	case "http":
		return dialHTTPConnect(u, v4, targetPort, timeout)
	default:
		return nil, fmt.Errorf("未实现的上游协议 %q", u.Protocol)
	}
}

// tls 返回 TLS 配置；不需要 TLS 时返回 nil（调用方据此判断是否包裹）。
func (u *Upstream) tls() *tls.Config {
	if !u.TLS {
		return nil
	}
	return u.tlsConfig()
}

// ───────────────────────── 预热连接池（A11）─────────────────────────
//
// 思路：把"连上游"这件事拆成两段 ——
//
//	预备（Prepare）：TCP + 可选 TLS + SOCKS 方法协商/认证   ← 与目标无关，可以提前做
//	打通（ConnectOn）：一条 CONNECT 请求                      ← 必须等知道目标才能做
//
// 连接池把"预备好的连接"养着，业务来了只做第二段。
// 实测：现网上游预备要 193～258ms（etyy 甚至 700ms+），打通只要 1 个 RTT。

// Prepare 连上上游并把握手做到"只差 CONNECT"。不支持的上游返回 ErrNoPrepare。
func (u *Upstream) Prepare(timeout time.Duration) (net.Conn, error) {
	switch u.Protocol {
	case "socks5":
		return socks.Prepare(u.Addr, u.Creds, u.tls(), timeout)
	case "socks4", "socks4a":
		return socks.PrepareSOCKS4(u.Addr, u.tls(), timeout)
	case "http":
		return prepareHTTPConnect(u, timeout)
	default:
		return nil, ErrNoPrepare
	}
}

// ConnectOn 在预备好的连接上打通到 targetIP:port。
func (u *Upstream) ConnectOn(conn net.Conn, targetIP net.IP, targetPort uint16, timeout time.Duration) error {
	v4 := targetIP.To4()
	if v4 == nil {
		return fmt.Errorf("仅支持 IPv4 目标: %v", targetIP)
	}
	switch u.Protocol {
	case "socks5":
		return socks.ConnectOn(conn, v4, targetPort, timeout)
	case "socks4", "socks4a":
		host := v4.String()
		if u.Protocol == "socks4a" {
			host = v4.String() // 目标是 IP，4a 与 4 等價
		}
		return socks.ConnectSOCKS4On(conn, u.Creds.User, host, targetPort, timeout)
	case "http":
		return connectHTTPConnect(u, conn, v4, targetPort, timeout)
	default:
		return ErrNoPrepare
	}
}

// ErrNoPrepare 这条上游不支持"先预备后打通"（只能整体 Dial）。
var ErrNoPrepare = errors.New("这条上游不支持预热（只能一次性拨号）")

// DialHost 把**域名**交给上游去解析并连接（而不是本机先解析成 IP）。
//
// 为什么需要它（真实场景）：内网域名往往只有上游那一侧能解析 —— 本机 DNS 要么查不到、
// 要么查到的是公网 IP。旧方案（Proxifier + 本地 gost）就是一路把域名传到上游的，
// 本工具要对齐这个能力，同时本机也不泄漏内网域名。
//
// 各协议的支持情况：
//
//	socks5        原生支持（ATYP=域名）
//	socks4a       原生支持（0.0.0.x 约定）
//	socks4        不支持域名 → 只能本机解析成 IP 再连（保底，会失去"上游侧解析"的意义）
//	http / https  CONNECT 里写 host:port，由代理解析
func (u *Upstream) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, fmt.Errorf("域名为空")
	}
	switch u.Protocol {
	case "socks5":
		return socks.DialTLSHost(u.Addr, u.Creds, u.tls(), host, port, timeout)
	case "socks4a":
		return socks.DialSOCKS4TLS(u.Addr, u.Creds.User, host, port, u.tls(), timeout)
	case "socks4":
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("SOCKS4 不支持域名，且本机解析 %s 失败: %v", host, err)
		}
		v4 := ips[0].To4()
		if v4 == nil {
			return nil, fmt.Errorf("SOCKS4 只支持 IPv4，%s 解析到 %v", host, ips[0])
		}
		return socks.DialSOCKS4TLS(u.Addr, u.Creds.User, v4.String(), port, u.tls(), timeout)
	case "http":
		return dialHTTPConnectHost(u, host, port, timeout)
	default:
		return nil, fmt.Errorf("这条上游不支持把域名交给它解析（协议 %s）", u.Protocol)
	}
}
