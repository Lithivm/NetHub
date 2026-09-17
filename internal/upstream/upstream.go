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
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"netproxy/internal/socks"
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
		i := strings.Index(s, ":")
		if i < 0 {
			return nil, fmt.Errorf("auth 解出来后没有冒号，期望 user:pass")
		}
		up.Creds.User, up.Creds.Pass = s[:i], s[i+1:]
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
