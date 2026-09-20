// Package socks 实现最小 SOCKS5 客户端（支持 no-auth 与用户名/口令认证）。
//
// 两种用途：
//  1. 连本机 gost 的 socks5 监听（no-auth）—— 旧路径，链路自检还在用
//  2. 在 TLS 隧道内连上游 socks5 代理（需要 RFC 1929 认证）—— 原生链路要用的
//
// 注意：我们不需要实现 gost 的 tls/auth 私有扩展方法，标准 SOCKS5 即可。
package socks

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	methodNoAuth   = 0x00
	methodUserPass = 0x02
	cmdConnect     = 0x01
	atypIPv4       = 0x01
	atypDomain     = 0x03
)

// Creds SOCKS5 用户名/口令（RFC 1929）。空表示 no-auth。
type Creds struct {
	User string
	Pass string
}

func (c Creds) empty() bool { return c.User == "" && c.Pass == "" }

// Dial 通过 proxy（如 127.0.0.1:1080）连到 dstIP:dstPort，无认证。
func Dial(proxy string, dstIP net.IP, dstPort uint16, timeout time.Duration) (net.Conn, error) {
	return DialAuth(proxy, Creds{}, dstIP, dstPort, timeout)
}

// DialHost 把**域名**交给代理解析后再连（等价 curl 的 --socks5-hostname），无认证。
func DialHost(proxy, host string, dstPort uint16, timeout time.Duration) (net.Conn, error) {
	return DialAuthHost(proxy, Creds{}, host, dstPort, timeout)
}

// DialAuth 带认证连到 dstIP:dstPort。
func DialAuth(proxy string, c Creds, dstIP net.IP, dstPort uint16, timeout time.Duration) (net.Conn, error) {
	v4 := dstIP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", dstIP)
	}
	return dialWith(proxy, c, nil, atypIPv4, v4, dstPort, timeout)
}

// DialAuthHost 带认证，把域名交给代理解析后再连。
func DialAuthHost(proxy string, c Creds, host string, dstPort uint16, timeout time.Duration) (net.Conn, error) {
	if ip := net.ParseIP(host); ip != nil {
		return DialAuth(proxy, c, ip, dstPort, timeout)
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("域名长度非法: %q", host)
	}
	body := append([]byte{byte(len(host))}, []byte(host)...)
	return dialWith(proxy, c, nil, atypDomain, body, dstPort, timeout)
}

// Prepare 先连上代理并做完“不依赖目标”的握手（TCP + 可选 TLS + 方法协商/认证），
// 返回一个**待用**的连接（还差一次 CONNECT）。
//
// 用途：预热连接池（A11）—— 把这三段提前做完并放着，业务来了只需发 CONNECT，
// 省掉 TCP+TLS+招呼（实测 193～258ms）。
func Prepare(proxy string, c Creds, tlsConf *tls.Config, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	raw, err := net.DialTimeout("tcp", proxy, timeout)
	if err != nil {
		return nil, fmt.Errorf("连代理失败: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

	var conn net.Conn = raw
	if tlsConf != nil {
		tc := tls.Client(raw, tlsConf)
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS 握手失败: %w", err)
		}
		conn = tc
	}
	if err := negotiate(conn, c); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// ConnectOn 在已预备好的连接上发 CONNECT（IPv4）。
// 成功后就变成一条正常的长连接（调用方自己清掉 deadline 或不管：我们下一次读写前会清）。
func ConnectOn(conn net.Conn, dstIP net.IP, dstPort uint16, timeout time.Duration) error {
	v4 := dstIP.To4()
	if v4 == nil {
		return fmt.Errorf("仅支持 IPv4 目标: %v", dstIP)
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if err := connect(conn, atypIPv4, v4, dstPort); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{}) // 清掉超时，之后是长连接
	return nil
}

// dialWith 发 SOCKS5 握手 + CONNECT（Prepare + ConnectOn 的组合，保留给老调用方）。
//
// tlsConf 非 nil 时先在连接上做 TLS（= 上游用 socks5+tls 的情况）。
// addr 是 ATYP 对应的地址体（IPv4 4 字节 / 域名 = 长度+字节）。
func dialWith(proxy string, c Creds, tlsConf *tls.Config, atyp byte, addr []byte,
	dstPort uint16, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn, err := Prepare(proxy, c, tlsConf, timeout)
	if err != nil {
		return nil, err
	}
	// 域名目标的 CONNECT 走原来的 connect()，不经过 ConnectOn（它只收 IPv4）
	if err := connect(conn, atyp, addr, dstPort); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// negotiate 方法协商 + 认证（RFC 1928 第 3 步 + RFC 1929）。
func negotiate(conn net.Conn, c Creds) error {
	// ① 方法协商。有凭据就优先提认证，同时也提 no-auth（有些代理允许匿名）
	methods := []byte{methodNoAuth}
	if !c.empty() {
		methods = []byte{methodUserPass, methodNoAuth}
	}
	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greet); err != nil {
		return fmt.Errorf("socks 握手写入失败: %w", err)
	}
	var rep [2]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		return fmt.Errorf("socks 握手读取失败: %w", err)
	}
	if rep[0] != 0x05 {
		return fmt.Errorf("socks 版本不对: %d", rep[0])
	}
	switch rep[1] {
	case methodNoAuth:
		// 不需要认证
	case methodUserPass:
		if err := authUserPass(conn, c); err != nil {
			return err
		}
	default:
		if rep[1] == 0xff {
			return fmt.Errorf("socks 服务端不接受我们提供的方法（需要认证？凭据没配？）")
		}
		return fmt.Errorf("socks 服务端选择了不支持的方法: 0x%02x", rep[1])
	}

	return nil
}

// connect 发 CONNECT 请求并读应答（Prepare 之后的第二步，也可以单独用）。
func connect(conn net.Conn, atyp byte, addr []byte, dstPort uint16) error {
	req := make([]byte, 0, 10+len(addr))
	req = append(req, 0x05, cmdConnect, 0x00, atyp)
	req = append(req, addr...)
	req = binary.BigEndian.AppendUint16(req, dstPort)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks CONNECT 写入失败: %w", err)
	}

	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("socks CONNECT 应答读取失败: %w", err)
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks CONNECT 被拒: %s", replyText(head[1]))
	}
	var addrLen int
	switch head[3] {
	case atypIPv4:
		addrLen = 4
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		addrLen = int(l[0])
	case 0x04: // IPv6
		addrLen = 16
	default:
		return fmt.Errorf("socks 应答 ATYP 未知: %d", head[3])
	}
	_, err := io.ReadFull(conn, make([]byte, addrLen+2))
	return err
}

// authUserPass 走 RFC 1929 用户名/口令认证。
func authUserPass(conn net.Conn, c Creds) error {
	u, p := []byte(c.User), []byte(c.Pass)
	if len(u) > 255 || len(p) > 255 {
		return fmt.Errorf("socks 凭据过长")
	}
	buf := make([]byte, 0, 3+len(u)+len(p))
	buf = append(buf, 0x01, byte(len(u)))
	buf = append(buf, u...)
	buf = append(buf, byte(len(p)))
	buf = append(buf, p...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks 认证写入失败: %w", err)
	}
	var rep [2]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		return fmt.Errorf("socks 认证读取失败: %w", err)
	}
	if rep[1] != 0x00 {
		// 不把凭据打进错误里
		return fmt.Errorf("socks 认证被拒（用户名或口令不对）")
	}
	return nil
}

func replyText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown 0x%02x", code)
	}
}

// DialTLS 带认证 + 可选 TLS 地连到 dstIP:dstPort。
// tlsConf 非 nil 时先在连接上做 TLS（= 上游是 socks5+tls 的情况）。
// 这是给 internal/upstream 用的入口 —— 原生链路不再需要本地 gost。
func DialTLS(addr string, c Creds, tlsConf *tls.Config, dstIP net.IP, dstPort uint16,
	timeout time.Duration) (net.Conn, error) {
	v4 := dstIP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", dstIP)
	}
	return dialWith(addr, c, tlsConf, atypIPv4, v4, dstPort, timeout)
}

// ───────────────────────── SOCKS4 / 4a ─────────────────────────
//
// 为什么还支持这么老的东西：它极简（没有方法协商、明文口令），
// 有些内网/老设备只提供 SOCKS4，作为兼容层留着成本很低。

// DialSOCKS4 走 SOCKS4（需要 IP）或 SOCKS4a（把域名交给代理解析）。
// host 给域名时走 4a 的 0.0.0.x 约定。
func DialSOCKS4(proxy, user, host string, dstPort uint16, timeout time.Duration) (net.Conn, error) {
	return DialSOCKS4TLS(proxy, user, host, dstPort, nil, timeout)
}

func socks4Handshake(c net.Conn, user, host string, dstPort uint16) error {
	req := []byte{0x04, 0x01}
	req = binary.BigEndian.AppendUint16(req, dstPort)
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, ip.To4()...)
	} else {
		// SOCKS4a：IP 段填 0.0.0.1，之后跟域名
		req = append(req, 0x00, 0x00, 0x00, 0x01)
	}
	req = append(req, []byte(user)...)
	req = append(req, 0x00)
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		req = append(req, []byte(host)...)
		req = append(req, 0x00)
	}
	if _, err := c.Write(req); err != nil {
		return fmt.Errorf("socks4 请求写入失败: %w", err)
	}
	var rep [8]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return fmt.Errorf("socks4 应答读取失败: %w", err)
	}
	if rep[1] != 0x5a {
		return fmt.Errorf("socks4 CONNECT 被拒: %s", socks4Text(rep[1]))
	}
	return nil
}

func socks4Text(code byte) string {
	switch code {
	case 0x5b:
		return "request rejected or failed"
	case 0x5c:
		return "identd not reachable"
	case 0x5d:
		return "identd user-id mismatch"
	default:
		return fmt.Sprintf("unknown 0x%02x", code)
	}
}

// DialSOCKS4TLS 与 DialSOCKS4 相同，但可先在连接上做 TLS。
// （SOCKS4 协议本身没有 TLS，这里是"TLS 传输层 + SOCKS4 协议"的组合，gost 也允许这么写。）
// PrepareSOCKS4 先连上代理（+可选 TLS），不做 CONNECT —— 给预热连接池用。
// SOCKS4 没有“方法协商”，所以预备阶段就是 TCP+TLS。
func PrepareSOCKS4(proxy string, tlsConf *tls.Config, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	raw, err := net.DialTimeout("tcp", proxy, timeout)
	if err != nil {
		return nil, fmt.Errorf("连代理失败: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))
	if tlsConf == nil {
		return raw, nil
	}
	tc := tls.Client(raw, tlsConf)
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS 握手失败: %w", err)
	}
	return tc, nil
}

// ConnectSOCKS4On 在预备好的连接上发 SOCKS4/4a 请求。
func ConnectSOCKS4On(conn net.Conn, user, host string, dstPort uint16, timeout time.Duration) error {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if err := socks4Handshake(conn, user, host, dstPort); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

func DialSOCKS4TLS(proxy, user, host string, dstPort uint16, tlsConf *tls.Config,
	timeout time.Duration) (net.Conn, error) {
	c, err := PrepareSOCKS4(proxy, tlsConf, timeout)
	if err != nil {
		return nil, err
	}
	if err := ConnectSOCKS4On(c, user, host, dstPort, timeout); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// DialTLSHost 同 DialTLS，但把**域名**交给代理解析（SOCKS5 的 ATYP=域名）。
//
// 用途："域名交给上游" —— 内网域名不必在本机解析得出，本机 DNS 也不会泄漏内网域名。
func DialTLSHost(addr string, c Creds, tlsConf *tls.Config, host string, dstPort uint16,
	timeout time.Duration) (net.Conn, error) {
	if strings.Contains(host, ":") {
		return nil, fmt.Errorf("域名里不该带端口: %q", host)
	}
	body := append([]byte{byte(len(host))}, []byte(host)...)
	return dialWith(addr, c, tlsConf, atypDomain, body, dstPort, timeout)
}
