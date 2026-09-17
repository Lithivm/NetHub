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

// dialWith 发 SOCKS5 握手 + CONNECT。
//
// tlsConf 非 nil 时先在连接上做 TLS（= 上游用 socks5+tls 的情况）。
// addr 是 ATYP 对应的地址体（IPv4 4 字节 / 域名 = 长度+字节）。
func dialWith(proxy string, c Creds, tlsConf *tls.Config, atyp byte, addr []byte,
	dstPort uint16, timeout time.Duration) (net.Conn, error) {
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

	if err := handshake(conn, c, atyp, addr, dstPort); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{}) // 清掉超时，之后是长连接
	return conn, nil
}

func handshake(conn net.Conn, c Creds, atyp byte, addr []byte, dstPort uint16) error {
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

	// ② CONNECT
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
