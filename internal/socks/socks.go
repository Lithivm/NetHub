// Package socks 实现最小 SOCKS5 客户端（no-auth）。
//
// 我们连的是本机 gost，明文 SOCKS5 即可；TLS 那一层由 gost 负责连上游，
// 所以这里不需要实现 gost 的 tls/tls-auth 私有扩展方法。
package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	methodNoAuth = 0x00
	cmdConnect   = 0x01
	atypIPv4     = 0x01
	atypDomain   = 0x03
)

// Dial 通过 proxy（如 127.0.0.1:1080）连到 dstIP:dstPort。
func Dial(proxy string, dstIP net.IP, dstPort uint16, timeout time.Duration) (net.Conn, error) {
	v4 := dstIP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", dstIP)
	}
	return dialWith(proxy, atypIPv4, v4, dstPort, timeout)
}

// DialHost 把**域名**交给代理解析后再连（等价 curl 的 --socks5-hostname）。
//
// 为什么不复用 Dial：判断"浏览器走代理时能不能到内网"必须用这条路。
// 浏览器经代理时交给代理的是域名，**解析权在代理手里**，
// 而代理通常看不到系统 hosts 文件 —— 这正是内网域名经代理必坏的原因。
func DialHost(proxy, host string, dstPort uint16, timeout time.Duration) (net.Conn, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return dialWith(proxy, atypIPv4, v4, dstPort, timeout)
		}
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", host)
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("域名长度非法: %q", host)
	}
	body := append([]byte{byte(len(host))}, []byte(host)...)
	return dialWith(proxy, atypDomain, body, dstPort, timeout)
}

// dialWith 发 SOCKS5 CONNECT。addr 是 ATYP 对应的地址体（IPv4 4 字节 / 域名 = 长度+字节）。
func dialWith(proxy string, atyp byte, addr []byte, dstPort uint16, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c, err := net.DialTimeout("tcp", proxy, timeout)
	if err != nil {
		return nil, fmt.Errorf("连本地 socks 失败: %w", err)
	}
	// 握手阶段设个总超时，成功后再清掉，避免长连接被读超时打断
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{0x05, 0x01, methodNoAuth}); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks 握手写入失败: %w", err)
	}
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks 握手读取失败: %w", err)
	}
	if rep[0] != 0x05 || rep[1] != methodNoAuth {
		c.Close()
		return nil, fmt.Errorf("socks 服务端拒绝 no-auth: %v", rep)
	}
	req := make([]byte, 0, 10+len(addr))
	req = append(req, 0x05, cmdConnect, 0x00, atyp)
	req = append(req, addr...)
	req = binary.BigEndian.AppendUint16(req, dstPort)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks CONNECT 写入失败: %w", err)
	}
	// 应答：VER REP RSV ATYP BND.ADDR BND.PORT
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks CONNECT 应答读取失败: %w", err)
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks CONNECT 被拒: %s", replyText(head[1]))
	}
	var addrLen int
	switch head[3] {
	case atypIPv4:
		addrLen = 4
	case 0x03: // 域名
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			c.Close()
			return nil, err
		}
		addrLen = int(l[0])
	case 0x04: // IPv6
		addrLen = 16
	default:
		c.Close()
		return nil, fmt.Errorf("socks 应答 ATYP 未知: %d", head[3])
	}
	if _, err := io.ReadFull(c, make([]byte, addrLen+2)); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{}) // 清掉超时，之后是长连接
	return c, nil
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
	}
	return fmt.Sprintf("unknown(%d)", code)
}
