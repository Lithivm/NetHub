package upstream

import (
	"fmt"
	"net"
	"time"

	"nethub/internal/socks"
)

// SOCKS4 / SOCKS4a / SOCKS5 三种协议（gost 的 socks5 / socks5h / socks 都是 SOCKS5）。
//
// 域名交给上游的能力各家不同，这也正是要拆成三个实现而不是一个的原因：
//
//	socks5   原生支持（ATYP=域名）
//	socks4a  原生支持（0.0.0.x 约定）
//	socks4   **不支持域名** → 只能本机解析成 IP 再连（保底，会失去"上游侧解析"的意义）

func init() {
	register("socks5", func(u *Upstream) Proxy { return &socks5Proxy{u} })
	register("socks4", func(u *Upstream) Proxy { return &socks4Proxy{u} })
	register("socks4a", func(u *Upstream) Proxy { return &socks4Proxy{u} })
}

type socks5Proxy struct{ u *Upstream }

func (p *socks5Proxy) Dial(ip net.IP, port uint16, timeout time.Duration) (net.Conn, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", ip)
	}
	return socks.DialTLS(p.u.Addr, p.u.Creds, p.u.tls(), v4, port, timeout)
}

func (p *socks5Proxy) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	return socks.DialTLSHost(p.u.Addr, p.u.Creds, p.u.tls(), host, port, timeout)
}

func (p *socks5Proxy) Prepare(timeout time.Duration) (net.Conn, error) {
	return socks.Prepare(p.u.Addr, p.u.Creds, p.u.tls(), timeout)
}

func (p *socks5Proxy) ConnectOn(conn net.Conn, ip net.IP, port uint16, timeout time.Duration) error {
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("仅支持 IPv4 目标: %v", ip)
	}
	return socks.ConnectOn(conn, v4, port, timeout)
}

func (p *socks5Proxy) SupportsPrepare() bool { return true }

type socks4Proxy struct{ u *Upstream }

func (p *socks4Proxy) Dial(ip net.IP, port uint16, timeout time.Duration) (net.Conn, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", ip)
	}
	// SOCKS4 协议本身没有 TLS；但 gost 允许 "socks4+tls" 这种"TLS 传输 + SOCKS4 协议"。
	return socks.DialSOCKS4TLS(p.u.Addr, p.u.Creds.User, v4.String(), port, p.u.tls(), timeout)
}

func (p *socks4Proxy) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	if p.u.Protocol != "socks4a" {
		// SOCKS4（无 a）只能带 IP → 本机解析。这是"保底"，会失去上游侧解析的意义。
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("SOCKS4 不支持域名，且本机解析 %s 失败: %v", host, err)
		}
		// 必须**挑 IPv4**，不能取 ips[0]：双栈名字（localhost 就是）常常先回 ::1，
		// 取第一条会直接报"只支持 IPv4"，而 A 记录其实是有的（契约测试拓出来的）。
		var v4 net.IP
		for _, ip := range ips {
			if x := ip.To4(); x != nil {
				v4 = x
				break
			}
		}
		if v4 == nil {
			return nil, fmt.Errorf("SOCKS4 只支持 IPv4，%s 解析到 %v", host, ips)
		}
		return socks.DialSOCKS4TLS(p.u.Addr, p.u.Creds.User, v4.String(), port, p.u.tls(), timeout)
	}
	return socks.DialSOCKS4TLS(p.u.Addr, p.u.Creds.User, host, port, p.u.tls(), timeout)
}

func (p *socks4Proxy) Prepare(timeout time.Duration) (net.Conn, error) {
	return socks.PrepareSOCKS4(p.u.Addr, p.u.tls(), timeout)
}

func (p *socks4Proxy) ConnectOn(conn net.Conn, ip net.IP, port uint16, timeout time.Duration) error {
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("仅支持 IPv4 目标: %v", ip)
	}
	// 目标是 IP，所以 4a 与 4 在这里等价。
	return socks.ConnectSOCKS4On(conn, p.u.Creds.User, v4.String(), port, timeout)
}

func (p *socks4Proxy) SupportsPrepare() bool { return true }
