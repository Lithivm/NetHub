package upstream

import (
	"fmt"
	"net"
	"time"
)

// HTTP / HTTPS 代理（CONNECT 隧道，支持 Basic 认证）。
//
// 注意一个反直觉的点：`http://` 这个名字的代理**代理的是任意 TCP**（走 CONNECT），
// 不是"只能代理 HTTP 流量"。真正的区别只是到上游那一跳用不着 TLS（https:// 才用）。

func init() {
	register("http", func(u *Upstream) Proxy { return &httpProxy{u} })
}

type httpProxy struct{ u *Upstream }

func (p *httpProxy) Dial(ip net.IP, port uint16, timeout time.Duration) (net.Conn, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", ip)
	}
	return dialHTTPConnect(p.u, v4, port, timeout)
}

func (p *httpProxy) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	// CONNECT 里写 host:port → 由代理自己去解析
	return dialHTTPConnectHost(p.u, host, port, timeout)
}

func (p *httpProxy) Prepare(timeout time.Duration) (net.Conn, error) {
	return prepareHTTPConnect(p.u, timeout)
}

func (p *httpProxy) ConnectOn(conn net.Conn, ip net.IP, port uint16, timeout time.Duration) error {
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("仅支持 IPv4 目标: %v", ip)
	}
	return connectHTTPConnect(p.u, conn, v4, port, timeout)
}

func (p *httpProxy) SupportsPrepare() bool { return true }
