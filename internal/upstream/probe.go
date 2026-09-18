package upstream

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Probe 探一下这条上游还活着吗：TCP 连通 +（需要时）完成 TLS 握手，返回耗时。
//
// 刻意**只测到代理这一段**：不做 SOCKS 协商、也不 CONNECT 任何目标 —— 目的是回答
// "这条链路通不通、大概多快"，而不是"某个业务目标通不通"（那是业务健康巡检的事）。
// 这样探活不会打扰任何内网服务器。
func (u *Upstream) Probe(timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", u.Addr, timeout)
	if err != nil {
		return 0, fmt.Errorf("连不上 %s", u.Addr)
	}
	defer conn.Close()
	if !u.TLS {
		return time.Since(start), nil
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, u.tlsConfig())
	if err := tc.Handshake(); err != nil {
		return 0, fmt.Errorf("TLS 握手失败: %v", err)
	}
	return time.Since(start), nil
}
