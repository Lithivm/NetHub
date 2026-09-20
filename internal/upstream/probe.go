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

// ProbeAuthResult 一次"代理段"体检的结果。
//
// 为什么要把"认证"单独分出来：旧的 Probe 只做 TCP+TLS 握手，**口令错了也报可用**
// （真实事故：sjy 的口令被上游间歇性拒掉，界面一直显示绿色"可用（96ms）"，
// 靠外部工具才查出来）。所以真正的"代理段可用"至少要完成一次性握手 + 认证，
// 再 CONNECT 一个**公网**地址确认它真的能转发 —— 探公网不会打扰任何内网服务器，
// 与"健康探测只测到代理这一段"这条取舍并不冲突。
type ProbeAuthResult struct {
	Latency time.Duration // 到"认证通过"为止的耗时
	AuthOK  bool          // TCP+TLS+SOCKS 协商 + 认证都过了
	Public  bool          // 还能 CONNECT 出去（出口能不能出公网）
	Err     error         // AuthOK=false 时的原因（认证被拒/超时/证书…）
}

// 公网探针地址：不依赖客户内网的任何东西，只用来确认"出口能转发"。
// 用 IP 而不是域名：省掉在出口侧做 DNS 的不确定性。
const (
	ProbePublicIP   = "223.5.5.5" // 阿里公共 DNS
	ProbePublicPort = 443
)

// ProbeAuth 代理段体检：握手 + 认证 + （尽量）转发一次。
func (u *Upstream) ProbeAuth(timeout time.Duration) ProbeAuthResult {
	start := time.Now()
	conn, err := u.Prepare(timeout)
	if err != nil {
		return ProbeAuthResult{Err: err}
	}
	defer conn.Close()
	res := ProbeAuthResult{Latency: time.Since(start), AuthOK: true}
	ip := net.ParseIP(ProbePublicIP).To4()
	if ip == nil {
		return res
	}
	if err := u.ConnectOn(conn, ip, ProbePublicPort, timeout); err != nil {
		// 认证已过，只是出口出不了公网 —— 很多客户出口就是这样，不算故障
		return res
	}
	res.Public = true
	return res
}
