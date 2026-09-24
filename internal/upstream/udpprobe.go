package upstream

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"nethub/internal/socks"
)

// ProbeUDP 探一件事：**这条上游现在能不能帮我们中继 UDP**。
//
// 为什么值得单独一个探针：项目明确不做 UDP 中继（QUIC 只拦不转），所以这里探出来的
// 不是“要开启的功能”，而是**事实**——
//   - 现在给不出能力，界面就不该让人以为“我们支持 UDP”；
//   - 将来上游（gost）侧放行了 UDP 端口，一条命令就能复测，不用凭感觉改架构。
//
// 判据只有一条：发一个真包、等一个真回包。SOCKS5 应答码 0 **不算数**
// （实测四条 gost 上游全是 0，真实往返 4/4 不通）。
type UDPProbeResult struct {
	// Supported 控制器与数据面都通了（真的能中继）
	Supported bool
	// BND 代理给出的转发地址（Supported 或 ASSOCIATE 通过时才有意义）
	BND string
	// RTT 真实往返耗时（Supported 时）
	RTT time.Duration
	// Reason 不可用时的人话原因（带原始错误）；Supported 时为空
	Reason string
}

// ProbeUDP 对一条上游做 UDP 能力探测：握手（含认证）→ UDP ASSOCIATE → 真实往返。
//
// 目标固定用公网 DNS（默认 114.114.114.114:53）：**不碰客户内网**。
func ProbeUDP(up *Upstream, dstIP net.IP, dstPort uint16, timeout time.Duration) UDPProbeResult {
	var tlsConf *tls.Config
	if up.TLS {
		// 和 gost 默认行为一致：不配 CA 就不校验
		tlsConf = &tls.Config{InsecureSkipVerify: !up.Verify, ServerName: up.ServerName}
	}
	conn, err := socks.Prepare(up.Addr, up.Creds, tlsConf, timeout)
	if err != nil {
		return UDPProbeResult{Reason: "连不上上游：" + err.Error()}
	}
	defer conn.Close()

	bnd, code, err := socks.UDPAssociate(conn, timeout)
	if err != nil {
		return UDPProbeResult{Reason: fmt.Sprintf("UDP ASSOCIATE 失败（应答码 %d）：%v", code, err)}
	}
	if code != 0x00 {
		return UDPProbeResult{BND: bnd, Reason: fmt.Sprintf("上游拒绝了 UDP ASSOCIATE（SOCKS 应答码 %d%s）", code, socksReplyText(code))}
	}

	start := time.Now()
	// 字节数不重要，重要的是“有没有回包”
	if _, err := socks.UDPRoundTrip(bnd, dstIP, dstPort, dnsQueryPayload("www.baidu.com"), timeout); err != nil {
		// 最容易被误读的一条：ASSOCIATE 通过 ≠ 能中继。
		return UDPProbeResult{BND: bnd, Reason: fmt.Sprintf("UDP ASSOCIATE 已被接受（bnd=%s），但真实往返没有回包：%v", bnd, err)}
	}
	return UDPProbeResult{Supported: true, BND: bnd, RTT: time.Since(start)}
}

// socksReplyText 给 SOSK5 应答码补一句人话（只补常见的几个，其余留空）。
func socksReplyText(code byte) string {
	switch code {
	case 0x01:
		return "，一般性失败"
	case 0x02:
		return "，规则不允许"
	case 0x07:
		return "，不支持该命令（上游没实现 UDP）"
	}
	return ""
}

// dnsQueryPayload 一个最小的 A 记录查询（txid 固定够用：只为了换一个回包）。
func dnsQueryPayload(name string) []byte {
	q := []byte{0x1d, 0x2b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range splitLabels(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0x00, 0x00, 0x01, 0x00, 0x01)
}

func splitLabels(s string) []string {
	var out []string
	cur := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if len(cur) > 0 {
				out = append(out, string(cur))
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, s[i])
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}
