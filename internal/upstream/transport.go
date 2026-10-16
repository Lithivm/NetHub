package upstream

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// 传输层：**TCP → [TLS] → [WS 握手]**，代理协议（SOCKS5 / HTTP CONNECT / shadowsocks /
// trojan / vless / vmess）的字节流跑在它上面。
//
// 这正是 gost 的组合语义（`handler+listener` / `connector+dialer`）：
//
//	socks5+tls   TLS 里跑 SOCKS5
//	socks5+ws    SOCKS5 字节直接塞进 ws 帧（**没有**额外自定义握手头）
//	socks5+wss   ws 再套 TLS
//
// ⚠ 只认**两段**：`socks5+ws+tls` 在 gost 里是**非法写法**（超过两段会被静默丢弃、
// 回落到 http/tcp 默认）—— 对我们要来说静默降级比报错更糟，所以解析期直接拒绝（见 scheme.go）。
const (
	transportTCP = "tcp" // 裸 TCP
	transportTLS = "tls" // TCP + TLS
	transportWS  = "ws"  // TCP + ws
	transportWSS = "wss" // TCP + TLS + ws
)

// dialTransport 拨通传输层，返回一条能当字节流用的连接。
//
// 协议实现**必须**走这里，别再各自 `net.DialTimeout` —— 否则"套了 ws 就少了一层 TLS"
// 这类问题会在每个协议里各写错一次。
func (u *Upstream) dialTransport(timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	raw, err := net.DialTimeout("tcp", u.Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("连代理失败: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))
	conn := raw
	if u.TLS {
		tc, err := tlsClient(raw, u.tlsConfig())
		if err != nil {
			return nil, fmt.Errorf("代理的 TLS 握手失败: %w", err)
		}
		conn = tc
	}
	if u.ws() {
		// wss 的 TLS 已经在上面做完了，这里只做 ws 握手（Host 头见 wsHost()）。
		wc, resp, err := wsDial(conn, u.wsHost(), u.WSPath, "", timeout)
		if err != nil {
			conn.Close()
			return nil, wsHandshakeError(resp, err)
		}
		conn = wc
	}
	// **不能在这里清 deadline**：握手才刚开始（协议层还要协商/认证/发协议头），
	// 清掉就等于把超时交给对端 —— 碰到黑洞上游会永远挂住（契约③就是这么拓出来的）。
	// 清 deadline 的责任在“隧道真的打通了”那一步（见 socks.ConnectOn / sendConnectRequest）。
	return conn, nil
}

// ws 这条上游要不要在传输层外面套 ws。
func (u *Upstream) ws() bool { return u.Transport == transportWS || u.Transport == transportWSS }

// wsHost Host 头：默认就是节点地址（gost 与 xray 都是这个口径），`?host=` 可以改。
func (u *Upstream) wsHost() string {
	if u.WSHost != "" {
		return u.WSHost
	}
	return u.Addr
}

// transportSuffix 传输层的写法（用于日志与界面显示，拼回 URL 形态）。
func (u *Upstream) transportSuffix() string {
	switch u.Transport {
	case transportWS, transportWSS:
		return "+" + u.Transport
	case transportTLS:
		return "+tls"
	}
	return ""
}

// SchemeTag 归一化后的协议写法：`socks5+ws` / `ss+tls` / `trojan` …（不含凭据）。
func (u *Upstream) SchemeTag() string { return u.Protocol + u.transportSuffix() }

// parseTransport 把 scheme 的第二段（传输）归一化。
//
// `mtls` 按普通 TLS 收下：gost 的 `mtls` 是 **m**ultiplexed TLS（smux/yamux 多路复用帧），
// 与业界说的 mutual TLS **撞名** —— 我们不做多路复用，也不把 `mtls` 当客户端证书
// （那要用 `?cert=&key=` 显式给，见 Parse）。真用了多路复用上游的话连不上，
// 报错里会说"我们按普通 TLS 处理"。
func parseTransport(seg string) (string, error) {
	switch strings.ToLower(seg) {
	case "", "tcp", "raw":
		return transportTCP, nil
	case "tls", "mtls":
		return transportTLS, nil
	case "ws":
		return transportWS, nil
	case "wss":
		return transportWSS, nil
	}
	return "", fmt.Errorf("不支持的传输 %q（支持 tls / ws / wss；多路复用的 mtls、mws、quic、kcp 不做）", seg)
}

// tlsClientOrRaw 需要 TLS 就握手，否则原样返回（shadowsocks / vless 等共用）。
func tlsClientOrRaw(raw net.Conn, cfg *tls.Config) (net.Conn, error) {
	if cfg == nil {
		return raw, nil
	}
	return tlsClient(raw, cfg)
}
