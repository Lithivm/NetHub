package upstream

import (
	"fmt"
	"sort"
	"strings"
)

// supported 已原生实现的协议名（用于错误提示与文档）。
//
// 分类说明（评估结论，详见 README）：
//   - socks5 / socks4 / http / ss / trojan / vless / vmess : 都能接受"我们给的目标 IP:port"，直接可用
//   - 传输层支持 tls / ws / wss；mtls（gost 的多路复用）、quic/kcp/obfs4（自研帧封装）不做
//   - forward/direct/remote 是"目标写死在配置里"的端口转发，与我们的动态目标语义不符
func SupportedSchemes() string {
	names := []string{"socks5", "socks4", "socks4a", "http", "https", "ss", "trojan", "vless", "vmess"}
	sort.Strings(names)
	return strings.Join(names, " / ")
}

// schemeInfo 一次 scheme 解析的结果。
type schemeInfo struct {
	Base      string // 归一化后的协议名（注册表里的键）
	Transport string // tcp | tls | ws | wss
}

// classify 解析 scheme。
//
// **只认两段**（与 gost 的 `handler+listener` / `connector+dialer` 一致）：
// 超过两段在 gost 里是**静默丢弃**并回落到 http/tcp 默认 —— 那种"写错了却还能跑"
// 最坑人（现场会以为是上游的问题），所以这里直接报错，并把正确写法写在报错里。
func classify(scheme string) (schemeInfo, error) {
	s := strings.ToLower(strings.TrimSpace(scheme))
	var info schemeInfo

	parts := strings.Split(s, "+")
	if len(parts) > 2 {
		return info, fmt.Errorf("上游协议写法只认两段（协议+传输），%q 有三段；"+
			"要「ws 外面再套 TLS」写 wss，例如 socks5+wss://host:8443", scheme)
	}
	base := parts[0]
	tr := transportTCP
	if len(parts) == 2 {
		var err error
		if tr, err = parseTransport(parts[1]); err != nil {
			return info, err
		}
	}

	switch base {
	case "socks", "socks5", "socks5h":
		// gost 里 socks / socks5h 就是 socks5（`socks5h` 只是别人的写法，gost 不认）
		base = "socks5"
	case "socks4", "socks4a":
	case "http":
	case "https":
		base, tr = "http", transportTLS
	case "ss", "shadowsocks":
		base = "ss"
	case "trojan":
		// trojan 天生就是 TLS（协议里没有明文形态）；显式写了别的传输就按写的来。
		if tr == transportTCP {
			tr = transportTLS
		}
	case "vless", "vmess":
	default:
		return info, fmt.Errorf("不支持的上游协议 %q（当前支持 %s）", scheme, SupportedSchemes())
	}
	info.Base, info.Transport = base, tr
	return info, nil
}
