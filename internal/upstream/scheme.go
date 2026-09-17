package upstream

import (
	"sort"
	"strings"
)

// supported 已原生实现的协议名（用于错误提示与文档）。
//
// 分类说明（评估结论，详见 README）：
//   - socks5 / socks4 / http : 都能接受"我们给的目标 IP:port"，直接可用
//   - 传输层目前支持 tls / mtls；ws/wss/ssh 可加；quic/kcp/obfs4 是 gost 自研帧
//     封装，复刻成本高且随版本变，不做
//   - forward/direct/remote 是"目标写死在配置里"的端口转发，与我们的动态目标语义不符
func SupportedSchemes() string {
	names := []string{"socks5", "socks4", "socks4a", "http", "https"}
	sort.Strings(names)
	return strings.Join(names, " / ")
}

// knownPrefix 判定 scheme 是否在我们的能力范围内（含传输后缀）。
//
// 除已实现的以外，故意把 ws/wss/ssh/mtls 这类"将来可加"的也标为 unknown 之外的
// 提示语不同，便于用户判断是自己写错还是我们没实现。
func classify(scheme string) (base string, tls bool, known bool) {
	s := strings.ToLower(scheme)
	tls = false
	if strings.Contains(s, "+") {
		parts := strings.Split(s, "+")
		s = parts[0]
		for _, p := range parts[1:] {
			switch p {
			case "tls", "mtls":
				tls = true
			}
		}
	}
	switch s {
	case "socks", "socks5", "socks5h", "socks4", "socks4a", "http", "https":
		switch s {
		case "https":
			tls = true
			s = "http"
		case "socks", "socks5h":
			s = "socks5" // 别名归一化：gost 里 socks / socks5h 就是 socks5
		}
		return s, tls, true
	}
	return s, tls, false
}
