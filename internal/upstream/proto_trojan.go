package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// trojan 上游。
//
// URL（两种习惯都收）：
//
//	trojan://<口令>@host:443                          ← 官方/分享链接的写法
//	trojan+ws://<口令>@host:443?path=/ws               ← 我们的传输后缀写法
//	trojan://<口令>@host:443?type=ws&path=/ws&sni=x    ← xray 分享链接的写法
//
// 线格式（TLS 之后，KB 有全文）：
//
//	hex(SHA224(口令)) 56 字节 + CRLF + 请求 + CRLF + 业务数据
//	请求 = CMD(0x01 CONNECT) | ATYP | ADDR | PORT
//
// **服务端成功时什么都不回**（认证失败会改接伪装站点，看起来像"连上了但没数据"）——
// 所以 trojan 的"通了"只能靠后续数据判断，不能像 socks5 那样等应答。这一点必须记住：
// 我们把超时交给上层（relay 的空闲超时），别在这里等一个永远不会来的应答。
//
// UDP（CMD=0x03）不做 —— 我们本来就不中继 UDP（见 AGENTS.md）。

func init() {
	register("trojan", func(u *Upstream) Proxy { return &trojanProxy{u} })
	registerURLSetup("trojan", trojanSetup)
}

func trojanSetup(u *Upstream, q url.Values) error {
	if err := applyXrayParams(u, q); err != nil {
		return err
	}
	if strings.TrimSpace(u.Creds.User) == "" && strings.TrimSpace(u.Creds.Pass) == "" {
		return fmt.Errorf("trojan 上游必须带口令：trojan://<口令>@host:443")
	}
	return nil
}

// trojanPassword 口令取法：`trojan://pw@host` 里 pw 落在 Creds.User（url 的单段 userinfo
// 就是"用户名"），而 `trojan://user:pw@host` 这种非常规写法取冒号后的部分 ——
// 官方的口令是**一段**，所以两种都按"口令 = 有冒号就取后半段"来处理。
func trojanPassword(u *Upstream) string {
	if u.Creds.Pass != "" {
		return u.Creds.Pass
	}
	return u.Creds.User
}

type trojanProxy struct{ u *Upstream }

func (p *trojanProxy) Dial(ip net.IP, port uint16, timeout time.Duration) (net.Conn, error) {
	target, err := appendAddr(nil, ip, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *trojanProxy) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	target, err := appendAddrHost(nil, host, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *trojanProxy) dial(target []byte, timeout time.Duration) (net.Conn, error) {
	raw, err := p.u.dialTransport(timeout)
	if err != nil {
		return nil, err
	}
	if !p.u.TLS {
		// trojan 的请求头是**明文**发在 TLS 里的；没有 TLS 就等于把口令哈希暴露在线上，
		// 而且现实里的 trojan 服务端都是 TLS 监听 —— 允许这么写只会让人配错了才发现。
		raw.Close()
		return nil, fmt.Errorf("trojan 必须走 TLS（写 trojan:// 即默认 TLS；" +
			"若上游真的没证书，请用别的协议）")
	}
	if _, err := raw.Write(trojanRequest(trojanPassword(p.u), target)); err != nil {
		raw.Close()
		return nil, fmt.Errorf("trojan 请求写入失败: %w", err)
	}
	// 不等应答（服务端成功时什么都不回），把超时交给上层。
	_ = raw.SetDeadline(time.Time{})
	return raw, nil
}

// Prepare 预热：把 TLS（+ws）握手做完，请求头留到 ConnectOn ——
// 请求头里有目标地址，不知道目标就发不出去。
func (p *trojanProxy) Prepare(timeout time.Duration) (net.Conn, error) {
	if !p.u.TLS {
		return nil, fmt.Errorf("trojan 必须走 TLS")
	}
	return p.u.dialTransport(timeout)
}

// ConnectOn 在预备好的连接上写 trojan 请求头（请求头里没有"应答"要等）。
func (p *trojanProxy) ConnectOn(conn net.Conn, ip net.IP, port uint16, timeout time.Duration) error {
	target, err := appendAddr(nil, ip, port)
	if err != nil {
		return err
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write(trojanRequest(trojanPassword(p.u), target)); err != nil {
		return fmt.Errorf("trojan 请求写入失败: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

func (p *trojanProxy) SupportsPrepare() bool { return true }

// trojanRequest 拼请求：hex(SHA224(口令)) + CRLF + CMD + 地址 + CRLF。
//
// SHA224 = SHA-224（不是 SHA-256 截断！），十六进制**小写** 56 个字符 —— 服务端是
// 按"定长 56 + CRLF"读的，长度或大小写错了会直接被当成伪装站点访问。
func trojanRequest(password string, target []byte) []byte {
	sum := sha256.Sum224([]byte(password))
	out := make([]byte, 0, 56+2+1+len(target)+2)
	out = append(out, hex.EncodeToString(sum[:])...)
	out = append(out, '\r', '\n')
	out = append(out, cmdConnect)
	out = append(out, target...)
	out = append(out, '\r', '\n')
	return out
}

// cmdConnect trojan 与 vless/vmess 的 CMD 值一样：0x01 = CONNECT（TCP）。
const cmdConnect = 0x01
