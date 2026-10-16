package upstream

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"nethub/internal/ss"
)

// shadowsocks（传统 AEAD）上游。
//
// URL 两种写法都收（现场两种都有人用）：
//
//	ss://method:password@host:port              ← gost 的写法（明文）
//	ss://base64(method:password)@host:port      ← SIP002 分享链接的写法
//
// 传输层与别的协议共用（`ss+tls` / `ss+ws` / `ss+wss` 都能写）。
//
// 不做的：老式流密码（aes-*-cfb …）与 none/dummy —— 解析期就拒，并给出该换成哪个（见 ss.Lookup）。
// 2022（SIP022）是另一套实现，见 proto_ss2022.go。

func init() {
	register("ss", func(u *Upstream) Proxy { return &ssProxy{u} })
	registerURLSetup("ss", ssSetup)
}

// ssSetup 解析期校验并归一化 ss 的参数（**在解析期就把错挡住**：
// 加密方式写错/口令为空这种"一看就知道不对"的配置，不该等到第一次拨号才报）。
func ssSetup(u *Upstream, q url.Values) error {
	method, password := u.Creds.User, u.Creds.Pass

	// SIP002：userinfo 是 base64(method:password)（没有冒号才可能是这种写法）。
	if !strings.Contains(method, ":") && password == "" {
		if m, p, ok := decodeSSUserinfo(method); ok {
			method, password = m, p
		}
	}
	if method == "" || password == "" {
		return fmt.Errorf("shadowsocks 上游必须带加密方式与口令：" +
			"ss://<加密方式>:<口令>@host:port（例如 ss://aes-256-gcm:你的口令@1.2.3.4:8388）")
	}
	if _, err := ss.Lookup(method); err != nil {
		return err
	}
	u.Creds.User, u.Creds.Pass = method, password
	return nil
}

// decodeSSUserinfo 解 SIP002 的 base64 userinfo（标准与 URL-safe、带/不带 padding 都试）。
func decodeSSUserinfo(s string) (method, password string, ok bool) {
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{
		base64.RawStdEncoding, base64.StdEncoding,
		base64.RawURLEncoding, base64.URLEncoding,
	} {
		dec, err := enc.DecodeString(trimmed)
		if err != nil {
			continue
		}
		if i := strings.Index(string(dec), ":"); i > 0 {
			return string(dec[:i]), string(dec[i+1:]), true
		}
	}
	return "", "", false
}

type ssProxy struct{ u *Upstream }

// cipher 取套件（解析期已经校验过，这里再取一次；成本是一次 map 查找）。
func (p *ssProxy) cipher() (ss.Cipher, error) { return ss.Lookup(p.u.Creds.User) }

func (p *ssProxy) Dial(ip net.IP, port uint16, timeout time.Duration) (net.Conn, error) {
	target, err := ss.Addr(ip, "", port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *ssProxy) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	// 域名透传给服务端解析（ATYP=域名）—— 内网域名因此不必在本机解析得出。
	target, err := ss.Addr(nil, host, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *ssProxy) dial(target []byte, timeout time.Duration) (net.Conn, error) {
	c, err := p.cipher()
	if err != nil {
		return nil, err
	}
	raw, err := p.u.dialTransport(timeout)
	if err != nil {
		return nil, err
	}
	conn, err := ss.ClientConn(raw, c, p.u.Creds.Pass, target)
	if err != nil {
		raw.Close()
		return nil, err
	}
	// shadowsocks **没有握手应答**（服务端解密失败就静默断开），所以这里没法"确认通了"，
	// 只能把超时交给上层（relay 的空闲/连接超时）。这也是它比 socks5 省一个 RTT 的原因。
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// Prepare 预热：只把传输层建好（TCP+TLS+WS），salt 与地址留到第一次 Write ——
// 预热池里放很久的连接不该提前把 salt 发出去。
func (p *ssProxy) Prepare(timeout time.Duration) (net.Conn, error) {
	c, err := p.cipher()
	if err != nil {
		return nil, err
	}
	raw, err := p.u.dialTransport(timeout)
	if err != nil {
		return nil, err
	}
	conn, err := ss.NewClient(raw, c, p.u.Creds.Pass)
	if err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// ConnectOn 在预备好的连接上"打通"到目标 —— 对 shadowsocks 就是设好目标地址。
func (p *ssProxy) ConnectOn(conn net.Conn, ip net.IP, port uint16, timeout time.Duration) error {
	sc, ok := conn.(*ss.Conn)
	if !ok {
		return fmt.Errorf("ss 预热连接类型不对: %T", conn)
	}
	target, err := ss.Addr(ip, "", port)
	if err != nil {
		return err
	}
	return sc.SetTarget(target)
}

func (p *ssProxy) SupportsPrepare() bool { return true }
