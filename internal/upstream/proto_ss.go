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

// shadowsocks 上游 —— 传统 AEAD（SIP004）与 2022（SIP022）两种都收。
//
// URL 两种写法都收（现场两种都有人用）：
//
//	ss://method:password@host:port              ← gost 的写法（明文）
//	ss://base64(method:password)@host:port      ← SIP002 分享链接的写法
//
// 传输层与别的协议共用（`ss+tls` / `ss+ws` / `ss+wss` 都能写）。
//
// 两种套件的差别（**同一个 scheme，看加密方式名分发**）：
//
//	传统：口令是口令，密钥 = EVP_BytesToKey(MD5)        见 internal/ss/conn.go
//	2022：口令字段是 **base64 的 PSK**，密钥直接就是它      见 internal/ss/ss2022.go
//
// 不做的：老式流密码（aes-*-cfb …）与 none/dummy（解析期就拒，并给出该换成哪个）、
// 2022 的多用户 PSK（要 EIH 报头）。

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
	if _, err := ss.LookupSuite(method); err != nil {
		return err
	}
	// 2022 的 PSK 在这里就解开校验（长度、base64、多用户写法），别等到拨号才报 ——
	// PSK 写错的表现是"服务端静默断开"，不在解析期拦住就只能靠人猜。
	if ss.Is2022(method) {
		if _, err := ss.ParsePSK(method, password); err != nil {
			return err
		}
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

// psk 解 2022 的 PSK（解析期校过一遍，这里再解一次；解不开说明配置被热改过）。
func (p *ssProxy) psk(method string) ([]byte, error) {
	return ss.ParsePSK(method, p.u.Creds.Pass)
}

func (p *ssProxy) Dial(ip net.IP, port uint16, timeout time.Duration) (net.Conn, error) {
	target, err := appendAddr(nil, ip, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *ssProxy) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	// 域名透传给服务端解析（ATYP=域名）—— 内网域名因此不必在本机解析得出。
	target, err := appendAddrHost(nil, host, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *ssProxy) dial(target []byte, timeout time.Duration) (net.Conn, error) {
	raw, err := p.u.dialTransport(timeout)
	if err != nil {
		return nil, err
	}
	conn, err := p.wrap(raw, target)
	if err != nil {
		raw.Close()
		return nil, err
	}
	// shadowsocks **没有握手应答**（服务端解密失败就静默断开），所以这里没法"确认通了"，
	// 只能把超时交给上层（relay 的空闲/连接超时）。这也是它比 socks5 省一个 RTT 的原因。
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// wrap 按加密方式选传统/2022 实现，并把目标地址设好。
func (p *ssProxy) wrap(raw net.Conn, target []byte) (net.Conn, error) {
	method := p.u.Creds.User
	if ss.Is2022(method) {
		c, err := ss.Lookup2022(method)
		if err != nil {
			return nil, err
		}
		psk, err := p.psk(method)
		if err != nil {
			return nil, err
		}
		return ss.ClientConn2022(raw, c, psk, target)
	}
	c, err := ss.Lookup(method)
	if err != nil {
		return nil, err
	}
	return ss.ClientConn(raw, c, p.u.Creds.Pass, target)
}

// Prepare 预热：只把传输层建好（TCP+TLS+WS），salt 与地址留到第一次 Write ——
// 预热池里放很久的连接不该提前把 salt 发出去（2022 还会把时间戳发出去，那会过期）。
func (p *ssProxy) Prepare(timeout time.Duration) (net.Conn, error) {
	raw, err := p.u.dialTransport(timeout)
	if err != nil {
		return nil, err
	}
	conn, err := p.newClient(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

func (p *ssProxy) newClient(raw net.Conn) (net.Conn, error) {
	method := p.u.Creds.User
	if ss.Is2022(method) {
		c, err := ss.Lookup2022(method)
		if err != nil {
			return nil, err
		}
		psk, err := p.psk(method)
		if err != nil {
			return nil, err
		}
		return ss.NewClient2022(raw, c, psk)
	}
	c, err := ss.Lookup(method)
	if err != nil {
		return nil, err
	}
	return ss.NewClient(raw, c, p.u.Creds.Pass)
}

// ConnectOn 在预备好的连接上"打通"到目标 —— 对 shadowsocks 就是设好目标地址。
func (p *ssProxy) ConnectOn(conn net.Conn, ip net.IP, port uint16, timeout time.Duration) error {
	target, err := appendAddr(nil, ip, port)
	if err != nil {
		return err
	}
	switch c := conn.(type) {
	case *ss.Conn:
		return c.SetTarget(target)
	case *ss.Conn2022:
		return c.SetTarget(target)
	}
	return fmt.Errorf("ss 预热连接类型不对: %T", conn)
}

func (p *ssProxy) SupportsPrepare() bool { return true }
