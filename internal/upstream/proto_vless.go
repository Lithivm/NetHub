package upstream

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// VLESS 上游（**裸 flow**，不声明 vision）。
//
// URL：
//
//	vless://<uuid>@host:443                                  ← 分享链接最常见
//	vless://<uuid>@host:443?type=ws&security=tls&path=/&sni=
//	vless+ws://<uuid>@host:443?path=/ws                       ← 我们的传输后缀写法
//
// 线格式（KB 有全文）：
//
//	请求 = Ver(0) | UUID(16 字节**原始值**) | AddonsLen(1) | Addons | Cmd(0x01) | Port(2BE) | AT | Addr
//	响应 = Ver(1) | AddonsLen(1) | Addons        ← **必须先读掉再交上层**
//
// 三件必须记住的事：
//  1. 地址是 B 族编码（**端口在前**、域名 AT=0x02），见 addr.go。
//  2. UUID 错时服务端**静默断开**（没有错误码）→ 表现是"请求写完了、读的时候断"。
//  3. flow / xtls-rprx-vision **本版不做**：服务端账号一旦配了 vision，客户端空 flow 会被
//     **硬拒**（不是降级）。所以配置里写了 flow 就在解析期直接报错，并让用户去掉它 ——
//     比"连不上但不知道为什么"清楚得多。REALITY 同理（要 uTLS 指纹 + X25519）。

func init() {
	register("vless", func(u *Upstream) Proxy { return &vlessProxy{u} })
	registerURLSetup("vless", vlessSetup)
}

func vlessSetup(u *Upstream, q url.Values) error {
	if err := applyXrayParams(u, q); err != nil {
		return err
	}
	if enc := strings.ToLower(q.Get("encryption")); enc != "" && enc != "none" {
		return fmt.Errorf("VLESS 的 encryption 只能是 none（现在写的是 %q）—— "+
			"xray 分享链接里这一项一直是 none，别的值不是 VLESS", enc)
	}
	if flow := q.Get("flow"); flow != "" {
		return fmt.Errorf("VLESS 的 flow=%s（Vision）本版不支持：声明它要双向做 TLS 记录层的"+
			"padding，不声明则服务端**直接拒连**（不会降级）。请让上游把该账号的 flow 去掉，"+
			"或在配置里删掉 flow 参数", flow)
	}
	id := firstNonEmpty(u.Creds.User, u.Creds.Pass)
	uid, err := parseUUID(id)
	if err != nil {
		return fmt.Errorf("vless 上游的凭据应当是 UUID：%w", err)
	}
	u.UserID = uid
	return nil
}

// parseUUID 把 UUID 文本转成 16 字节原始值（vless/vmess 线上写的是**字节**，不是字符串）。
//
// 两种写法都收：标准的 8-4-4-4-12，或者去掉横线的 32 位十六进制（分享链接里都见过）。
func parseUUID(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("UUID 为空（vless://<uuid>@host:port）")
	}
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return nil, fmt.Errorf("%q 不是合法 UUID（应为 8-4-4-4-12 或 32 位十六进制）", s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%q 不是合法 UUID: %w", s, err)
	}
	return b, nil
}

// RandomUUID 生成一个 UUID 文本（测试与"界面上造一个"用）。
func RandomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

type vlessProxy struct{ u *Upstream }

func (p *vlessProxy) Dial(ip net.IP, port uint16, timeout time.Duration) (net.Conn, error) {
	target, err := appendAddrXray(nil, ip, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *vlessProxy) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	target, err := appendAddrHostXray(nil, host, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *vlessProxy) dial(target []byte, timeout time.Duration) (net.Conn, error) {
	raw, err := p.u.dialTransport(timeout)
	if err != nil {
		return nil, err
	}
	if err := p.writeRequest(raw, target, timeout); err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return &vlessConn{Conn: raw}, nil
}

// writeRequest 写请求头。
func (p *vlessProxy) writeRequest(conn net.Conn, target []byte, timeout time.Duration) error {
	if len(p.u.UserID) != 16 {
		return fmt.Errorf("vless 的 UUID 没解析出来（配置错）")
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	// Ver(0) + UUID + AddonsLen(0) + Cmd + 地址（B 族）
	head := make([]byte, 0, 1+16+1+1+len(target))
	head = append(head, 0x00)
	head = append(head, p.u.UserID...)
	head = append(head, 0x00) // AddonsLen = 0（没有 addon 时必须是 0）
	head = append(head, cmdConnect)
	head = append(head, target...)
	if _, err := conn.Write(head); err != nil {
		return fmt.Errorf("VLESS 请求写入失败: %w", err)
	}
	return nil
}

// vlessConn 一条 VLESS 连接：**第一次 Read 时**把响应头剥掉。
//
// 为什么不在这里（Dial 里）就等响应头 —— 实测（xray 26.3.27 对测）：
// **服务端的响应头是随它要发的第一段数据一起出去的**，如果目标不先发数据，
// 服务端根本不会发响应头；我们在 Dial 里等就成了"客户端等服务端、服务端等数据"的死锁
// （表现是拨号超时，而目标那边其实已经被连上了 —— 日志里能看到 xray accepted）。
// xray 自己的客户端也是这么做的（读路径上惰性剥头）。
//
// 代价：UUID/口令错时错误出现在**第一次 Read/Write**（服务端静默断开）而不是 Dial。
// 这一点写在 README 的协议说明里，别让现场把"连上了"理解成"认证通过"。
type vlessConn struct {
	net.Conn
	rmu sync.Mutex
	hdr bool
}

func (c *vlessConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.hdr {
		if err := readVLESSResponse(c.Conn); err != nil {
			return 0, fmt.Errorf("VLESS 响应头读取失败（UUID 不对时服务端会静默断开）: %w", err)
		}
		c.hdr = true
	}
	return c.Conn.Read(p)
}

// readVLESSResponse 读响应头：Ver(1) + AddonsLen(1) + Addons(变长)。
//
// **必须先读掉再交上层** —— 否则那几个字节会被当成业务数据（表现是"收到的头几个字节是乱码"）。
// 只读这两个字节 + addons，绝不能多读（多读会吃掉目标回的第一段数据，和 HTTP CONNECT 那个坑同源）。
func readVLESSResponse(conn net.Conn) error {
	var h [2]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return err
	}
	if n := int(h[1]); n > 0 {
		if n > 255 {
			return fmt.Errorf("VLESS 响应 addons 长度异常: %d", n)
		}
		if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
			return err
		}
	}
	return nil
}

// Prepare 预热：把传输层（TCP + [TLS] + [ws]）做好，请求头留到 ConnectOn
// （请求头里有目标地址，而且**每个连接都必须重写**，不能缓存）。
func (p *vlessProxy) Prepare(timeout time.Duration) (net.Conn, error) {
	raw, err := p.u.dialTransport(timeout)
	if err != nil {
		return nil, err
	}
	// 立刻包成 vlessConn：这样 ConnectOn 之后的第一次 Read 才会剥响应头。
	return &vlessConn{Conn: raw}, nil
}

// ConnectOn 在预备好的连接上写请求头 + 读响应头。
func (p *vlessProxy) ConnectOn(conn net.Conn, ip net.IP, port uint16, timeout time.Duration) error {
	target, err := appendAddrXray(nil, ip, port)
	if err != nil {
		return err
	}
	if err := p.writeRequest(conn, target, timeout); err != nil {
		return err
	}
	// 响应头不在这里等（见 vlessConn 的说明）：它由 Read 路径惰性剥掉。
	_ = conn.SetDeadline(time.Time{})
	return nil
}

func (p *vlessProxy) SupportsPrepare() bool { return true }
