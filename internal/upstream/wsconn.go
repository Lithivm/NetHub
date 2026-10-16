package upstream

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket 传输：把协议字节流塞进 ws 帧（gost 的 `+ws` / `+wss`）。
//
// 线上要求（照 KB:资源/代理/上游协议线格式规格.md，别凭记忆改）：
//   - HTTP/1.1 GET + Upgrade，path 默认 `/ws`（gost 服务端**严格匹配**，不符直接不是 101）
//   - `Host` 头 = 节点地址（gost 可用 ?host= 改；xray 的 vless/vmess 看重这个）
//   - **不发 `Sec-WebSocket-Protocol`**（gost 不认子协议）
//   - Binary 帧；客户端帧必须掩码（RFC6455 要求，gorilla 默认做）
//
// 实现用 gorilla/websocket（本来就在依赖树里，Wails 带的）：握手、掩码、控制帧
// （ping/pong/close）都归它 —— 自己写这四样是白写一遍还可能写错的地方。
// 我们只补一个 `net.Conn` 适配器：上面的协议（SOCKS5 / shadowsocks / trojan /
// vless / vmess）都当它是字节流。

// wsDial 在**已经建好**的连接（TCP，或 TCP+TLS）上做 ws 握手。
//
// 为什么不让 gorilla 自己拨：我们的连接可能已经套了 TLS（wss），也可能来自
// 预热池；这里传 `NetDial` 直接把它交出去，gorilla 就不再自己拨一次。
// 也正因此 URL 一律写 `ws://`：TLS 我们自己做了，写 `wss://` 会被它**再套一层**。
func wsDial(conn net.Conn, host, path, origin string, timeout time.Duration) (*wsConn, *http.Response, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if path == "" {
		path = defaultWSPath
	}
	u := url.URL{Scheme: "ws", Host: host, Path: path}
	d := websocket.Dialer{
		HandshakeTimeout: timeout,
		NetDial: func(_, _ string) (net.Conn, error) {
			return conn, nil
		},
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}
	hdr := http.Header{}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	ws, resp, err := d.Dial(u.String(), hdr)
	if err != nil {
		return nil, resp, err
	}
	return &wsConn{ws: ws, conn: conn}, resp, nil
}

// defaultWSPath gost 与 xray 的默认 path 都是 `/ws`。
const defaultWSPath = "/ws"

// wsConn 把 `*websocket.Conn` 适配成 `net.Conn`（协议实现只认字节流）。
type wsConn struct {
	ws   *websocket.Conn
	conn net.Conn // 底层连接（TCP/TLS），用于地址与超时

	rmu    sync.Mutex
	reader io.Reader // 当前 BinaryMessage 的读游标

	wmu sync.Mutex // 同一时刻只能有一个写者（gorilla 的写不是并发安全的）
}

func (c *wsConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if c.reader != nil {
			n, err := c.reader.Read(p)
			if n > 0 {
				return n, nil
			}
			if err != io.EOF {
				return 0, err
			}
			c.reader = nil // 这一帧读完了，取下一帧
		}
		mt, r, err := c.ws.NextReader()
		if err != nil {
			return 0, err
		}
		if mt != websocket.BinaryMessage {
			// 文本帧：不静默丢（那会表现成"业务卡住没人报错"），但也别把整个连接杀掉 ——
			// 有些中间设备会插一条文本帧。忽略它，继续读下一条。
			continue
		}
		c.reader = r
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close 发 close 帧再关底层连接。
// 写 close 帧是要给对端一个"正常结束"的信号（gost 收到就直接收摊）；
// 但**不能等**它回，所以给一个很短的写期限 —— 对端已经死了的话，等下去就是拖住业务。
func (c *wsConn) Close() error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = c.ws.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	err := c.ws.Close()
	if c2 := c.conn.Close(); err == nil && c2 != nil {
		err = c2
	}
	return err
}

func (c *wsConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline 三个都转给底层连接 —— gorilla 的读写在底层 conn 上生效，
// 超时语义因此与普通连接一致（引擎的握手超时、relay 的空闲超时都靠它）。
func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.conn.SetDeadline(t); err != nil {
		return err
	}
	_ = c.ws.SetReadDeadline(t)
	return c.ws.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// wsHandshakeError 把"ws 握手被拒"翻译成人话（现场只看得到"连不上"时很难查）。
func wsHandshakeError(resp *http.Response, err error) error {
	if resp != nil {
		// 401/403/404 是最常见的三种：口令错 / 不允许 / path 不对（gost 严格匹配 path）。
		return fmt.Errorf("ws 握手被拒: HTTP %d（检查 path 与端口；gost 的 path 是严格匹配的，默认 /ws）", resp.StatusCode)
	}
	return fmt.Errorf("ws 握手失败: %w", err)
}

// tlsClient 建一条 TLS 连接（wss / +tls / trojan 等共用）。
func tlsClient(raw net.Conn, cfg *tls.Config) (net.Conn, error) {
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}
