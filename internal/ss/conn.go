package ss

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Conn 一条传统 AEAD 的 shadowsocks 连接：对上层是**字节流**，对下层是 AEAD chunk 流。
//
// 读与写各自独立的 AEAD + nonce 计数器（SIP004：两个方向各从 0 开始）。
// 连接建立时（写方向）第一段明文必须是"目标地址 + 首包"。
type Conn struct {
	raw  net.Conn
	c    Cipher
	pass string // 主密钥要用（读方向惰性派生时还得算一次 EVP_BytesToKey）

	// 写方向（一切都惰性：预热池里放着的连接不该提前发 salt/地址）
	wmu    sync.Mutex
	w      *chunkStream
	target []byte // 目标地址（首段明文）
	wSent  bool   // salt+地址是否已发出

	// 读方向（同样惰性：收到第一个字节时才读 salt）
	rmu   sync.Mutex
	r     *chunkStream
	rInit bool
}

// saltSize 与密钥等长（SIP004）；AEAD 的 nonce 固定 12 字节（本包只支持 AEAD）。
func (c Cipher) saltSize() int { return c.KeySize }

// ClientConn 在已建好的连接上做客户端握手，目标是 target（shadowsocks 的地址编码）。
//
// 握手与首包**延迟到第一次 Write**：salt 是随首段一起出去的，提前写就等于把 salt
// 白放在线上（预热池里的连接可能放几十秒才用）。
func ClientConn(raw net.Conn, c Cipher, password string, target []byte) (*Conn, error) {
	conn, err := NewClient(raw, c, password)
	if err != nil {
		return nil, err
	}
	if err := conn.SetTarget(target); err != nil {
		return nil, err
	}
	return conn, nil
}

// NewClient 只做好连接，**不指定目标**（预热用：目标要等业务来了才知道）。
func NewClient(raw net.Conn, c Cipher, password string) (*Conn, error) {
	if _, err := c.NewAEAD(make([]byte, c.KeySize)); err != nil {
		return nil, err
	}
	return &Conn{raw: raw, c: c, pass: password}, nil
}

// SetTarget 设置目标地址（只能设一次，而且必须在写出第一段之前）。
func (c *Conn) SetTarget(target []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wSent {
		return fmt.Errorf("ss 连接已经开始写数据，不能再换目标")
	}
	if len(target) == 0 {
		return fmt.Errorf("ss 目标地址为空")
	}
	c.target = target
	return nil
}

// ───────────────────────── 写 ─────────────────────────

// Write 把 p 切成 ≤0x3FFF 的块，每块加长度域与两个 tag。
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	if !c.wSent {
		if err := c.flushFirst(); err != nil {
			return 0, err
		}
	}
	for len(p) > 0 {
		n := len(p)
		if n > c.w.maxChunk {
			n = c.w.maxChunk
		}
		if err := c.w.writeChunk(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// flushFirst 发第一段：salt（**明文**）‖ [E(目标地址)]。
func (c *Conn) flushFirst() error {
	if len(c.target) == 0 {
		return fmt.Errorf("ss 还没设目标地址")
	}
	salt := make([]byte, c.c.saltSize())
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	sk, err := subkey(EVPBytesToKey(c.pass, c.c.KeySize), salt, c.c.KeySize)
	if err != nil {
		return err
	}
	aead, err := c.c.NewAEAD(sk)
	if err != nil {
		return err
	}
	c.w = newChunkStream(c.raw, aead, maxChunk)
	if _, err := c.raw.Write(salt); err != nil {
		return err
	}
	if err := c.w.writeChunk(c.target); err != nil {
		return err
	}
	c.wSent = true
	return nil
}

// ───────────────────────── 读 ─────────────────────────

// Read 解 chunk：先读 2+tag 解出长度，再读 len+tag 解出载荷。
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.rInit {
		if err := c.initRead(); err != nil {
			return 0, err
		}
	}
	for len(c.r.rbuf) == 0 {
		if err := c.r.readChunk(); err != nil {
			return 0, err
		}
	}
	return c.r.take(p), nil
}

// initRead 读 salt 并派生读方向的 AEAD。
//
// ⚠ 端口/地址**不由这里解析**：shadowsocks 服务端的响应里没有地址，第一个密文块
// 直接就是业务数据（这一点与"客户端首块带地址"不对称，别照着客户端写）。
func (c *Conn) initRead() error {
	salt := make([]byte, c.c.saltSize())
	if _, err := io.ReadFull(c.raw, salt); err != nil {
		return err
	}
	master := EVPBytesToKey(c.pass, c.c.KeySize)
	sk, err := subkey(master, salt, c.c.KeySize)
	if err != nil {
		return err
	}
	aead, err := c.c.NewAEAD(sk)
	if err != nil {
		return err
	}
	c.r = newChunkStream(c.raw, aead, maxChunk)
	c.rInit = true
	return nil
}

// ───────────────────────── net.Conn 其余部分 ─────────────────────────

func (c *Conn) Close() error                       { return c.raw.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
