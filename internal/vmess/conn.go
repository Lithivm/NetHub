package vmess

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Conn 一条 VMess 连接：对上层是字节流，对下层是 ① 头 + ③ 数据块。
//
// 握手（请求头）在 NewClientConn 里就写出去；**响应头在第一次 Read 时**才读 ——
// 与 VLESS 同样的理由：万一服务端把响应头和第一段数据一起发（或者干脆先不发），
// 在拨号里等就会死等。代价是"凭据错"暴露在读的时候，不是拨号时。
type Conn struct {
	raw net.Conn
	sec byte

	reqKey  []byte // 16：请求方向数据块的 AES 密钥
	reqIV   []byte // 16
	respKey []byte // 16 = SHA256(reqKey)[:16]
	respIV  []byte // 16 = SHA256(reqIV)[:16]
	respV   byte   // 我们发出去的 RespV，响应头里必须一致

	// 写方向
	wmu     sync.Mutex
	wNonce  []byte
	wCount  uint16
	wClosed bool

	// 读方向
	rmu     sync.Mutex
	hdrDone bool
	rNonce  []byte
	rCount  uint16
	rBuf    []byte
	rEOF    bool
}

// NewClientConn 建连并**立刻写请求头**（含目标地址）。
// uuid 必须是 16 字节原始值；target 是 B 族编码（Port|AT|Addr）。
func NewClientConn(raw net.Conn, uuid []byte, target []byte, timeout time.Duration) (*Conn, error) {
	if len(uuid) != 16 {
		return nil, fmt.Errorf("vmess 的 UUID 必须是 16 字节（得到 %d）", len(uuid))
	}
	c := &Conn{raw: raw, sec: SecurityAES128}

	// 33 字节随机：请求 IV(16) + 请求 Key(16) + RespV(1)（xray: CreateRequestHeader）
	var seed [33]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, err
	}
	c.reqIV, c.reqKey, c.respV = seed[0:16], seed[16:32], seed[32]
	k := sha256.Sum256(c.reqKey)
	v := sha256.Sum256(c.reqIV)
	c.respKey, c.respIV = k[:16], v[:16]

	cmdKey := CmdKey(uuid)
	plain := buildInstruction(c.reqIV, c.reqKey, c.respV, SecurityAES128, target)
	head, err := sealHeader(cmdKey, plain, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := raw.Write(head); err != nil {
		return nil, fmt.Errorf("VMess 请求头写入失败: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})
	return c, nil
}

// ───────────────────────── 读 ─────────────────────────

func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rBuf) == 0 {
		if c.rEOF {
			return 0, io.EOF
		}
		if !c.hdrDone {
			respV, _, err := openResponseHeader(c.raw, c.respKey, c.respIV)
			if err != nil {
				return 0, err
			}
			if respV != c.respV {
				// 唯一认证点：对不上说明对面不是"认出我们的那个服务端"
				return 0, fmt.Errorf("VMess 响应头校验失败：RespV 期望 %#x 得到 %#x"+
					"（客户端 UUID 与服务端不符，或撞上了别的服务）", c.respV, respV)
			}
			c.hdrDone = true
		}
		if err := c.readChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.rBuf)
	c.rBuf = c.rBuf[n:]
	return n, nil
}

func (c *Conn) readChunk() error {
	var lb [2]byte
	if _, err := io.ReadFull(c.raw, lb[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(lb[:]))
	if size == 16 {
		// 长度恰为 tag 长度 = 空块 = EOF（服务端就是这么表示结束的）
		c.rEOF = true
		return nil
	}
	if size < 16 {
		return fmt.Errorf("VMess 数据块长度异常: %d", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(c.raw, body); err != nil {
		return err
	}
	aead, err := newGCM(c.respKey) // 响应方向的数据块用**派生出来的 respKey**
	// （respKey = SHA256(reqKey)[:16]，与响应头同源；用 reqKey 会解不开 —— 这就是
	//  "KDF 嵌套写反了只报 invalid user" 之外的另一个静默坑）
	if err != nil {
		return err
	}
	plain, err := aead.Open(nil, c.chunkNonce(true), body, nil)
	if err != nil {
		return fmt.Errorf("VMess 数据块解密失败: %w", err)
	}
	c.rBuf = append(c.rBuf, plain...)
	return nil
}

// chunkNonce nonce = 计数器(2B 大端) ‖ IV[2:12]，每块 +1（收发各自独立计数）。
func (c *Conn) chunkNonce(read bool) []byte {
	iv, cnt := c.reqIV, &c.wCount
	if read {
		iv, cnt = c.respIV, &c.rCount
	}
	n := make([]byte, 12)
	copy(n, iv[:12])
	binary.BigEndian.PutUint16(n[0:2], *cnt)
	*cnt++
	return n
}

// ───────────────────────── 写 ─────────────────────────

// Write 把数据切成块：每块 [2B 长度+16][密文][tag]（没有 padding，因为我们没开 GlobalPadding）。
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wClosed {
		return 0, fmt.Errorf("VMess 连接已关闭")
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPayload {
			n = maxPayload
		}
		if err := c.writeChunk(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

const maxPayload = 16384 - 16 - 2 // xray 用 buf.Size(16384) 当整块缓冲，减去 tag 与长度域

func (c *Conn) writeChunk(payload []byte) error {
	aead, err := newGCM(c.reqKey)
	if err != nil {
		return err
	}
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(payload)+16))
	sealed := aead.Seal(nil, c.chunkNonce(false), payload, nil)
	out := make([]byte, 0, 2+len(sealed))
	out = append(out, lb[:]...)
	out = append(out, sealed...)
	_, err = c.raw.Write(out)
	return err
}

// Close 关掉连接（发一个空块 = EOF 是"优雅结束"；这里直接关，因为 relay 侧已经决定了）。
func (c *Conn) Close() error {
	c.wmu.Lock()
	c.wClosed = true
	c.wmu.Unlock()
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
