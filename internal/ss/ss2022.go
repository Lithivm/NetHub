package ss

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zeebo/blake3"
)

// shadowsocks 2022（SIP022）—— 与老版（SIP004）是**两套东西**，线格式几乎不重叠：
//
//	salt   = 密钥长度随机字节，明文写在最前（同老版）
//	subkey = BLAKE3 derive_key(context="shadowsocks 2022 session subkey", material=PSK‖salt)
//	         ← 老版是 HKDF-SHA1；PSK 直接就是主密钥（老版要先 EVP_BytesToKey 口令）
//	请求 = salt ‖ E(定长头: 类型0 ‖ 时间戳秒 u64BE ‖ 变长头长度 u16BE)
//	              ‖ E(变长头: 地址 ‖ padding 长度 u16BE ‖ padding ‖ 首段载荷)
//	数据块 = [E(长度 u16BE)][tag][E(载荷)][tag]        ← 与老版同形，但上限 0xFFFF（老版 0x3FFF）
//	响应 = salt ‖ E(定长头: 类型1 ‖ 时间戳 ‖ **回显我们发的请求 salt** ‖ 首块长度 u16BE)
//	              ‖ E(首块)
//
// 与老版的三个语义差别（写错了本地自测照样过、只有真服务端会失败）：
//  1. 定长头/变长头这两块**没有长度域**（长度由协议定死 / 由定长头给出），不能套数据块的形状；
//  2. 时间戳容忍 ±30s（上游机器时钟漂了就是"认证失败"，报错要说清是时钟）；
//  3. 响应头必须**回显我们发的请求 salt** —— 这是 2022 唯一的服务端身份凭据，必须校验。
//
// 不做：UDP（我们本来就只做 TCP）· 多用户 PSK（要 EIH，见下）。
const (
	maxChunk2022  = 0xFFFF // 单块载荷上限（2 字节长度域，2022 没有保留位）
	headerTypeCli = 0      // 请求方向
	headerTypeSrv = 1      // 响应方向
	maxPadding    = 900    // 规范给的 padding 上限
	timeTolerance = 30 * time.Second
)

// 两个 KDF 的 context 串（规范定死，写错就解不开）。EIH 用的那个我们用不上，
// 但记在这里，免得以后要做多用户时又去翻源码。
const (
	sessionSubkeyContext  = "shadowsocks 2022 session subkey"
	identitySubkeyContext = "shadowsocks 2022 identity subkey"
)

// Cipher2022 一个 2022 套件。
type Cipher2022 struct {
	Name    string
	KeySize int // 同时也是 salt 长度与 PSK 解码后的长度
	NewAEAD func(subkey []byte) (cipher.AEAD, error)
}

var ciphers2022 = map[string]Cipher2022{
	"2022-blake3-aes-128-gcm": {Name: "2022-blake3-aes-128-gcm", KeySize: 16, NewAEAD: aesGCM},
	"2022-blake3-aes-256-gcm": {Name: "2022-blake3-aes-256-gcm", KeySize: 32, NewAEAD: aesGCM},
	"2022-blake3-chacha20-poly1305": {Name: "2022-blake3-chacha20-poly1305", KeySize: 32,
		NewAEAD: func(k []byte) (cipher.AEAD, error) { return chacha20New(k) }},
}

// SupportedMethods2022 支持的 2022 套件名（排序，用于错误提示）。
func SupportedMethods2022() []string { return sortedKeys(ciphers2022) }

// Is2022 名字是不是 2022 那一套（别用 prefix 判断："2022-blake3-…" 是我们认的全部）。
func Is2022(method string) bool {
	_, ok := ciphers2022[strings.ToLower(strings.TrimSpace(method))]
	return ok
}

// Lookup2022 取一个 2022 套件。
func Lookup2022(method string) (Cipher2022, error) {
	m := strings.ToLower(strings.TrimSpace(method))
	if c, ok := ciphers2022[m]; ok {
		return c, nil
	}
	return Cipher2022{}, fmt.Errorf("不认识的 shadowsocks 2022 加密方式 %q（支持 %s）",
		method, strings.Join(SupportedMethods2022(), " / "))
}

// ParsePSK 解 2022 的 PSK（URL 里写的是 base64）。
//
// **长度必须正好等于密钥长度**（16/32 字节）：写错长度的表现是"服务端静默断开"，
// 所以宁可在解析期就拒掉并说清楚。多用户写法（`psk1:psk2`）要 EIH，本版不做。
func ParsePSK(method, password string) ([]byte, error) {
	c, err := Lookup2022(method)
	if err != nil {
		return nil, err
	}
	if strings.Contains(password, ":") {
		return nil, fmt.Errorf("shadowsocks 2022 的多用户写法（多个 PSK，用 : 分隔）要 EIH 报头，本版不做 —— " +
			"请用单用户 PSK（服务端只配一个 PSK 的那种）")
	}
	raw, err := decodeBase64Any(password)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks 2022 的 PSK 是 base64 串（%s 要解码出 %d 字节），这个解不开: %v",
			method, c.KeySize, err)
	}
	if len(raw) != c.KeySize {
		return nil, fmt.Errorf("shadowsocks 2022 的 PSK base64 解码后要正好 %d 字节（%s），"+
			"这个解出来是 %d 字节 —— 多半是把口令当 PSK 写了，PSK 应在服务端用 `openssl rand -base64 %d` 生成",
			c.KeySize, method, len(raw), c.KeySize)
	}
	return raw, nil
}

// decodeBase64Any 标准/URL-safe、带/不带 padding 都试（现场抄来的串经常少个 =）。
func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	trimmed := strings.TrimRight(s, "=")
	var lastErr error
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		dec, err := enc.DecodeString(trimmed)
		if err == nil {
			return dec, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// sessionKey2022 会话子密钥：BLAKE3 derive_key(context, PSK‖salt)，长度 = 密钥长度。
// 参数顺序（PSK 在前、salt 在后）与 context 串都不能动 —— 错了服务端直接静默断开。
func sessionKey2022(psk, salt []byte, keySize int) []byte {
	material := make([]byte, 0, len(psk)+len(salt))
	material = append(material, psk...)
	material = append(material, salt...)
	out := make([]byte, keySize)
	blake3.DeriveKey(sessionSubkeyContext, material, out)
	return out
}

// randInt 0..n-1 的随机数（padding 长度用；crypto/rand 就行，偏差无所谓）。
func randInt(n int) int {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b[:])) % n
}

// ───────────────────────── 连接 ─────────────────────────

// Conn2022 一条 shadowsocks 2022 连接（客户端）。
//
// 与老版一样：写方向的第一段必须带目标地址；salt 与请求头**延迟到第一次 Write**
// （预热池里放着的连接不该提前把 salt 放到线上）。
type Conn2022 struct {
	raw    net.Conn
	c      Cipher2022
	psk    []byte
	target []byte

	wmu     sync.Mutex
	w       *chunkStream
	reqSalt []byte // 请求 salt（响应头要回显校验）
	wSent   bool

	rmu   sync.Mutex
	r     *chunkStream
	rInit bool
}

// NewClient2022 建一条 2022 客户端连接（**不指定目标**，预热用）。
func NewClient2022(raw net.Conn, c Cipher2022, psk []byte) (*Conn2022, error) {
	if len(psk) != c.KeySize {
		return nil, fmt.Errorf("shadowsocks 2022 的 PSK 长度不对: %d（%s 要 %d）", len(psk), c.Name, c.KeySize)
	}
	return &Conn2022{raw: raw, c: c, psk: psk}, nil
}

// ClientConn2022 建连接并设好目标（target 是 SOCKS5 风格的 ATYP+ADDR+PORT）。
func ClientConn2022(raw net.Conn, c Cipher2022, psk, target []byte) (*Conn2022, error) {
	conn, err := NewClient2022(raw, c, psk)
	if err != nil {
		return nil, err
	}
	if err := conn.SetTarget(target); err != nil {
		return nil, err
	}
	return conn, nil
}

// SetTarget 设置目标地址（只能设一次，且必须在写出第一段之前）。
func (c *Conn2022) SetTarget(target []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wSent {
		return fmt.Errorf("ss2022 连接已经开始写数据，不能再换目标")
	}
	if len(target) == 0 {
		return fmt.Errorf("ss2022 目标地址为空")
	}
	if len(target)+2+maxPadding > maxChunk2022 {
		return fmt.Errorf("ss2022 目标地址过长: %d 字节", len(target))
	}
	c.target = target
	return nil
}

// ───────────────────────── 写 ─────────────────────────

// Write 首段按"定长头 + 变长头"发（载荷装不下就留给后面的数据块），之后每块加长度域。
func (c *Conn2022) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	if !c.wSent {
		n, err := c.flushFirst(p)
		if err != nil {
			return 0, err
		}
		total, p = n, p[n:]
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

// flushFirst 发请求头：salt ‖ E(定长头) ‖ E(变长头)。返回装进变长头里的载荷字节数。
//
// padding：载荷装得下时给 1..900 字节随机 padding（规范要求变长头非空，且 padding 是
// 2022 唯一的流量整形手段）；载荷本身够大就不加（省带宽）。
func (c *Conn2022) flushFirst(payload []byte) (int, error) {
	if len(c.target) == 0 {
		return 0, fmt.Errorf("ss2022 还没设目标地址")
	}
	salt := make([]byte, c.c.KeySize)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}
	key := sessionKey2022(c.psk, salt, c.c.KeySize)
	aead, err := c.c.NewAEAD(key)
	if err != nil {
		return 0, err
	}
	c.w = newChunkStream(c.raw, aead, maxChunk2022)

	padLen := 0
	if len(payload) < maxPadding {
		padLen = 1 + randInt(maxPadding)
	}
	// 变长头能装多少载荷：长度域是 2 字节，装不下就留给后面的数据块
	room := maxChunk2022 - len(c.target) - 2 - padLen
	if room < 0 {
		return 0, fmt.Errorf("ss2022 目标地址过长（%d 字节）", len(c.target))
	}
	take := len(payload)
	if take > room {
		take = room
	}

	variable := make([]byte, 0, len(c.target)+2+padLen+take)
	variable = append(variable, c.target...)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(padLen))
	variable = append(variable, lb[:]...)
	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := rand.Read(pad); err != nil {
			return 0, err
		}
		variable = append(variable, pad...)
	}
	variable = append(variable, payload[:take]...)

	fixed := make([]byte, 0, 1+8+2)
	fixed = append(fixed, headerTypeCli)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
	fixed = append(fixed, ts[:]...)
	binary.BigEndian.PutUint16(lb[:], uint16(len(variable)))
	fixed = append(fixed, lb[:]...)

	out := make([]byte, 0, len(salt)+len(fixed)+len(variable)+aead.Overhead()*2)
	out = append(out, salt...)
	out = append(out, c.w.seal(fixed)...)
	out = append(out, c.w.seal(variable)...)
	if _, err := c.raw.Write(out); err != nil {
		return 0, err
	}
	c.reqSalt, c.wSent = salt, true
	return take, nil
}

// ───────────────────────── 读 ─────────────────────────

// Read 先剥响应头（第一次读时），之后按数据块解。
func (c *Conn2022) Read(p []byte) (int, error) {
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

// initRead 读服务端 salt + 定长响应头 + 首块。
//
// 定长头 = 类型(1) ‖ 时间戳秒(8) ‖ 回显请求 salt(密钥长度) ‖ 首块明文长度(2)，**没有长度域**。
func (c *Conn2022) initRead() error {
	ks := c.c.KeySize
	salt := make([]byte, ks)
	if _, err := io.ReadFull(c.raw, salt); err != nil {
		return err
	}
	key := sessionKey2022(c.psk, salt, ks)
	aead, err := c.c.NewAEAD(key)
	if err != nil {
		return err
	}
	c.r = newChunkStream(c.raw, aead, maxChunk2022)
	c.rInit = true // 后面读数据块不受影响；这一步失败就当连接坏了

	fixedLen := 1 + 8 + ks + 2
	head, err := c.r.openRaw(fixedLen, "响应头")
	if err != nil {
		return err
	}
	if head[0] != headerTypeSrv {
		return fmt.Errorf("ss2022 响应头类型不对: %d（期望 %d）—— 上游多半不是 2022",
			head[0], headerTypeSrv)
	}
	ts := int64(binary.BigEndian.Uint64(head[1:9]))
	if d := time.Since(time.Unix(ts, 0)); d > timeTolerance || d < -timeTolerance {
		return fmt.Errorf("ss2022 服务端时间戳差 %s（容忍 ±30s）—— 上游机器时钟漂了？",
			d.Round(time.Second))
	}
	if c.reqSalt != nil && !hmac.Equal(head[9:9+ks], c.reqSalt) {
		return fmt.Errorf("ss2022 响应头回显的 salt 与我们发的请求 salt 不一致" +
			"（中间有人/不是同一个服务端，或口令不对）")
	}
	first := int(binary.BigEndian.Uint16(head[9+ks:]))
	if first > 0 {
		body, err := c.r.openRaw(first, "首块")
		if err != nil {
			return err
		}
		c.r.rbuf = append(c.r.rbuf, body...)
	}
	return nil
}

// ───────────────────────── net.Conn 其余部分 ─────────────────────────

func (c *Conn2022) Close() error                       { return c.raw.Close() }
func (c *Conn2022) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn2022) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn2022) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn2022) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn2022) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
