// Package vmess 实现 VMess 客户端（AEAD 头，无 alterId / 无 legacy）。
//
// 为什么要单独一个包：VMess 的加解密比 VLESS 复杂一个量级（KDF 嵌套 + 三层 AEAD + 块流），
// 与 shadowsocks 同级别的"必须单独写、单独测"的东西。upstream 那边只做 URL 解析与注册。
//
// 规格来源：**对着 xray-core 源码核过**（proxy/vmess/aead/{kdf,authid,encrypt}.go、
// proxy/vmess/encoding/client.go、common/crypto/auth.go，2026-10-16，Xray 26.3.27），
// 不是凭记忆写 —— 这一套写错了的症状只有一个"invalid user"，没有别的线索。
//
// 三层结构（自外向内）：
//
//	① AEAD 头   EAuID(16) | ALength(18) | Nonce(8) | AHeader(16+N)
//	             KDF = HMAC-SHA256 嵌套；EAuID = AES-128-ECB(时间戳|随机|crc32)
//	② 指令明文  Ver(1) | IV(16) | Key(16) | RespV(1) | Opt(1) | (pad<<4|sec)(1) | 0(1) | Cmd(1)
//	             | Port(2BE) | AT(1) | Addr | padding | FNV1a-32(4BE)
//	③ 数据块    [2B 长度 L][E(payload)][tag16]   L = len(payload)+16（我们没有 padding）
//	             nonce = 计数器(2B BE) ‖ IV[2:12]，每块 +1，收发各自独立计数
//
// 响应头（服务端发的）：先 18 字节解出长度，再解 (长度+16) 字节；明文第一字节 **必须等于
// 我们发出去的 RespV** —— 这是 VMess 里唯一的认证点，别忘了比对。
package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"io"
	"math/big"
)

// KDF 的盐串（xray: KDFSaltConst*）—— 一个字都不能改。
const (
	kdfSalt       = "VMess AEAD KDF"
	saltAuthIDKey = "AES Auth ID Encryption"
	saltLenKey    = "VMess Header AEAD Key_Length"
	saltLenIV     = "VMess Header AEAD Nonce_Length"
	saltHdrKey    = "VMess Header AEAD Key"
	saltHdrIV     = "VMess Header AEAD Nonce"
	saltRespLenK  = "AEAD Resp Header Len Key"
	saltRespLenIV = "AEAD Resp Header Len IV"
	saltRespHdrK  = "AEAD Resp Header Key"
	saltRespHdrIV = "AEAD Resp Header IV"
)

// uuidSalt VMess 的 CmdKey 尾巴（xray: userID 后面固定接这一段）。
const uuidSalt = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

// kdfHashFn 一个“哈希函数”（把数据映到摘要）。
//
// 为什么要把它表示成纯函数：xray 的 KDF 是把**上一个 HMAC 对象**当成下一层 HMAC 的哈希函数用
// （proxy/vmess/aead/kdf.go 里的 hash2），内外层共用同一个对象。**Go 1.27 的 hmac 会为此 panic**
// （crypto/hmac: hash generation function does not produce unique values，实测踩到），
// 所以这里换成等价写法：HMAC 对数据是纯函数，于是“把 HMAC 当哈希”就等于把那个 HMAC 算一遍。
// 各层的 BlockSize 都是 64（sha256 的块大小，一路传下来），Size 都是 32。
type hashFn func([]byte) []byte

// hmacFn 用任意哈希函数 h 做一次 HMAC（key 短于块长时不需要先哈希 key）。
func hmacFn(h hashFn, key []byte) hashFn {
	const blockSize = 64
	k := key
	if len(k) > blockSize {
		k = h(k) // 与 Go 的 hmac 同一规则（我们的 key 都是盐串，实际不会走到）
	}
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := range ipad {
		ipad[i], opad[i] = 0x36, 0x5c
	}
	for i := 0; i < len(k); i++ {
		ipad[i] ^= k[i]
		opad[i] ^= k[i]
	}
	return func(data []byte) []byte {
		in := make([]byte, 0, len(ipad)+len(data))
		in = append(in, ipad...)
		in = append(in, data...)
		inner := h(in)
		out := make([]byte, 0, len(opad)+len(inner))
		out = append(out, opad...)
		out = append(out, inner...)
		return h(out)
	}
}

// KDF key 先依次套过 path 各层，最后写入 key 求和（顺序不能反）。
func KDF(key []byte, path ...string) []byte {
	// 第 0 层：HMAC-SHA256(key = "VMess AEAD KDF", ·)
	h := func(data []byte) []byte {
		m := hmac.New(sha256.New, []byte(kdfSalt))
		m.Write(data)
		return m.Sum(nil)
	}
	for _, p := range path {
		h = hmacFn(h, []byte(p))
	}
	return h(key)
}

// KDF16 取前 16 字节当 AES-128 的密钥。
func KDF16(key []byte, path ...string) []byte { return KDF(key, path...)[:16] }

// CmdKey = MD5(UUID16 ‖ "c48619fe-…")（xray: protocol.ID.CmdKey）。
func CmdKey(uuid []byte) [16]byte {
	h := md5.New()
	h.Write(uuid)
	h.Write([]byte(uuidSalt))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// createAuthID EAuID：AES-128-ECB( timestamp(8B BE) | rand(4B) | crc32(前 12B)(4B) )。
// 服务端容忍时间戳 ±120 秒（时钟漂移的表现是"用户不存在"，见 README）。
func createAuthID(cmdKey [16]byte, unix int64) ([16]byte, error) {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(unix))
	if _, err := io.ReadFull(rand.Reader, buf[8:12]); err != nil {
		return [16]byte{}, err
	}
	binary.BigEndian.PutUint32(buf[12:16], crc32.ChecksumIEEE(buf[0:12]))

	blk, err := aes.NewCipher(KDF16(cmdKey[:], saltAuthIDKey))
	if err != nil {
		return [16]byte{}, err
	}
	var out [16]byte
	blk.Encrypt(out[:], buf[:])
	return out, nil
}

// sealHeader 把指令明文封成 ① 那一层：EAuID | ALength | Nonce | AHeader。
func sealHeader(cmdKey [16]byte, plain []byte, unix int64) ([]byte, error) {
	eauid, err := createAuthID(cmdKey, unix)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aad := eauid[:]

	// 长度块：AAD 也是 EAuID（服务端用它认证"这个长度属于这个 EAuID"）
	lenKey := KDF16(cmdKey[:], saltLenKey, string(aad), string(nonce))
	lenIV := KDF(cmdKey[:], saltLenIV, string(aad), string(nonce))[:12]
	lenAEAD, err := newGCM(lenKey)
	if err != nil {
		return nil, err
	}
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(plain)))
	encLen := lenAEAD.Seal(nil, lenIV, lb[:], aad)

	// 头块
	hdrKey := KDF16(cmdKey[:], saltHdrKey, string(aad), string(nonce))
	hdrIV := KDF(cmdKey[:], saltHdrIV, string(aad), string(nonce))[:12]
	hdrAEAD, err := newGCM(hdrKey)
	if err != nil {
		return nil, err
	}
	encHdr := hdrAEAD.Seal(nil, hdrIV, plain, aad)

	out := make([]byte, 0, 16+len(encLen)+8+len(encHdr))
	out = append(out, aad...)
	out = append(out, encLen...)
	out = append(out, nonce...)
	out = append(out, encHdr...)
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// openResponseHeader 解服务端的响应头，返回 (RespV, Opt, cmdID, cmdData)。
//
// 读法固定：18 字节解出长度 → 读 (长度+16) → 解明文 = RespV(1) | Opt(1) | cmdID(1) | cmdDataLen(1) | cmdData。
// **AAD 都是 nil**（与请求头的 AAD=EAuID 不同，别顺手抄错）。
func openResponseHeader(raw io.Reader, respKey, respIV []byte) (respV byte, opt byte, err error) {
	lenKey := KDF16(respKey, saltRespLenK)
	lenIV := KDF(respIV, saltRespLenIV)[:12]
	lenAEAD, err := newGCM(lenKey)
	if err != nil {
		return 0, 0, err
	}
	var encLen [18]byte
	if _, err := io.ReadFull(raw, encLen[:]); err != nil {
		return 0, 0, fmt.Errorf("读响应头长度失败: %w", err)
	}
	lb, err := lenAEAD.Open(nil, lenIV, encLen[:], nil)
	if err != nil {
		return 0, 0, fmt.Errorf("响应头长度解密失败（口令/加密方式不对？）: %w", err)
	}
	n := int(binary.BigEndian.Uint16(lb))

	hdrKey := KDF16(respKey, saltRespHdrK)
	hdrIV := KDF(respIV, saltRespHdrIV)[:12]
	hdrAEAD, err := newGCM(hdrKey)
	if err != nil {
		return 0, 0, err
	}
	body := make([]byte, n+16)
	if _, err := io.ReadFull(raw, body); err != nil {
		return 0, 0, fmt.Errorf("读响应头失败: %w", err)
	}
	plain, err := hdrAEAD.Open(nil, hdrIV, body, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("响应头解密失败: %w", err)
	}
	if len(plain) < 4 {
		return 0, 0, fmt.Errorf("响应头长度异常: %d", len(plain))
	}
	return plain[0], plain[1], nil
}

// 指令明文里的常量
const (
	Version        = 1
	CmdTCP         = 0x01
	SecurityAES128 = 0x03 // 0x04 = ChaCha20-Poly1305（本版不发它）
	OptChunkStream = 0x01 // 只要这一位：ChunkStream（省掉 masking 与 global padding 那套）
)

// buildInstruction 拼 ② 指令明文（含 padding 与 FNV1a 校验）。
//
// target 是 **B 族编码**（Port 2B 大端 + AT + 地址，见 upstream/addr.go）——
// VMess 这里是端口在前、域名 AT=0x02，与 shadowsocks/trojan 不同。
func buildInstruction(reqIV, reqKey []byte, respV byte, security byte, target []byte) []byte {
	padLen := 0
	if n, err := rand.Int(rand.Reader, big.NewInt(16)); err == nil {
		padLen = int(n.Int64()) // xray 是 dice.Roll(16)：0..15
	}
	out := make([]byte, 0, 41+len(target)+padLen+4)
	out = append(out, Version)
	out = append(out, reqIV...)
	out = append(out, reqKey...)
	out = append(out, respV)
	out = append(out, OptChunkStream)
	out = append(out, byte(padLen)<<4|security)
	out = append(out, 0x00) // 保留字节必须 0
	out = append(out, CmdTCP)
	out = append(out, target...)
	if padLen > 0 {
		p := make([]byte, padLen)
		if _, err := io.ReadFull(rand.Reader, p); err != nil {
			// 密码学随机的来源坏了就没法保证协议正确，宁可不发（上层会报错）
			p = make([]byte, padLen)
		}
		out = append(out, p...)
	}
	h := fnv.New32a()
	_, _ = h.Write(out)
	return binary.BigEndian.AppendUint32(out, h.Sum32())
}
