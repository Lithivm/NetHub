// Package ss 实现 shadowsocks 客户端 —— 传统 AEAD（SIP004 / SIP007）。
//
// 范围（KB:资源/代理/上游协议线格式规格.md 有全文，别凭记忆改）：
//
//	aes-128-gcm / aes-192-gcm / aes-256-gcm / chacha20-ietf-poly1305
//
// **不做**：老式流密码（aes-*-cfb / rc4 / bf-cfb …）与 none/dummy —— 不安全且上游基本停用；
// 2022（SIP022）是另一套（BLAKE3 派生 + 时间戳 + padding），单独实现。
//
// 线格式（照规范逐条实现）：
//
//	key   = EVP_BytesToKey(MD5, password)            ← OpenSSL 的老 KDF，不是 PBKDF2
//	salt  = 随机 SaltSize 字节，**明文**写在最前
//	subkey= HKDF-SHA1(master, salt, info="ss-subkey")
//	chunk = [E(len 2B ≤ 0x3FFF)][tag] [E(payload)][tag]
//	nonce = 12 字节**小端计数器**，从 0 起，**每个 AEAD 操作 +1**（一个 chunk 用两次）
//	首段明文 = SOCKS5 风格的 ATYP+ADDR+PORT，后面紧跟真正的业务数据
//
// 为什么第一段要带地址：shadowsocks 是"目标地址写在第一个密文块里"，所以握手与
// 首包可以合成一次写（少一次往返）。ATYP=域名时域名交给服务端解析。
package ss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// subkeyInfo HKDF 的 info 串（SIP004 定死，写错就解不开）。
const subkeyInfo = "ss-subkey"

// maxChunk 单个 chunk 的载荷上限（0x3FFF，2 字节长度域的高两位是保留的）。
const maxChunk = 0x3FFF

// Cipher 一个 AEAD 密码套件。
type Cipher struct {
	Name    string
	KeySize int
	NewAEAD func(subkey []byte) (cipher.AEAD, error)
}

// ciphers 支持的套件表。
var ciphers = map[string]Cipher{
	"aes-128-gcm": {Name: "aes-128-gcm", KeySize: 16, NewAEAD: aesGCM},
	"aes-192-gcm": {Name: "aes-192-gcm", KeySize: 24, NewAEAD: aesGCM},
	"aes-256-gcm": {Name: "aes-256-gcm", KeySize: 32, NewAEAD: aesGCM},
	"chacha20-ietf-poly1305": {Name: "chacha20-ietf-poly1305", KeySize: 32,
		NewAEAD: func(k []byte) (cipher.AEAD, error) { return chacha20poly1305.New(k) }},
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// SupportedMethods 支持的套件名（排序，用于错误提示）。
func SupportedMethods() []string {
	out := make([]string, 0, len(ciphers))
	for k := range ciphers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Lookup 取一个套件（名字大小写不敏感 —— 配置里大小写混着写是常事）。
func Lookup(method string) (Cipher, error) {
	m := strings.ToLower(strings.TrimSpace(method))
	if c, ok := ciphers[m]; ok {
		return c, nil
	}
	// 老式流密码与 2022 单独给提示：这两种写法的用户诉求完全不同（一个该换，
	// 一个是"我们还没做"），混在一句"不支持"里会让人不知道该干什么。
	switch {
	case strings.Contains(m, "2022"):
		return Cipher{}, fmt.Errorf("shadowsocks 2022（%s）还没实现；"+
			"请先用传统 AEAD 套件（%s）", method, strings.Join(SupportedMethods(), " / "))
	case strings.HasSuffix(m, "-cfb") || strings.HasSuffix(m, "-ctr") || strings.HasSuffix(m, "-ofb") ||
		m == "rc4" || m == "rc4-md5" || m == "bf-cfb" || m == "none" || m == "dummy":
		return Cipher{}, fmt.Errorf("shadowsocks 的老式流密码（%s）不安全也不做；"+
			"请让上游换成 %s", method, strings.Join(SupportedMethods(), " / "))
	}
	return Cipher{}, fmt.Errorf("不认识的 shadowsocks 加密方式 %q（支持 %s）",
		method, strings.Join(SupportedMethods(), " / "))
}

// EVPBytesToKey OpenSSL 的老派生（shadowsocks 一直用它）：D_i = MD5(D_{i-1} ‖ password)，
// 拼起来取前 keyLen 字节。**不是** PBKDF2、不做迭代次数 —— 这里"照抄"就是正确。
func EVPBytesToKey(password string, keyLen int) []byte {
	var out []byte
	var prev []byte
	pass := []byte(password)
	for len(out) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write(pass)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

// subkey 由主密钥 + salt 派生会话密钥（HKDF-SHA1）。
func subkey(master, salt []byte, keySize int) ([]byte, error) {
	k := make([]byte, keySize)
	r := hkdf.New(sha1.New, master, salt, []byte(subkeyInfo))
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}
