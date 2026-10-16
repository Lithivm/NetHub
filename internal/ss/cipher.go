// Package ss 实现 shadowsocks 客户端 —— 传统 AEAD（SIP004 / SIP007）与 2022（SIP022）。
//
// 范围（KB:资源/代理/上游协议线格式规格.md 有全文，别凭记忆改）：
//
//	传统：aes-128-gcm / aes-192-gcm / aes-256-gcm / chacha20-ietf-poly1305
//	2022：2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm / 2022-blake3-chacha20-poly1305
//
// **不做**：老式流密码（aes-*-cfb / rc4 / bf-cfb …）与 none/dummy —— 不安全且上游基本停用；
// 2022 的多用户 PSK（要 EIH 报头）与 UDP（我们本来就只做 TCP，见 Conn2022 的注释）。
//
// 两个版本的公共形状（长度域 + 小端 nonce 计数器）在 stream.go；两套线格式的差别见
// conn.go（传统）与 ss2022.go（2022）的文件头注释。
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
	"aes-128-gcm":            {Name: "aes-128-gcm", KeySize: 16, NewAEAD: aesGCM},
	"aes-192-gcm":            {Name: "aes-192-gcm", KeySize: 24, NewAEAD: aesGCM},
	"aes-256-gcm":            {Name: "aes-256-gcm", KeySize: 32, NewAEAD: aesGCM},
	"chacha20-ietf-poly1305": {Name: "chacha20-ietf-poly1305", KeySize: 32, NewAEAD: chacha20New},
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// LookupSuite 认**所有**支持的加密方式（传统与 2022），返回它是不是 2022 那一套。
// 给上游做"解析期就把写错的名字挡住"用 —— 拨号时才报错的体验太差了。
func LookupSuite(method string) (is2022 bool, err error) {
	if Is2022(method) {
		return true, nil
	}
	if _, err := Lookup(method); err != nil {
		return false, err
	}
	return false, nil
}

// SupportedMethods 支持的传统套件名（排序，用于错误提示）。
func SupportedMethods() []string { return sortedKeys(ciphers) }

// sortedKeys 把 map 的键排好序（错误提示里要稳定顺序，不然每次报的名字顺序都不一样）。
func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// chacha20New 和 aesGCM 并列的构造器（两张套件表都用）。
func chacha20New(k []byte) (cipher.AEAD, error) { return chacha20poly1305.New(k) }

// Lookup 取一个套件（名字大小写不敏感 —— 配置里大小写混着写是常事）。
func Lookup(method string) (Cipher, error) {
	m := strings.ToLower(strings.TrimSpace(method))
	if c, ok := ciphers[m]; ok {
		return c, nil
	}
	// 2022 是另一套（BLAKE3 派生 + 时间戳 + padding），走 Lookup2022 —— 这里指个路，
	// 免得调用方把 2022 当成"我们没做"（它是我们做了，只是入口不同）。
	switch {
	case Is2022(method):
		return Cipher{}, fmt.Errorf("shadowsocks 2022（%s）是另一套实现（SIP022），用 Lookup2022 / "+
			"upstream 的 ss 会自己分发", method)
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
