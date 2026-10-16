package vmess

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// KDF 是最容易写错、错法最隐蔽的一环（错了只表现为服务端说 "invalid user"）。
// 这里钉住两条可独立验算的性质：
//   - 没有 path 时就是一次普通 HMAC-SHA256(key="VMess AEAD KDF", data)
//   - 有 path 时，第 1 层等于 HMAC-SHA256(key="VMess AEAD KDF", ipad‖key) 再套外层
func TestKDFProperties(t *testing.T) {
	key := []byte("0123456789abcdef")

	// ① 无 path：直接就是 HMAC-SHA256(kdfSalt, key)
	want := func() []byte {
		m := hmac.New(sha256.New, []byte(kdfSalt))
		m.Write(key)
		return m.Sum(nil)
	}()
	if got := KDF(key); !bytes.Equal(got, want) {
		t.Fatalf("无 path 的 KDF 不是 HMAC-SHA256(kdfSalt, key)\n得到 %x\n期望 %x", got, want)
	}

	// ② 有 path 时，绝不该等于"把 path 拼进 key 再算一次"（那种偷懒写法也是错的）
	naive := func() []byte {
		m := hmac.New(sha256.New, []byte(kdfSalt))
		m.Write(key)
		m.Write([]byte("AES Auth ID Encryption"))
		return m.Sum(nil)
	}()
	got := KDF(key, "AES Auth ID Encryption")
	if bytes.Equal(got, naive) {
		t.Error("KDF 的 path 被拼成了数据 —— path 是**外层 HMAC 的 key**，不是数据")
	}

	// ③ 确定性 + KDF16 是前缀
	if !bytes.Equal(got, KDF(key, "AES Auth ID Encryption")) {
		t.Error("同样的输入两次结果不同")
	}
	if !bytes.Equal(KDF16(key, "x"), KDF(key, "x")[:16]) {
		t.Error("KDF16 不是 KDF 的前 16 字节")
	}

	// ④ path 顺序影响结果（顺序反了就是另一个密钥 —— 这一点没有任何别的表现）
	a := KDF(key, "one", "two")
	b := KDF(key, "two", "one")
	if bytes.Equal(a, b) {
		t.Error("path 顺序居然不影响结果，说明只用了最后一层")
	}
}

// CmdKey = MD5(UUID16 ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")。
// 这个尾巴串写错的表现同样是 "invalid user"，所以在这里钉住。
func TestCmdKey(t *testing.T) {
	uuid, err := hex.DecodeString("bce347154e71431998736d2d3bb5f157")
	if err != nil {
		t.Fatal(err)
	}
	h := md5.New()
	h.Write(uuid)
	h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	var want [16]byte
	copy(want[:], h.Sum(nil))
	if got := CmdKey(uuid); got != want {
		t.Fatalf("CmdKey 不对：得到 %x，期望 %x", got, want)
	}
	if uuidSalt != "c48619fe-8f02-49e0-b9e9-edf763e17e21" {
		t.Error("uuidSalt 被改过 —— 这个串写错只能靠服务端说 invalid user 才发现")
	}
}
