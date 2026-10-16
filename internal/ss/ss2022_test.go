package ss

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zeebo/blake3"
)

// 会话子密钥是"写错了只表现为服务端静默断开"的那一环：这里是性质用例，
// 真正的判据是 interop 测试（对着 xray 的 2022 服务端跑）。
func TestSessionKey2022(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(255 - i)
	}

	// ① 长度 = 密钥长度（aes-128 要 16，别的 32）
	if got := sessionKey2022(psk, salt, 16); len(got) != 16 {
		t.Fatalf("aes-128 的子密钥应该是 16 字节，得到 %d", len(got))
	}
	if got := sessionKey2022(psk, salt, 32); len(got) != 32 {
		t.Fatalf("aes-256 的子密钥应该是 32 字节，得到 %d", len(got))
	}

	// ② 确定性
	if !bytes.Equal(sessionKey2022(psk, salt, 32), sessionKey2022(psk, salt, 32)) {
		t.Fatal("同样的输入两次结果不同")
	}

	// ③ 用 BLAKE3 独立拼一遍：context 串与"PSK 在前、salt 在后"都不能变
	want := make([]byte, 32)
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(append([]byte{}, psk...), salt...), want)
	if got := sessionKey2022(psk, salt, 32); !bytes.Equal(got, want) {
		t.Fatalf("会话子密钥不对：得到 %x，期望 %x", got, want)
	}

	// ④ 顺序反过来必须得到不同的值（这条最容易写错，而且错了没有第二条线索）
	rev := make([]byte, 32)
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(append([]byte{}, salt...), psk...), rev)
	if bytes.Equal(sessionKey2022(psk, salt, 32), rev) {
		t.Error("PSK 与 salt 的顺序居然不影响结果")
	}

	// ⑤ 不能跟老版的 HKDF-SHA1 混用（两套派生必须是两个结果）
	master := EVPBytesToKey("sesame", 32)
	if old, err := subkey(master, salt, 32); err == nil && bytes.Equal(old, sessionKey2022(psk, salt, 32)) {
		t.Error("2022 的子密钥居然等于老版 HKDF 的结果")
	}
}

func TestParsePSK(t *testing.T) {
	k32 := make([]byte, 32)
	k16 := make([]byte, 16)
	_, _ = rand.Read(k32)
	_, _ = rand.Read(k16)

	ok32 := base64.StdEncoding.EncodeToString(k32)
	ok16 := base64.StdEncoding.EncodeToString(k16)

	cases := []struct {
		name    string
		method  string
		pass    string
		want    []byte
		wantErr string // 报错里必须出现这些字样（现场要看得懂）
	}{
		{name: "256正常", method: "2022-blake3-aes-256-gcm", pass: ok32, want: k32},
		{name: "128正常", method: "2022-blake3-aes-128-gcm", pass: ok16, want: k16},
		{name: "无padding也收", method: "2022-blake3-aes-256-gcm",
			pass: strings.TrimRight(ok32, "="), want: k32},
		{name: "URL-safe也收", method: "2022-blake3-aes-256-gcm",
			pass: base64.RawURLEncoding.EncodeToString(k32), want: k32},
		{name: "长度不符", method: "2022-blake3-aes-256-gcm", pass: ok16, wantErr: "正好 32 字节"},
		{name: "不是base64", method: "2022-blake3-aes-256-gcm", pass: "中文口令!!", wantErr: "base64"},
		{name: "多用户要EIH", method: "2022-blake3-aes-256-gcm", pass: ok32 + ":" + ok32, wantErr: "EIH"},
		{name: "方式不认识", method: "2022-blake3-aes-512-gcm", pass: ok32, wantErr: "不认识的"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePSK(tc.method, tc.pass)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("应该报错")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("报错里要说 %q: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("PSK 解出来不对: %x", got)
			}
		})
	}
}

func TestIs2022AndLookupSuite(t *testing.T) {
	for _, m := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305", " 2022-BLAKE3-AES-256-GCM "} {
		if !Is2022(m) {
			t.Errorf("%q 应该被认成 2022", m)
		}
		if yes, err := LookupSuite(m); err != nil || !yes {
			t.Errorf("LookupSuite(%q) = %v, %v", m, yes, err)
		}
	}
	for _, m := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		if Is2022(m) {
			t.Errorf("%q 不该被认成 2022", m)
		}
		if yes, err := LookupSuite(m); err != nil || yes {
			t.Errorf("LookupSuite(%q) = %v, %v", m, yes, err)
		}
	}
	if _, err := LookupSuite("aes-512-gcm"); err == nil {
		t.Error("不认识的方式要报错")
	}
	// 传统入口不许再把 2022 当成"我们没做"，要指向 Lookup2022
	if _, err := Lookup("2022-blake3-aes-256-gcm"); err == nil || !strings.Contains(err.Error(), "Lookup2022") {
		t.Errorf("Lookup 对 2022 的报错要指路: %v", err)
	}
}

// ───────── 结构用例：一个能解密我们请求的"假服务端" ─────────
//
// 这**不是**互操作测试（互操作见 internal/upstream 里对着 xray 跑的那些）。
// 它的用途只有一个：构造真服务端不会给我们的**坏响应头**，钉住我们的报错与校验
// （时间戳漂了、salt 回显不对 —— 这两种必须报得让人看得懂，不能只报"解密失败"）。

type fakeSS2022Server struct {
	t    *testing.T
	ln   net.Listener
	psk  []byte
	conn net.Conn

	// 请求解出来的东西
	headerType byte
	timestamp  uint64
	reqAddr    []byte
	padLen     int
	payload    []byte
	salt       []byte
}

func newFakeSS2022Server(t *testing.T, keySize int) *fakeSS2022Server {
	t.Helper()
	psk := make([]byte, keySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSS2022Server{t: t, ln: ln, psk: psk}
}

func (s *fakeSS2022Server) addr() string { return s.ln.Addr().String() }
func (s *fakeSS2022Server) pskB64() string {
	return base64.StdEncoding.EncodeToString(s.psk)
}

// acceptAndReadRequest 读一个请求（salt ‖ E(定长头) ‖ E(变长头)）并解出来。
func (s *fakeSS2022Server) acceptAndReadRequest(keySize int) {
	s.t.Helper()
	c, err := s.ln.Accept()
	if err != nil {
		s.t.Fatal(err)
	}
	s.conn = c
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	salt := make([]byte, keySize)
	if _, err := readFullLoose(c, salt); err != nil {
		s.t.Fatal(err)
	}
	s.salt = salt
	aead, err := ciphers2022["2022-blake3-aes-256-gcm"].NewAEAD(sessionKey2022(s.psk, salt, keySize))
	if err != nil {
		s.t.Fatal(err)
	}
	nonce := make([]byte, 12)
	fixed := s.openChunk(c, aead, 11, nonce)
	s.headerType = fixed[0]
	s.timestamp = binary.BigEndian.Uint64(fixed[1:9])
	vn := int(binary.BigEndian.Uint16(fixed[9:11]))
	variable := s.openChunk(c, aead, vn, nonce)
	// 变长头 = 地址（1 + 4/16/1+len） ‖ padding 长度 ‖ padding ‖ 载荷
	alen := addrLen(variable)
	s.reqAddr = variable[:alen]
	if alen+2 > len(variable) {
		s.t.Fatalf("变长头太短: %d", len(variable))
	}
	s.padLen = int(binary.BigEndian.Uint16(variable[alen : alen+2]))
	rest := variable[alen+2:]
	if s.padLen > len(rest) {
		s.t.Fatalf("padding 长度 %d 超过变长头剩余 %d", s.padLen, len(rest))
	}
	s.payload = rest[s.padLen:]
}

func (s *fakeSS2022Server) openChunk(c net.Conn, aead interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
}, n int, nonce []byte) []byte {
	s.t.Helper()
	body := make([]byte, n+aead.Overhead())
	if _, err := readFullLoose(c, body); err != nil {
		s.t.Fatal(err)
	}
	out, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	incNonce(nonce)
	return out
}

// writeResponse 按 keySize 拼一个响应头（可定制坏在哪），再跟一段数据。
func (s *fakeSS2022Server) writeResponse(keySize int, mk func(salt []byte, echo []byte) ([]byte, []byte)) {
	s.t.Helper()
	salt := make([]byte, keySize)
	if _, err := rand.Read(salt); err != nil {
		s.t.Fatal(err)
	}
	method := ciphers2022["2022-blake3-aes-256-gcm"]
	aead, err := method.NewAEAD(sessionKey2022(s.psk, salt, keySize))
	if err != nil {
		s.t.Fatal(err)
	}
	nonce := make([]byte, 12)
	fixed, data := mk(salt, s.salt)
	out := append([]byte{}, salt...)
	out = append(out, aead.Seal(nil, nonce, fixed, nil)...)
	incNonce(nonce)
	if len(data) > 0 {
		out = append(out, aead.Seal(nil, nonce, data, nil)...)
		incNonce(nonce)
	}
	if _, err := s.conn.Write(out); err != nil {
		s.t.Fatal(err)
	}
}

// 正常的响应头 + 首块（"hello"）：用来证明假服务端本身是对的（不然坏头用例没有意义）。
func (s *fakeSS2022Server) respondGood(keySize int) {
	s.writeResponse(keySize, func(_, echo []byte) ([]byte, []byte) {
		data := []byte("hello")
		fixed := make([]byte, 0, 1+8+keySize+2)
		fixed = append(fixed, headerTypeSrv)
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
		fixed = append(fixed, ts[:]...)
		fixed = append(fixed, echo...)
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(data)))
		fixed = append(fixed, lb[:]...)
		return fixed, data
	})
}

func addrLen(b []byte) int {
	switch b[0] {
	case 0x01:
		return 1 + 4 + 2
	case 0x04:
		return 1 + 16 + 2
	default:
		return 1 + 1 + int(b[1]) + 2
	}
}

func readFullLoose(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// 请求头的结构必须与规范逐字节一致：类型 0、时间戳是当前秒、变长头长度对得上、
// 地址在变长头最前面、padding 至少 1 字节。
func TestSS2022RequestLayout(t *testing.T) {
	srv := newFakeSS2022Server(t, 32)
	defer srv.ln.Close()
	done := make(chan struct{})
	go func() { defer close(done); srv.acceptAndReadRequest(32) }()

	psk := srv.psk
	method := ciphers2022["2022-blake3-aes-256-gcm"]
	target := []byte{0x01, 10, 0, 0, 5, 0x1f, 0x90} // 10.0.0.5:8080
	raw, err := net.Dial("tcp", srv.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c, err := ClientConn2022(raw, method, psk, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	<-done

	if srv.headerType != headerTypeCli {
		t.Errorf("请求头类型应为 %d，得到 %d", headerTypeCli, srv.headerType)
	}
	if d := time.Since(time.Unix(int64(srv.timestamp), 0)); d > 5*time.Second || d < -5*time.Second {
		t.Errorf("时间戳不是当前秒（差 %s）", d)
	}
	if !bytes.Equal(srv.reqAddr, target) {
		t.Errorf("变长头里的地址不对: %x（期望 %x）", srv.reqAddr, target)
	}
	if srv.padLen < 1 || srv.padLen > maxPadding {
		t.Errorf("padding 长度应在 1..%d，得到 %d", maxPadding, srv.padLen)
	}
	if string(srv.payload) != "ping" {
		t.Errorf("首段载荷不对: %q", srv.payload)
	}
}

// 响应头的三种坏法都必须报得让人看得懂。
func TestSS2022ResponseHeaderErrors(t *testing.T) {
	cases := []struct {
		name    string
		mk      func(salt, echo []byte) ([]byte, []byte)
		wantErr string
	}{
		{
			name: "类型不是1",
			mk: func(_ []byte, echo []byte) ([]byte, []byte) {
				return mkResp(0, time.Now().Unix(), echo, nil), nil
			},
			wantErr: "类型不对",
		},
		{
			name: "时间戳漂了",
			mk: func(_ []byte, echo []byte) ([]byte, []byte) {
				return mkResp(headerTypeSrv, time.Now().Unix()-3600, echo, nil), nil
			},
			wantErr: "时钟",
		},
		{
			name: "salt回显不对",
			mk: func(_ []byte, _ []byte) ([]byte, []byte) {
				wrong := make([]byte, 32)
				return mkResp(headerTypeSrv, time.Now().Unix(), wrong, nil), nil
			},
			wantErr: "salt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, good := range []bool{false, true} {
				if !good {
					srv := newFakeSS2022Server(t, 32)
					done := make(chan struct{})
					go func() { defer close(done); srv.acceptAndReadRequest(32) }()
					raw, err := net.Dial("tcp", srv.addr())
					if err != nil {
						srv.ln.Close()
						t.Fatal(err)
					}
					c, err := ClientConn2022(raw, ciphers2022["2022-blake3-aes-256-gcm"], srv.psk,
						[]byte{0x01, 127, 0, 0, 1, 0x00, 0x50})
					if err != nil {
						srv.ln.Close()
						t.Fatal(err)
					}
					if _, err := c.Write([]byte("x")); err != nil {
						t.Fatal(err)
					}
					<-done
					srv.writeResponse(32, tc.mk)
					_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
					_, err = c.Read(make([]byte, 8))
					srv.ln.Close()
					if err == nil {
						t.Fatal("坏响应头却读成功了")
					}
					if !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("报错里要说 %q，得到: %v", tc.wantErr, err)
					}
					return
				}
				// good=true：同一个假服务端发**正常**响应头必须能读出数据 ——
				// 否则上面三条"能报错"可能只是因为假服务端整个是坏的（假绿灯）。
				srv := newFakeSS2022Server(t, 32)
				done := make(chan struct{})
				go func() { defer close(done); srv.acceptAndReadRequest(32) }()
				raw, err := net.Dial("tcp", srv.addr())
				if err != nil {
					srv.ln.Close()
					t.Fatal(err)
				}
				c, err := ClientConn2022(raw, ciphers2022["2022-blake3-aes-256-gcm"], srv.psk,
					[]byte{0x01, 127, 0, 0, 1, 0x00, 0x50})
				if err != nil {
					srv.ln.Close()
					t.Fatal(err)
				}
				if _, err := c.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				<-done
				srv.respondGood(32)
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				got := make([]byte, 5)
				if _, err := readFullLoose(c, got); err != nil {
					t.Fatalf("正常响应头读失败（假服务端可能本身是坏的）: %v", err)
				}
				if string(got) != "hello" {
					t.Fatalf("正常响应数据不对: %q", got)
				}
				srv.ln.Close()
			}
		})
	}
}

// mkResp 拼一个定长响应头（data 为 nil → 长度域写 0）。
func mkResp(typ byte, ts int64, echo []byte, data []byte) []byte {
	out := make([]byte, 0, 1+8+len(echo)+2)
	out = append(out, typ)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	out = append(out, echo...)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(data)))
	return append(out, lb[:]...)
}
