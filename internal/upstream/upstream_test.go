package upstream

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseSchemes(t *testing.T) {
	cases := []struct {
		raw      string
		protocol string
		tls      bool
		user     string
		pass     string
		addr     string
	}{
		{"socks5+tls://1.2.3.4:10080?auth=dXNlcjpwYXNz", "socks5", true, "user", "pass", "1.2.3.4:10080"},
		{"socks5://1.2.3.4:1080", "socks5", false, "", "", "1.2.3.4:1080"},
		{"socks5h://1.2.3.4:1080", "socks5", false, "", "", "1.2.3.4:1080"},
		{"socks://1.2.3.4:1080", "socks5", false, "", "", "1.2.3.4:1080"},
		{"socks4://1.2.3.4:1080", "socks4", false, "", "", "1.2.3.4:1080"},
		{"socks4a://1.2.3.4:1080", "socks4a", false, "", "", "1.2.3.4:1080"},
		{"http://proxy:8080", "http", false, "", "", "proxy:8080"},
		{"https://proxy:8443", "http", true, "", "", "proxy:8443"},
		{"http://u:p@proxy:8080", "http", false, "u", "p", "proxy:8080"},
		{"socks5+tls://u:p@1.2.3.4:443", "socks5", true, "u", "p", "1.2.3.4:443"},
		// 只有 token、没有 user:pass：gost 的含义是“整个值 = 用户名、口令空”
		// （实测：同事的 snzyy 链就是这种，见 upstream.go 里的注释）
		{"socks5+tls://1.2.3.4:10080?auth=dG9rZW4tb25seQ==", "socks5", true, "token-only", "", "1.2.3.4:10080"},
		// 真实的 snzyy：auth 解出来是 38 字节二进制（含非 ASCII），也得原样当用户名
		{"socks5+tls://1.2.3.4:10084?auth=dGhpcy1pcy1hLWZha2UtdG9rZW4=", "socks5", true, "this-is-a-fake-token", "", "1.2.3.4:10084"},
	}
	for _, c := range cases {
		up, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%s: 解析失败 %v", c.raw, err)
			continue
		}
		if up.Protocol != c.protocol || up.TLS != c.tls || up.Addr != c.addr {
			t.Errorf("%s: 得到 %s tls=%v addr=%s，期望 %s tls=%v addr=%s",
				c.raw, up.Protocol, up.TLS, up.Addr, c.protocol, c.tls, c.addr)
		}
		if up.Creds.User != c.user || up.Creds.Pass != c.pass {
			t.Errorf("%s: 凭据得到 %q/%q，期望 %q/%q", c.raw, up.Creds.User, up.Creds.Pass, c.user, c.pass)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, bad := range []string{
		"", "relay+tls://1.2.3.4:5678", "quic://1.2.3.4:5678", "ss://1.2.3.4:8388",
		"socks5+tls://noport", "http://",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q 应该被拒绝，但解析通过了", bad)
		}
	}
}

func TestStringHidesCreds(t *testing.T) {
	up, _ := Parse("socks5+tls://203.0.113.10:10080?auth=dXNlcjpwYXNz")
	s := up.String()
	if s == "" || strings.Contains(s, "user") || strings.Contains(s, "pass") || strings.Contains(s, "dXNlc") {
		t.Errorf("String() 泄漏了凭据: %q", s)
	}
}

// Probe 只测到代理这一段：死端口要快速失败（不碰任何业务目标）。
func TestProbeDeadUpstream(t *testing.T) {
	u, err := Parse("socks5://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Probe(2 * time.Second); err == nil {
		t.Error("127.0.0.1:1 应该探测失败")
	}
}

// A13：TLS 会话复用要真的生效 —— 第二次握手应命中缓存（DidResume=true），
// 否则"省一个 RTT"只是纸面收益。
func TestTLSSessionResume(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 16)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					if _, err := c.Write(buf[:1]); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	up, err := Parse("socks5+tls://" + ln.Addr().String()) // 不校验证书（与生产默认一致）
	if err != nil {
		t.Fatal(err)
	}
	if up.tlsConfig().ClientSessionCache == nil {
		t.Fatal("tlsConfig 没挂会话缓存")
	}

	dial := func() tls.ConnectionState {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		tc := tls.Client(raw, up.tlsConfig())
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		// 写一点东西，让 TLS 1.3 的会话票据回来
		if _, err := tc.Write([]byte{0x01, 0x02}); err != nil {
			t.Fatal(err)
		}
		if _, err := tc.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		st := tc.ConnectionState()
		time.Sleep(50 * time.Millisecond) // 等票据到达
		_ = tc.Close()
		return st
	}

	first := dial()
	if first.DidResume {
		t.Log("第一次就复用了（同一进程内之前跑过，正常）")
	}
	second := dial()
	if !second.DidResume {
		t.Error("第二次握手没有复用会话 —— 缓存没起作用（每次都要重做完整握手）")
	}
}

// selfSignedCert 生成一张临时自签证书（仅测试用）。
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nethub-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// 代理段体检：口令对 → AuthOK；口令错 → AuthOK=false 且原因说清"认证被拒"。
//
// 钉住一个真实教训：旧的探测只做 TCP+TLS，口令错了界面照样显示"可用（96ms）"，
// 把人骗了很久（真实事故：sjy 的口令被上游间歇性拒掉，界面一直绿着）。
func TestProbeAuth(t *testing.T) {
	addr, stop := fakeSocks5(t, "u", "p")
	defer stop()

	good, err := Parse("socks5://u:p@" + addr)
	if err != nil {
		t.Fatal(err)
	}
	if r := good.ProbeAuth(3 * time.Second); !r.AuthOK {
		t.Fatalf("口令正确时应通过认证，得到 %+v", r)
	}

	bad, err := Parse("socks5://u:wrong@" + addr)
	if err != nil {
		t.Fatal(err)
	}
	r2 := bad.ProbeAuth(3 * time.Second)
	if r2.AuthOK {
		t.Error("口令错误时必须判为不通过（否则界面会一直显示“可用”）")
	}
	if r2.Err == nil || !strings.Contains(r2.Err.Error(), "认证") {
		t.Errorf("原因要说清是认证问题，得到 %v", r2.Err)
	}
}

// fakeSocks5 起一个最小 SOCKS5 服务端：只支持 用户名/口令 认证，CONNECT 一律回成功。
func fakeSocks5(t *testing.T, user, pass string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假上游失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				// ① 方法协商：只提供"用户名/口令"
				if _, err := c.Read(buf); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
					return
				}
				// ② 认证：ULEN + USER + PLEN + PASS（按长度精确读）
				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				uname := make([]byte, head[1])
				if _, err := io.ReadFull(c, uname); err != nil {
					return
				}
				plen := make([]byte, 1)
				if _, err := io.ReadFull(c, plen); err != nil {
					return
				}
				passwd := make([]byte, plen[0])
				if _, err := io.ReadFull(c, passwd); err != nil {
					return
				}
				if string(uname) != user || string(passwd) != pass {
					_, _ = c.Write([]byte{0x01, 0x01})
					return
				}
				if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
					return
				}
				// ③ CONNECT → 一律成功，然后挂住（模拟隧道，由调用方关闭）
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90})
				_, _ = c.Read(buf)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// 脱敏占位符不能当凭据用。
//
// 真实坑：从「导出配置（无凭据）」或文档里拷回来的地址，口令被抹成 `***` ——
// 以前它原样通过校验，运行时才报"认证被拒"，看起来像上游坏了。
func TestRejectMaskedCreds(t *testing.T) {
	bad := []string{
		"socks5://u:***@1.2.3.4:1080",
		"socks5://***:***@1.2.3.4:1080",
		"socks5+tls://1.2.3.4:10080?auth=" + cod("u:***"),
		"socks5+tls://1.2.3.4:10080?auth=" + cod("****"),
	}
	for _, raw := range bad {
		_, err := Parse(raw)
		if err == nil {
			t.Errorf("%s 的凭据是占位符，应被拒绝", raw)
			continue
		}
		if !strings.Contains(err.Error(), "占位符") {
			t.Errorf("%s 的报错要说清是占位符，得到 %v", raw, err)
		}
	}
	// 别误伤：真口令、短口令、无凭据都要照常通过
	good := []string{
		"socks5://u:p@1.2.3.4:1080",
		"socks5://u:xx@1.2.3.4:1080",     // 两个字符不算占位符
		"socks5://u:xxxx@1.2.3.4:1080",   // x 不再是占位符字符（真口令可能长这样）
		"socks5://u:XXXXXX@1.2.3.4:1080", // 同上
		"socks5://u:P@ss**word@1.2.3.4:1080",
		"socks5://1.2.3.4:1080",
	}
	for _, raw := range good {
		if _, err := Parse(raw); err != nil {
			t.Errorf("%s 应该能解析，得到 %v", raw, err)
		}
	}
}

func cod(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// “把域名交给上游”必须在**报文层**真的这样做：SOCKS5 的 ATYP=域名（0x03）。
// 这条测试是为了防“看起来实现了、其实还是发 IP”（那样上游永远不会自己解析）。
func TestDialHostSendsDomain(t *testing.T) {
	got := make(chan string, 1)
	addr, stop := fakeSocks5Capturing(t, "u", "p", got)
	defer stop()

	u, err := Parse("socks5://u:p@" + addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := u.DialHost("main.example.com", 8443, 3*time.Second)
	if err != nil {
		t.Fatalf("DialHost 失败: %v", err)
	}
	defer conn.Close()

	select {
	case req := <-got:
		// 请求形如：VER=5 CMD=1 RSV=0 ATYP=3 LEN name PORT(2)
		if len(req) < 5 {
			t.Fatalf("CONNECT 请求太短: %x", req)
		}
		if req[0] != 0x05 || req[1] != 0x01 {
			t.Errorf("VER/CMD 不对: %x", req[:2])
		}
		if req[3] != 0x03 {
			t.Fatalf("ATYP 应为 0x03（域名），实际 0x%02x —— 说明还是把 IP 发给上游了", req[3])
		}
		if n := int(req[4]); len(req) < 5+n+2 {
			t.Fatalf("域名长度字段与实际不符: %x", req)
		} else if string(req[5:5+n]) != "main.example.com" {
			t.Errorf("域名应为 main.example.com，实际 %q", string(req[5:5+n]))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没收到 CONNECT 请求")
	}
}

// fakeSocks5Capturing 与 fakeSocks5 相同，但把 CONNECT 请求原文送回 got。
func fakeSocks5Capturing(t *testing.T, user, pass string, got chan<- string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假上游失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				if _, err := c.Read(buf); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
					return
				}
				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				uname := make([]byte, head[1])
				if _, err := io.ReadFull(c, uname); err != nil {
					return
				}
				plen := make([]byte, 1)
				if _, err := io.ReadFull(c, plen); err != nil {
					return
				}
				passwd := make([]byte, plen[0])
				if _, err := io.ReadFull(c, passwd); err != nil {
					return
				}
				if string(uname) != user || string(passwd) != pass {
					_, _ = c.Write([]byte{0x01, 0x01})
					return
				}
				if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
					return
				}
				// CONNECT 请求：读头 4 字节（VER CMD RSV ATYP）再按 ATYP 读地址
				h := make([]byte, 4)
				if _, err := io.ReadFull(c, h); err != nil {
					return
				}
				full := append([]byte{}, h...)
				switch h[3] {
				case 0x03:
					l := make([]byte, 1)
					if _, err := io.ReadFull(c, l); err != nil {
						return
					}
					full = append(full, l[0])
					host := make([]byte, l[0])
					if _, err := io.ReadFull(c, host); err != nil {
						return
					}
					full = append(full, host...)
				case 0x01:
					b := make([]byte, 4)
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					full = append(full, b...)
				default:
					return
				}
				port := make([]byte, 2)
				if _, err := io.ReadFull(c, port); err != nil {
					return
				}
				full = append(full, port...)
				select {
				case got <- string(full):
				default:
				}
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90})
				_, _ = c.Read(buf)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// 2022 的 PSK 是 base64 的随机串 —— **里面出现 / + = ? # 是常态**。
// 现场抄来的链接往往没做 percent 编码，那段 base64 会让 url.Parse 直接炸
// （`/` 被当路径分隔）或者更阴（`#` 能解析成功但把主机名吃掉）。
// 这两种都必须能正常解析出**同一个** PSK，而且已经写对的 %2B 不能被二次转义。
func TestParseSloppyBase64Creds(t *testing.T) {
	// 一个真的 32 字节 PSK：它的 base64 里 `+` `/` `=` 全有（这三类字符在 userinfo 里都不合法）
	pskBytes := make([]byte, 32)
	for i := range pskBytes {
		pskBytes[i] = []byte{0xfb, 0xff, 0xbf}[i%3]
	}
	psk := base64.StdEncoding.EncodeToString(pskBytes)
	if !strings.ContainsAny(psk, "+/=") {
		t.Fatalf("这个 PSK 没有脏字符，用例白测了: %s", psk)
	}
	plain := "ss://2022-blake3-aes-256-gcm:" + psk + "@127.0.0.1:8388"
	encoded := "ss://2022-blake3-aes-256-gcm:" + url.QueryEscape(psk) + "@127.0.0.1:8388"

	for _, raw := range []string{plain, encoded} {
		up, err := Parse(raw)
		if err != nil {
			t.Fatalf("解析失败（%q）: %v", raw, err)
		}
		if up.Addr != "127.0.0.1:8388" {
			t.Errorf("主机端口解析错了: %q", up.Addr)
		}
		if up.Creds.Pass != psk {
			t.Errorf("口令应该是 %q，得到 %q（%q）", psk, up.Creds.Pass, raw)
		}
	}

	// 中文口令（现场真有人这么用）：url.Parse 会报 “invalid userinfo”，我们兜底转义
	up, err := Parse("ss://aes-256-gcm:中文口令@1.2.3.4:8388")
	if err != nil {
		t.Fatalf("中文口令解析失败: %v", err)
	}
	if up.Creds.Pass != "中文口令" {
		t.Errorf("中文口令解错: %q", up.Creds.Pass)
	}

	// 老版 ss 的 SIP002 写法（userinfo 是 base64(method:pass)）同样会遇到脏字符 —— 也得收
	ui := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pa/ss+word="))
	up, err = Parse("ss://" + ui + "@1.2.3.4:8388")
	if err != nil {
		t.Fatalf("SIP002 脏 userinfo 解析失败: %v", err)
	}
	if up.Creds.User != "aes-256-gcm" || up.Creds.Pass != "pa/ss+word=" {
		t.Errorf("SIP002 凭据解错: user=%q pass=%q", up.Creds.User, up.Creds.Pass)
	}
}

// 分享链接形态（vmess://base64）本来就没有端口，别被"重新转义再试"那条兜底路径弄坏。
func TestParseShareLinkStillWorks(t *testing.T) {
	js := `{"v":"2","add":"1.2.3.4","port":"443","id":"bce34715-e471-4319-9873-6d2d3bb5f157","net":"tcp"}`
	up, err := Parse("vmess://" + base64.RawStdEncoding.EncodeToString([]byte(js)))
	if err != nil {
		t.Fatal(err)
	}
	if up.Addr != "1.2.3.4:443" {
		t.Errorf("分享链接里的地址没取到: %q", up.Addr)
	}
}

// 2022：解析期就要把写错的地方挡住（长度不对、多用户写法、base64 坏了）——
// 这些错在拨号时的表现只有"服务端静默断开"，等于没有线索。
func TestParseSS2022Validation(t *testing.T) {
	k32 := make([]byte, 32)
	for i := range k32 {
		k32[i] = byte(i + 1)
	}
	ok := base64.StdEncoding.EncodeToString(k32)
	for _, tc := range []struct{ name, raw, wantErr string }{
		{"正常", "ss://2022-blake3-aes-256-gcm:" + ok + "@127.0.0.1:8388", ""},
		{"长度不对", "ss://2022-blake3-aes-256-gcm:" + base64.StdEncoding.EncodeToString(k32[:16]) + "@127.0.0.1:8388", "正好 32 字节"},
		{"多用户", "ss://2022-blake3-aes-256-gcm:" + ok + ":" + ok + "@127.0.0.1:8388", "EIH"},
		{"base64坏了", "ss://2022-blake3-aes-256-gcm:!!!!@127.0.0.1:8388", "base64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.raw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("应该通过: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("应该报错")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("报错里要说 %q: %v", tc.wantErr, err)
			}
		})
	}
}
