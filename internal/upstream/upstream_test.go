package upstream

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
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
		// 只有 token、没有 user:pass（真实客户里有：同行的 snzyy 链就是这种）
		{"socks5+tls://1.2.3.4:10080?auth=dG9rZW4tb25seQ==", "socks5", true, "", "token-only", "1.2.3.4:10080"},
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
