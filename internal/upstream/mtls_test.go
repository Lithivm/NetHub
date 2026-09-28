package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mTLS（客户端证书）端到端：`?cert=<证书>&key=<私钥>`。
//
// 为什么要按参数而不是按 `+mtls` 后缀来触发：gost 的 `mtls` 是 **m**ultiplexed TLS，
// 与业界通常说的 mutual TLS **撞名**（KB 特意记过这个坑）。按参数显式给证书，
// 既不猜语义，也不会让写了 `+mtls` 的老配置突然失败。
//
// 这条测的不是"配置能解析"，而是**证书真的被发出去了** —— 后者只有在服务端要求客户端证书时
// 才看得出来，所以这里起的是一个 `RequireAnyClientCert` 的 TLS 上游。

// writePEM 把自签证书与私钥写成文件（我们的配置按**文件路径**给，不是内联）。
func writePEM(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	c := selfSignedCert(t)
	// 复用 selfSignedCert 生成的密钥对；它的 ExtKeyUsage 是 ServerAuth，
	// 而 RequireAnyClientCert 不校验 EKU，所以拿它当客户端证书足够。
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// tlsSocks5Echo 起一个"要求客户端证书"的 TLS SOCKS5 上游，并把
// 「服务端到底有没有收到客户端证书」记在 sawCert 里。
func tlsSocks5Echo(t *testing.T, user, pass string) (addr string, sawCert func() bool, stop func()) {
	t.Helper()
	srv := selfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tln := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{srv},
		ClientAuth:   tls.RequireAnyClientCert, // 只要求"出示"，不校验颁发者
	})
	var mu sync.Mutex
	seen := false
	go func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						return
					}
					if n := len(tc.ConnectionState().PeerCertificates); n > 0 {
						mu.Lock()
						seen = true
						mu.Unlock()
					}
				}
				if !fakeSocks5Handshake(c, user, pass) {
					return
				}
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() bool { mu.Lock(); defer mu.Unlock(); return seen }, func() { tln.Close() }
}

func TestMutualTLSSendsClientCert(t *testing.T) {
	addr, sawCert, stop := tlsSocks5Echo(t, "u", "p")
	defer stop()
	cert, key := writePEM(t, t.TempDir())

	up, err := Parse("socks5+tls://u:p@" + addr + "?cert=" + cert + "&key=" + key)
	if err != nil {
		t.Fatalf("带客户端证书的地址应当能解析: %v", err)
	}
	if up.ClientCert == nil {
		t.Fatal("解析后 ClientCert 应当是加载好的证书（解析期就加载，别等拨号）")
	}

	conn, err := up.Dial(net.ParseIP("10.1.2.3"), 443, 4*time.Second)
	if err != nil {
		t.Fatalf("Dial 失败: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn, "mTLS 连上了但数据走不通")

	// 关键断言：证书**真的发出去了**（只解析对不算）
	if !sawCert() {
		t.Error("服务端要求客户端证书，但我们没有把证书发出去")
	}
}

// 配置错要在**解析期**挡住，不能等到第一次拨号才发现（那时现场只会看到业务连不上）。
func TestMutualTLSConfigErrors(t *testing.T) {
	cert, key := writePEM(t, t.TempDir())
	missing := filepath.Join(t.TempDir(), "nope.crt")

	cases := []struct {
		name, url string
	}{
		{"只给 cert 没给 key", "socks5+tls://1.2.3.4:1080?cert=" + cert},
		{"只给 key 没给 cert", "socks5+tls://1.2.3.4:1080?key=" + key},
		{"文件不存在", "socks5+tls://1.2.3.4:1080?cert=" + missing + "&key=" + key},
		{"非 TLS 上游给了证书", "socks5://1.2.3.4:1080?cert=" + cert + "&key=" + key},
	}
	for _, c := range cases {
		if _, err := Parse(c.url); err == nil {
			t.Errorf("%s：应当解析失败，但它通过了", c.name)
		}
	}
}
