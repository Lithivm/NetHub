package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// 互操作测试的家当：**真的起一个 gost 服务端，真的连它**。
//
// 为什么非要真的起进程（而不是写个"照着规范"的假服务端）：我们要的是"能跟现实里的
// 那个实现互通"，假服务端只会把"我读规范理解错了"这个错误**照抄一遍**（两边一起错，
// 测试全绿，上线连不上）。KB 里的线格式规格就是这么定的：ws/tls/ss 用 gost 对测，
// trojan/vless/vmess 用 xray-core。
//
// gost.exe 在 `local/bin/`（local/ 不入库），**没有就跳过** —— 这样别人 clone 下来
// `go test` 不会因为缺文件而红，而本机能跑就真跑。

// gostPath 找 gost.exe（仓库根的 local/bin/gost.exe）。
func gostPath() string {
	// 测试的工作目录是包目录（internal/upstream），所以要往上两级。
	for _, p := range []string{
		filepath.Join("..", "..", "local", "bin", "gost.exe"),
		filepath.Join("..", "..", "local", "bin", "gost"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
			return p
		}
	}
	return ""
}

// freePort 要一个空闲端口（让 gost 去听）。用完就关，会有极小的竞争窗口 ——
// 够用（本机测试没有别的进程在抢端口）。
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startGost 起一个 gost 服务端（监听 URL 由调用方给），等端口真的起来再返回。
func startGost(t *testing.T, listen string, port int) {
	t.Helper()
	bin := gostPath()
	if bin == "" {
		t.Skip("local/bin/gost.exe 不在，跳过互操作测试（见 KB:资源/代理/上游协议线格式规格.md）")
	}
	cmd := exec.Command(bin, "-L", listen)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("起 gost 失败: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	waitListen(t, port)
}

// waitListen 等端口可连（gost 从 exec 到 listen 要几十毫秒）。
func waitListen(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("gost 端口 %d 没起来", port)
}

// echoServer 一个把收到的字节原样回送的 TCP 服务端（互操作测试的目标）。
// 返回它的地址与关闭函数。
func echoServer(t *testing.T) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().String(), func() { l.Close(); wg.Wait() }
}

// echoThrough 通过 up 连到 target（IP:port），发一句、收一句（验证"数据真的双向走"）。
func echoThrough(t *testing.T, up *Upstream, target string, msg string) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	c, err := up.Dial(ip, port, 5*time.Second)
	if err != nil {
		t.Fatalf("经 %s 拨号失败: %v", up.SchemeTag(), err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := readFull(c, got); err != nil {
		t.Fatalf("读失败: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("回显不对：想要 %q，拿到 %q", msg, got)
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ───────── 传输层解析：写法 → Transport ─────────

func TestParseTransportSchemes(t *testing.T) {
	cases := []struct {
		raw       string
		protocol  string
		transport string
		tls       bool
		path      string
		host      string
	}{
		{"socks5://1.2.3.4:1080", "socks5", transportTCP, false, "", ""},
		{"socks5+tls://1.2.3.4:1080", "socks5", transportTLS, true, "", ""},
		{"socks5+ws://1.2.3.4:1080", "socks5", transportWS, false, "", ""},
		{"socks5+wss://1.2.3.4:1080", "socks5", transportWSS, true, "", ""},
		{"socks5+ws://1.2.3.4:1080?path=/abc&host=cdn.example.com", "socks5", transportWS, false, "/abc", "cdn.example.com"},
		{"https://1.2.3.4:8443", "http", transportTLS, true, "", ""},
		{"http+ws://1.2.3.4:8080", "http", transportWS, false, "", ""},
		{"ss://chacha20-ietf-poly1305:pw@1.2.3.4:8388", "ss", transportTCP, false, "", ""},
		{"ss+ws://aes-256-gcm:pw@1.2.3.4:8388", "ss", transportWS, false, "", ""},
		{"trojan://pw@1.2.3.4:443", "trojan", transportTLS, true, "", ""},
		{"trojan+ws://pw@1.2.3.4:443", "trojan", transportWS, false, "", ""},
	}
	for _, c := range cases {
		up, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%s: 解析失败 %v", c.raw, err)
			continue
		}
		if up.Protocol != c.protocol || up.Transport != c.transport || up.TLS != c.tls {
			t.Errorf("%s: 得到 %s/%s tls=%v，期望 %s/%s tls=%v",
				c.raw, up.Protocol, up.Transport, up.TLS, c.protocol, c.transport, c.tls)
		}
		if up.WSPath != c.path || up.WSHost != c.host {
			t.Errorf("%s: ws 参数得到 path=%q host=%q，期望 %q/%q", c.raw, up.WSPath, up.WSHost, c.path, c.host)
		}
	}
}

// 三段写法必须**报错**，不能静默降级 —— gost 只认两段，多出来的段会被它悄悄丢掉，
// 于是"写错了"表现成"连不上/走错协议"，现场极难查（KB 里专门记了这一条）。
func TestParseRejectsThreeSegments(t *testing.T) {
	for _, raw := range []string{
		"socks5+ws+tls://1.2.3.4:1080",
		"socks5+tls+ws://1.2.3.4:1080",
		"http+ws+tls://1.2.3.4:8080",
	} {
		_, err := Parse(raw)
		if err == nil {
			t.Errorf("%q 应该被拒绝（三段写法）", raw)
			continue
		}
		if !strings.Contains(err.Error(), "两段") && !strings.Contains(err.Error(), "wss") {
			t.Errorf("%q 的报错没告诉用户正确写法: %v", raw, err)
		}
	}
}

func TestParseRejectsUnknownTransport(t *testing.T) {
	for _, raw := range []string{
		"socks5+quic://1.2.3.4:1080",
		"socks5+kcp://1.2.3.4:1080",
		"socks5+obfs4://1.2.3.4:1080",
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%q 的传输我们不支持，应该报错", raw)
		}
	}
}

// ───────── 真的和 gost 对一遍（ws / wss）─────────

// gost 的 ws 传输：SOCKS5 字节塞进 ws 帧（path 默认 /ws）。
func TestInteropGostSocks5OverWS(t *testing.T) {
	tgt, stopEcho := echoServer(t)
	defer stopEcho()

	port := freePort(t)
	startGost(t, fmt.Sprintf("socks5+ws://user:pass@127.0.0.1:%d?path=/ws", port), port)

	for _, scheme := range []string{"socks5+ws", "socks5+wss"} {
		t.Run(scheme, func(t *testing.T) {
			// wss 需要服务端有证书 —— 这里同一个 ws 监听上再起一个 wss 监听不方便，
			// 所以 wss 用一个自带证书的 gost（自签，客户端默认不校验证书）。
			if scheme == "socks5+wss" {
				cert, key := selfSignedCertPEM(t)
				port2 := freePort(t)
				startGost(t, fmt.Sprintf("socks5+wss://user:pass@127.0.0.1:%d?path=/ws&cert=%s&key=%s",
					port2, cert, key), port2)
				up, err := Parse(fmt.Sprintf("socks5+wss://user:pass@127.0.0.1:%d?path=/ws", port2))
				if err != nil {
					t.Fatal(err)
				}
				echoThrough(t, up, tgt, "hello-wss")
				return
			}
			up, err := Parse(fmt.Sprintf("socks5+ws://user:pass@127.0.0.1:%d?path=/ws", port))
			if err != nil {
				t.Fatal(err)
			}
			echoThrough(t, up, tgt, "hello-ws")
		})
	}
}

// path 不匹配要**明确失败**（gost 严格匹配 path）—— 顺手钉住"报错里提 path"。
func TestInteropGostWSWrongPathFails(t *testing.T) {
	port := freePort(t)
	startGost(t, fmt.Sprintf("socks5+ws://user:pass@127.0.0.1:%d?path=/ws", port), port)

	up, err := Parse(fmt.Sprintf("socks5+ws://user:pass@127.0.0.1:%d?path=/nope", port))
	if err != nil {
		t.Fatal(err)
	}
	c, err := up.Dial(net.ParseIP("127.0.0.1"), 9, 3*time.Second)
	if err == nil {
		c.Close()
		t.Fatal("path 不对居然连上了")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Errorf("报错里应该提 path（现场就靠这句查）: %v", err)
	}
}

// 预热在 ws 上也要成立：Prepare + ConnectOn 与 Dial 等价（契约⑤）。
func TestInteropGostWSPrepare(t *testing.T) {
	tgt, stopEcho := echoServer(t)
	defer stopEcho()

	port := freePort(t)
	startGost(t, fmt.Sprintf("socks5+ws://user:pass@127.0.0.1:%d?path=/ws", port), port)

	up, err := Parse(fmt.Sprintf("socks5+ws://user:pass@127.0.0.1:%d?path=/ws", port))
	if err != nil {
		t.Fatal(err)
	}
	p, err := up.Prepare(5 * time.Second)
	if err != nil {
		t.Fatalf("Prepare 失败: %v", err)
	}
	defer p.Close()
	host, portStr, _ := net.SplitHostPort(tgt)
	var tp uint16
	fmt.Sscanf(portStr, "%d", &tp)
	if err := up.ConnectOn(p, net.ParseIP(host), tp, 5*time.Second); err != nil {
		t.Fatalf("ConnectOn 失败: %v", err)
	}
	_ = p.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := p.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := readFull(p, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("回显不对: %q", got)
	}
}

// selfSignedCert 现场生成一张自签证书（互操作测试要用真 TLS）。
//
// 为什么自签也行：我们的客户端默认**不校验**上游证书（与 gost 的 socks5+tls 默认一致），
// 所以 wss 对测不需要真证书 —— 只要服务端能起 TLS 就行。
func selfSignedCertPEM(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// 不能用 t.TempDir()：它的目录名取自子测试名，里面可能有空格（"socks5+wss" 会被
	// 规范成 "socks5 wss"），而 gost 解析 ?cert= 时会被那个空格坑（实测报找不到路径）。
	dir, err := os.MkdirTemp("", "nethub-testcert")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// ───────── shadowsocks（传统 AEAD）：与 gost 的 ss 服务端对测 ─────────

func TestInteropGostShadowsocks(t *testing.T) {
	tgt, stopEcho := echoServer(t)
	defer stopEcho()

	for _, method := range []string{"chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			port := freePort(t)
			startGost(t, fmt.Sprintf("ss://%s:sesame@127.0.0.1:%d", method, port), port)

			up, err := Parse(fmt.Sprintf("ss://%s:sesame@127.0.0.1:%d", method, port))
			if err != nil {
				t.Fatal(err)
			}
			echoThrough(t, up, tgt, "hello-ss-"+method)

			// 域名交给服务端解析（ATYP=域名）这条路也要通 —— 现场内网域名就靠它。
			host, portStr, _ := net.SplitHostPort(tgt)
			var p uint16
			fmt.Sscanf(portStr, "%d", &p)
			c, err := up.DialHost("localhost", p, 5*time.Second)
			if err != nil {
				t.Fatalf("域名路径拨号失败: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Write([]byte("byname")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 6)
			if _, err := readFull(c, got); err != nil {
				t.Fatalf("域名路径读失败: %v", err)
			}
			if string(got) != "byname" {
				t.Fatalf("域名路径回显不对: %q（目标 %s）", got, host)
			}
		})
	}
}

// 口令错：shadowsocks 服务端**不会回错**，它是静默断开（协议里没有错误码）——
// 所以这里断言的是"写能过、读会失败"，而不是"拨号报错"。这个语义差别写进注释，
// 免得后来人把"Dial 成功"误解成"认证通过"。
func TestInteropGostShadowsocksWrongPassword(t *testing.T) {
	tgt, stopEcho := echoServer(t)
	defer stopEcho()

	port := freePort(t)
	startGost(t, fmt.Sprintf("ss://aes-256-gcm:sesame@127.0.0.1:%d", port), port)

	up, err := Parse(fmt.Sprintf("ss://aes-256-gcm:wrongpw@127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(tgt)
	var p uint16
	fmt.Sscanf(portStr, "%d", &p)
	c, err := up.Dial(net.ParseIP(host), p, 3*time.Second)
	if err != nil {
		t.Fatalf("ss 握手没有应答，拨号不该失败: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte("hello"))
	buf := make([]byte, 8)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("口令错却读到了数据 —— 要么服务端没校验，要么我们解错了")
	}
}
