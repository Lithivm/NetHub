package upstream

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
// 返回它的地址与关闭函数（关闭时会**等**所有连接处理完）。
func echoServer(t *testing.T) (string, func()) {
	return echoServerImpl(t, true)
}

// echoServerNoWait 同上，但关闭时不等待 —— 给"服务端不回收出口连接"的场景用。
//
// 实测（2026-10-16）：**xray 的 ss2022 服务端在客户端正常关闭后不回收**它到 echo 的连接，
// 等下去只会把测试挂到超时 —— 拿 xray 自己当 ss2022 客户端（socks 进→ss2022 出）跑同样的
// 12 万字节，echo 连接同样不被回收，所以那是**那个服务端的脾气**，不是我们客户端的 bug。
// gost（传统 ss / ws）没有这个问题。
func echoServerNoWait(t *testing.T) (string, func()) {
	return echoServerImpl(t, false)
}

func echoServerImpl(t *testing.T, wait bool) (string, func()) {
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
	return l.Addr().String(), func() {
		l.Close()
		if wait {
			wg.Wait()
		}
	}
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

// ───────── xray-core 服务端（trojan / vless / vmess 用 gost 测不了）─────────

// xrayPath 找 xray.exe（仓库根的 local/bin/）。
func xrayPath() string {
	for _, p := range []string{
		filepath.Join("..", "..", "local", "bin", "xray.exe"),
		filepath.Join("..", "..", "local", "bin", "xray"),
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

// startXray 起一个 xray 服务端（config 里的 %CERT% / %KEY% 会被替换成临时证书路径）。
func startXray(t *testing.T, cfg string, ports ...int) {
	t.Helper()
	bin := xrayPath()
	if bin == "" {
		t.Skip("local/bin/xray.exe 不在，跳过互操作测试（见 KB:资源/代理/上游协议线格式规格.md）")
	}
	cert, key := selfSignedCertPEM(t)
	cfg = strings.ReplaceAll(cfg, "%CERT%", filepath.ToSlash(cert))
	cfg = strings.ReplaceAll(cfg, "%KEY%", filepath.ToSlash(key))
	dir, err := os.MkdirTemp("", "nethub-xray")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("起 xray 失败: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	for _, p := range ports {
		waitListen(t, p)
	}
}

// trojan 对测：TLS 直连 与 ws 两条路（xray 同时开两个 inbound）。
func TestInteropXrayTrojan(t *testing.T) {
	tgt, stopEcho := echoServer(t)
	defer stopEcho()

	tlsPort, wsPort := freePort(t), freePort(t)
	cfg := strings.ReplaceAll(xrayTrojanCfg, "%TLS%", fmt.Sprint(tlsPort))
	cfg = strings.ReplaceAll(cfg, "%WS%", fmt.Sprint(wsPort))
	startXray(t, cfg, tlsPort, wsPort)

	t.Run("tls", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("trojan://sesame@127.0.0.1:%d", tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		if !up.TLS {
			t.Fatal("trojan 默认就该带 TLS")
		}
		echoThrough(t, up, tgt, "hello-trojan")
	})

	t.Run("ws", func(t *testing.T) {
		// xray 分享链接的写法（type=ws + path + sni）
		up, err := Parse(fmt.Sprintf("trojan://sesame@127.0.0.1:%d?type=ws&path=/tr&sni=127.0.0.1", wsPort))
		if err != nil {
			t.Fatal(err)
		}
		if up.Transport != transportWSS {
			t.Fatalf("type=ws + security=tls 应该归一化成 wss，得到 %s", up.Transport)
		}
		echoThrough(t, up, tgt, "hello-trojan-ws")
	})

	t.Run("域名透传", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("trojan://sesame@127.0.0.1:%d", tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		_, portStr, _ := net.SplitHostPort(tgt)
		var p uint16
		fmt.Sscanf(portStr, "%d", &p)
		c, err := up.DialHost("localhost", p, 5*time.Second)
		if err != nil {
			t.Fatal(err)
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
			t.Fatalf("域名路径回显不对: %q", got)
		}
	})

	t.Run("口令错", func(t *testing.T) {
		// trojan 与 ss 一样：**请求不报错**，服务端只是不理你（xray 会直接断开）。
		// 所以断言"写能过、读会失败"，别把 Dial 成功当认证通过。
		up, err := Parse(fmt.Sprintf("trojan://wrong@127.0.0.1:%d", tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		_, portStr, _ := net.SplitHostPort(tgt)
		var p uint16
		fmt.Sscanf(portStr, "%d", &p)
		c, err := up.Dial(net.ParseIP("127.0.0.1"), p, 3*time.Second)
		if err != nil {
			t.Fatalf("trojan 没有握手应答，拨号不该失败: %v", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Write([]byte("hello"))
		if _, err := c.Read(make([]byte, 8)); err == nil {
			t.Fatal("口令错却读到了数据")
		}
	})
}

// xrayTrojanCfg trojan 对测用的 xray 配置（两个 inbound：TLS 直连 + ws）。
const xrayTrojanCfg = `{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"listen": "127.0.0.1", "port": %TLS%, "protocol": "trojan",
     "settings": {"clients": [{"password": "sesame"}]},
     "streamSettings": {"network": "tcp", "security": "tls",
       "tlsSettings": {"certificates": [{"certificateFile": "%CERT%", "keyFile": "%KEY%"}]}}},
    {"listen": "127.0.0.1", "port": %WS%, "protocol": "trojan",
     "settings": {"clients": [{"password": "sesame"}]},
     "streamSettings": {"network": "ws", "security": "tls",
       "wsSettings": {"path": "/tr"},
       "tlsSettings": {"certificates": [{"certificateFile": "%CERT%", "keyFile": "%KEY%"}]}}}
  ],
  "outbounds": [{"protocol": "freedom"}]
}`

// ───────── VLESS（裸 flow）与 xray 对测 ─────────

// xrayVlessCfg vless 对测配置（两个 inbound：TLS 直连 + ws，均无 flow）。
const xrayVlessCfg = `{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"listen": "127.0.0.1", "port": %TLS%, "protocol": "vless",
     "settings": {"clients": [{"id": "%ID%"}], "decryption": "none"},
     "streamSettings": {"network": "tcp", "security": "tls",
       "tlsSettings": {"certificates": [{"certificateFile": "%CERT%", "keyFile": "%KEY%"}]}}},
    {"listen": "127.0.0.1", "port": %WS%, "protocol": "vless",
     "settings": {"clients": [{"id": "%ID%"}], "decryption": "none"},
     "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/vl"},
       "tlsSettings": {"certificates": [{"certificateFile": "%CERT%", "keyFile": "%KEY%"}]}}}
  ],
  "outbounds": [{"protocol": "freedom"}]
}`

func TestInteropXrayVless(t *testing.T) {
	tgt, stopEcho := echoServer(t)
	defer stopEcho()

	id := RandomUUID()
	tlsPort, wsPort := freePort(t), freePort(t)
	cfg := xrayVlessCfg
	cfg = strings.ReplaceAll(cfg, "%ID%", id)
	cfg = strings.ReplaceAll(cfg, "%TLS%", fmt.Sprint(tlsPort))
	cfg = strings.ReplaceAll(cfg, "%WS%", fmt.Sprint(wsPort))
	startXray(t, cfg, tlsPort, wsPort)

	t.Run("tls", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vless://%s@127.0.0.1:%d?encryption=none&security=tls&sni=127.0.0.1", id, tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		echoThrough(t, up, tgt, "hello-vless")
	})

	t.Run("ws", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vless://%s@127.0.0.1:%d?encryption=none&security=tls&type=ws&path=/vl&sni=127.0.0.1",
			id, wsPort))
		if err != nil {
			t.Fatal(err)
		}
		echoThrough(t, up, tgt, "hello-vless-ws")
	})

	t.Run("无横线大写UUID也认", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=127.0.0.1",
			strings.ToUpper(strings.ReplaceAll(id, "-", "")), tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		echoThrough(t, up, tgt, "uuid-form")
	})

	t.Run("域名透传", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=127.0.0.1", id, tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		_, portStr, _ := net.SplitHostPort(tgt)
		var p uint16
		fmt.Sscanf(portStr, "%d", &p)
		c, err := up.DialHost("localhost", p, 5*time.Second)
		if err != nil {
			t.Fatal(err)
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
			t.Fatalf("域名路径回显不对: %q", got)
		}
	})

	t.Run("预热等价于直连", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=127.0.0.1", id, tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		pre, err := up.Prepare(5 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer pre.Close()
		host, portStr, _ := net.SplitHostPort(tgt)
		var p uint16
		fmt.Sscanf(portStr, "%d", &p)
		if err := up.ConnectOn(pre, net.ParseIP(host), p, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		_ = pre.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := pre.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 4)
		if _, err := readFull(pre, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != "ping" {
			t.Fatalf("回显不对: %q", got)
		}
	})

	t.Run("UUID错要在读的时候暴露", func(t *testing.T) {
		// VLESS 的响应头是**随第一段数据**发的（xray 如此），所以错误不可能在 Dial 里出现：
		// 服务端对无效 UUID 是静默断开，我们只会在第一次读时发现。
		// 这条用例把这个语义钉住 —— 别把"Dial 成功"当成"认证通过"。
		up, err := Parse(fmt.Sprintf("vless://%s@127.0.0.1:%d?security=tls&sni=127.0.0.1", RandomUUID(), tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		c, err := up.Dial(net.ParseIP("127.0.0.1"), 9, 3*time.Second)
		if err != nil {
			t.Logf("Dial 直接失败也可以（服务端断得够快）: %v", err)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte("hello"))
		if _, err := c.Read(make([]byte, 8)); err == nil {
			t.Fatal("UUID 不对却读到了数据 —— 服务端应该静默断开")
		}
	})

	t.Run("flow要拒绝", func(t *testing.T) {
		_, err := Parse(fmt.Sprintf("vless://%s@127.0.0.1:%d?flow=xtls-rprx-vision", id, tlsPort))
		if err == nil {
			t.Fatal("声明 flow 应该被解析期拒绝")
		}
		if !strings.Contains(err.Error(), "flow") {
			t.Errorf("报错里要提 flow: %v", err)
		}
	})
}

// ───────── VMess（AEAD）与 xray 对测 ─────────

const xrayVmessCfg = `{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"listen": "127.0.0.1", "port": %TLS%, "protocol": "vmess",
     "settings": {"clients": [{"id": "%ID%", "alterId": 0}]},
     "streamSettings": {"network": "tcp", "security": "tls",
       "tlsSettings": {"certificates": [{"certificateFile": "%CERT%", "keyFile": "%KEY%"}]}}},
    {"listen": "127.0.0.1", "port": %WS%, "protocol": "vmess",
     "settings": {"clients": [{"id": "%ID%", "alterId": 0}]},
     "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/vm"},
       "tlsSettings": {"certificates": [{"certificateFile": "%CERT%", "keyFile": "%KEY%"}]}}}
  ],
  "outbounds": [{"protocol": "freedom"}]
}`

func TestInteropXrayVmess(t *testing.T) {
	tgt, stopEcho := echoServer(t)
	defer stopEcho()

	id := RandomUUID()
	tlsPort, wsPort := freePort(t), freePort(t)
	cfg := xrayVmessCfg
	cfg = strings.ReplaceAll(cfg, "%ID%", id)
	cfg = strings.ReplaceAll(cfg, "%TLS%", fmt.Sprint(tlsPort))
	cfg = strings.ReplaceAll(cfg, "%WS%", fmt.Sprint(wsPort))
	startXray(t, cfg, tlsPort, wsPort)

	t.Run("tls", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vmess://%s@127.0.0.1:%d?security=tls&sni=127.0.0.1&scy=auto", id, tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		echoThrough(t, up, tgt, "hello-vmess")
	})

	t.Run("ws分享链接式", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vmess://%s@127.0.0.1:%d?security=tls&type=ws&path=/vm&sni=127.0.0.1", id, wsPort))
		if err != nil {
			t.Fatal(err)
		}
		echoThrough(t, up, tgt, "hello-vmess-ws")
	})

	t.Run("base64分享链接", func(t *testing.T) {
		// 现场拿到的是这一种：vmess://<base64(json)>
		js := fmt.Sprintf(`{"v":"2","ps":"test","add":"127.0.0.1","port":"%d","id":"%s","aid":"0","scy":"auto","net":"tcp","tls":"tls","sni":"127.0.0.1"}`,
			tlsPort, id)
		link := "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(js))
		up, err := Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if up.Protocol != "vmess" || up.UserID == nil {
			t.Fatalf("分享链接解析不对: %+v", up)
		}
		echoThrough(t, up, tgt, "share-link")
	})

	t.Run("大包要分块", func(t *testing.T) {
		// 一次写 40KB（超过 xray 的 16KB 块上限）→ 走多块路径，读回来必须一模一样
		up, err := Parse(fmt.Sprintf("vmess://%s@127.0.0.1:%d?security=tls&sni=127.0.0.1", id, tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		host, portStr, _ := net.SplitHostPort(tgt)
		var p uint16
		fmt.Sscanf(portStr, "%d", &p)
		c, err := up.Dial(net.ParseIP(host), p, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, 40000)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		go func() { _, _ = c.Write(payload) }()
		got := make([]byte, len(payload))
		if _, err := readFull(c, got); err != nil {
			t.Fatalf("读大包失败: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("大包回显不一致（分块/拼接写错了）")
		}
	})

	t.Run("域名透传", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vmess://%s@127.0.0.1:%d?security=tls&sni=127.0.0.1", id, tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		_, portStr, _ := net.SplitHostPort(tgt)
		var p uint16
		fmt.Sscanf(portStr, "%d", &p)
		c, err := up.DialHost("localhost", p, 5*time.Second)
		if err != nil {
			t.Fatal(err)
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
			t.Fatalf("域名路径回显不对: %q", got)
		}
	})

	t.Run("UUID错在读的时候暴露", func(t *testing.T) {
		up, err := Parse(fmt.Sprintf("vmess://%s@127.0.0.1:%d?security=tls&sni=127.0.0.1", RandomUUID(), tlsPort))
		if err != nil {
			t.Fatal(err)
		}
		c, err := up.Dial(net.ParseIP("127.0.0.1"), 9, 3*time.Second)
		if err != nil {
			t.Logf("Dial 直接失败也可以: %v", err)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Read(make([]byte, 8)); err == nil {
			t.Fatal("UUID 不对却读到了数据")
		}
	})

	t.Run("aid非0要拒绝", func(t *testing.T) {
		js := fmt.Sprintf(`{"v":"2","add":"127.0.0.1","port":"%d","id":"%s","aid":"4","net":"tcp"}`, tlsPort, id)
		_, err := Parse("vmess://" + base64.RawStdEncoding.EncodeToString([]byte(js)))
		if err == nil {
			t.Fatal("alterId != 0 应该被拒绝")
		}
		if !strings.Contains(err.Error(), "alterId") {
			t.Errorf("报错要提 alterId: %v", err)
		}
	})
}

// ───────── shadowsocks 2022（SIP022）与 xray 对测 ─────────

// 为什么用 xray 而不是 gost 测 2022：**gost 不支持 2022**
// （实测 `gost -L "ss://2022-blake3-aes-256-gcm:<psk>@:8388"` → `cipher not supported`）。
// KB 的资源文档里曾写着 gost 支持，是错的 —— 已改。
//
// xray 的 shadowsocks inbound 里 method 写 2022-blake3-*、password 写 **base64 的 PSK**。

// xraySS2022Cfg 2022 对测配置（%METHOD% / %PSK% / %PORT% 会被替换）。
const xraySS2022Cfg = `{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"listen": "127.0.0.1", "port": %PORT%, "protocol": "shadowsocks",
     "settings": {"method": "%METHOD%", "password": "%PSK%", "network": "tcp"}}
  ],
  "outbounds": [{"protocol": "freedom"}]
}`

// testPSK 按密钥长度生成一个 base64 PSK（测试里每次都不一样，避免"写死一个串"）。
func testPSK(t *testing.T, keySize int) string {
	t.Helper()
	buf := make([]byte, keySize)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func TestInteropXraySS2022(t *testing.T) {
	tgt, stopEcho := echoServerNoWait(t)
	defer stopEcho()

	cases := []struct {
		method  string
		keySize int
	}{
		{"2022-blake3-aes-256-gcm", 32},
		{"2022-blake3-aes-128-gcm", 16},
		{"2022-blake3-chacha20-poly1305", 32},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			port := freePort(t)
			psk := testPSK(t, tc.keySize)
			cfg := strings.ReplaceAll(xraySS2022Cfg, "%METHOD%", tc.method)
			cfg = strings.ReplaceAll(cfg, "%PSK%", psk)
			cfg = strings.ReplaceAll(cfg, "%PORT%", fmt.Sprint(port))
			startXray(t, cfg, port)

			up, err := Parse(fmt.Sprintf("ss://%s:%s@127.0.0.1:%d", tc.method, psk, port))
			if err != nil {
				t.Fatal(err)
			}
			echoThrough(t, up, tgt, "hello-ss2022-"+tc.method)

			// 域名交给服务端解析（ATYP=域名）。
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

// 分块与首段容量：一次写 40KB（首段变长头装得下就跟着请求走，装不下就落到数据块），
// 再写 70KB（必须走多块，每块 ≤0xFFFF）。读回来要一模一样。
func TestInteropXraySS2022Chunking(t *testing.T) {
	tgt, stopEcho := echoServerNoWait(t)
	defer stopEcho()

	port := freePort(t)
	psk := testPSK(t, 32)
	cfg := strings.ReplaceAll(xraySS2022Cfg, "%METHOD%", "2022-blake3-aes-256-gcm")
	cfg = strings.ReplaceAll(cfg, "%PSK%", psk)
	cfg = strings.ReplaceAll(cfg, "%PORT%", fmt.Sprint(port))
	startXray(t, cfg, port)

	up, err := Parse(fmt.Sprintf("ss://2022-blake3-aes-256-gcm:%s@127.0.0.1:%d", psk, port))
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(tgt)
	var p uint16
	fmt.Sscanf(portStr, "%d", &p)
	c, err := up.Dial(net.ParseIP(host), p, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := make([]byte, 40000+70000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	go func() { _, _ = c.Write(payload[:40000]) }()
	got := make([]byte, 40000)
	if _, err := readFull(c, got); err != nil {
		t.Fatalf("读首段大包失败: %v", err)
	}
	if !bytes.Equal(got, payload[:40000]) {
		t.Fatal("首段大包回显不一致")
	}
	go func() { _, _ = c.Write(payload[40000:]) }()
	got2 := make([]byte, 70000)
	if _, err := readFull(c, got2); err != nil {
		t.Fatalf("读后续大包失败: %v", err)
	}
	if !bytes.Equal(got2, payload[40000:]) {
		t.Fatal("后续大包回显不一致（多块路径写错了）")
	}
}

// 预热路径：Prepare 只建传输层（**一个字节的请求都不发**），ConnectOn 设目标，之后才发。
func TestInteropXraySS2022Prepare(t *testing.T) {
	tgt, stopEcho := echoServerNoWait(t)
	defer stopEcho()

	port := freePort(t)
	psk := testPSK(t, 32)
	cfg := strings.ReplaceAll(xraySS2022Cfg, "%METHOD%", "2022-blake3-aes-256-gcm")
	cfg = strings.ReplaceAll(cfg, "%PSK%", psk)
	cfg = strings.ReplaceAll(cfg, "%PORT%", fmt.Sprint(port))
	startXray(t, cfg, port)

	up, err := Parse(fmt.Sprintf("ss://2022-blake3-aes-256-gcm:%s@127.0.0.1:%d", psk, port))
	if err != nil {
		t.Fatal(err)
	}
	pre, err := up.Prepare(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer pre.Close()
	// 预热连接在池子里放一会儿（时间戳是**第一次写**时才取的，放久了也不该过期）
	time.Sleep(1200 * time.Millisecond)
	host, portStr, _ := net.SplitHostPort(tgt)
	var p uint16
	fmt.Sscanf(portStr, "%d", &p)
	if err := up.ConnectOn(pre, net.ParseIP(host), p, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	_ = pre.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := pre.Write([]byte("warm")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := readFull(pre, got); err != nil {
		t.Fatalf("预热连接读失败: %v", err)
	}
	if string(got) != "warm" {
		t.Fatalf("预热回显不对: %q", got)
	}
}

// PSK 错：服务端静默断开（协议里没有错误码）—— 所以断言的是"写能过、读会失败"。
// 另外：口令错时服务端仍会发自己的 salt + 响应头，我们解不开 **或者** 解开了但 salt 回显不对，
// 两种情况都必须表现为错误，绝不能读到数据。
func TestInteropXraySS2022WrongPSK(t *testing.T) {
	tgt, stopEcho := echoServerNoWait(t)
	defer stopEcho()

	port := freePort(t)
	psk := testPSK(t, 32)
	cfg := strings.ReplaceAll(xraySS2022Cfg, "%METHOD%", "2022-blake3-aes-256-gcm")
	cfg = strings.ReplaceAll(cfg, "%PSK%", psk)
	cfg = strings.ReplaceAll(cfg, "%PORT%", fmt.Sprint(port))
	startXray(t, cfg, port)

	up, err := Parse(fmt.Sprintf("ss://2022-blake3-aes-256-gcm:%s@127.0.0.1:%d", testPSK(t, 32), port))
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(tgt)
	var p uint16
	fmt.Sscanf(portStr, "%d", &p)
	c, err := up.Dial(net.ParseIP(host), p, 3*time.Second)
	if err != nil {
		t.Fatalf("ss2022 没有握手应答，拨号不该失败: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("hello"))
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("PSK 错却读到了数据 —— 要么服务端没校验，要么我们把响应头校验放过了")
	}
}
