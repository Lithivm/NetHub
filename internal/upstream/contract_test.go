package upstream

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// 上游协议适配器的**契约测试**。
//
// 为什么要有它：protocol.go 那个"加协议 = 加一个文件"的承诺，只有在"新协议会被同一套断言
// 自动考核"时才成立。这些断言是**照着契约写的**，不照着某个实现写：
//
//  1. 正常连：Dial 成功后数据能双向走（不是"连上了但写不出去"）
//  2. 认证失败：要报明确的错，不能静默降级成"连上了却没鉴权"
//  3. 超时：上游不回话时必须在 timeout 量级内返回错误（不能挂死）
//  4. 域名：DialHost 能走通（把域名交给上游，或按协议能力本机解析）
//  5. 预热：SupportsPrepare 为真时 Prepare+ConnectOn 必须等价于 Dial
//  6. 并发：多路并发 Dial 都成功（实现里不能有共享可变状态）
//
// 表里只有**基础协议名**（TLS 是传输层开关，不是协议名）；TLS 与 mTLS 由
// TestMutualTLSSendsClientCert 与既有的 TestTLSSessionResume 覆盖。
//
// 往协议表里加一行，它就会被下面全部断言考核一遍 —— 这就是这个文件存在的意义。

// echoProxy 起一个"最小上游"：按 kind 处理认证与握手，CONNECT 一律成功，
// 之后把收到的字节原样回写（这样"双向能走"是可断言的）。
func echoProxy(t *testing.T, kind, user, pass string) (addr string, stop func()) {
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
				switch kind {
				case "socks5":
					if !fakeSocks5Handshake(c, user, pass) {
						return
					}
				case "socks4", "socks4a":
					if !fakeSocks4Handshake(c, user) {
						return
					}
				case "http":
					if !fakeHTTPHandshake(c, user, pass) {
						return
					}
				}
				_, _ = io.Copy(c, c) // CONNECT 之后：回声，模拟隧道
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func fakeSocks5Handshake(c net.Conn, user, pass string) bool {
	buf := make([]byte, 512)
	if _, err := c.Read(buf); err != nil {
		return false
	}
	if _, err := c.Write([]byte{0x05, 0x02}); err != nil { // 只提供 用户名/口令
		return false
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return false
	}
	uname := make([]byte, head[1])
	if _, err := io.ReadFull(c, uname); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return false
	}
	passwd := make([]byte, plen[0])
	if _, err := io.ReadFull(c, passwd); err != nil {
		return false
	}
	if string(uname) != user || string(passwd) != pass {
		_, _ = c.Write([]byte{0x01, 0x01})
		return false
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
		return false
	}
	// CONNECT：读 4 + 地址 + 端口（ATYP=1 时是 4+2，域名时带长度）—— 一律回成功
	if _, err := c.Read(buf); err != nil {
		return false
	}
	_, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90})
	return err == nil
}

func fakeSocks4Handshake(c net.Conn, user string) bool {
	head := make([]byte, 8) // VN CD DSTPORT(2) DSTIP(4)
	if _, err := io.ReadFull(c, head); err != nil {
		return false
	}
	if head[0] != 0x04 {
		return false
	}
	uid, err := readUntilNUL(c)
	if err != nil {
		return false
	}
	if user != "" && uid != user {
		_, _ = c.Write([]byte{0x00, 0x5b}) // 拒绝
		return false
	}
	// SOCKS4a：DSTIP 前三个字节为 0 且末字节非 0 时，后面还跟一个域名
	if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
		if _, err := readUntilNUL(c); err != nil {
			return false
		}
	}
	_, err = c.Write([]byte{0x00, 0x5a, 0, 0, 0, 0, 0, 0}) // 成功
	return err == nil
}

func readUntilNUL(c net.Conn) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := c.Read(one)
		if n > 0 {
			if one[0] == 0 {
				return string(b), nil
			}
			b = append(b, one[0])
		}
		if err != nil {
			return "", err
		}
	}
}

func fakeHTTPHandshake(c net.Conn, user, pass string) bool {
	br := bufio.NewReader(c)
	var auth string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return false
		}
		if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
			auth = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	if user != "" && auth != want {
		_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
		return false
	}
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return false
	}
	// 握手与隧道之间可能已经夹带了客户端先发的字节（回归测试覆盖过）——
	// 回声要先把它们吐回去，否则"先发数据"的用法会丢首包。
	if n := br.Buffered(); n > 0 {
		peek, _ := br.Peek(n)
		if _, err := c.Write(peek); err != nil {
			return false
		}
	}
	return true
}

// blackhole 接受连接但**什么都不回**（用来试超时：上游没死，就是不说话）。
func blackhole(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起黑洞上游失败: %v", err)
	}
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	}
}

// 契约表：**加协议就往这里加一行**（或者更准确地说：register 之后这里必须能覆盖到它，
// 由 TestRegistryCoversClassifiedSchemes 把关）。
//
// badCred 是"理应被拒"的凭据写法。注意 SOCKS4 系列 **只有 userid、根本没有口令**，
// 所以它的"认证失败"只能靠换 userid 来构造 —— 拿错口令去试是试不出东西的（测试会假过）。
var contractProtocols = []struct {
	name    string
	badCred string
}{
	{"socks5", "u:WRONG"},
	{"socks4", "nobody"},
	{"socks4a", "nobody"},
	{"http", "u:WRONG"},
}

func TestProtocolContract(t *testing.T) {
	for _, pc := range contractProtocols {
		proto, badCred := pc.name, pc.badCred
		t.Run(proto, func(t *testing.T) {
			addr, stop := echoProxy(t, proto, "u", "p")
			defer stop()
			good := fmt.Sprintf("%s://u:p@%s", proto, addr)

			up, err := Parse(good)
			if err != nil {
				t.Fatalf("解析自己的协议地址失败: %v", err)
			}

			// ── 1. 正常连 + 双向数据 ──
			conn, err := up.Dial(net.ParseIP("10.1.2.3"), 443, 3*time.Second)
			if err != nil {
				t.Fatalf("契约①：Dial 失败: %v", err)
			}
			assertEcho(t, conn, "契约①：连上了但数据走不通")
			conn.Close()

			// ── 4. 域名（socks4 会本机解析；localhost 一定解析得出来）──
			conn, err = up.DialHost("localhost", 80, 3*time.Second)
			if err != nil {
				t.Fatalf("契约④：DialHost 失败: %v", err)
			}
			assertEcho(t, conn, "契约④：DialHost 连上了但数据走不通")
			conn.Close()

			// ── 5. 预热与直拨必须等价 ──
			p, err := up.proxy()
			if err != nil {
				t.Fatal(err)
			}
			if p.SupportsPrepare() {
				pc, err := up.Prepare(3 * time.Second)
				if err != nil {
					t.Fatalf("契约⑤：Prepare 失败: %v", err)
				}
				if err := up.ConnectOn(pc, net.ParseIP("10.1.2.3"), 443, 3*time.Second); err != nil {
					pc.Close()
					t.Fatalf("契约⑤：ConnectOn 失败: %v", err)
				}
				assertEcho(t, pc, "契约⑤：预热路径连上了但数据走不通")
				pc.Close()
			}

			// ── 2. 认证失败必须报错（不能"连上了却没鉴权"）──
			bad, err := Parse(fmt.Sprintf("%s://%s@%s", proto, badCred, addr))
			if err != nil {
				t.Fatal(err)
			}
			if c2, err := bad.Dial(net.ParseIP("10.1.2.3"), 443, 3*time.Second); err == nil {
				c2.Close()
				t.Errorf("契约②：口令错了却连上了 —— 认证失败必须是错误")
			}

			// ── 6. 并发（实现里不能有共享可变状态）──
			var wg sync.WaitGroup
			errs := make(chan error, 4)
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, err := up.Dial(net.ParseIP("10.1.2.3"), 443, 3*time.Second)
					if err != nil {
						errs <- err
						return
					}
					defer c.Close()
					if err := echoOnce(c, "x"); err != nil {
						errs <- err
					}
				}()
			}
			wg.Wait()
			close(errs)
			for e := range errs {
				t.Errorf("契约⑥：并发 Dial 出错: %v", e)
			}
		})
	}
}

// ── 3. 超时：上游不回话，必须在 timeout 量级内返回错误（不能挂死）──
func TestProtocolContractTimeout(t *testing.T) {
	addr, stop := blackhole(t)
	defer stop()
	for _, pc := range contractProtocols {
		up, err := Parse(fmt.Sprintf("%s://u:p@%s", pc.name, addr))
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		c, err := up.Dial(net.ParseIP("10.1.2.3"), 443, 400*time.Millisecond)
		took := time.Since(start)
		if err == nil {
			c.Close()
			t.Errorf("契约③（%s）：黑洞上游居然连上了", pc.name)
			continue
		}
		if took > 3*time.Second {
			t.Errorf("契约③（%s）：超时 %v —— 远超过传入的 400ms，说明没走 deadline", pc.name, took)
		}
	}
}

func assertEcho(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := echoOnce(c, "ping"); err != nil {
		t.Fatal(msg + "：" + err.Error())
	}
}

func echoOnce(c net.Conn, want string) error {
	if _, err := c.Write([]byte(want)); err != nil {
		return fmt.Errorf("写失败: %w", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("读失败: %w", err)
	}
	if string(got) != want {
		return fmt.Errorf("回显不对: 期望 %q 得到 %q", want, got)
	}
	return nil
}

// 解析器认得的协议（classify）与注册表必须同步 ——
// 这条是"加协议时忘了 register"或"注册了但解析器不认"的唯一防线：
// 以前那种"解析通过了，运行到拨号才报未实现"的坑，就靠它挡住。
func TestRegistryCoversClassifiedSchemes(t *testing.T) {
	// classify 认得的原始写法（见 scheme.go）；别名归一化后的 base 必须在注册表里。
	accepted := []string{"socks", "socks5", "socks5h", "socks4", "socks4a", "http", "https",
		"socks5+tls", "socks4+tls", "socks5+mtls"}
	for _, s := range accepted {
		base, _, known := classify(s)
		if !known {
			t.Errorf("classify 不认 %q，但它是我们对外声称支持的写法", s)
			continue
		}
		if _, ok := registry[base]; !ok {
			t.Errorf("写法 %q 归一化成 %q，但注册表里没有这个协议（忘了 register？）", s, base)
		}
	}
	// 反向：注册表里有的，classify 也必须认得（否则用户根本写不出这个协议）
	for name := range registry {
		if _, ok := registry[name]; !ok {
			continue
		}
		if _, _, known := classify(name); !known {
			t.Errorf("注册了协议 %q，但 classify 不认 —— 用户没法在配置里写出来", name)
		}
	}
	// SupportedSchemes 是给用户看的清单，不能漏掉已注册的协议
	got := SupportedSchemes()
	for name := range registry {
		if !strings.Contains(got, name) {
			t.Errorf("SupportedSchemes()=%q 里没有已注册的 %q（提示与实际能力不一致）", got, name)
		}
	}
}
