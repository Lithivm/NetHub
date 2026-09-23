package upstream

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// 回归：HTTP 代理把「CONNECT 的 200 应答」与「目标先发来的数据」放在同一段里时，
// 首包不能被丢掉（以前用 bufio.Reader 读应答，会把多读的字节随缓冲一起丢弃）。
func TestHTTPConnectKeepsTunnelFirstBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const payload = "HELLO-TUNNEL-FIRST-BYTES"
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// 逐字节读请求头（避免测试自身也犯“多读”的错）
		head := make([]byte, 0, 128)
		one := make([]byte, 1)
		for {
			n, err := c.Read(one)
			if n > 0 {
				head = append(head, one[0])
				if bytes.HasSuffix(head, []byte("\r\n\r\n")) {
					break
				}
			}
			if err != nil {
				return
			}
		}
		// 一次 Write 里同时给出响应头与隧道首包
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n"+
			"Proxy-Agent: fake\r\n\r\n"+payload)
		time.Sleep(2 * time.Second) // 保持连接
	}()

	u, err := Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialHTTPConnect(u, net.ParseIP("10.0.0.5"), 443, 3*time.Second)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读隧道首包失败（首包被吃掉了？）: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("首包 = %q，期望 %q", got, payload)
	}
}

// 非 2xx 要能读出状态码；407 要给出认证提示。
func TestHTTPConnectRejectsNon2xx(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		_, _ = c.Read(buf) // 请求
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	}()

	u, err := Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = dialHTTPConnect(u, net.ParseIP("10.0.0.5"), 443, 3*time.Second)
	if err == nil {
		t.Fatal("407 应当返回错误")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("407")) {
		t.Fatalf("错误里应包含 407，得到: %v", err)
	}
}
