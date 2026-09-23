package upstream

import (
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// 回归：?auth=<base64> 里含 '+' 时必须能解析。
// url.Values 会把 '+' 解成空格，导致合法凭据被当成非法 base64（旧版必失败）。
func TestParseAuthParamWithPlus(t *testing.T) {
	cred := "user:pas>" // base64 的第 4 个字符恰好是 '+'
	enc := base64.StdEncoding.EncodeToString([]byte(cred))
	if !strings.Contains(enc, "+") {
		t.Fatalf("测试前提不成立：%q 的 base64 %q 不含 '+'", cred, enc)
	}

	u, err := Parse("socks5://1.2.3.4:1080?auth=" + enc)
	if err != nil {
		t.Fatalf("含 '+' 的 auth 应能解析: %v", err)
	}
	if u.Creds.User != "user" || u.Creds.Pass != "pas>" {
		t.Fatalf("凭据解析错误: user=%q pass=%q", u.Creds.User, u.Creds.Pass)
	}

	// 百分号编码形式（%2B）同样要能解析
	u2, err := Parse("socks5://1.2.3.4:1080?auth=" + strings.ReplaceAll(enc, "+", "%2B"))
	if err != nil {
		t.Fatalf("%%2B 形式应能解析: %v", err)
	}
	if u2.Creds.User != "user" || u2.Creds.Pass != "pas>" {
		t.Fatalf("百分号编码解析错误: user=%q pass=%q", u2.Creds.User, u2.Creds.Pass)
	}
}

// 回归：HTTP 代理返回 407 时，ProbeAuth 必须判 AuthOK=false ——
// 旧版把 ConnectOn 的任何错误都当“出口出不了公网”，口令错了也报“可用”。
func TestProbeAuthHTTPDetectsAuthFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				buf := make([]byte, 1024)
				_, _ = c.Read(buf) // 读掉 CONNECT 请求
				_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()

	u, err := Parse("http://user:wrong@" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := u.ProbeAuth(3 * time.Second)
	if r.AuthOK {
		t.Fatalf("407 应判为认证失败，得到 %+v", r)
	}
	if r.Err == nil {
		t.Fatal("认证失败必须带回原因")
	}
}

// 回归：HTTP 代理正常转发（200）时 AuthOK=true 且 Public=true。
func TestProbeAuthHTTPOK(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				time.Sleep(500 * time.Millisecond)
			}(c)
		}
	}()

	u, err := Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := u.ProbeAuth(3 * time.Second)
	if !r.AuthOK || !r.Public {
		t.Fatalf("正常代理应 AuthOK+Public，得到 %+v", r)
	}
}
