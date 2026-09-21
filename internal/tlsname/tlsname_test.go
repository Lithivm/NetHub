package tlsname

import (
	"bytes"
	"strings"
	"testing"
)

// edit 造一个 ClientHello（带指定的扩展）。
func clientHello(exts []byte) []byte {
	body := []byte{0x03, 0x03}                  // client version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0)                      // session id 长度 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression methods
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{hsClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{recordHandshake, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func sniExt(names ...string) []byte {
	var list []byte
	for _, n := range names {
		list = append(list, 0, byte(len(n)>>8), byte(len(n)))
		list = append(list, n...)
	}
	inner := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	return append([]byte{0x00, 0x00, byte(len(inner) >> 8), byte(len(inner))}, inner...)
}

func echExt() []byte {
	inner := []byte{0x01, 0x02, 0x03, 0x04}
	return append([]byte{0xfe, 0x0d, 0x00, 0x04}, inner...)
}

func TestTLSSNI(t *testing.T) {
	// 顺手加一个我们不关心的扩展在前面，确认偏移没错
	other := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	hello := clientHello(append(other, sniExt("MAIN.HIS.com")...))

	name, ech, ok := TLS(hello)
	if !ok || name != "main.his.com" || ech {
		t.Fatalf("SNI = %q ech=%v ok=%v（期望 main.his.com, false, true）", name, ech, ok)
	}
	if !LooksLikeTLS(hello) || !Complete(hello) {
		t.Error("应该被认成完整的 TLS 记录")
	}

	// 多个名字时取第一个（真实世界里也只有一个）
	hello2 := clientHello(sniExt("a.his.com", "b.his.com"))
	if n, _, ok := TLS(hello2); !ok || n != "a.his.com" {
		t.Errorf("多个名字取第一个，得到 %q ok=%v", n, ok)
	}
}

// ECH：真名被加密，SNI 里只是"公开名" —— 必须标出来，否则我们会以为学到了真名字。
func TestTLSSNIWithECH(t *testing.T) {
	hello := clientHello(append(sniExt("public.example"), echExt()...))
	name, ech, ok := TLS(hello)
	if !ok || !ech || name != "public.example" {
		t.Fatalf("SNI = %q ech=%v ok=%v（期望 public.example, true, true）", name, ech, ok)
	}
}

// 半截报文：不能 panic，也不能"自作聪明"当成没有 SNI。
func TestTLSIncomplete(t *testing.T) {
	hello := clientHello(sniExt("main.his.com"))
	for _, cut := range []int{0, 1, 5, 9, 20, 40, len(hello) - 1} {
		if cut < 0 || cut > len(hello) {
			continue
		}
		b := hello[:cut]
		if _, _, ok := TLS(b); ok && cut < len(hello) {
			t.Errorf("截断到 %d 字节不该解析成功", cut)
		}
	}
	if Complete(hello[:len(hello)-1]) {
		t.Error("少一个字节不该算完整")
	}
}

// 没有 SNI 扩展 / 不是 ClientHello：返回 false，不误报。
func TestTLSNoSNI(t *testing.T) {
	if _, _, ok := TLS(clientHello(nil)); ok {
		t.Error("没有 SNI 扩展不该返回名字")
	}
	if _, _, ok := TLS(clientHello([]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00})); ok {
		t.Error("只有无关扩展不该返回名字")
	}
	// ServerHello（握手类型 2）不是我们要的
	sh := clientHello(sniExt("x.com"))
	sh[5] = 0x02
	if _, _, ok := TLS(sh); ok {
		t.Error("ServerHello 不该被当成 ClientHello")
	}
	// 明显不是 TLS
	if _, _, ok := TLS([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Error("HTTP 报文不该被当成 TLS")
	}
}

func TestHTTPHost(t *testing.T) {
	req := []byte("GET /index.do HTTP/1.1\r\nUser-Agent: x\r\nHost: MAIN.his.com:8443\r\nAccept: */*\r\n\r\n")
	name, ok := HTTP(req)
	if !ok || name != "main.his.com" {
		t.Fatalf("Host = %q ok=%v（期望 main.his.com，端口要去掉）", name, ok)
	}
	if !LooksLikeHTTP(req) {
		t.Error("应该被认成 HTTP 请求")
	}
	// 大小写不敏感 + 只取第一行 Host
	req2 := []byte("POST /a HTTP/1.0\r\nhOsT: opm.his.com\r\n\r\n")
	if n, _ := HTTP(req2); n != "opm.his.com" {
		t.Errorf("Host 大小写应不敏感，得到 %q", n)
	}
	// 没有 Host 头
	if _, ok := HTTP([]byte("GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n")); ok {
		t.Error("没有 Host 头不该返回名字")
	}
	// HTTP/2 前言：看不到 :authority（压缩的），不能瞎猜
	if _, ok := HTTP([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); ok {
		t.Error("HTTP/2 前言不该返回名字")
	}
}

func TestNameDispatch(t *testing.T) {
	r, ok := Name(clientHello(sniExt("a.his.com")))
	if !ok || r.Kind != "tls" || r.Name != "a.his.com" {
		t.Fatalf("TLS 分派错: %+v ok=%v", r, ok)
	}
	r, ok = Name([]byte("GET / HTTP/1.1\r\nHost: b.his.com\r\n\r\n"))
	if !ok || r.Kind != "http" || r.Name != "b.his.com" {
		t.Fatalf("HTTP 分派错: %+v ok=%v", r, ok)
	}
	if _, ok := Name([]byte{0x99, 0x88, 0x77}); ok {
		t.Error("乱码不该解析出名字")
	}
}

// 脏名字（带空白/控制字符/超长）不能进名字表 —— 否则会污染匹配。
func TestNormalizeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", " ", "a b.com", "a\tb.com", "x/../y", "a\\b.com"} {
		if got := normalize(bad); got != "" {
			t.Errorf("normalize(%q) = %q，应该被拒", bad, got)
		}
	}
	if got := normalize(" MAIN.HIS.com. "); got != "main.his.com" {
		t.Errorf("正常名字要归一化，得到 %q", got)
	}
	long := strings.Repeat("a", 300) + ".com"
	if normalize(long) != "" {
		t.Error("超长名字应该被拒")
	}
}

// 乱码里随便切一刀都不能 panic（网络上什么字节都可能来）。
func TestNoPanicOnGarbage(t *testing.T) {
	seed := clientHello(sniExt("main.his.com"))
	var buf bytes.Buffer
	for i := 0; i < len(seed); i++ {
		for _, flip := range []byte{0x00, 0xff, 0x16, 0x01, 0xc0} {
			m := append([]byte{}, seed[:i+1]...)
			m[i] = flip
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("第 %d 字节改成 %#x 后 panic: %v", i, flip, r)
					}
				}()
				_, _, _ = TLS(m)
			}()
		}
	}
	// 随机长度 + 随机内容
	for n := 0; n < 64; n++ {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i * 7)
		}
		buf.Write(b)
		_, _, _ = TLS(b)
		_, _ = HTTP(b)
	}
}
