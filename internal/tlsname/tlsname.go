// Package tlsname 从连接最初的几个字节里读出"要去哪个域名"。
//
// 为什么需要它：域名通配（*.his.com）靠"观察到名字 → 把 IP 塞进过滤器"工作，
// 而名字原本来自明文 DNS 应答。可一旦应用用了**加密 DNS**（DoH/DoT）或自带
// 解析器，DNS 层就什么都看不到 —— 名字只剩两个还能看见的地方：
//
//	TLS ClientHello 里的 SNI（握手是明文的）        最常见
//	明文 HTTP 请求里的 Host 头                       老内网系统常见
//
// 两个都要按"不可信字节"对待：越界、半截报文、乱码都不能 panic，也不能死等 ——
// 拿不到就返回 false，由调用方决定再等等还是放弃。
package tlsname

import (
	"bytes"
	"strings"
)

const (
	recordHandshake = 0x16 // TLS record: handshake
	hsClientHello   = 0x01 // handshake type: client hello
	extServerName   = 0x0000
	extECH          = 0xfe0d // encrypted client hello（真名被加密，SNI 只剩个公开名）
)

// Result 一次解析的结果。
type Result struct {
	Name string // 归一化后的名字（小写、无尾点）
	ECH  bool   // 用了 ECH：Name 只是"公开名"，不是真实目标
	Kind string // "tls" / "http"
}

// LooksLikeTLS 这段字节像是 TLS 记录的开头吗（用来决定要不要继续攒）。
func LooksLikeTLS(b []byte) bool {
	return len(b) >= 1 && b[0] == recordHandshake
}

// LooksLikeHTTP 这段字节像是明文 HTTP 请求的开头吗。
func LooksLikeHTTP(b []byte) bool {
	sp := bytes.IndexByte(b, ' ')
	if sp < 0 || sp > 8 {
		return false
	}
	switch string(b[:sp]) {
	case "GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE", "PATCH", "TRACE":
		return true
	}
	return false
}

// Complete TLS 记录是否已经收全（没收全就该继续攒，而不是当成"没有 SNI"）。
func Complete(b []byte) bool {
	if len(b) < 5 || b[0] != recordHandshake {
		return false
	}
	need := 5 + int(b[3])<<8 + int(b[4])
	return len(b) >= need
}

// TLS 从 TLS ClientHello 里取 SNI。
//
// 拿到时返回 (名字, ECH 标记, true)；报文不完整/没有 SNI 返回 false
// （不完整不是错误：调用方攒够了再来一次）。
func TLS(b []byte) (string, bool, bool) {
	if len(b) < 6 || b[0] != recordHandshake {
		return "", false, false
	}
	// 只处理握手记录（0x16）；其它类型的记录（如 CCS）不是我们要的
	if len(b) < 9 {
		return "", false, false
	}
	if b[5] != hsClientHello {
		return "", false, false
	}
	// 握手体长度（3 字节），只信它比我们的缓冲小
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	body := b[9:]
	if hsLen < len(body) {
		body = body[:hsLen]
	}
	if len(body) < 34 {
		return "", false, false
	}
	// 版本(2) + random(32)
	off := 34
	// session id
	if off >= len(body) {
		return "", false, false
	}
	sidLen := int(body[off])
	off += 1 + sidLen
	// cipher suites
	if off+2 > len(body) {
		return "", false, false
	}
	csLen := int(body[off])<<8 | int(body[off+1])
	off += 2 + csLen
	// compression methods
	if off >= len(body) {
		return "", false, false
	}
	cmLen := int(body[off])
	off += 1 + cmLen
	// extensions
	if off+2 > len(body) {
		return "", false, false
	}
	extLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	end := off + extLen
	if end > len(body) {
		// 扩展段没收全：把已收到的部分也解析一遍（SNI 通常在最前面）
		end = len(body)
	}

	var name string
	var ech bool
	for off+4 <= end {
		typ := int(body[off])<<8 | int(body[off+1])
		l := int(body[off+2])<<8 | int(body[off+3])
		data := body[off+4:]
		if l < 0 || l > len(data) {
			break
		}
		data = data[:l]
		switch typ {
		case extServerName:
			if n, ok := parseServerName(data); ok && name == "" {
				name = n
			}
		case extECH:
			// 有 ECH 就是"真名看不见了"，这时 SNI 里只是个公开的中转名
			ech = true
		}
		off += 4 + l
	}
	if name == "" {
		return "", ech, false
	}
	return name, ech, true
}

// parseServerName 解析 server_name 扩展：列表长度(2) + [类型(1)=0 + 长度(2) + 名字]。
func parseServerName(d []byte) (string, bool) {
	if len(d) < 2 {
		return "", false
	}
	listLen := int(d[0])<<8 | int(d[1])
	d = d[2:]
	if listLen < len(d) {
		d = d[:listLen]
	}
	for len(d) >= 3 {
		typ := d[0]
		l := int(d[1])<<8 | int(d[2])
		d = d[3:]
		if l > len(d) {
			return "", false
		}
		if typ == 0 { // host_name
			return normalize(string(d[:l])), true
		}
		d = d[l:]
	}
	return "", false
}

// HTTP 从明文 HTTP 请求头里取 Host（HTTP/1.x 才有；HTTP/2 的 :authority 是压缩的，看不到）。
func HTTP(b []byte) (string, bool) {
	if !LooksLikeHTTP(b) {
		return "", false
	}
	// 只看请求头（到空行为止），且限制长度 —— 别把整个 body 当头部扫
	head := b
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		head = b[:i]
	} else if len(head) > 8192 {
		head = head[:8192]
	}
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		if len(line) < 5 {
			continue
		}
		if !bytes.EqualFold(line[:5], []byte("host:")) {
			continue
		}
		h := strings.TrimSpace(string(line[5:]))
		// 去掉端口（:8443 之类），保留 IPv6 字面量的方括号
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.HasSuffix(h, "]") {
			if _, err := parsePortOK(h[i+1:]); err == nil {
				h = h[:i]
			}
		}
		if h == "" {
			return "", false
		}
		return normalize(h), true
	}
	return "", false
}

func parsePortOK(s string) (int, error) {
	if s == "" {
		return 0, errBad
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errBad
		}
		n = n*10 + int(s[i]-'0')
		if n > 65535 {
			return 0, errBad
		}
	}
	return n, nil
}

var errBad = errStr("bad port")

type errStr string

func (e errStr) Error() string { return string(e) }

// Name 通用入口：先按 TLS 试，再按明文 HTTP 试。
func Name(b []byte) (Result, bool) {
	if name, ech, ok := TLS(b); ok {
		return Result{Name: name, ECH: ech, Kind: "tls"}, true
	}
	if name, ok := HTTP(b); ok {
		return Result{Name: name, Kind: "http"}, true
	}
	return Result{}, false
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	// 域名不该带别的空白/控制字符 —— 脏名字进了名字表会污染匹配
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == 0x7f {
			return ""
		}
	}
	if strings.ContainsAny(s, "/\\") || len(s) > 253 {
		return ""
	}
	return s
}
