package dnssniff

import (
	"encoding/binary"
	"testing"
	"time"
)

// ---- 造报文的测试工具（不引入第三方 DNS 库，报文自己拼） ----

func enc(n string) []byte {
	var b []byte
	start := 0
	for i := 0; i <= len(n); i++ {
		if i == len(n) || n[i] == '.' {
			if i > start {
				b = append(b, byte(i-start))
				b = append(b, n[start:i]...)
			}
			start = i + 1
		}
	}
	return append(b, 0)
}

type rr struct {
	name  string
	ptrTo int // >0 时名字用压缩指针指到这个偏移
	typ   uint16
	ttl   uint32
	rdata []byte
}

func msg(t *testing.T, id uint16, flags uint16, qname string, rrs ...rr) []byte {
	t.Helper()
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1) // qd
	binary.BigEndian.PutUint16(b[6:], uint16(len(rrs)))
	b = append(b, enc(qname)...)
	b = append(b, 0, 1, 0, 1) // QTYPE=A QCLASS=IN
	for _, r := range rrs {
		if r.ptrTo > 0 {
			b = append(b, 0xc0, byte(r.ptrTo))
		} else {
			b = append(b, enc(r.name)...)
		}
		hdr := make([]byte, 10)
		binary.BigEndian.PutUint16(hdr[0:], r.typ)
		binary.BigEndian.PutUint16(hdr[2:], 1) // IN
		binary.BigEndian.PutUint32(hdr[4:], r.ttl)
		binary.BigEndian.PutUint16(hdr[8:], uint16(len(r.rdata)))
		b = append(b, hdr...)
		b = append(b, r.rdata...)
	}
	return b
}

func a(ip ...byte) []byte { return ip }

const (
	qrResp  = 0x8180 // 应答 + RD + RA + RCODE=0
	qrNXDOM = 0x8183 // 应答 + NXDOMAIN
)

// ---- 用例 ----

func TestParseSimpleA(t *testing.T) {
	m := msg(t, 0x1234, qrResp, "main.his.com", rr{name: "main.his.com", typ: 1, ttl: 60, rdata: a(172, 30, 4, 217)})
	r, err := Parse(m)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !r.IsResponse || r.RCode != 0 {
		t.Errorf("IsResponse=%v RCode=%d", r.IsResponse, r.RCode)
	}
	if r.Question != "main.his.com" {
		t.Errorf("问题名 = %q", r.Question)
	}
	if len(r.Pairs) != 1 || r.Pairs[0].IP != "172.30.4.217" || r.Pairs[0].Name != "main.his.com" {
		t.Fatalf("Pairs = %+v", r.Pairs)
	}
	if r.Pairs[0].TTL != 60*time.Second {
		t.Errorf("TTL = %v，期望 60s", r.Pairs[0].TTL)
	}
}

// 答案是压缩指针（真实应答基本都是这样）也要能解出来。
func TestParseCompressedAnswerName(t *testing.T) {
	m := msg(t, 1, qrResp, "a.example.com", rr{ptrTo: 12, typ: 1, ttl: 30, rdata: a(10, 1, 2, 3)})
	r, err := Parse(m)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(r.Pairs) != 1 || r.Pairs[0].Name != "a.example.com" || r.Pairs[0].IP != "10.1.2.3" {
		t.Fatalf("Pairs = %+v", r.Pairs)
	}
}

// CNAME 链：问题名和链上的别名都要指向同一个 IP（匹配是按 IP 反查名字做的）。
func TestParseCNAMEChain(t *testing.T) {
	rrs := []rr{
		{name: "www.x.com", typ: 5, ttl: 120, rdata: enc("real.x.cdn.net")},
		{name: "real.x.cdn.net", typ: 1, ttl: 45, rdata: a(203, 0, 113, 7)},
	}
	r, err := Parse(msg(t, 2, qrResp, "www.x.com", rrs...))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(r.Pairs) != 2 {
		t.Fatalf("期望 2 条（问题名 + 别名），得到 %+v", r.Pairs)
	}
	got := map[string]string{}
	for _, p := range r.Pairs {
		got[p.Name] = p.IP
	}
	if got["www.x.com"] != "203.0.113.7" || got["real.x.cdn.net"] != "203.0.113.7" {
		t.Fatalf("CNAME 链没串起来: %+v", r.Pairs)
	}
}

// 大小写与尾点都要归一化：规则里的名字是小写的，不能因为应答里大写就匹配不上。
func TestParseNormalizesCase(t *testing.T) {
	r, err := Parse(msg(t, 3, qrResp, "Main.HIS.com", rr{name: "MAIN.his.COM", typ: 1, ttl: 10, rdata: a(1, 1, 1, 1)}))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if r.Question != "main.his.com" {
		t.Errorf("问题名 = %q", r.Question)
	}
	if len(r.Pairs) != 1 || r.Pairs[0].Name != "main.his.com" {
		t.Errorf("Pairs = %+v", r.Pairs)
	}
}

func TestParseNXDOMAIN(t *testing.T) {
	r, err := Parse(msg(t, 4, qrNXDOM, "nope.his.com"))
	if err != nil {
		t.Fatalf("NXDOMAIN 不该算解析失败: %v", err)
	}
	if r.RCode != 3 || len(r.Pairs) != 0 {
		t.Errorf("RCode=%d Pairs=%+v", r.RCode, r.Pairs)
	}
}

// 查询报文（出方向）也要能取到名字，只是没有 Pairs。
func TestParseQuery(t *testing.T) {
	m := msg(t, 5, 0x0100, "opm.his.com")
	r, err := Parse(m)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if r.IsResponse || len(r.Pairs) != 0 {
		t.Errorf("IsResponse=%v Pairs=%+v", r.IsResponse, r.Pairs)
	}
	if r.Question != "opm.his.com" {
		t.Errorf("问题名 = %q", r.Question)
	}
	if n, ok := Question(m); !ok || n != "opm.his.com" {
		t.Errorf("Question() = %q, %v", n, ok)
	}
}

func TestParseAAAAIgnored(t *testing.T) {
	aaaa := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	r, err := Parse(msg(t, 6, qrResp, "v6.x.com", rr{name: "v6.x.com", typ: 28, ttl: 60, rdata: aaaa}))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(r.Pairs) != 0 {
		t.Errorf("AAAA 应该被忽略（引擎是 IPv4 的），得到 %+v", r.Pairs)
	}
}

// 畸形报文：一律返回 error 或空结果，绝不 panic、绝不卡住。
func TestParseMalformed(t *testing.T) {
	good := msg(t, 7, qrResp, "x.com", rr{name: "x.com", typ: 1, ttl: 60, rdata: a(1, 2, 3, 4)})
	cases := map[string][]byte{
		"空":       {},
		"太短":      {0, 1, 2},
		"只有头":     good[:12],
		"问题被截断":   good[:15],
		"资源记录被截断": good[:len(good)-2],
	}
	for name, m := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic 了: %v", name, r)
				}
			}()
			if _, err := Parse(m); err != nil {
				t.Logf("%s: 正确报错 %v", name, err)
			}
		}()
	}

	// 指针成环：名字指向自己的位置
	loop := make([]byte, 12)
	binary.BigEndian.PutUint16(loop[4:], 1)
	loop = append(loop, 0xc0, 12, 0, 1, 0, 1)
	if _, err := Parse(loop); err == nil {
		t.Errorf("指针成环应该报错")
	}

	// 指针指向报文外
	out := append([]byte{}, good...)
	out[12], out[13] = 0xc0, 0xff
	if _, err := Parse(out); err == nil {
		t.Errorf("指针越界应该报错")
	}
}

// 名字太长（单标签长度字段骗人）也不能崩。
func TestParseBadLabelLength(t *testing.T) {
	m := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
	m = append(m, 0x40) // 标签长度 64，但后面没有内容
	if _, err := Parse(m); err == nil {
		t.Errorf("越界标签应该报错")
	}
}
