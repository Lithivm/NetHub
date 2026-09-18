package engine

import (
	"net"
	"testing"
)

// 造一个最小的 IPv4 + TCP SYN 包（20+20 字节，无选项）。
func mkSyn(t *testing.T, src, dst string, sport, dport uint16, seq uint32) []byte {
	t.Helper()
	pkt := make([]byte, 40)
	pkt[0] = 0x45     // IPv4, IHL=5
	pkt[offProto] = 6 // TCP
	copy(pkt[offSrcIP:offSrcIP+4], net.ParseIP(src).To4())
	copy(pkt[offDstIP:offDstIP+4], net.ParseIP(dst).To4())
	putBE16(pkt, 2, 40) // total length
	tcp := 20
	putBE16(pkt, tcp+offSrcPort, sport)
	putBE16(pkt, tcp+offDstPort, dport)
	putBE32(pkt, tcp+tcpOffSeq, seq)
	pkt[tcp+tcpOffDataOff] = 5 << 4 // data offset = 5
	pkt[tcp+offFlags] = 0x02        // SYN
	return pkt
}

// buildReset 产出的是"目标 → 应用"的 RST/ACK：IP/端口互换、seq=0、ack=对方 seq+1、
// 头长收缩到 20 字节、总长同步改小。
func TestBuildReset(t *testing.T) {
	pkt := mkSyn(t, "192.168.199.42", "10.10.10.237", 55555, 5432, 0x11223344)
	rst, ok := buildReset(pkt, 20,
		net.ParseIP("192.168.199.42"), net.ParseIP("10.10.10.237"), 55555, 5432)
	if !ok {
		t.Fatal("buildReset 应该成功")
	}

	if len(rst) != 40 {
		t.Errorf("RST 长度应为 40，实际 %d", len(rst))
	}
	if got := be16(rst, 2); got != 40 {
		t.Errorf("IP 总长应为 40，实际 %d", got)
	}
	if got := net.IPv4(rst[offSrcIP], rst[offSrcIP+1], rst[offSrcIP+2], rst[offSrcIP+3]).String(); got != "10.10.10.237" {
		t.Errorf("源 IP 应为目标，实际 %s", got)
	}
	if got := net.IPv4(rst[offDstIP], rst[offDstIP+1], rst[offDstIP+2], rst[offDstIP+3]).String(); got != "192.168.199.42" {
		t.Errorf("目标 IP 应为应用，实际 %s", got)
	}
	if got := be16(rst, 20+offSrcPort); got != 5432 {
		t.Errorf("源端口应为目标的 5432，实际 %d", got)
	}
	if got := be16(rst, 20+offDstPort); got != 55555 {
		t.Errorf("目标端口应为应用的 55555，实际 %d", got)
	}
	if got := be32(rst, 20+tcpOffSeq); got != 0 {
		t.Errorf("RST 的 seq 应为 0，实际 %d", got)
	}
	if got := be32(rst, 20+tcpOffAck); got != 0x11223344+1 {
		t.Errorf("ack 应为对方 seq+1，实际 %#x", got)
	}
	if got := rst[20+offFlags]; got != 0x14 {
		t.Errorf("标志位应为 RST|ACK(0x14)，实际 %#x", got)
	}
	if got := rst[20+tcpOffDataOff] >> 4; got != 5 {
		t.Errorf("首部长度应为 5 个字，实际 %d", got)
	}
}

// 畸形/太短的包不该 panic，也不该产出垃圾包（返回 false 让调用方只丢弃）。
func TestBuildResetBadInput(t *testing.T) {
	if _, ok := buildReset(make([]byte, 8), 0, net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), 1, 2); ok {
		t.Error("太短的包应返回 false")
	}
	// 带选项的 SYN（TCP 头 24 字节）也要能处理：总长按最小头收缩
	pkt := mkSyn(t, "192.168.199.42", "10.10.10.237", 1234, 80, 7)
	pkt = append(pkt, 0, 0, 0, 0) // 假装有 4 字节选项
	pkt[20+tcpOffDataOff] = 6 << 4
	putBE16(pkt, 2, 44)
	rst, ok := buildReset(pkt, 20, net.ParseIP("192.168.199.42"), net.ParseIP("10.10.10.237"), 1234, 80)
	if !ok {
		t.Fatal("带选项的 SYN 也应能构造 RST")
	}
	if len(rst) != 40 || be16(rst, 2) != 40 {
		t.Errorf("RST 应收缩到 40 字节，实际 %d / 总长 %d", len(rst), be16(rst, 2))
	}
}
