package engine

import (
	"net"

	"github.com/imgk/divert-go"
)

// 构造 RST 用到的偏移（TCP 头内相对偏移）。
const (
	tcpOffSeq     = 4
	tcpOffAck     = 8
	tcpOffDataOff = 12 // 高 4 位是首部长度（32 位字）
	tcpOffWindow  = 14
	tcpOffUrgent  = 18
	tcpHdrMin     = 20
	ipOffTotalLen = 2
)

// buildReset 把"应用 → 目标"的包原地改成"目标 → 应用"的 RST/ACK，返回要注入的字节。
//
// 序号按 RFC 793 处理拒绝连接的场景：seq=0、ack=对方 seq+1（若对方带 SYN），
// TCP 首部收缩到最小 20 字节（RST 不该带选项），IP 总长同步改小。
// 第二个返回值为 false 表示包太短/畸形，调用方应放弃注入（只丢弃）。
func buildReset(pkt []byte, t int, src, dst net.IP, sport, dport uint16) ([]byte, bool) {
	if len(pkt) < t+tcpHdrMin || len(pkt) < offDstIP+4 {
		return nil, false
	}
	s4, d4 := src.To4(), dst.To4()
	if s4 == nil || d4 == nil {
		return nil, false
	}
	seq := be32(pkt, t+tcpOffSeq)

	// IP 头：源/目标互换，总长按 RST 的实际长度改
	copy(pkt[offSrcIP:offSrcIP+4], d4) // 源 = 目标
	copy(pkt[offDstIP:offDstIP+4], s4) // 目标 = 应用
	total := t + tcpHdrMin
	putBE16(pkt, ipOffTotalLen, uint16(total))

	// TCP 头：端口互换、序号、标志位、去掉选项
	putBE16(pkt, t+offSrcPort, dport)
	putBE16(pkt, t+offDstPort, sport)
	putBE32(pkt, t+tcpOffSeq, 0)
	putBE32(pkt, t+tcpOffAck, seq+1)
	pkt[t+tcpOffDataOff] = byte(5 << 4) // 首部长度 = 5 个字 = 20 字节（无选项）
	pkt[t+offFlags] = 0x14              // RST | ACK
	putBE16(pkt, t+tcpOffWindow, 0)
	putBE16(pkt, t+tcpOffUrgent, 0)
	return pkt[:total], true
}

// sendReset 给被阻断的连接回一个 RST，让应用立刻看到"连接被拒"，而不是干等到超时。
//
// 尽力而为：注入失败也不影响阻断本身（包已经丢了，只是应用会表现为超时）。
func (e *Engine) sendReset(h *divert.Handle, pkt []byte, addr *divert.Address, t int,
	src, dst net.IP, sport, dport uint16) {

	rst, ok := buildReset(pkt, t, src, dst, sport, dport)
	if !ok {
		return
	}
	divert.CalcChecksums(rst, addr, divert.ChecksumDefault)
	if _, err := h.Send(rst, addr); err != nil {
		e.bus.Warn("阻断 RST 注入失败: %v", err)
	}
}

func be32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
}

func putBE32(b []byte, off int, v uint32) {
	if off+4 > len(b) {
		return
	}
	b[off] = byte(v >> 24)
	b[off+1] = byte(v >> 16)
	b[off+2] = byte(v >> 8)
	b[off+3] = byte(v)
}
