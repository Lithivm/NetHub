package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// 这个文件只有一件事：**问上游能不能帮我们中继 UDP**（SOCKS5 UDP ASSOCIATE）。
//
// 为什么单独问一次：项目不做 UDP 中继（QUIC 只拦不转），所以这里产出的不是转发能力，
// 而是**事实**——“这条上游现在到底有没有 UDP 能力”。有了它，将来上游一放行就能复测，
// 不用靠猜（见 ProbeUDP）。

// UDPAssociate 在**已握手（含认证）**的 SOCKS5 连接上发 UDP ASSOCIATE（CMD=3）。
//
// 返回代理给的转发地址与 SOCKS 应答码：code==0 表示代理接受（bnd 是它让我们把
// UDP 数据报发过去的地方）；code!=0 表示它不支持/不允许（7 = command not supported）。
//
// ⚠️ **应答码 0 只说明控制面通了**，数据面能不能真中继必须发个包实测（见 UDPRoundTrip）。
// 实测踩过：四条 gost 上游全部返回 0（每会话还给一个独立端口，说明真绑定了 socket），
// 但真实往返 4/4 收不到回包 —— 只看应答码会得出“上游支持 UDP”这个错结论。
func UDPAssociate(conn net.Conn, timeout time.Duration) (string, byte, error) {
	// VER CMD=3 RSV ATYP=IPv4 0.0.0.0:0 —— 地址/端口留空 = “你随便挑一个”
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return "", 0, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", 0, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", 0, err
	}
	if hdr[0] != 0x05 {
		return "", hdr[1], fmt.Errorf("不是 SOCKS5 应答（ver=%d）", hdr[0])
	}
	host, err := readAddr(conn, hdr[3])
	if err != nil {
		return "", hdr[1], err
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(conn, p); err != nil {
		return "", hdr[1], err
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(p))), hdr[1], nil
}

// readAddr 按 ATYP 读一个 SOCKS5 地址（IPv4 / IPv6 / 域名）。
func readAddr(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 0x01, 0x04:
		n := 4
		if atyp == 0x04 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", fmt.Errorf("未知 ATYP=%d", atyp)
}

// UDPRoundTrip 把 payload 按 SOCKS5 UDP 请求格式发给代理的转发地址，等一个回包。
//
// 返回回包字节数（含 SOCKS5 UDP 头）；err != nil 时说明**数据面没通**。
// 这是唯一能证明“上游真能中继 UDP”的判据：发一个真包、等一个真回包。
func UDPRoundTrip(bnd string, dstIP net.IP, dstPort uint16, payload []byte, timeout time.Duration) (int, error) {
	c, err := net.Dial("udp", bnd)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	v4 := dstIP.To4()
	if v4 == nil {
		return 0, fmt.Errorf("目前只测 IPv4 目标（%s）", dstIP)
	}
	pkt := make([]byte, 0, 10+len(payload))
	pkt = append(pkt, 0x00, 0x00, 0x00) // RSV RSV FRAG=0
	pkt = append(pkt, 0x01)
	pkt = append(pkt, v4...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], dstPort)
	pkt = append(pkt, port[:]...)
	pkt = append(pkt, payload...)

	if _, err := c.Write(pkt); err != nil {
		return 0, err
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return 0, err
	}
	if n <= 10 {
		return n, fmt.Errorf("回包太短（%d 字节）", n)
	}
	return n, nil
}
