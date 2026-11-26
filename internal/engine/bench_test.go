package engine

import (
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// 吞吐上限不是"跑个 speedtest"能说清的：我们的路径分两段，各有各的瓶颈。
//
//	段 1（按包计费）：每包都要在内核与用户态之间走一趟（WinDivert Recv/Send），
//	                 并在用户态改地址 + **重算整包校验和**。
//	段 2（按字节计费）：relay 把字节在两个 socket 之间对拷（32KB 缓冲）。
//
// 真实吞吐 ≈ min(段1, 段2) × 折扣（内核拷贝、TLS、上游链路）。
// 下面分别量，好知道瓶颈到底在哪一段。

// mkPkt 造一个 IPv4 + TCP 包（仅用于计时，校验和不要求合法）。
func mkPkt(size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45                             // version/IHL
	p[2], p[3] = byte(size>>8), byte(size)  // total length
	p[9] = 6                                // protocol = TCP
	copy(p[12:16], []byte{192, 168, 1, 42}) // src
	copy(p[16:20], []byte{10, 0, 0, 5})     // dst
	p[20], p[21] = 0x30, 0x39               // sport
	p[22], p[23] = 0x01, 0xbb               // dport 443
	p[32] = 0x50                            // data offset = 5（20 字节 TCP 头）
	return p
}

func BenchmarkParseIPv4(b *testing.B) {
	pkt := mkPkt(1500)
	for i := 0; i < b.N; i++ {
		if _, _, _, _, ok := parseIPv4(pkt); !ok {
			b.Fatal("解析失败")
		}
	}
}

// 每包最贵的一步：重算 IP + TCP 校验和（要扫过整个包）。
//
// 注意：生产里这一步是调 WinDivert DLL 的（WinDivertHelperCalcChecksums），
// 测试进程里加载不了那个 DLL，所以这里用**等价算法**的纯 Go 实现计时 ——
// 数字会略慢于 DLL 版本（DLL 里也可能是同样的一条循环）。
func ipv4Checksum(p []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(p); i += 2 {
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum 带伪头部的 TCP 校验和（扫过整个包载荷 —— 这就是吞吐的命门）。
func tcpChecksum(packet []byte, ihl int) uint16 {
	var sum uint32
	// 伪头部：src(4) + dst(4) + zero(1) + proto(1) + tcp_len(2)
	for i := 12; i < 20; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	sum += 6
	tcpLen := len(packet) - ihl
	sum += uint32(tcpLen)
	for i := ihl; i+1 < len(packet); i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	if (len(packet)-ihl)%2 == 1 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func BenchmarkCalcChecksums1500(b *testing.B) {
	pkt := mkPkt(1500)
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		putBE16(pkt, 10, ipv4Checksum(pkt[:20]))
		putBE16(pkt, 20+16, tcpChecksum(pkt, 20))
	}
}

func BenchmarkCalcChecksums64(b *testing.B) {
	pkt := mkPkt(64)
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		putBE16(pkt, 10, ipv4Checksum(pkt[:20]))
		putBE16(pkt, 20+16, tcpChecksum(pkt, 20))
	}
}

// 完整"出方向改写"的纯计算部分（不含 WinDivert Recv/Send 的系统调用）。
func BenchmarkRewriteOutboundPure(b *testing.B) {
	pkt := mkPkt(1500)
	relayIP := net.IPv4(127, 0, 0, 1).To4()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		_, _, t, proto, ok := parseIPv4(pkt)
		if !ok || proto != 6 {
			b.Fatal("解析失败")
		}
		copy(pkt[offDstIP:offDstIP+4], relayIP)
		putBE16(pkt, t+offDstPort, 58123)
		copy(pkt[offSrcIP:offSrcIP+4], relayIP)
		putBE16(pkt, 10, ipv4Checksum(pkt[:20]))
		putBE16(pkt, 20+16, tcpChecksum(pkt, 20))
	}
}

// 段 2：走完整 copyAndClose（relay 真实用的那段代码）的单向搬运吞吐。
// 拓扑：upstream(写) →(relay 的 copyAndClose)→ app(读)，全是回环 TCP。
//
// **这个数字只能做 A/B 对照，不能当吞吐结论**（2026-11-26 实测）：
// 在一台装了火绒（HipsDaemon）、网卡与 CPU 都老的机器上，纯回环 8MB 单向只有
// 42MB/s 上限；同一环境下 copyAndClose 27MB/s、io.Copy 24MB/s —— 即我们的实现
// 不输标准库，慢的是环境（安全软件的过滤驱动会拦所有 TCP，含 loopback）。
// 要量真实吞吐，先跑 BenchmarkLoopbackCeiling 校准本机环境。
func BenchmarkRelayCopy(b *testing.B) {
	const total = 8 << 20 // 每轮 8MB
	chunk := make([]byte, 64*1024)

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer upLn.Close()
	appLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer appLn.Close()

	// upstream 端：连接来了就狂写 total 字节
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for sent := 0; sent < total; {
					n, err := c.Write(chunk)
					if err != nil {
						return
					}
					sent += n
				}
			}(c)
		}
	}()
	// app 端：读光就关
	go func() {
		for {
			c, err := appLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64*1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		up, err := net.Dial("tcp", upLn.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		app, err := net.Dial("tcp", appLn.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		var counter, grand atomic.Uint64
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			copyAndClose(app, up, &counter, &grand, nil) // ← relay 里真正用的实现
		}()
		wg.Wait()
		if counter.Load() != grand.Load() {
			b.Fatalf("搬运不完整：%d / %d", counter.Load(), total)
		}
	}
}

// 顺带量一下 relay 的"每连接固定成本"（建连即断），对应"很多短连接"的场景。
func BenchmarkRelayPerConn(b *testing.B) {
	upLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer upLn.Close()
	appLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer appLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { c.Close() }(c)
		}
	}()
	go func() {
		for {
			c, err := appLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { c.Close() }(c)
		}
	}()
	for i := 0; i < b.N; i++ {
		up, err := net.Dial("tcp", upLn.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		app, err := net.Dial("tcp", appLn.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		var counter, grand atomic.Uint64
		copyAndClose(app, up, &counter, &grand, nil)
	}
}

// BenchmarkLoopbackCeiling 量本机"回环 TCP 单向搬运"的上限 —— **环境校准基准**，不是产品指标。
//
// 为什么需要它：上面各基准的数字会被环境整段压下去（安全软件的过滤驱动、老网卡、
// 虚拟化网卡都会拦/降速 loopback），拿绝对值讨论性能会得出完全错误的结论。
// 先跑它，再跑其他基准，两个数一起看才有意义：
//
//	go test -bench 'LoopbackCeiling|RelayCopy' -benchtime=4x ./internal/engine
//
// 参考（2026-11-26，老 4 核 + 火绒 hrwfpdrv.sys）：本机 TCP loopback 42~231MB/s
// （波动极大），同一台机器 AF_UNIX 1519MB/s —— 说明瓶颈在网络栈（WFP + TCP 协议
// 处理），不是 CPU/内存。低于 300MB/s 时，任何吞吐基准的绝对值都别信。
//
// 和 BenchmarkUnixSocketCeiling 一起看：两者的差距 = 网络栈（含安全软件过滤）的成本。
func BenchmarkLoopbackCeiling(b *testing.B) {
	const total = 8 << 20
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				chunk := make([]byte, 64*1024)
				for sent := 0; sent < total; {
					n, err := c.Write(chunk)
					if err != nil {
						return
					}
					sent += n
				}
			}(c)
		}
	}()
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", upLn.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, c)
		c.Close()
	}
}

// BenchmarkUnixSocketCeiling 用 AF_UNIX 量"不经 WFP 网络层"的同规模搬运，
// 与 BenchmarkLoopbackCeiling 配对：差距 = TCP 协议栈 + 安全软件 WFP 过滤的成本。
//
// 用途：客户说"装了以后慢"时，先分辨是**网络栈被过滤**（两者差距大）还是
// **机器本身就慢**（两者都低）。AF_UNIX 需要 Win10 1803+，不支持时自动 SKIP。
func BenchmarkUnixSocketCeiling(b *testing.B) {
	const total = 8 << 20
	ln, err := net.Listen("unix", filepath.Join(b.TempDir(), "s"))
	if err != nil {
		b.Skipf("本机不支持 AF_UNIX: %v", err)
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
				chunk := make([]byte, 64*1024)
				for sent := 0; sent < total; {
					n, err := c.Write(chunk)
					if err != nil {
						return
					}
					sent += n
				}
			}(c)
		}
	}()
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("unix", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, c)
		c.Close()
	}
}
