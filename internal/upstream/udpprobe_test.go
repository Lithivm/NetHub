package upstream

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSocks5UDP 起一个假上游，专测 UDP 能力探测。三种行为：
//
//	"ok"          ASSOCIATE 回 0，且 UDP 端口真回声（应答码与数据面都通）
//	"refuse"      ASSOCIATE 回 7（command not supported）
//	"blackhole"   ASSOCIATE 回 0，但 UDP 端口**只收不回** —— 这正是实测到的真实情形
//	              （四条 gost 上游全部返回 0，真实往返 4/4 没回包）：只看应答码会误判成“支持”。
func fakeSocks5UDP(t *testing.T, mode string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假上游失败: %v", err)
	}
	var closers []io.Closer
	closers = append(closers, ln)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				// ① 方法协商（无认证）
				if _, err := c.Read(buf); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				// ② 请求头
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				if _, err := readSocksAddr(c, head[3]); err != nil { // 地址 + 端口
					return
				}
				if head[1] != 0x03 { // 只支持 UDP ASSOCIATE
					_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				if mode == "refuse" {
					_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				// ③ 开一个 UDP 端口并把它告诉客户端
				uc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return
				}
				closers = append(closers, uc)
				port := uint16(uc.LocalAddr().(*net.UDPAddr).Port)
				reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1}
				reply = binary.BigEndian.AppendUint16(reply, port)
				if _, err := c.Write(reply); err != nil {
					return
				}
				if mode == "blackhole" {
					// 收但什么都不回（模拟“上游侧没放行 UDP 端口”）
					p := make([]byte, 2048)
					for {
						if _, _, err := uc.ReadFrom(p); err != nil {
							return
						}
					}
				}
				// 回声：把 SOCKS5 UDP 请求里的目标地址与载荷原样带回去
				p := make([]byte, 2048)
				for {
					n, from, err := uc.ReadFrom(p)
					if err != nil {
						return
					}
					if n < 10 {
						continue
					}
					atyp := p[3]
					off := 4
					var addr []byte
					switch atyp {
					case 0x01:
						addr, off = p[4:8], 8
					case 0x04:
						addr, off = p[4:20], 20
					case 0x03:
						l := int(p[4])
						addr, off = p[4:4+l], 4+l
					default:
						continue
					}
					portB := p[off : off+2]
					payload := p[off+2 : n]
					out := []byte{0x00, 0x00, 0x00}
					if atyp == 0x03 {
						out = append(out, 0x03, byte(len(addr)))
					} else {
						out = append(out, atyp)
					}
					out = append(out, addr...)
					out = append(out, portB...)
					out = append(out, payload...)
					_, _ = uc.WriteTo(out, from)
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}
}

// readSocksAddr 按 ATYP 读地址 + 端口（测试用，不做校验）。
func readSocksAddr(c net.Conn, atyp byte) ([]byte, error) {
	var n int
	switch atyp {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return nil, err
		}
		n = int(l[0])
	}
	rest := make([]byte, n+2)
	_, err := io.ReadFull(c, rest)
	return rest, err
}

func TestProbeUDP(t *testing.T) {
	dst := net.ParseIP("114.114.114.114")
	const port = 53

	t.Run("能中继：应答码与数据面都通", func(t *testing.T) {
		addr, stop := fakeSocks5UDP(t, "ok")
		defer stop()
		up, err := Parse("socks5://" + addr)
		if err != nil {
			t.Fatal(err)
		}
		r := ProbeUDP(up, dst, port, 2*time.Second)
		if !r.Supported {
			t.Fatalf("回声正常时应判为可用，得到 %+v", r)
		}
		if r.RTT < 0 || r.RTT > 2*time.Second {
			t.Errorf("往返耗时应当是个合理值（本机回声不会到秒级）：%+v", r)
		}
	})

	t.Run("上游不支持：应答码非 0", func(t *testing.T) {
		addr, stop := fakeSocks5UDP(t, "refuse")
		defer stop()
		up, _ := Parse("socks5://" + addr)
		r := ProbeUDP(up, dst, port, 2*time.Second)
		if r.Supported {
			t.Fatalf("应答码 7 不该判为可用：%+v", r)
		}
		if !strings.Contains(r.Reason, "不支持") {
			t.Errorf("原因要说清是“上游没实现/不允许”，得到 %q", r.Reason)
		}
	})

	// 回归：这条正是实测踩到的坑 —— 应答码 0 只说明控制面通了。
	t.Run("应答码 0 但数据面不通（实测遇到的真实情形）", func(t *testing.T) {
		addr, stop := fakeSocks5UDP(t, "blackhole")
		defer stop()
		up, _ := Parse("socks5://" + addr)
		r := ProbeUDP(up, dst, port, 800*time.Millisecond)
		if r.Supported {
			t.Fatalf("没有回包时**绝不能**判为可用（只看应答码就会误判）：%+v", r)
		}
		if !strings.Contains(r.Reason, "没有回包") {
			t.Errorf("原因要指出“往返没有回包”，得到 %q", r.Reason)
		}
		if !strings.Contains(r.Reason, "bnd=") {
			t.Errorf("原因里带上代理给的转发地址，便于判断是否可达：%q", r.Reason)
		}
	})

	t.Run("连不上上游", func(t *testing.T) {
		up, err := Parse("socks5://127.0.0.1:1")
		if err != nil {
			t.Fatal(err)
		}
		r := ProbeUDP(up, dst, port, 300*time.Millisecond)
		if r.Supported || !strings.Contains(r.Reason, "连不上上游") {
			t.Errorf("应报“连不上上游”，得到 %+v", r)
		}
	})
}
