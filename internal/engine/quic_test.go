package engine

import (
	"net"
	"strings"
	"testing"

	"nethub/internal/config"
	"nethub/internal/fakeip"
	"nethub/internal/logbus"
	"nethub/internal/rules"
)

// mkUDPQuic 造一个完整的 IPv4 + UDP(443) QUIC 包（应用 → 目标）。
func mkUDPQuic(payload []byte) []byte {
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	total := 20 + 8 + len(payload)
	pkt[2], pkt[3] = byte(total>>8), byte(total)
	pkt[9] = 17                                // UDP
	copy(pkt[12:16], []byte{192, 168, 31, 85}) // 应用
	copy(pkt[16:20], []byte{10, 100, 100, 99}) // 目标（内网）
	pkt[20], pkt[21] = 0xd4, 0x31              // sport = 54321
	pkt[22], pkt[23] = 0x01, 0xbb              // dport = 443
	ul := 8 + len(payload)
	pkt[24], pkt[25] = byte(ul>>8), byte(ul)
	copy(pkt[28:], payload)
	return pkt
}

// ICMP 端口不可达：外层要源=原目标、目标=应用，type/code=3/3，
// 且必须内嵌原数据报的 IP 头 + 前 8 字节（少了内核认不出属于哪个 socket，
// 应用就不会回落 TCP —— 那这个功能等于没做）。
func TestBuildICMPUnreachable(t *testing.T) {
	payload := make([]byte, 120) // 模拟 QUIC Initial
	pkt := mkUDPQuic(payload)
	src, dst, ihl, proto, ok := parseIPv4(pkt)
	if !ok || proto != 17 || ihl != 20 {
		t.Fatalf("测试包不合法: ok=%v proto=%d ihl=%d", ok, proto, ihl)
	}
	out, ok := buildICMPUnreachable(pkt, ihl, src, dst)
	if !ok {
		t.Fatal("应能构造 ICMP 差错报文")
	}
	if len(out) != 20+8+20+8 {
		t.Fatalf("长度应正好是 IP+ICMP+原 IP+8 字节 = 56，得到 %d", len(out))
	}
	if out[0] != 0x45 {
		t.Errorf("IPv4 版本/首部长度不对: %#x", out[0])
	}
	if out[9] != 1 {
		t.Errorf("外层协议应为 ICMP(1)，得到 %d", out[9])
	}
	if got := net.IP(out[12:16]); !got.Equal(dst) {
		t.Errorf("ICMP 报文源应=原目标 %s，得到 %s", dst, got)
	}
	if got := net.IP(out[16:20]); !got.Equal(src) {
		t.Errorf("ICMP 报文目标应=应用 %s，得到 %s", src, got)
	}
	if out[20] != 3 || out[21] != 3 {
		t.Errorf("应为 type=3 code=3（端口不可达），得到 %d/%d", out[20], out[21])
	}
	// 内嵌：原 IP 头（20 字节）逐字节一致 + 原 UDP 头前 8 字节
	embedded := out[28:]
	if string(embedded[:20]) != string(pkt[:20]) {
		t.Error("内嵌的 IP 头应与原包一致")
	}
	if string(embedded[20:28]) != string(pkt[20:28]) {
		t.Error("内嵌的 UDP 头（前 8 字节）应与原包一致")
	}
	// 畸形包要能拒掉（不能越界 panic）
	if _, ok := buildICMPUnreachable([]byte{0x45}, 20, src, dst); ok {
		t.Error("短包不该构造成功")
	}
	if _, ok := buildICMPUnreachable(pkt, 20, net.ParseIP("fe80::1"), dst); ok {
		t.Error("IPv6 源不该构造成功")
	}
}

// QUIC 阻断要进主过滤器：只装“走链/阻断”的区间（直连目标一个包不碰），
// 且假 IP 段要带上（否则应用连假 IP 的 QUIC 会一直干等）。
func TestBuildMainFilterQuicClause(t *testing.T) {
	rs := rules.New()
	if err := rs.Load([]rules.Route{
		{Name: "内网", Targets: []string{"10.1.0.0/24"}, Chain: "etyy"},
		{Name: "只走 8080", Targets: []string{"10.2.0.0/24"}, Ports: []string{"8080"}, Chain: "etyy"},
		{Name: "直连", Targets: []string{"192.168.5.0/24"}, Chain: "direct", Action: rules.ActionDirect},
	}); err != nil {
		t.Fatal(err)
	}
	e := newRulesEngine(&config.Config{}, rs)
	pool, err := fakeip.NewPool("198.19.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	e.fake = pool

	f, _ := e.buildMainFilter(rs, 13001)
	if !strings.Contains(f, " or (outbound and udp and udp.DstPort == 443") {
		t.Fatalf("过滤器里应有独立的 UDP 子句：%s", f)
	}
	udp := f[strings.Index(f, " or (outbound and udp"):]
	if !strings.Contains(udp, "10.1.0.0") {
		t.Errorf("走链的网段应出现在 UDP 子句里：%s", udp)
	}
	if strings.Contains(udp, "10.2.0.0") {
		t.Errorf("只写 8080 的规则不该进 UDP 443 子句：%s", udp)
	}
	if strings.Contains(udp, "192.168.5.0") {
		t.Errorf("直连目标的 QUIC 不该被我们碰：%s", udp)
	}
	if !strings.Contains(udp, "198.19.0.0") {
		t.Errorf("假 IP 段应进 UDP 子句（应用会拿假 IP 试 QUIC）：%s", udp)
	}

	// 关掉开关 → 过滤器里没有 udp
	cfg := &config.Config{}
	cfg.Tuning.QuicBlockDisabled = true
	e2 := newRulesEngine(cfg, rs)
	f2, _ := e2.buildMainFilter(rs, 13001)
	if strings.Contains(f2, "udp") {
		t.Fatalf("关掉 QUIC 阻断后不该有 UDP 子句：%s", f2)
	}
}

// 默认开、显式关。
func TestQuicBlockDefaultOn(t *testing.T) {
	cfg := &config.Config{}
	if !cfg.QuicBlockEnabled() {
		t.Fatal("QUIC 阻断应默认开启")
	}
	cfg.Tuning.QuicBlockDisabled = true
	if cfg.QuicBlockEnabled() {
		t.Fatal("quic_block_disabled: true 时应关闭")
	}
}

// 回归：quicNotices 是 map，若没在 New 里初始化，“写 nil map”会 panic ——
// 而 GUI 构建（-H=windowsgui，没有控制台）里 goroutine 的 panic 是**静默**的：
// 整个进程直接消失、日志里一个字都没有。实测就是这一下让引擎在收到第一个
// QUIC 包时无声无息地死掉（托盘图标没了都不知道为什么）。
func TestLogQUICBlockNoPanic(t *testing.T) {
	e := New(logbus.New(50), rules.New(), &config.Config{})
	e.logQUICBlock(net.ParseIP("10.1.2.3"), 443) // 首次（要写 map）
	e.logQUICBlock(net.ParseIP("10.1.2.3"), 443) // 再次（走“已存在”分支）
	e.pruneQUICNotices()
}

// panic 兜底：常驻循环 panic 后不能把进程带走，而且必须留下能查的东西
// （Fatal 一置，界面就变红“已中断”，而不是继续显示“运行中”）。
func TestGuardRecoversPanic(t *testing.T) {
	e := New(logbus.New(50), rules.New(), &config.Config{})
	e.guard("测试循环", func() { panic("boom") })
	if e.Fatal() == nil {
		t.Fatal("panic 应被记进 Fatal")
	}
}

// ICMP / IP 校验和必须是对的：错的校验和会被内核静默丢弃 —— 包能抓到、
// 应用却什么都收不到，看起来跟“功能没生效”一模一样（实测绕过一圈）。
func TestICMPUnreachableChecksums(t *testing.T) {
	pkt := mkUDPQuic(make([]byte, 100))
	src, dst, ihl, _, ok := parseIPv4(pkt)
	if !ok {
		t.Fatal("测试包不合法")
	}
	out, ok := buildICMPUnreachable(pkt, ihl, src, dst)
	if !ok {
		t.Fatal("构造失败")
	}
	if got := checksum(out[:20]); got != 0 {
		t.Errorf("IP 头校验和不对（整和为 0 才合法），得到 %#x", got)
	}
	if got := checksum(out[20:]); got != 0 {
		t.Errorf("ICMP 校验和不对（整和为 0 才合法），得到 %#x", got)
	}
}
