package engine

import (
	"net"
	"testing"
	"time"

	"nethub/internal/rules"
)

// 直连的字节要按**方向**分账：环回直连的回包也是被引擎拦下来的（内核过滤器把它
// 当 outbound 交给我们），以前拿回包的源端口（对端端口）去查连接表，永远查不到，
// 于是界面上"直连下行"恒为 0。这组用例钉住"两个方向都记对、且不会互相串账"。
func TestPassCountDirection(t *testing.T) {
	e := newTestEngine()
	// 一条应用侧连接：应用端口 50000 → 对端 127.0.0.1:7897（环回直连的典型形态）
	out := &connState{dst: net.ParseIP("127.0.0.1"), dport: 7897, app: net.ParseIP("127.0.0.1"),
		appPort: 50000, action: rules.ActionDirect, start: time.Now()}
	out.touch()
	e.conns[50000] = out

	// 出方向：源端口 = 应用端口
	e.passCount(50000, 7897, 100, rules.ActionDirect, false)
	if got := out.up.Load(); got != 100 {
		t.Fatalf("出方向应记 up=100，得到 %d", got)
	}
	if got := out.down.Load(); got != 0 {
		t.Fatalf("出方向不该动 down，得到 %d", got)
	}
	if e.dirUp.Load() != 100 || e.dirDown.Load() != 0 {
		t.Fatalf("直连口径不对: dirUp=%d dirDown=%d", e.dirUp.Load(), e.dirDown.Load())
	}

	// 回方向：源端口 = 对端端口，目标端口 = 应用端口
	e.passCount(7897, 50000, 4096, rules.ActionDirect, false)
	if got := out.down.Load(); got != 4096 {
		t.Fatalf("回方向应记 down=4096，得到 %d", got)
	}
	if got := out.up.Load(); got != 100 {
		t.Fatalf("回方向不该动 up，得到 %d", got)
	}
	if e.dirDown.Load() != 4096 {
		t.Fatalf("直连下行口径 = %d，期望 4096", e.dirDown.Load())
	}
	if got := out.packets.Load(); got != 2 {
		t.Fatalf("两个方向都该算一个包，packets=%d", got)
	}
}

// 端口对不上就不许认亲：出方向的包（源端口是应用端口）如果在连接表里已经查不到，
// 兜底反查会拿到"应用端口恰好等于本包源端口"的另一条连接 —— 必须靠 st.dport 挡住。
func TestPassCountPortPairing(t *testing.T) {
	e := newTestEngine()
	// 另一条连接：应用端口 50000 连的是 10.0.0.5:80，跟 7897 没关系
	other := &connState{dst: net.ParseIP("10.0.0.5"), dport: 80, app: net.ParseIP("10.0.0.1"),
		appPort: 50000, action: rules.ActionDirect, start: time.Now()}
	other.touch()
	e.conns[50000] = other

	// 源端口 7897 查不到，反查 50000 拿到 other，但 other.dport(80) != 7897 → 不认
	e.passCount(7897, 50000, 999, rules.ActionDirect, false)
	if other.up.Load() != 0 || other.down.Load() != 0 {
		t.Fatalf("端口对不上却记了账: up=%d down=%d", other.up.Load(), other.down.Load())
	}
	if e.dirUp.Load() != 0 || e.dirDown.Load() != 0 {
		t.Fatalf("直连口径不该涨: dirUp=%d dirDown=%d", e.dirUp.Load(), e.dirDown.Load())
	}
}

// 阻断的连接即使端口对得上也不记字节（它一个包都没出去/回来）；
// 但包数要算 —— 与以前的 passThrough 一致：能查到连接就 touch + 计数。
func TestPassCountBlockedNoBytes(t *testing.T) {
	e := newTestEngine()
	blocked := &connState{dst: net.ParseIP("10.9.9.9"), dport: 7897, app: net.ParseIP("10.0.0.1"),
		appPort: 50000, action: rules.ActionBlock, start: time.Now()}
	blocked.touch()
	e.conns[50000] = blocked

	e.passCount(50000, 7897, 500, rules.ActionBlock, false) // 出方向
	if blocked.up.Load() != 0 || blocked.down.Load() != 0 {
		t.Fatalf("阻断连接不该记字节: up=%d down=%d", blocked.up.Load(), blocked.down.Load())
	}
	if blocked.packets.Load() != 1 {
		t.Fatalf("阻断包也要算包数，得到 %d", blocked.packets.Load())
	}

	// 回方向反查只认直连连接：阻断的连接不该被当成“回包”的归属
	e.passCount(7897, 50000, 500, rules.ActionBlock, false)
	if blocked.down.Load() != 0 {
		t.Fatalf("阻断连接的回包不该记 down=%d", blocked.down.Load())
	}
}

// 收尾只认出方向的 FIN/RST：回包的 FIN 和出方向那条 FIN 是同一个连接，
// 收两次会把字节记两遍（统计卡的累计桶靠 st.ended 的 CAS 兜，但不该走到那一步）。
func TestPassCountFinOnlyOutbound(t *testing.T) {
	e := newTestEngine()
	c := &connState{dst: net.ParseIP("127.0.0.1"), dport: 7897, app: net.ParseIP("127.0.0.1"),
		appPort: 50000, action: rules.ActionDirect, start: time.Now()}
	c.touch()
	e.conns[50000] = c

	e.passCount(7897, 50000, 10, rules.ActionDirect, true) // 回包的 FIN
	if c.ended.Load() {
		t.Fatal("回包的 FIN 不该收尾")
	}
	e.passCount(50000, 7897, 10, rules.ActionDirect, true) // 出方向的 FIN
	if !c.ended.Load() {
		t.Fatal("出方向的 FIN 应当收尾")
	}
}
