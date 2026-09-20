package engine

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"nethub/internal/config"
	"nethub/internal/logbus"
)

// 半死上游：接受 TCP 连接后一个字节都不回（握手永远不完成）。
// 这是现网最常见的坏法之一（能连上但没响应），也是以前 TTFB 偏高的根因。
func silentUpstream(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				c.Close()
			}(c)
		}
	}()
	return ln.Addr().String(), func() { close(done); ln.Close() }
}

// newFakeSocks 起一个能正常完成握手（no-auth + CONNECT 成功）的本地假 SOCKS5。
func newFakeSocks(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				if _, err := c.Read(buf); err != nil { // 打招呼
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				if _, err := c.Read(buf); err != nil { // CONNECT 请求
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				select {}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// dialUpstream 必须遵守「单次超时」和「总预算」：
//   - 一条半死上游不能把业务卡满 10s（老行为）
//   - 候选多时不能逐个超时耗尽（预算到点就停，并且留痕）
func TestDialBudgetAndTimeout(t *testing.T) {
	a, stopA := silentUpstream(t)
	defer stopA()
	b, stopB := silentUpstream(t)
	defer stopB()
	c, stopC := silentUpstream(t)
	defer stopC()

	// 单次 1s、总预算 2s（配置会被 clamp，1s 是允许的最小值）
	e := newTestEngine()
	e.bus = logbus.New(50)
	e.cfg = &config.Config{Tuning: config.Tuning{DialTimeout: "1s", DialBudget: "2s"}}
	if got := e.cfg.DialTimeoutDur(); got != time.Second {
		t.Fatalf("单次超时应为 1s，得到 %s", got)
	}
	if got := e.cfg.DialBudgetDur(); got != 2*time.Second {
		t.Fatalf("总预算应为 2s，得到 %s", got)
	}

	// 两条半死：应在 ~2s 内失败返回（而不是 2×10s 或 2×1s 之后还继续等）
	ch := config.Chain{Name: "c", Forwards: []string{"socks5://" + a, "socks5://" + b}}
	t0 := time.Now()
	conn, err := e.dialUpstream(ch, net.IPv4(10, 0, 0, 1), 443)
	el := time.Since(t0)
	if err == nil {
		conn.Close()
		t.Fatal("两条半死上游不该拨成功")
	}
	if el > 2500*time.Millisecond {
		t.Errorf("超时+预算没生效：耗时 %s（期望 ≈2s）", el)
	}
	if el < 900*time.Millisecond {
		t.Errorf("太早放弃：耗时 %s（第一条应至少等满单次超时）", el)
	}

	// 三条半死：默认开了竞速（race_after=150ms）→ 三条会被并发试完，
	// 总耗时 ≈ 一个单次超时，而不是三个。（这正是竞速要的效果）
	ch3 := config.Chain{Name: "c3", Forwards: []string{
		"socks5://" + a, "socks5://" + b, "socks5://" + c}}
	t0 = time.Now()
	conn, err = e.dialUpstream(ch3, net.IPv4(10, 0, 0, 1), 443)
	el = time.Since(t0)
	if err == nil {
		conn.Close()
		t.Fatal("三条半死上游不该拨成功")
	}
	if el > 2000*time.Millisecond {
		t.Errorf("竞速后应≈一个单次超时，实际 %s", el)
	}
	if !containsStr(err.Error(), "所有上游") {
		t.Errorf("全失败要把话说清楚，实际：%v", err)
	}

	// 关掉竞速 → 回到“顺序等满”，此时预算 2s 只够试两条，必须留痕
	e.cfg = &config.Config{Tuning: config.Tuning{DialTimeout: "1s", DialBudget: "2s", RaceAfter: "off"}}
	t0 = time.Now()
	conn, err = e.dialUpstream(ch3, net.IPv4(10, 0, 0, 1), 443)
	el = time.Since(t0)
	if err == nil {
		conn.Close()
		t.Fatal("不该成功")
	}
	if el > 2500*time.Millisecond {
		t.Errorf("预算没封顶：耗时 %s", el)
	}
	if !containsStr(err.Error(), "未尝试") {
		t.Errorf("顺序模式下截断必须说清楚剩余候选没试，实际：%v", err)
	}
}

// 「拒绝」型失败（端口没人听）几乎不花时间 → 不该被总预算挡住，
// 否则会出现“配了 3 条上游，只试了 2 条就报错”。
func TestDialBudgetAllowsFastFailures(t *testing.T) {
	e := newTestEngine()
	e.bus = logbus.New(50)
	e.cfg = &config.Config{Tuning: config.Tuning{DialTimeout: "1s", DialBudget: "1s"}}

	// 4 条全是拒绝（127.0.0.1:1 无监听），最后一条是能用的本地 socks5
	good := newFakeSocks(t)
	ch := config.Chain{Name: "c", Forwards: []string{
		"socks5://127.0.0.1:1", "socks5://127.0.0.1:2",
		"socks5://127.0.0.1:3", "socks5://" + good,
	}}
	t0 := time.Now()
	conn, err := e.dialUpstream(ch, net.IPv4(10, 0, 0, 1), 443)
	if err != nil {
		t.Fatalf("前面三条拒绝不该挡住第四条可用上游：%v（耗时 %s）", err, time.Since(t0))
	}
	conn.Close()
	if el := time.Since(t0); el > 2*time.Second {
		t.Errorf("快速失败也花太久：%s", el)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// A10 慢则竞速：第一条半死时不该傻等满单次超时，其余候选要立刻并发试出去。
func TestDialRacing(t *testing.T) {
	dead, stopDead := silentUpstream(t)
	defer stopDead()
	good := newFakeSocks(t)

	e := newTestEngine()
	e.bus = logbus.New(50)
	e.cfg = &config.Config{Tuning: config.Tuning{DialTimeout: "3s", DialBudget: "6s"}}

	ch := config.Chain{Name: "c", Forwards: []string{"socks5://" + dead, "socks5://" + good}}

	// 默认 race_after=150ms：必须在远小于单次超时（3s）的时间内拿到好上游
	t0 := time.Now()
	conn, err := e.dialUpstream(ch, net.IPv4(10, 0, 0, 1), 443)
	el := time.Since(t0)
	if err != nil {
		t.Fatalf("竞速应能拿到好上游：%v（耗时 %s）", err, el)
	}
	conn.Close()
	if el > 1500*time.Millisecond {
		t.Errorf("竞速没起作用：耗时 %s（期望 ~150ms 起跑）", el)
	}

	// 关掉竞速（race_after: off）→ 退回顺序等满，明显更慢
	e.cfg = &config.Config{Tuning: config.Tuning{DialTimeout: "1s", DialBudget: "3s", RaceAfter: "off"}}
	t0 = time.Now()
	conn, err = e.dialUpstream(ch, net.IPv4(10, 0, 0, 1), 443)
	el = time.Since(t0)
	if err != nil {
		t.Fatalf("顺序模式也该能连上：%v", err)
	}
	conn.Close()
	if el < 900*time.Millisecond {
		t.Errorf("关掉竞速后应先等满第一条超时（1s），实际 %s", el)
	}

	// 竞速成功时多余的连接必须被关掉（不能泄漏）：连跑 5 次
	e.cfg = &config.Config{Tuning: config.Tuning{DialTimeout: "2s", DialBudget: "6s"}}
	for i := 0; i < 5; i++ {
		conn, err := e.dialUpstream(ch, net.IPv4(10, 0, 0, 1), 443)
		if err != nil {
			t.Fatalf("第 %d 次失败：%v", i, err)
		}
		conn.Close()
	}
}

// slowSocks 起一个假 SOCKS5：**先慢 delay 再回话**，模拟"到上游的握手延迟"。
// 用它验证预热池到底省不省时间（这才是它唯一的意义）。
func slowSocks(t *testing.T, delay time.Duration) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				if _, err := c.Read(buf); err != nil { // 方法协商
					return
				}
				time.Sleep(delay) // ← 模拟慢链路（TCP/TLS/招呼都算在这里）
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				if _, err := c.Read(buf); err != nil { // CONNECT
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				select {} // 挂住
			}(c)
		}
	}()
	return ln.Addr().String(), &conns
}

// A11 预热连接池：第二次业务连接应该**不用再等**握手（只发 CONNECT）。
func TestWarmPoolSkipsHandshake(t *testing.T) {
	addr, conns := slowSocks(t, 300*time.Millisecond)

	e := newTestEngine()
	e.bus = logbus.New(50)
	e.cfg = &config.Config{Tuning: config.Tuning{DialTimeout: "3s", DialBudget: "6s", RaceAfter: "off"}}
	e.pool = newWarmPool()

	ch := config.Chain{Name: "c", Forwards: []string{"socks5://" + addr}}

	// 第一条（冷）必须等满那 300ms
	t0 := time.Now()
	c1, err := e.dialUpstream(ch, net.IPv4(10, 0, 0, 1), 443)
	cold := time.Since(t0)
	if err != nil {
		t.Fatalf("冷启动拨号失败：%v", err)
	}
	c1.Close()
	if cold < 250*time.Millisecond {
		t.Fatalf("冷启动应该等满握手延迟，实际只有 %s", cold)
	}

	// 等后台补货完成
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, warm := e.PoolStats()
		if warm > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, _, warm := e.PoolStats(); warm == 0 {
		t.Fatal("补货没成功：池子里一条预热会话都没有")
	}

	// 第二条（热）应该几乎不用等（只有一次 CONNECT 往返）
	t0 = time.Now()
	c2, err := e.dialUpstream(ch, net.IPv4(10, 0, 0, 1), 443)
	hot := time.Since(t0)
	if err != nil {
		t.Fatalf("热拨号失败：%v", err)
	}
	c2.Close()
	if hot > 150*time.Millisecond {
		t.Errorf("预热没起作用：热拨号花了 %s（期望只剩 CONNECT，远小于 %s 的握手）", hot, cold)
	}
	t.Logf("冷 %s → 热 %s（省了 %s）；新建连接数 %d", cold, hot, cold-hot, conns.Load())
}

// 关掉预热（warm_sessions: off）时不该有池子行为，也不该多建连接。
func TestWarmPoolDisabled(t *testing.T) {
	addr, _ := slowSocks(t, 10*time.Millisecond)
	e := newTestEngine()
	e.bus = logbus.New(50)
	e.cfg = &config.Config{Tuning: config.Tuning{
		DialTimeout: "2s", DialBudget: "4s", RaceAfter: "off", WarmSessions: "off"}}
	e.pool = newWarmPool()
	ch := config.Chain{Name: "c", Forwards: []string{"socks5://" + addr}}
	for i := 0; i < 3; i++ {
		c, err := e.dialUpstream(ch, net.IPv4(10, 0, 0, 1), 443)
		if err != nil {
			t.Fatalf("第 %d 次失败：%v", i, err)
		}
		c.Close()
	}
	if taken, made, warm := e.PoolStats(); taken != 0 || made != 0 || warm != 0 {
		t.Errorf("关掉预热后不该有池子活动：taken=%d made=%d warm=%d", taken, made, warm)
	}
}
