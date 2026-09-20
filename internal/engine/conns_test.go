package engine

import (
	"net"
	"strings"
	"testing"
	"time"

	"nethub/internal/config"
	"nethub/internal/rules"
)

// newTestEngine 造一个够用的空引擎：没有驱动、没有 relay，只测连接表的快照与统计。
func newTestEngine() *Engine {
	return &Engine{
		cfg:         &config.Config{},
		conns:       map[uint16]*connState{},
		notices:     map[uint16]noticeSeen{},
		statPerRule: map[string]uint64{},
	}
}

// Conns 快照：进行中在前、字节数/状态/动作正确、limit 生效。
func TestConnsSnapshot(t *testing.T) {
	e := newTestEngine()

	live := &connState{dst: net.ParseIP("10.0.0.5"), dport: 5432, chain: "proxy-a",
		action: rules.ActionChain, start: time.Now().Add(-3 * time.Second)}
	live.up.Store(2048)
	live.down.Store(1024 * 1024)
	live.packets.Store(12)

	done := &connState{dst: net.ParseIP("192.168.1.10"), dport: 445, chain: "direct",
		action: rules.ActionDirect, start: time.Now().Add(-30 * time.Second)}
	done.touch()
	done.up.Store(500)
	done.packets.Store(7)
	done.ended.Store(true)

	failed := &connState{dst: net.ParseIP("10.0.0.9"), dport: 443, chain: "proxy-a",
		action: rules.ActionChain, start: time.Now().Add(-2 * time.Second)}
	failed.touch()
	failed.fail("连代理失败: i/o timeout")
	e.finish(failed) // 真实代码里隧道建立失败也会收尾（fail + finish）

	blocked := &connState{dst: net.ParseIP("10.9.9.9"), dport: 22, chain: "block",
		action: rules.ActionBlock, start: time.Now().Add(-1 * time.Second)}
	blocked.touch()
	blocked.last.Store(time.Now().Add(-time.Minute).UnixNano())
	blocked.packets.Store(3)

	// live 显式给一个“更晚”的时间戳：列表里“进行中”按最后活动倒序，它就该排第一。
	// （不能用两次 touch 比先后：Windows 上 time.Now() 精度粗，会落到同一个值）
	live.last.Store(time.Now().Add(time.Second).UnixNano())

	e.conns[1001] = live
	e.conns[1002] = done
	e.conns[1003] = failed
	e.conns[1004] = blocked
	e.statActive = 1 // 只剩 live 这条还在进行中

	got := e.Conns(10, false)
	if len(got) != 4 {
		t.Fatalf("应有 4 条，实际 %d", len(got))
	}
	// 进行中的排在前面
	if got[0].Target != "10.0.0.5:5432" || got[0].State != "进行中" || got[0].Action != "隧道" {
		t.Errorf("第一条应是进行中的隧道连接: %+v", got[0])
	}
	if got[0].Up != 2048 || got[0].Down != 1024*1024 {
		t.Errorf("字节数不对: up=%d down=%d", got[0].Up, got[0].Down)
	}
	if got[0].Chain != "proxy-a" {
		t.Errorf("链名不对: %s", got[0].Chain)
	}

	// 直连结束的那条：状态已结束、动作直连
	var direct *ConnView
	var fail *ConnView
	var block *ConnView
	for i := range got {
		switch got[i].Target {
		case "192.168.1.10:445":
			direct = &got[i]
		case "10.0.0.9:443":
			fail = &got[i]
		case "10.9.9.9:22":
			block = &got[i]
		}
	}
	if direct == nil || direct.State != "已结束" || direct.Action != "直连" || direct.Packets != 7 {
		t.Errorf("直连那条不对: %+v", direct)
	}
	if fail == nil || fail.State != "失败" || fail.Error == "" {
		t.Errorf("失败那条不对: %+v", fail)
	}
	if block == nil || block.State != "已阻断" {
		t.Errorf("阻断那条不对: %+v", block)
	}

	// limit 生效
	if got := e.Conns(2, false); len(got) != 2 {
		t.Errorf("limit=2 应只返回 2 条，实际 %d", len(got))
	}
}

// finish 幂等：重复收尾不能把活跃数扣成负数。
func TestFinishIdempotent(t *testing.T) {
	e := newTestEngine()
	st := &connState{dst: net.ParseIP("10.0.0.5"), dport: 80, action: rules.ActionChain, start: time.Now()}
	st.touch()
	e.conns[1001] = st
	e.statActive = 1

	e.finish(st)
	e.finish(st)
	e.finish(st)
	if e.statActive != 0 {
		t.Errorf("活跃数应为 0，实际 %d", e.statActive)
	}
	if !st.ended.Load() {
		t.Error("应收尾为已结束")
	}
}

// 字节/时长的可读写法。
func TestHuman(t *testing.T) {
	bytes := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"}, {1023, "1023 B"}, {1024, "1.0 KB"}, {1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"}, {1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, c := range bytes {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q（期望 %q）", c.in, got, c.want)
		}
	}
	durs := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"}, {5 * time.Second, "5s"}, {65 * time.Second, "1m05s"},
		{time.Hour, "1h00m"}, {90 * time.Minute, "1h30m"}, {-time.Second, "0s"},
	}
	for _, c := range durs {
		if got := humanDur(c.in); got != c.want {
			t.Errorf("humanDur(%v) = %q（期望 %q）", c.in, got, c.want)
		}
	}
}

// A20：连接快照能查出真实进程名。
//
// 为什么值得单测：整条链是「应用端口 → TCP 表 → PID → 进程名」，任何一段错了
// 界面上就只会永远显示“未知”，而人肉看代码看不出来 —— 必须真连一条。
func TestConnsResolveProcess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr)

	e := newTestEngine()
	e.proc = procNewResolver()
	e.mu.Lock()
	st := &connState{dst: net.ParseIP("10.0.0.5"), dport: 5432, chain: "proxy-a",
		action: rules.ActionChain, start: time.Now(), appPort: uint16(local.Port)}
	st.touch()
	e.conns[uint16(local.Port)] = st
	e.mu.Unlock()

	got := e.Conns(10, true)
	if len(got) != 1 {
		t.Fatalf("快照条数 = %d", len(got))
	}
	if got[0].Proc == "" {
		t.Skipf("查不到端口 %d 的进程（受限环境），跳过", local.Port)
	}
	if !strings.Contains(strings.ToLower(got[0].Proc), "engine.test") {
		t.Errorf("进程名 = %q（PID %d），期望是测试二进制自己", got[0].Proc, got[0].PID)
	}
	// withProc=false 时必须不查（零开销路径）
	e2 := newTestEngine()
	e2.proc = procNewResolver()
	e2.mu.Lock()
	e2.conns[uint16(local.Port)] = st
	e2.mu.Unlock()
	if got2 := e2.Conns(10, false); got2[0].Proc != "" {
		t.Errorf("withProc=false 时不该去查进程，却得到 %q", got2[0].Proc)
	}
	t.Logf("端口 %d → %s (PID %d)", local.Port, got[0].Proc, got[0].PID)
}
