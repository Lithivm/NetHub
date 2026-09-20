package engine

import (
	"net"
	"testing"

	"nethub/internal/config"
	"nethub/internal/logbus"
)

// A14 环路检测：三种判据都要能判出来，正常流量不能误报。
func TestLoopDetection(t *testing.T) {
	e := newTestEngine()
	e.bus = logbus.New(200)
	e.loop = newLoopGuard()
	e.cfg = &config.Config{Chains: []config.Chain{
		{Name: "c", Forward: "socks5://10.9.9.9:1080"},
	}}

	// 判据 1：目标就是上游自己 → 立刻报（规则把上游地址也圈进来的典型事故）
	if !e.checkLoop(net.IPv4(192, 168, 1, 5), net.IPv4(10, 9, 9, 9), 1080, "c") {
		t.Error("目标=上游自己 应被判为环路")
	}
	n, last, _ := e.LoopAlerts()
	if n == 0 || last == "" {
		t.Errorf("应记下告警：n=%d last=%q", n, last)
	}

	// 判据 2：源 == 目标
	e2 := newTestEngine()
	e2.bus = logbus.New(200)
	e2.loop = newLoopGuard()
	e2.cfg = &config.Config{}
	if !e2.checkLoop(net.IPv4(10, 0, 0, 5), net.IPv4(10, 0, 0, 5), 443, "") {
		t.Error("源=目标 应被判为环路")
	}

	// 判据 3：同目标短窗口内疯狂新建连接
	e3 := newTestEngine()
	e3.bus = logbus.New(200)
	e3.loop = newLoopGuard()
	e3.cfg = &config.Config{}
	dst := net.IPv4(10, 1, 1, 1)
	alerted := false
	for i := 0; i < loopSynLimit+5; i++ {
		if e3.checkLoop(net.IPv4(192, 168, 1, 5), dst, 443, "c") {
			alerted = true
		}
	}
	if !alerted {
		t.Errorf("同目标 %d 次新建连接应触发疑似环路", loopSynLimit+5)
	}

	// 正常流量：不同目标、低频 → 一次都不该报
	e4 := newTestEngine()
	e4.bus = logbus.New(200)
	e4.loop = newLoopGuard()
	e4.cfg = &config.Config{Chains: []config.Chain{{Name: "c", Forward: "socks5://10.9.9.9:1080"}}}
	for i := 0; i < 5; i++ {
		for j := 1; j <= 5; j++ {
			if e4.checkLoop(net.IPv4(192, 168, 1, 5), net.IPv4(10, 2, 2, byte(j)), 443, "c") {
				t.Fatalf("正常流量被误报（第 %d 轮第 %d 个目标）", i, j)
			}
		}
	}
	if n, _, _ := e4.LoopAlerts(); n != 0 {
		t.Errorf("正常流量不该有告警，实际 %d 次", n)
	}
}
