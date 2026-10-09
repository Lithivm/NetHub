package engine

import (
	"net"
	"testing"
	"time"

	"nethub/internal/rules"
)

// 速率是"两拍做差"：dt<=0 与"计数变小"都必须给 0，绝不给负值（uint64 会变成天文数字）。
func TestPerSecond(t *testing.T) {
	cases := []struct {
		name      string
		now, prev uint64
		dt        float64
		want      uint64
	}{
		{name: "正常：1 秒传了 3 MB", now: 3 << 20, prev: 0, dt: 1, want: 3 << 20},
		{name: "半秒传了 1 KB（采样间隔抖动）", now: 1024, prev: 0, dt: 0.5, want: 2048},
		{name: "两拍一样：0", now: 4096, prev: 4096, dt: 1, want: 0},
		{name: "dt=0（时钟没走）", now: 4096, prev: 0, dt: 0, want: 0},
		{name: "dt<0", now: 4096, prev: 0, dt: -1, want: 0},
		{name: "计数变小（端口复用那种情况）：不报负值", now: 10, prev: 4096, dt: 1, want: 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := perSecond(c.now, c.prev, c.dt); got != c.want {
				t.Fatalf("perSecond(%d, %d, %v) = %d，期望 %d", c.now, c.prev, c.dt, got, c.want)
			}
		})
	}
}

// 采样：第一拍只记底数（速率 0），第二拍才有速率；已结束的连接速率归 0；
// 自己的探针既不进合计也不采。
func TestSampleRates(t *testing.T) {
	e := newTestEngine()
	now := time.Now()

	live := &connState{dst: net.ParseIP("10.0.0.5"), dport: 5432, appPort: 51000, chain: "proxy-a",
		action: rules.ActionChain, start: now.Add(-3 * time.Second)}
	live.up.Store(1000)
	live.down.Store(2000)
	live.touch()
	e.conns[51000] = live

	done := &connState{dst: net.ParseIP("10.0.0.6"), dport: 5432, appPort: 51001, chain: "proxy-a",
		action: rules.ActionChain, start: now.Add(-9 * time.Second)}
	done.up.Store(7 << 20)
	done.touch()
	done.ended.Store(true)
	e.conns[51001] = done

	probe := &connState{dst: net.ParseIP("10.0.0.7"), dport: 5432, appPort: 51002, chain: "proxy-a",
		action: rules.ActionChain, start: now, self: true}
	probe.up.Store(9 << 20)
	probe.touch()
	e.conns[51002] = probe

	// 第一拍：只记底数，任何连接都还没有速率
	e.sampleRates(now)
	if v := e.Conns(0, false); len(v) != 2 {
		t.Fatalf("探针不该进列表，期望 2 条，实际 %d", len(v))
	}
	for _, c := range e.Conns(0, false) {
		if c.UpBps != 0 || c.DownBps != 0 {
			t.Fatalf("第一拍还没有速率，%s 却是 up=%d down=%d", c.Target, c.UpBps, c.DownBps)
		}
	}

	// 第二拍：live 在 1 秒里又传了 3000 出 / 6000 入 → 3000 / 6000 字节每秒
	live.up.Store(1000 + 3000)
	live.down.Store(2000 + 6000)
	e.sampleRates(now.Add(time.Second))

	var gotUp, gotDown uint64
	for _, c := range e.Conns(0, false) {
		if c.Sport != 51000 {
			continue
		}
		gotUp, gotDown = c.UpBps, c.DownBps
	}
	if gotUp != 3000 || gotDown != 6000 {
		t.Fatalf("速率 = up %d / down %d，期望 3000 / 6000", gotUp, gotDown)
	}

	// 合计：只有 live 在传（探针不算、已结束的归 0）
	sumUp, sumDown := e.Rates()
	if sumUp != 3000 || sumDown != 6000 {
		t.Fatalf("全表速率合计 = %d / %d，期望 3000 / 6000", sumUp, sumDown)
	}

	// 结束之后速率归 0（不然界面上"已结束"旁边还挂着一个速率，看着像还在跑）
	live.ended.Store(true)
	e.sampleRates(now.Add(2 * time.Second))
	for _, c := range e.Conns(0, false) {
		if c.Sport == 51000 && (c.UpBps != 0 || c.DownBps != 0) {
			t.Fatalf("已结束的连接速率应为 0，实际 %d / %d", c.UpBps, c.DownBps)
		}
	}
	if sumUp, sumDown = e.Rates(); sumUp != 0 || sumDown != 0 {
		t.Fatalf("已结束的连接不该再计入合计，实际 %d / %d", sumUp, sumDown)
	}
}
