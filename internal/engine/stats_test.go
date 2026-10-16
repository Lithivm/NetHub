package engine

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"nethub/internal/dnsmap"
	"nethub/internal/fakeip"
	"nethub/internal/rules"
)

// mkConn 造一条已经"收尾"的连接（直接喂 finish 用）。
func mkConn(proc string, ip string, port uint16, act rules.Action, up, down uint64) *connState {
	st := &connState{
		dst: net.ParseIP(ip), dport: port, action: act, procName: proc,
		chain: "etyy", start: time.Now().Add(-10 * time.Second),
	}
	st.up.Store(up)
	st.down.Store(down)
	return st
}

// 按应用 / 按目标两个维度：同一条连接同时进两边，合计互通。
func TestStatBucketsByAppAndTarget(t *testing.T) {
	e := newTestEngine()

	ok := mkConn("his.exe", "10.0.0.5", 5432, rules.ActionChain, 1000, 9000)
	e.finish(ok)

	bad := mkConn("his.exe", "10.0.0.5", 5432, rules.ActionChain, 0, 0)
	bad.fail("上游不通")
	e.finish(bad)

	anon := mkConn("", "10.0.0.9", 80, rules.ActionDirect, 500, 0)
	e.finish(anon)

	p := e.StatsPage(StatScopeRun, 20)
	if p.Conns != 3 || p.Failed != 1 {
		t.Fatalf("合计错：conns=%d failed=%d（想要 3 / 1）", p.Conns, p.Failed)
	}
	if p.Up != 1500 || p.Down != 9000 {
		t.Fatalf("字节错：up=%d down=%d（想要 1500 / 9000）", p.Up, p.Down)
	}
	if p.Chain != 2 || p.Direct != 1 || p.Blocked != 0 {
		t.Fatalf("动作分解错：chain=%d direct=%d blocked=%d（想要 2 / 1 / 0）", p.Chain, p.Direct, p.Blocked)
	}
	// 应用维度：his.exe 两条（1 失败、9000 下行），未知一条
	if p.KeysApps != 2 {
		t.Fatalf("应用键数 = %d（想要 2）", p.KeysApps)
	}
	if p.Apps[0].Name != "his.exe" || p.Apps[0].Conns != 2 || p.Apps[0].Failed != 1 || p.Apps[0].Down != 9000 {
		t.Fatalf("应用首行错：%+v", p.Apps[0])
	}
	if p.Apps[1].Name != StatUnknownApp || p.Apps[1].Conns != 1 {
		t.Fatalf("未知进程那行错：%+v", p.Apps[1])
	}
	// 目标维度：10.0.0.5（两条，端口 5432）、10.0.0.9
	if p.KeysTargets != 2 {
		t.Fatalf("目标键数 = %d（想要 2）", p.KeysTargets)
	}
	if p.Targets[0].Name != "10.0.0.5" || p.Targets[0].Conns != 2 || p.Targets[0].Ports != "5432" {
		t.Fatalf("目标首行错：%+v", p.Targets[0])
	}
	if p.Targets[0].Failed != 1 {
		t.Fatalf("目标首行的失败数 = %d（想要 1）", p.Targets[0].Failed)
	}
}

// 两个口径：Start 之后「本次运行」从头数，累计不动。
func TestStatScopes(t *testing.T) {
	e := newTestEngine()
	e.finish(mkConn("a.exe", "10.0.0.5", 443, rules.ActionChain, 10, 20))

	if p := e.StatsPage(StatScopeRun, 20); p.Conns != 1 || p.Up != 10 {
		t.Fatalf("本次运行：conns=%d up=%d（想要 1 / 10）", p.Conns, p.Up)
	}
	e.stats.beginRun(time.Now()) // 相当于引擎 Start
	r := e.StatsPage(StatScopeRun, 20)
	if r.Conns != 0 || r.Up != 0 || len(r.Apps) != 0 {
		t.Fatalf("Start 之后本次运行应该是空的：%+v", r)
	}
	a := e.StatsPage(StatScopeAll, 20)
	if a.Conns != 1 || a.Up != 10 {
		t.Fatalf("Start 不该动累计口径：conns=%d up=%d（想要 1 / 10）", a.Conns, a.Up)
	}
	// 清零：两个口径都从头数
	e.ResetStats()
	if x := e.StatsPage(StatScopeAll, 20); x.Conns != 0 || x.Up != 0 {
		t.Fatalf("清零之后累计还留着数：%+v", x)
	}
}

// 还开着的连接：读快照时实时算进去；收尾之后**不重复计**。
func TestStatLiveConnCountedOnce(t *testing.T) {
	e := newTestEngine()
	live := &connState{dst: net.ParseIP("10.0.0.7"), dport: 443, action: rules.ActionChain,
		chain: "sjy", procName: "chrome.exe", appPort: 51000, start: time.Now().Add(-5 * time.Second)}
	live.up.Store(300)
	live.down.Store(700)
	live.rateUp.Store(30)
	live.rateDown.Store(70)
	e.mu.Lock()
	e.conns[51000] = live
	e.statActive++
	e.mu.Unlock()

	p := e.StatsPage(StatScopeRun, 20)
	if p.Conns != 1 || p.Active != 1 || p.Up != 300 || p.Down != 700 {
		t.Fatalf("还开着的连接没算进去：%+v", p)
	}
	if len(p.Apps) != 1 || p.Apps[0].Active != 1 || p.Apps[0].UpBps != 30 || p.Apps[0].DownBps != 70 {
		t.Fatalf("行内没有活跃数/速率：%+v", p.Apps)
	}

	e.finish(live) // 收尾：条目还留在表里（界面还要看 15 秒），但统计只能算一次
	q := e.StatsPage(StatScopeRun, 20)
	if q.Conns != 1 || q.Active != 0 || q.Up != 300 || q.Down != 700 {
		t.Fatalf("收尾之后数字变了（重复计或漏计）：%+v", q)
	}
	if len(q.Apps) != 1 || q.Apps[0].Conns != 1 || q.Apps[0].Active != 0 {
		t.Fatalf("收尾之后行内不对：%+v", q.Apps)
	}
}

// 阻断算失败；我们自己的探针不算（与「连接」页同一个口径）。
func TestStatBlockedAndSelf(t *testing.T) {
	e := newTestEngine()
	e.finish(mkConn("cmd.exe", "10.9.9.9", 22, rules.ActionBlock, 0, 0))

	probe := mkConn("nethub.exe", "10.0.0.1", 80, rules.ActionChain, 9999, 9999)
	probe.self = true
	e.finish(probe)

	p := e.StatsPage(StatScopeRun, 20)
	if p.Conns != 1 || p.Failed != 1 || p.Blocked != 1 || p.Up != 0 || p.Down != 0 {
		t.Fatalf("阻断/探针口径错：%+v", p)
	}
	if len(p.Apps) != 1 || p.Apps[0].Name != "cmd.exe" || p.Apps[0].Failed != 1 {
		t.Fatalf("阻断那条行内不对：%+v", p.Apps)
	}
}

// 目标是域名时按**名字**归并（同一个域名，无论应用是拿域名/假 IP/真实 IP 连的，都进同一行）。
func TestStatTargetNameMerging(t *testing.T) {
	e := newTestEngine()
	names := dnsmap.New()
	names.Set("his.example.com", []string{"10.0.0.5"}, 0)
	e.names = names

	// 一条按真实 IP 连的 + 一条按"我们发的假 IP"连的（假 IP 在池里，名字表也认它）
	e.finish(mkConn("his.exe", "10.0.0.5", 5432, rules.ActionChain, 100, 200))

	pool, err := fakeip.NewPool("198.19.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	e.fake = pool
	fake := pool.Assign("his.example.com", time.Minute)
	if fake == nil {
		t.Fatal("假 IP 没分到")
	}

	st := mkConn("his.exe", fake.String(), 5432, rules.ActionChain, 50, 50)
	e.finish(st)

	p := e.StatsPage(StatScopeRun, 20)
	if p.KeysTargets != 1 {
		t.Fatalf("域名与 IP 没有并成一行：keys=%d %+v", p.KeysTargets, p.Targets)
	}
	if p.Targets[0].Name != "his.example.com" || p.Targets[0].Conns != 2 {
		t.Fatalf("归并结果不对：%+v", p.Targets[0])
	}
	if p.Targets[0].IP == "" {
		t.Fatalf("域名那行应该带上实际地址（%+v）", p.Targets[0])
	}
}

// 桶上限：超出时淘汰最久没活动的，并且把"挤掉了几个"报出来。
func TestStatBucketCapEvictsOldest(t *testing.T) {
	e := newTestEngine()
	now := time.Now()
	for i := 0; i < StatBucketCap+7; i++ {
		st := mkConn("a.exe", net.IPv4(10, 1, byte(i/256), byte(i%256)).String(), 80, rules.ActionChain, 1, 1)
		e.stats.noteEnd(st, "a.exe", st.dst.String(), nil, now.Add(time.Duration(i)*time.Millisecond))
	}
	p := e.StatsPage(StatScopeRun, 1000)
	if p.KeysTargets != StatBucketCap {
		t.Fatalf("目标键数 = %d（想要 %d）", p.KeysTargets, StatBucketCap)
	}
	if p.Evicted != 7 {
		t.Fatalf("evicted = %d（想要 7）", p.Evicted)
	}
	// 合计**不随桶淘汰而丢**：合计是单独一份计数
	if p.Conns != uint64(StatBucketCap+7) {
		t.Fatalf("合计 = %d（想要 %d）—— 合计不能被桶上限影响", p.Conns, StatBucketCap+7)
	}
	if p.KeysApps != 1 {
		t.Fatalf("应用维度只有 a.exe 一个键，keys=%d", p.KeysApps)
	}
}

// TopN：表只给前 N 行，但键数与合计要报完整（别让人以为"就这么点"）。
func TestStatTopNAndTotalKeys(t *testing.T) {
	e := newTestEngine()
	now := time.Now()
	for i := 0; i < 25; i++ {
		st := mkConn("a.exe", net.IPv4(10, 2, 0, byte(i+1)).String(), 80, rules.ActionChain, uint64(100-i), 0)
		e.stats.noteEnd(st, "a.exe", st.dst.String(), nil, now)
	}
	p := e.StatsPage(StatScopeRun, 5)
	if len(p.Targets) != 5 || p.KeysTargets != 25 {
		t.Fatalf("TopN 错：rows=%d keys=%d（想要 5 / 25）", len(p.Targets), p.KeysTargets)
	}
	// 默认按流量倒序：第一个不是最大的那个就说明排序错了
	if p.Targets[0].Name != "10.2.0.1" {
		t.Fatalf("排序不对（应该流量大的在前）：%+v", p.Targets[0])
	}
}

// janitor 回收那些“应用没发 FIN 就走了”的条目：字节数必须落进统计，
// 而且**只落一次**（同一条连接被 finish 落过之后，回收时不能再算一遍）。
func TestStatJanitorCommitsRecycled(t *testing.T) {
	e := newTestEngine()

	// ① 一条“没人动的进行中”（20 分钟没动静）：只有 janitor 会收它
	stale := &connState{dst: net.ParseIP("10.0.0.8"), dport: 3306, action: rules.ActionChain,
		chain: "etyy", procName: "magic-api.exe", appPort: 52001,
		start: time.Now().Add(-40 * time.Minute), counted: true}
	stale.up.Store(111)
	stale.down.Store(222)
	stale.touch()
	stale.last.Store(time.Now().Add(-20 * time.Minute).UnixNano())

	// ② 一条正常结束过的（finish 已经落过统计）：回收时不能再落
	finished := &connState{dst: net.ParseIP("10.0.0.9"), dport: 5432, action: rules.ActionChain,
		chain: "etyy", procName: "his.exe", appPort: 52002, start: time.Now().Add(-30 * time.Minute), counted: true}
	finished.up.Store(1000)
	finished.down.Store(2000)
	finished.touch()
	finished.last.Store(time.Now().Add(-20 * time.Minute).UnixNano())

	e.mu.Lock()
	e.conns[52001] = stale
	e.conns[52002] = finished
	e.statActive = 2
	e.mu.Unlock()

	e.finish(finished) // 正常收尾（FIN/RST 那条路）—— 它会 touch()，所以把时间再拨回去：
	// 模拟“已经收尾 20 分钟了”，这时 janitor 会把它从表里物理回收
	finished.last.Store(time.Now().Add(-20 * time.Minute).UnixNano())
	e.sweepConns()

	if n := len(e.conns); n != 0 {
		t.Fatalf("两个条目都该被回收，还剩 %d 个", n)
	}
	if e.statActive != 0 {
		t.Fatalf("活跃数没扣回来：%d", e.statActive)
	}

	p := e.StatsPage(StatScopeRun, 20)
	if p.Conns != 2 {
		t.Fatalf("连接数 = %d（想要 2：一条被回收的 + 一条正常收尾的）", p.Conns)
	}
	if p.Up != 1111 || p.Down != 2222 {
		t.Fatalf("字节数 = %d/%d（想要 1111/2222）—— 多了就是重复计（回收路径又落了一遍）", p.Up, p.Down)
	}
	if len(p.Apps) != 2 {
		t.Fatalf("应用维度应该有两行：%+v", p.Apps)
	}
	for _, r := range p.Apps {
		if r.Conns != 1 {
			t.Fatalf("每个应用各一条，不该重复：%+v", r)
		}
	}
}

// 没有引擎（界面与引擎分进程时的只读态）也要能返回一个空页，而不是崩。
func TestStatPageReadonly(t *testing.T) {
	var e *Engine
	p := e.StatsPage(StatScopeRun, 0)
	if !p.Readonly || p.Conns != 0 || p.TopN != StatTopN {
		t.Fatalf("只读态应该给空页：%+v", p)
	}
}

// 「时长」= **这组数字覆盖了多久**，不是引擎/进程跑了多久。
// 两种错法都会让卡片自相矛盾，所以两条都钉住：
//
//	· 累计口径用引擎起点 → 引擎重启后显示"累计 100 条 · 时长 2 分钟"
//	· 清零之后不重置 → 显示"累计 0 条 · 时长 6 小时"
func TestStatUptimeFollowsWindow(t *testing.T) {
	e := newTestEngine()
	e.finish(mkConn("a.exe", "10.0.0.5", 443, rules.ActionChain, 10, 20))

	// 累计口径：窗口起点是"程序启动 / 上次清零"（引擎刚重启过也不动它）
	e.stats.since = time.Now().Add(-3 * time.Hour)
	e.startedAt = time.Now().Add(-2 * time.Minute) // 引擎刚重启过（只影响本次运行口径）
	e.stats.runSince = e.startedAt
	all := e.StatsPage(StatScopeAll, 20)
	if all.Uptime == "" || all.Uptime == "—" {
		t.Fatalf("累计口径该有时长: %+v", all.Uptime)
	}
	if d := durOf(t, all.Uptime); d < 170*time.Minute {
		t.Fatalf("累计口径的时长要用窗口起点（程序启动/上次清零 = 3h），得到 %s —— 用引擎起点就会出现“累计 100 条 · 时长 2 分钟”", all.Uptime)
	}

	// 本次运行口径：用引擎起点
	run := e.StatsPage(StatScopeRun, 20)
	if d := durOf(t, run.Uptime); d > 10*time.Minute {
		t.Fatalf("本次运行口径的时长要用引擎「启动」那一刻（2m），得到 %s", run.Uptime)
	}

	// 清零：窗口从头算，时长必须跟着变短（否则"累计 0 条 · 时长 6 小时"）
	e.ResetStats()
	after := e.StatsPage(StatScopeAll, 20)
	if after.Conns != 0 {
		t.Fatalf("清零没生效: %+v", after)
	}
	if d := durOf(t, after.Uptime); d > time.Minute {
		t.Fatalf("清零之后时长要跟着重算（现在应是几毫秒），得到 %s", after.Uptime)
	}
}

// durOf 把 humanDur 的输出（"3h2m" / "12s" / "5m"）解回 time.Duration。
func durOf(t *testing.T, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(strings.ReplaceAll(s, "h", "h"))
	if err == nil {
		return d
	}
	// humanDur 可能是 "6h12m"（可解析）或 "3d4h"（不可解析 → 粗略处理）
	var total time.Duration
	re := regexp.MustCompile(`(\d+)([dhms])`)
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		n, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "d":
			total += time.Duration(n) * 24 * time.Hour
		case "h":
			total += time.Duration(n) * time.Hour
		case "m":
			total += time.Duration(n) * time.Minute
		case "s":
			total += time.Duration(n) * time.Second
		}
	}
	if total == 0 {
		t.Fatalf("解不出时长: %q", s)
	}
	return total
}
