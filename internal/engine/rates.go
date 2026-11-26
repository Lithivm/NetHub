package engine

import (
	"fmt"
	"sync/atomic"
	"time"

	"nethub/internal/rules"
)

//	  得到的是"这两次拉取之间"的均值 —— 中间隔了多久就摊多久，数字会荒谬地小；
//	- 速率是"现在还在不在传"的答案，它不该受界面在不在看影响。
//
// 采样点固定每秒一次：上一拍的字节数与时刻记在**连接自己身上**（见 connState.prevAt），
// 所以引擎里不需要额外维护一张会越积越大的表。
const rateTick = time.Second

func (e *Engine) rateLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(rateTick)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			e.sampleRates(time.Now())
		}
	}
}

// sampleRates 给每条连接算一次速率，并记下这一拍供下一拍做差。
func (e *Engine) sampleRates(now time.Time) {
	nowN := now.UnixNano()
	e.mu.RLock()
	conns := make([]*connState, 0, len(e.conns))
	for _, st := range e.conns {
		conns = append(conns, st)
	}
	e.mu.RUnlock()

	var sumUp, sumDown uint64
	for _, st := range conns {
		// 我们自己的探针（自检/共存检测）不算：它不进连接列表，速率里也不该有它。
		if st.self {
			continue
		}
		// 已结束的连接速率归 0：界面上"已结束"旁边还挂着一个速率，看着像还在跑。
		if st.ended.Load() {
			st.rateUp.Store(0)
			st.rateDown.Store(0)
			continue
		}
		up, down := st.up.Load(), st.down.Load()
		prevAt := st.prevAt.Swap(nowN)
		if prevAt == 0 { // 第一次采样只记底数，速率下一拍才有
			st.prevUp.Store(up)
			st.prevDown.Store(down)
			continue
		}
		pu, pd := st.prevUp.Swap(up), st.prevDown.Swap(down)
		dt := float64(nowN-prevAt) / float64(time.Second)
		ru, rd := perSecond(up, pu, dt), perSecond(down, pd, dt)
		st.rateUp.Store(ru)
		st.rateDown.Store(rd)
		sumUp, sumDown = sumUp+ru, sumDown+rd
	}
	e.rateUp.Store(sumUp)
	e.rateDown.Store(sumDown)
}

// perSecond 两拍之间的平均速率（字节/秒）。
//
// 时钟没走（dt<=0，理论上不该有）与"计数变小了"都返回 0 而不报负值：
// 后者只可能在端口复用/重冒烟的情况下出现，宁可显示"没在传"也不能显示一个负数。
func perSecond(now, prev uint64, dt float64) uint64 {
	if dt <= 0 || now < prev {
		return 0
	}
	return uint64(float64(now-prev) / dt)
}

// Rates 全表速率合计（字节/秒，出/入方向）。
//
// 只对**当前开着的连接**有意义（已结束的被归零），是给连接列表那种“这一行还在不在传”用的。
// 画历史曲线不要用它，用 TrafficTotals 做差 —— 见 tunUp 上面的注释。
func (e *Engine) Rates() (up, down uint64) { return e.rateUp.Load(), e.rateDown.Load() }

// TrafficTotals 自本次运行起的字节总数：走链路的（tunneled）与直连的（direct）分开。
//
// 分开是为了界面上那个「也统计直连流量」开关：关着时直连的包根本不进连接表、
// 这两个数也不会涨（见 handleInbound/handleOutbound 里的 ActionDirect 分支），
// 所以调用方按开关挑口径即可 —— 开关一改，整个 60 秒窗口的表现跟着改，不会出现
// “刚关掉但图上还留着一段直连”的自相矛盾。
func (e *Engine) TrafficTotals() (tunUp, tunDown, dirUp, dirDown uint64) {
	return e.tunUp.Load(), e.tunDown.Load(), e.dirUp.Load(), e.dirDown.Load()
}

// tunTotal 这条连接该记进哪个全局计数器；我们自己的探针返回 nil（不计）。
//
// 与“探针不进连接列表、不计速率”是同一条原则（见 selfconn.go）：共存检测、自检
// 都是直接 dial 内网目标的，它们走的是**同一条 relay**，不注意就把几 KB 的探针流量
// 画进顶栏的曲线里了 —— 用户看到“没人用的时候图上有流量”。
func (e *Engine) tunTotal(st *connState, up bool) *atomic.Uint64 {
	if st == nil || st.self {
		return nil
	}
	if up {
		return &e.tunUp
	}
	return &e.tunDown
}

// janitor 定期清理已经没人用的连接条目（已结束的留得短一些）。
func (e *Engine) janitor() {
	defer e.wg.Done()
	tk := time.NewTicker(60 * time.Second)
	defer tk.Stop()
	tick := 0
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			e.pruneLoops() // A14：清掉过期的环路检测窗口
			e.pruneQUICNotices()
			e.pruneSelfPorts() // 我们自己探针登记的端口（见 selfconn.go）
			e.pruneOnce()
			e.bus.FlushThrottled() // 把“噪声停了但还是欠着”的去重计数补出来
			if tick++; tick%5 == 0 {
				e.logStatsSummary()
			}
			e.fillMissingProcs()
			e.sweepConns()
		}
	}
}

// sweepConns 回收长时间没动的连接条目（janitor 每分钟调一次）。
//
// 单独成方法是为了能被测试直接调 —— 这一段里有两个容易写错的口径：
//
//	① 只有“这一次才标结束”的条目要落统计：finish 已经落过的那些（比如正常收到 FIN）
//	   在回收时**不能再落一次**，否则同一条连接的字节数会被算两遍；
//	② 落统计必须在**锁外** —— noteStatEnd 要看进程名，拿的是读锁，在写锁里调就是自己锁自己。
func (e *Engine) sweepConns() {
	activeCut := time.Now().Add(-10 * time.Minute).UnixNano()
	endedCut := time.Now().Add(-2 * time.Minute).UnixNano()
	// recycled 这一轮**由我们标成结束**的条目，出锁后再落统计。
	var recycled []*connState
	e.mu.Lock()
	for k, st := range e.conns {
		cut := activeCut
		if st.ended.Load() {
			cut = endedCut
		}
		if st.last.Load() >= cut {
			continue
		}
		// 收尾时发现是“没人动的进行中”，把活跃数一起扣回来
		wasLive := st.ended.CompareAndSwap(false, true)
		if wasLive && e.statActive > 0 {
			e.statActive--
		}
		if wasLive {
			recycled = append(recycled, st)
		}
		delete(e.conns, k)
	}
	for k, d := range e.notices {
		if d.last.Before(time.Unix(0, activeCut)) {
			delete(e.notices, k)
		}
	}
	e.mu.Unlock()
	for _, st := range recycled {
		e.noteStatEnd(st)
	}
}

// relayGrace 拦截到 SYN 之后，等 relay 收到这条连接的时间上限。
//
// 正常路径是毫秒级（本机环回一跳）；4 秒已经比它大三个数量级，
// 而客户端 SYN 重传是 1s / 2s / 4s…，所以 4 秒足够判定“改写的包根本没到 relay”。
const relayGrace = 4 * time.Second

// relayWatch 看门狗：拦截了但 relay 没收到 → 必须报错。
//
// 为什么非有不可（真实事故）：客户端机上的安全软件/另一个代理在内核层拦走了
// 我们改写后注入的包 → 包到不了本机 relay → 客户端 SYN 无人应答，一直重传到
// 约 30 秒才放弃、再重试；而日志里只有一行“拦截 X → relay”，**既没有失败也没有下文**，
// 用户看到的就是“软件里显示一切正常，但内网访问不通”。
func (e *Engine) relayWatch() {
	defer e.wg.Done()
	tk := time.NewTicker(1500 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			e.checkUnrelayed()
		}
	}
}

// checkUnrelayed 找出“已拦截、超时仍未送达 relay”的连接，报一次错（不刷屏）。
func (e *Engine) checkUnrelayed() {
	now := time.Now()
	type bad struct {
		sport uint16
		dst   string
		chain string
		proc  string
		since time.Duration
	}
	var fresh []bad
	e.mu.RLock()
	for sport, st := range e.conns {
		if st.action != rules.ActionChain || st.ended.Load() {
			continue
		}
		if st.relayed.Load() || st.unrelayed.Load() {
			continue
		}
		if d := now.Sub(st.start); d >= relayGrace {
			fresh = append(fresh, bad{sport, fmt.Sprintf("%s:%d", st.displayTarget(), st.dport), st.chain, st.procName, d})
		}
	}
	e.mu.RUnlock()
	if len(fresh) == 0 {
		return
	}

	// 先给这几条连接打上“未送达”标记，供界面展示（幂等，不会重复报）
	for _, b := range fresh {
		e.mu.RLock()
		st := e.conns[b.sport]
		e.mu.RUnlock()
		if st == nil {
			continue
		}
		if st.unrelayed.CompareAndSwap(false, true) {
			st.fail(fmt.Sprintf("已拦截改写，但 %.0f 秒内没有送达本机 relay（正常应 <1ms）—— "+
				"基本可断定：改写的包在内核层被别的程序拦走了（安全软件 / Clash 的 TUN 模式 / 另一个代理），"+
				"或者有另一个本程序实例在抢管。客户端表现：连不上，约 30 秒后重试。", relayGrace.Seconds()))
		}
	}

	e.bus.Error("【没送达 relay】%d 条连接已被拦截改写，但 %.0f 秒内没送到本机 relay（正常 <1ms）：",
		len(fresh), relayGrace.Seconds())
	for i, b := range fresh {
		if i >= 5 {
			e.bus.Error("   …还有 %d 条", len(fresh)-5)
			break
		}
		who := b.proc
		if who == "" {
			who = "未定位到进程（系统服务/已退出）"
		}
		e.bus.Error("   %s （链 %s，%s，已等 %.1fs）", b.dst, b.chain, who, b.since.Seconds())
	}
	e.bus.Error("   怎么办：① 把内网网段加进 Clash 等代理的「绕过/直连」列表（否则它们的内核钩子会先把包吃掉）；" +
		"② 安全软件里放行 nethub.exe 与 WinDivert64.sys（火绒 6.0 的驱动要在「系统防护 → 漏洞驱动拦截 → 例外驱动」里加，只加信任区不够）；" +
		"③ 确认没有同时开着第二个 nethub；" +
		"④ 看日志开始的 `reflectwatch:` 那行 —— 它会列出本机**还有谁在用 WinDivert**（那是最可能抢包的；" +
		"注意 Clash 的 TUN 与杀软驱动不在那个列表里，它们不用 WinDivert）。")

	// 应用内也提一句（同一分钟内只说一次，避免刷屏）
	if e.Notify != nil {
		e.mu.Lock()
		if time.Since(e.unrelayedNotified) > time.Minute {
			e.unrelayedNotified = now
			e.mu.Unlock()
			e.Notify("改写的包没送到中转", fmt.Sprintf(
				"%d 条连接被拦截后卡住了（客户端会一直连不上）。\n"+
					"多半是安全软件或 Clash（TUN/系统代理）先一步把包拦走了，\n"+
					"把内网网段加进它们的直连/绕过列表，然后重启本程序。", len(fresh)), true)
		} else {
			e.mu.Unlock()
		}
	}
}
