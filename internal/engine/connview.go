package engine

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"nethub/internal/rules"
)

func (st *connState) touch() { st.last.Store(time.Now().UnixNano()) }

// realTarget 真实目标 IP（未解析到返回 nil）。
func (st *connState) realTarget() net.IP {
	if v, ok := st.realDst.Load().(net.IP); ok {
		return v
	}
	return nil
}

// displayTarget 展示/巡检用的目标：优先真实 IP，拿不到就用应用连的地址。
func (st *connState) displayTarget() net.IP {
	if r := st.realTarget(); r != nil {
		return r
	}
	return st.dst
}

func (st *connState) fail(msg string) { st.errText.Store(msg) }

// setClient 登记“应用侧那条连接”（用户手动结束它时要用）。
func (st *connState) setClient(c net.Conn) {
	if st == nil || c == nil {
		return
	}
	st.killMu.Lock()
	if st.killed {
		// 用户在建链路期间已经点了结束：直接把它关了，不往下跑
		st.killMu.Unlock()
		c.Close()
		return
	}
	st.c = c
	st.killMu.Unlock()
}

// setUpstream 登记上游连接；返回值表示“已经被用户结束过了”（调用方要立刻收摊）。
//
// 为什么需要这个返回值：拨号要几百毫秒到几秒，用户完全可能在这段时间点“结束”。
// 不告诉调用方的话，拨通后会把一条已经没人要的上游会话留在池子/协程里。
func (st *connState) setUpstream(up net.Conn) bool {
	if st == nil {
		return false
	}
	st.killMu.Lock()
	defer st.killMu.Unlock()
	if st.killed {
		if up != nil {
			up.Close()
		}
		return true
	}
	st.upConn = up
	return false
}

func (st *connState) err() string {
	if v, ok := st.errText.Load().(string); ok {
		return v
	}
	return ""
}

// TheEnd 结束时间（未结束时返回零值）。
func (st *connState) endTime() time.Time {
	if st.ended.Load() {
		return time.Unix(0, st.last.Load())
	}
	return time.Time{}
}

// finish 连接收尾：标结束、扣活跃数（幂等）。条目留给界面看，不立刻删。
func (e *Engine) finish(st *connState) {
	st.touch()
	if !st.ended.CompareAndSwap(false, true) {
		return // 已经结束过了，别重复扣活跃数
	}
	// 历史存档：只留界面看得见的这段时间之外的“刚刚那批”
	// （「当前连接」15 秒就不显示了，janitor 2 分钟物理删 —— 诊断常常来不及看）
	e.noteHistory(st)
	// 统计：这条连接的数字落进累计桶。
	// 幂等性由**上面那次 CAS** 保证：只有把 ended 从 false 翻成 true 的那一条路径会走到这里，
	// 所以 janitor 回收同一条条目时那次 CAS 一定失败，不会重复计数。
	e.noteStatEnd(st)
	// 直连/阻断的连接不走中转，也就永远不会有一行 close —— “这条直连了多少字节、
	// 活了多久”在日志里查不到。归 verbose（normal 只留开头那行 [直连]/[阻断]，不翻倍）。
	if e.bus.Verbose() && st.action != rules.ActionChain && !st.self {
		e.mu.Lock()
		procName, pid, action := st.procName, st.pid, st.action
		dst, dport := st.dst, st.dport
		e.mu.Unlock()
		kind := "direct.done"
		if action == rules.ActionBlock {
			kind = "block.done"
		}
		e.bus.Detail("%s: %s → %s ↑%s ↓%s dur=%dms", kind, connWho(procName, pid),
			e.connTarget(dst, dport), humanBytes(st.up.Load()), humanBytes(st.down.Load()),
			time.Since(st.start).Milliseconds())
	}
	// 只有建条目时**真的加过**活跃数的那条才扣：
	// 直连/阻断的条目以前不加只扣（用了 block 规则后，界面“活跃”会被持续偷走）。
	if !st.counted {
		return
	}
	e.mu.Lock()
	if e.statActive > 0 {
		e.statActive--
	}
	e.mu.Unlock()
}

// ConnView 一条连接的快照（给界面用）。
type ConnView struct {
	Target string `json:"target"`
	Action string `json:"action"`
	Chain  string `json:"chain"`
	// Sport 本地（源）端口：**一条连接的唯一标识**。
	//
	// 为什么必须给出来：同一个进程往同一个目标可以有很多条连接（浏览器对同一 origin
	// 就允许 6 条并发），界面上它们长得一模一样 —— 只有本地端口能把它们分开，
	// 也才能对着 netstat 核对。
	Sport    uint16 `json:"sport"`
	Proc     string `json:"proc"` // 发起这条连接的进程名（空 = 未知）
	PID      uint32 `json:"pid"`
	RuleNo   int    `json:"ruleNo"`   // 命中的第几条规则（0 = 没命中）
	RuleName string `json:"ruleName"` // 规则名
	Started  string `json:"started"`
	Dur      string `json:"dur"`
	// AgeSec 已存活秒数：界面把同目标的并发连接合并成一行时，靠它取“最长的那条”
	// （纯字符串的 Dur 比不了大小）。
	AgeSec  int    `json:"ageSec"`
	Up      uint64 `json:"up"`
	Down    uint64 `json:"down"`
	Packets uint64 `json:"packets"`
	// UpBps / DownBps：这条连接**当前的速率**（字节/秒；见 rateLoop 的采样）。
	//
	// 为什么必须与累计字节分开给：累计字节回答"这条一共传了多少"，回答不了
	// "现在还在不在传" —— 业务卡住时，看的就是后者（卡住的那条累计字节是正常的）。
	// 已结束的连接一律为 0（界面不该在"已结束"旁边挂一个速率）。
	UpBps   uint64 `json:"upBps"`
	DownBps uint64 `json:"downBps"`
	State   string `json:"state"`
	Error   string `json:"error"`
}

// connEndedViewKeep 已结束的连接在**界面上**还留多久。
//
// 为什么只有 15 秒：已结束的条目看的是“刚刚发生了什么”，几十秒之后没人再去看它，
// 留着只会把在跑的挤下去（一条结束的连接很快就不再提供任何信息）。
// 注意这只是**显示**窗口：条目本身仍由 janitor 按 2 分钟物理回收（见 janitor），
// 所以它不影响“最近访问过的目标”那类后台判据（recentTargets 自己一个窗口）。
const connEndedViewKeep = 15 * time.Second

// ConnsActive 界面上“进行中”的连接数。
//
// 为什么不用 statActive：那个只统计**走隧道**的连接 —— 打开“直连流量统计”之后
// 直连/阻断的行会出现在列表里却不计入，于是显示成“列了 3 条、活跃 0”，自相矛盾。
// 界面上的“活跃”就用它（同一个口径：不算自己的探针、不算已结束）。
func (e *Engine) ConnsActive() int {
	countDirect := e.cfg.CountDirectEnabled()
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, st := range e.conns {
		if st.self || st.ended.Load() {
			continue
		}
		// 直连统计关着时，直连的条目已经不处于“被观察”状态了，不能算
		if st.statsOnly && !countDirect {
			continue
		}
		n++
	}
	return n
}

// Conns 返回连接表快照：进行中在前，其余按最后活动时间倒序；limit<=0 表示不限。
//
// 已结束的只保留最近 connEndedViewKeep（15 秒）内的，更早的丢给 janitor。
//
// withProc 为真时，给还没查过进程的连接补上进程名（连接页打开时用）。
// 为什么不在建连接时无脑查：TCP 表是全量枚举，毫秒级开销；只有界面真要看到
// “是谁在连”时才值得付。**规则里写了进程条件时另一条路已经查过了**（flowProc），
// 这里只是补上那些连接。
func (e *Engine) Conns(limit int, withProc bool) []ConnView {
	e.mu.RLock()
	snap := make([]*connState, 0, len(e.conns))
	for _, st := range e.conns {
		snap = append(snap, st)
	}
	e.mu.RUnlock()

	sort.Slice(snap, func(i, j int) bool {
		ei, ej := snap[i].ended.Load(), snap[j].ended.Load()
		if ei != ej {
			return !ei // 进行中在前
		}
		return snap[i].last.Load() > snap[j].last.Load()
	})

	now := time.Now()
	endedCut := now.Add(-connEndedViewKeep).UnixNano()
	countDirect := e.cfg.CountDirectEnabled()
	out := make([]ConnView, 0, len(snap))
	for _, st := range snap {
		if limit > 0 && len(out) >= limit {
			break
		}
		// 已结束且已经过了显示窗口：界面上不再出现（“累计/按链分布”里仍然算过它）
		if st.ended.Load() && st.last.Load() < endedCut {
			continue
		}
		// 我们自己发的探针连接不进列表（见 selfconn.go：那是仪器，不是应用流量）
		if st.self {
			continue
		}
		// “直连统计”关掉后，直连的条目立即从列表消失（直到开关再打开）
		if st.statsOnly && !countDirect {
			continue
		}
		state := connStateName(st)
		end := now
		if t := st.endTime(); !t.IsZero() {
			end = t
		}
		name, pid := st.procName, st.pid
		if withProc && name == "" && e.proc != nil {
			// 只读查询，不写回 connState —— 快照是拿读锁生成的，写回会与包路径抢。
			// 代价可控：解析器自己有缓存，最多每个刷新周期多枚举一次 TCP 表。
			if n, p, ok := e.proc.ByPort(st.appPort); ok {
				name, pid = n, p
			}
		}
		out = append(out, ConnView{
			Target:   fmt.Sprintf("%s:%d", st.displayTarget(), st.dport),
			Action:   st.action.String(),
			Chain:    st.chain,
			Sport:    st.appPort,
			Proc:     name,
			PID:      pid,
			RuleNo:   st.ruleNo,
			RuleName: st.ruleName,
			Started:  st.start.Format("15:04:05"),
			Dur:      humanDur(end.Sub(st.start)),
			AgeSec:   int(end.Sub(st.start).Seconds()),
			Up:       st.up.Load(),
			Down:     st.down.Load(),
			Packets:  st.packets.Load(),
			UpBps:    st.rateUp.Load(),
			DownBps:  st.rateDown.Load(),
			State:    state,
			Error:    st.err(),
		})
	}
	return out
}

// logStatsSummary 每 5 分钟一行流量概览。
//
// 为什么要有：现场拿到一段日志，第一句要问的是“这 5 分钟大概多少连接、有没有断”，
// 而不是从几十行连接日志里数（Envoy/squid 那类访问日志也是先看总量再看单条）。
// 只报事实（总数/新增/在途/分链），不做任何解读。
func (e *Engine) logStatsSummary() {
	e.mu.Lock()
	total, active, prev := e.statTotal, e.statActive, e.statSummaryAt
	e.statSummaryAt = total
	counts := make(map[string]uint64, len(e.statPerRule))
	for k, v := range e.statPerRule {
		counts[k] = v
	}
	e.mu.Unlock()

	type kv struct {
		chain string
		n     uint64
	}
	list := make([]kv, 0, len(counts))
	for k, v := range counts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].chain < list[j].chain
	})
	const maxChain = 4
	var b strings.Builder
	for i, x := range list {
		if i == maxChain {
			fmt.Fprintf(&b, ",+%d", len(list)-maxChain)
			break
		}
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s:%d", x.chain, x.n)
	}
	// 两张会随运行时间变化的表（名字表 / 假 IP 池）也报出来 ——
	// 客户机连跑几个月，"到底住不住"要看的就是这几个数，光看进程内存看不出是哪个表在涨。
	// 详见 local/memwatch.ps1 的采样与 KB 的长跑结论。
	names, fakeUsed, fakeCap := 0, 0, 0
	if e.names != nil {
		names = len(e.names.Status())
	}
	if e.fake != nil {
		fakeUsed, fakeCap = e.fake.Stats()
	}
	// 周期快照：这是**仪表盘数据**（界面上的连接/名字表/假 IP 池本来就显示着），
	// 不是“刚发生了什么事”—— 按 Proxifier 的三档定义归 verbose。
	// 要看它时切 verbose（local/memwatch.ps1 就是这么采样的）。
	e.bus.Detail("stats: total=%d new=%d active=%d names=%d fake=%d/%d chain=%s",
		total, total-prev, active, names, fakeUsed, fakeCap, b.String())
}

// fillMissingProcs 给“还在活动、但进程名还没查到”的连接补一次查询（janitor 调）。
//
// 为什么需要它：flowProc 只能靠**包**触发重试，而空闲的长连接（典型的 HIS 会话）
// 建立之后可能几秒到几分钟没包 —— 那它的进程名就永远补不上，界面上一直是“未知”。
// 每分钟补一次、每次最多 200 条，代价可忽略。
func (e *Engine) fillMissingProcs() {
	if e.proc == nil {
		return
	}
	now := time.Now().UnixNano()
	cut := now - int64(10*time.Minute) // 只补还在活动的（和 janitor 的清理窗口一致）

	e.mu.Lock()
	type want struct {
		st   *connState
		port uint16
	}
	list := make([]want, 0, 16)
	for port, st := range e.conns {
		if st.procName != "" || st.ended.Load() || st.last.Load() < cut {
			continue
		}
		list = append(list, want{st, port})
		if len(list) >= 200 {
			break
		}
	}
	e.mu.Unlock()
	for _, w := range list {
		if n, pid, ok := e.proc.ByPort(w.port); ok {
			e.mu.Lock()
			w.st.procName, w.st.pid = n, pid
			e.mu.Unlock()
		}
	}
}

// ChainCounts 每条链累计接管了多少条连接。
func (e *Engine) ChainCounts() map[string]uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]uint64, len(e.statPerRule))
	for k, v := range e.statPerRule {
		out[k] = v
	}
	return out
}
