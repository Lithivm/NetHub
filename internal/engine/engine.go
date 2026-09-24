// Package engine 是核心：用 WinDivert 在内核层拦截"目标落在规则网段内的 TCP 连接"，
// 改写地址把它劫持到本地 relay，再由 relay 经 gost 的本地 socks5 端口转发出去。
//
// 为什么这样设计（而不是 PAC / 应用配合）：
//   - 数据库协议（PostgreSQL/MySQL）、Navicat、以及任何未知客户端都不认系统代理，
//     只有驱动级透明接管才能一次覆盖全部，且应用零改动。
//   - WinDivert 的 filter 在内核层生效，只有命中网段的包进用户态，
//     其余流量（公网、视频、微信）根本不经过我们 —— 顺带天然防循环。
//
// 关键实现细节（都是实测踩出来的，别改）：
//   - 改写目标的同时**必须把源 IP 也改成 relay 的 IP**，否则 Windows 在环回口
//     丢弃"非环回源地址"的包，劫持会静默失败。
//   - 注入时保留 addr 的 Outbound 标志（Flags 的 bit1），不要去翻转它。
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"nethub/internal/dnsmap"
	"nethub/internal/dnssniff"
	"nethub/internal/fakeip"
	"nethub/internal/tlsname"
	"nethub/internal/winrun"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/config"
	"nethub/internal/logbus"
	"nethub/internal/proc"
	"nethub/internal/rules"
	"nethub/internal/upstream"
)

const (
	offSrcIP   = 12
	offDstIP   = 16
	offProto   = 9
	offSrcPort = 0
	offDstPort = 2
	offFlags   = 13 // FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10
)

// connState 一条被接管的连接（隧道/直连/阻断共用一张表，按源端口索引）。
//
// 计数与时间戳用原子操作：字节累加发生在 relay 的两条拷贝协程里，包计数发生在
// packetLoop 里，两条路径并发，不能共用 e.mu（否则每个包都要抢锁）。
//
// 连接结束后条目**不删**：留着让界面能看到最后状态与字节数，由 janitor 按
// 更短的时限回收（已结束 2 分钟 / 进行中 10 分钟）。
type connState struct {
	dst     net.IP
	dport   uint16
	app     net.IP
	appPort uint16
	chain   string
	action  rules.Action
	start   time.Time

	// ruleNo / ruleName：这条连接命中了哪条规则（1 起；0 = 没命中）。
	// 日志与界面都拿它回答“为什么走了这条链”，与 chain 一样**发布后不再改**。
	ruleNo   int
	ruleName string

	// 进程名 / PID（A20）：SYN 时查一次，建 connState 前就写定 → 发布后不再改，无需加锁。
	// 空串 = 查不到（受保护进程/系统服务/已消失）——界面显示“未知”。
	procName string
	pid      uint32
	// procTries / procNext：已查几次、以及下一次最早什么时候再查。
	//
	// 为什么不缓存“查不到”，也不连着重试：实测（proc.lookup 详细日志）连接刚建时
	// 这个端口**还不在 TCP 表里**（后台 500ms 一刷，短连接总是差一拍），
	// 而连着重试三次也都在几十毫秒内用完了（表还是没刷新）。
	// 所以按**时间间隔**重试（最多 5 次、每次至少隔 200ms）：
	// 短连接只试一次（便宜），长会话（真正要排障的那些）会被后续包补上。
	procTries atomic.Int32
	procNext  atomic.Int64

	// counted 建这条条目时加过 statActive（只有走 relay 的连接加）。
	// finish 据此决定要不要扣 —— 否则直连/阻断的条目会把活跃数越扣越少。
	counted bool

	// fakeName/realDst：DNS 接管相关。目标是我们发的假 IP 时，fakeName 是它对应的
	// 域名，realDst 是这个域名在本机解析出的**真实 IP**（假 IP 绝不能拿去连）。
	//
	// ⚠ st.dst 是“**应用实际连的那个地址**”（假 IP 场景下就是假 IP），**发布后不再修改**：
	//   - rewriteInbound 必须用它作回包源地址，否则应用内核不认（它连的是假 IP）；
	//   - 它同时还被 Conns/recentTargets/checkUnrelayed 在锁下读，改了就是数据竞争。
	// 真实 IP 只用于拨号与展示，存在 realDst（原子，允许在包路径之外写）。
	fakeName string
	realDst  atomic.Value // net.IP：本机解析出的真实 IP（未解析到时为 nil）

	last    atomic.Int64  // unix nano：最后一次看到包/数据的时间
	up      atomic.Uint64 // 应用 → 目标 的字节（直连只能统计出方向）
	down    atomic.Uint64 // 目标 → 应用 的字节
	packets atomic.Uint64 // 包数（直连/阻断时用得上）
	ended   atomic.Bool
	errText atomic.Value // string：失败原因（如隧道建立失败）

	// relayed / unrelayed：看门狗用（真实事故，见 AGENTS.md）。
	// relayed = relay 真的收到了这条连接（handleConn 开始处理时置位）；
	// 如果 SYN 被改写注入后**迟迟没有**送达 relay，客户端会卡到 SYN 重传耗尽（约 30s）
	// 然后重试 —— 而旧版代码在这条路径上一条日志都不打，看着“一切正常”。
	relayed   atomic.Bool
	unrelayed atomic.Bool
}

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
	Target  string `json:"target"`
	Action  string `json:"action"`
	Chain   string `json:"chain"`
	Proc    string `json:"proc"` // 发起这条连接的进程名（空 = 未知）
	PID     uint32 `json:"pid"`
	Started string `json:"started"`
	Dur     string `json:"dur"`
	Up      uint64 `json:"up"`
	Down    uint64 `json:"down"`
	Packets uint64 `json:"packets"`
	State   string `json:"state"`
	Error   string `json:"error"`
}

// Conns 返回连接表快照：进行中在前，其余按最后活动时间倒序；limit<=0 表示不限。
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
	out := make([]ConnView, 0, len(snap))
	for _, st := range snap {
		if limit > 0 && len(out) >= limit {
			break
		}
		state := "进行中"
		switch {
		case st.unrelayed.Load():
			state = "未送达中转"
		case st.action == rules.ActionBlock:
			state = "已阻断"
		case st.err() != "":
			state = "失败"
		case st.ended.Load():
			state = "已结束"
		}
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
			Target:  fmt.Sprintf("%s:%d", st.displayTarget(), st.dport),
			Action:  st.action.String(),
			Chain:   st.chain,
			Proc:    name,
			PID:     pid,
			Started: st.start.Format("15:04:05"),
			Dur:     humanDur(end.Sub(st.start)),
			Up:      st.up.Load(),
			Down:    st.down.Load(),
			Packets: st.packets.Load(),
			State:   state,
			Error:   st.err(),
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
	e.bus.Info("stats: total=%d new=%d active=%d chain=%s", total, total-prev, active, b.String())
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

type Engine struct {
	bus *logbus.Bus
	// rules 当前生效的规则集。用**原子指针**而不是普通字段：规则可以热替换
	// （见 ReloadRules），而包路径上每个包都要匹配一次 —— 不能被锁挡住，
	// 也不能读到半更新的状态（读到旧集或新集都可以，读到半个就是崩溃）。
	rules atomic.Pointer[rules.Set]
	cfg   *config.Config

	mu     sync.RWMutex
	handle *divert.Handle
	// mainStop 主句柄的停止信号：热重载要换主句柄，靠它区分“我们在换”与“过滤器出错”。
	// mainFilter 当前主过滤器原文：重载时比对，没变就不折腾句柄（省一次开/关）。
	mainStop   chan struct{}
	mainFilter string
	// dynHandle 第二只句柄：只装「通配域名当前覆盖到的 IP」。
	// 通配域名没法主动解析，只能等观察到应用的 DNS 应答才知道 IP，
	// 所以它必须可热替换（先开新的、再关旧的，中间不丢包）。
	dynHandle *divert.Handle
	dynStop   chan struct{}
	dynFilter string
	dynAt     time.Time
	// dnsSeen/dnsLearn/sniLearn 只读嗅探的统计（界面与日志用）。
	dnsSeen  atomic.Uint64
	dnsLearn atomic.Uint64
	sniLearn atomic.Uint64
	// quicBlocked 累计拦下的 QUIC 包数；quicNotices 是日志去重（目标 → 上次报的时间，
	// 一次浏览能刷出上百个 QUIC 包，逐个记会把日志淹掉）。
	quicBlocked atomic.Uint64
	quicNotices map[string]time.Time
	// onceAt 通用的“这件事刚说过”记录（见 noteOnce）：键 → 上次说的时刻。
	// 只给“重复出现也没有新信息”的日志用（如同一个域名又用了 ECH）。
	onceAt map[string]time.Time
	// fake/injector/tookOver/tookSeen：DNS 接管（发假 IP）。
	fake     *fakeip.Pool
	injector *divert.Handle // filter=false 的“只塞”句柄

	// 只读噢探句柄（dnsLoop / sniLoop 各自 Open 的）：它们阻塞在自己的 Recv 上，
	// 关 e.done 唤醒不了 —— Stop 必须主动 Close，否则 wg.Wait() 卡住、退不出去。
	sniffMu      sync.Mutex
	sniffHandles []*divert.Handle
	sniffClosing bool
	tookOver     atomic.Uint64
	tookSeen     map[string]bool
	dnsBox       *dnsBlackbox // 排查用：DNS 黑匣子（tuning.dns_blackbox 打开时才有）
	// tunBlocked 本机已有别的 TUN 模式代理在接管流量（检测到就自动让路）。
	// 每次 Start 都要重新问一次：上一轮开着 Clash TUN、这轮关掉了，
	// 如果这个标记不复位，我们会一直“让路”（不学名字、不接管 DNS）却谁也看不出来。
	tunBlocked bool
	// dohSeen 已报过的加密 DNS 端点（避免刷屏）。
	dohSeen map[string]bool
	// dynDirty/dynLast 动态过滤器的重建节流（见 onWildcardsChanged）。
	dynDirty chan struct{}
	dynLast  atomic.Int64
	ln       net.Listener
	relay    string
	conns    map[uint16]*connState
	notices  map[uint16]noticeSeen    // 直连/阻断日志去重：源端口 → 上次报过的动作+目标
	health   map[string][]*upHealth   // 每条链的上游健康（与 Upstreams() 下标对齐）
	targets  map[string]*targetHealth // 业务目标巡检结果（按 ip:port 索引）
	round    int                      // 轮询策略的游标
	run      bool

	// 统计
	statTotal   uint64
	statActive  int
	statPerRule map[string]uint64
	// statSummaryAt 上一次“5 分钟概览”时的累计连接数（算增量用）。
	statSummaryAt uint64

	// startMu 串行化 Start/Stop：两者都要能在同一个 Engine 上反复调用
	// （托盘“停止 → 启动”、界面重启都会走到），且不能互相插队。
	startMu sync.Mutex
	stopped bool // 已停过（Stop 幂等用；Start 时清掉）

	// fatalMu/fatal 记下“拦截已中断”的原因（驱动被卸载、句柄被抢等）
	fatalMu sync.Mutex
	fatal   error

	// loop 环路检测（A14）：与其它代理共存时发现自己打转
	loop *loopGuard

	// unrelayedNotified 上次因“包没送到 relay”弹应用内提示的时间（节流用）
	unrelayedNotified time.Time

	// cap 抓包（A19）：按需把包写成 pcap
	cap *capturer

	// relayConns 在途的 relay 连接（Stop 时逐个关掉）。
	// 以前这些连接不进 wg 也不被关：界面说“已停止”了，隧道还在转发；
	// 而它们跨轮结束后还会去扣**新一轮**的活跃数。
	relayConns map[net.Conn]struct{}

	// pool 预热连接池（A11）：养着“已握手、只差 CONNECT”的会话
	pool *warmPool

	// proc 端口→进程（A20）：只在规则里写了进程条件时才查（见 rules.NeedsProc）
	proc *proc.Resolver

	// names 域名↔IP 映射（域名规则 + 把域名交给上游都用它）
	names *dnsmap.Map

	done chan struct{}
	wg   sync.WaitGroup

	// Notify 由上层（App）注入：把"状态变化"变成应用内提示。
	// 第二个参数为 true 表示是不好的消息。
	Notify func(title, text string, bad bool)
}

func New(bus *logbus.Bus, rs *rules.Set, cfg *config.Config) *Engine {
	e := &Engine{
		bus: bus, cfg: cfg,
		conns:       map[uint16]*connState{},
		statPerRule: map[string]uint64{},
		done:        make(chan struct{}),
		pool:        newWarmPool(),
		loop:        newLoopGuard(),
		cap:         newCapturer(),
		proc:        proc.NewResolver(),
		names:       dnsmap.New(),
		dynDirty:    make(chan struct{}, 1),
		// quicNotices 必须在这里建好：向 nil map 写入会 panic，而在 GUI 构建里
		// （-H=windowsgui，没有控制台）goroutine 的 panic 是**静默**的 ——
		// 整个进程直接消失、日志里一个字都没有。实测踩过这一下。
		quicNotices: map[string]time.Time{},
	}
	e.rules.Store(rs)
	return e
}

// ruleSet 当前生效的规则集（永不为 nil，New 已装入；ReloadRules 只换非 nil 的）。
func (e *Engine) ruleSet() *rules.Set { return e.rules.Load() }

// startLoop 起一个受 WaitGroup 跟踪、且有 panic 兜底的常驻协程。
//
// 每个循环各自 Add(1)，**不要用固定数字** —— 条件分支一多就必然算错：曾经写成
// Add(10)，而没有通配域名规则（或命中 TUN 让路）时只起了 8 个，于是 Stop 里的
// wg.Wait() 永远不返回；开了 TLS 嗅探又多一次 Done，直接把计数打成负数 panic。
//
// 兜底 panic 为什么必需：GUI 构建没有控制台（-H=windowsgui），goroutine 里的 panic
// 会把整个进程直接带走，而 stderr 无处可去 —— 现场只能看到“程序突然没了”，
// 日志里一个字都没有，连个下手的地方都没有（实测踩过）。
func (e *Engine) startLoop(name string, fn func()) {
	e.wg.Add(1)
	go e.guard(name, fn)
}

// guard 跑一个循环并兜住 panic。
//
// 循环自己 defer 的 wg.Done() 在 panic 展开时**照常执行**，所以计数不会漏；
// 这里只负责把栈写进日志、把引擎置成“已中断”，再把消息弹给用户。
func (e *Engine) guard(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			e.reportPanic(name, r)
		}
	}()
	fn()
}

// reportPanic 把一个 panic 变成“能查的东西”：日志里有栈、界面/托盘有提示。
func (e *Engine) reportPanic(name string, r any) {
	err := fmt.Errorf("%s 内部错误: %v", name, r)
	e.bus.Error("engine.panic: loop=%s err=%v", name, r)
	for _, line := range strings.Split(string(debug.Stack()), "\n") {
		e.bus.Error("    %s", line)
	}
	e.setFatal(err)
	if e.Notify != nil {
		e.Notify("引擎内部错误", fmt.Sprintf("%s 出错了：%v（已在日志里记下调用栈，请重启服务）", name, r), true)
	}
}

// trackSniff 登记一个只读噢探句柄；返回 false 表示已经在停止中（调用方直接退出即可）。
func (e *Engine) trackSniff(h *divert.Handle) bool {
	e.sniffMu.Lock()
	defer e.sniffMu.Unlock()
	if e.sniffClosing {
		return false
	}
	e.sniffHandles = append(e.sniffHandles, h)
	return true
}

// closeSniffHandles 关闭所有只读噢探句柄（Stop 时调，用来唤醒卡在 Recv 的循环）。
func (e *Engine) closeSniffHandles() {
	e.sniffMu.Lock()
	e.sniffClosing = true
	hs := e.sniffHandles
	e.sniffHandles = nil
	e.sniffMu.Unlock()
	for _, h := range hs {
		h.Close()
	}
}

// PoolStats 预热连接池的近况：命中次数、建了多少、当前养着几条。
func (e *Engine) PoolStats() (taken, made, warm uint64) { return e.pool.stats() }

// Running 是否在拦截中。
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.run
}

// RelayAddr 当前 relay 监听地址。
func (e *Engine) RelayAddr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.relay
}

// RuleCount 当前生效的规则条数（运行态自报用：外部据此核验“热重载到底吃进去没有”）。
func (e *Engine) RuleCount() int { return len(e.ruleSet().List()) }

// Stats 返回 (累计连接数, 当前活跃数)。
func (e *Engine) Stats() (uint64, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statTotal, e.statActive
}

// Start 启动拦截。返回后即处于运行状态。
func (e *Engine) Start() error {
	e.startMu.Lock()
	defer e.startMu.Unlock()

	e.setFatal(nil)      // 重新启动就清掉“已中断”状态
	e.tunBlocked = false // 上一轮的让路结论不带进这一轮（见字段注释）
	e.mu.Lock()
	if e.run {
		e.mu.Unlock()
		return fmt.Errorf("已在运行")
	}
	// 允许 Stop 之后再 Start：done/stopped 是“一次性”的，在这里重置。
	// 托盘与界面都有“停止 → 启动”这条路径，不重置的话新协程会立刻读到已关闭的 done。
	e.done = make(chan struct{})
	e.stopped = false
	// 清掉上一轮遗留的连接表与活跃计数（句柄、relay 都是新的）
	e.conns = map[uint16]*connState{}
	e.notices = nil
	e.statActive = 0
	// 动态过滤器也要清：旧句柄已在 Stop 里关了，如果不清 dynFilter，
	// 重启后 rebuildDynFilter 会因为“过滤器字符串没变”直接 return，
	// 于是通配域名的第二只句柄永远建不起来（静默失效）。
	e.dynHandle, e.dynStop, e.dynFilter, e.dynAt = nil, nil, "", time.Time{}
	// 主过滤器同理：句柄与过滤器原文一起重置，否则重启后主句柄的字段指向旧句柄。
	e.mainStop, e.mainFilter = nil, ""
	e.mu.Unlock()
	e.sniffMu.Lock()
	e.sniffClosing, e.sniffHandles = false, nil
	e.sniffMu.Unlock()
	if e.proc != nil {
		e.proc.Start() // 端口→进程 的后台刷新（幂等、可重启）
	}

	// 1) 先起 relay，拿到真实端口（端口可能配的是 0=自动分配，过滤器要用它）
	ln, err := net.Listen("tcp", e.cfg.RelayAddr())
	if err != nil {
		return fmt.Errorf("relay 监听 %s 失败: %w", e.cfg.RelayAddr(), err)
	}
	relay := ln.Addr().String()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// 域名规则：先把域名解析成 IP（供匹配与过滤器用），再装配过滤器。
	// 必须在 buildFilter 之前 —— 否则这些 IP 不在过滤器里，包根本不到我们手上。
	// （实测 0ms：域名规则本来就少，hosts 里的名字还是直接查文件的）
	e.resolveHostTargets(false)

	// 启动时读一次 Windows DNS 客户端缓存：把“NetHub 启动之前就解析过”的名字
	// 也灌进名字表（顺带覆盖系统级 DoH —— 那种场景看不到明文报文，但缓存照写）。
	//
	// ⚠ 必须放**后台**：本机实测这一步要 16.3 秒（缓存条目多 + 逐条 DnsQuery_A），
	// 而它只补“按名字匹配的覆盖面”，不影响服务立即可用 —— 以前“服务已就绪”
	// 就被它噎住 16 秒（点完启动半天没反应）。它只动名字表，结果经
	// applyHostIPs → 动态过滤器补上（先开新句柄再关旧的，零丢包）。
	if e.ruleSet().HasWildcards() {
		// seedDNSCache 要 16s 且中途不可中断：**不计入 wg**，否则退出/重启要等它。
		// 它只写名字表（线程安全），跑完顺带重建过滤器，不跑完也不影响服务可用。
		go e.seedDNSCache()
	}

	// DNS 接管（发假 IP）：池子在这里建，它覆盖的**整段**假 IP 要进主过滤器 ——
	// 应用拿到假 IP 后会去连它，那段地址不在过滤器里的话包到不了我们手上。
	var fakeRange *net.IPNet
	if e.ruleSet().HasWildcards() && e.cfg.DNSTakeoverEnabled() {
		pool, perr := fakeip.NewPool(e.cfg.FakeIPRangeOr())
		if perr != nil {
			e.bus.Error("DNS 接管：假 IP 段不可用（%v）—— 退回只读嗅探（域名通配仍能用，但首次连接可能漏）", perr)
		} else {
			e.fake = pool
			fakeRange = pool.Range()
		}
	}

	// 2) 用规则区间拼内核过滤器（直连规则的目标不进过滤器，见 rules.FilterRanges）
	filter, nrange := e.buildMainFilter(e.ruleSet(), port)
	if filter == "" {
		ln.Close()
		return fmt.Errorf("没有需要拦截的规则（只填了直连规则时无事可做）")
	}
	if fakeRange != nil {
		e.bus.Info("DNS 接管：假 IP 段 %s 已并入过滤器", fakeRange)
	}
	e.bus.Info("filter.main: rules=%d ranges=%d filter=%s", len(e.ruleSet().List()), nrange, filter)

	// 3) 打开 WinDivert（含首次安装驱动的重试）
	h, err := openDivert(e.bus, filter)
	if err != nil {
		ln.Close()
		return fmt.Errorf("WinDivert 打开失败: %w", err)
	}
	e.mu.Lock()
	stop := make(chan struct{})
	e.ln, e.relay, e.handle, e.mainStop, e.mainFilter, e.run = ln, relay, h, stop, filter, true
	e.mu.Unlock()

	e.bus.Info("engine.start: relay=%s rules=%d", relay, len(e.ruleSet().List()))
	for _, r := range e.ruleSet().List() {
		switch r.Action {
		case rules.ActionDirect:
			e.bus.Info("route: %s action=direct", r.Label())
		case rules.ActionBlock:
			e.bus.Info("route: %s action=block", r.Label())
		default:
			e.bus.Info("route: %s action=chain/%s", r.Label(), r.Chain)
		}
	}
	for _, ch := range e.cfg.ChainsSnapshot() {
		e.bus.Info("    链 %s：%d 个上游，策略 %s，探测 %s",
			ch.Name, len(ch.Upstreams()), ch.StrategyName(), ch.ProbeInterval())
	}
	if e.cfg.BuiltinDirectEnabled() {
		e.bus.Info("builtin.direct: tcp dport=%d 直连（Windows 更新传递优化；关掉：tuning.builtin_direct_disabled: true）",
			builtinDirectPort)
	}

	e.startLoop("acceptLoop", e.acceptLoop)
	e.startLoop("packetLoop", func() { e.packetLoop(h, stop, loopMain) })
	e.startLoop("janitor", e.janitor)
	e.startLoop("relayWatch", e.relayWatch)
	e.startLoop("nameLoop", e.nameLoop)
	e.startLoop("healthLoop", e.healthLoop)
	e.startLoop("targetLoop", e.targetLoop)
	e.startLoop("localNetLoop", e.localNetLoop)
	// 只读嗅探 DNS + SNI/Host：只有真的用了通配域名才开（否则一分钱不花）。
	// 它们负责把“应用实际要去哪个名字”学回来，并维护动态过滤器。
	if e.ruleSet().HasWildcards() {
		// 先看本机是不是已经有别的程序在用 TUN 模式接管流量（多为 Clash/mihomo）：
		// TUN 与我们的透明接管互斥 —— 那时包根本到不了我们手上，继续“假装在工作”
		// 是最坏的结果，所以直接说清楚并**不开**嗅探/接管（把 DNS 让给对方）。
		tun := detectTun()
		if tun.Active() {
			e.bus.Error("检测到本机已有 TUN 模式的代理在接管流量：%s", tun.Summary())
			e.bus.Error("  —— TUN 模式与 NetHub 的透明接管互斥（全机流量与 DNS 都被它抓走），两者只能二选一。" +
				"域名通配的名字学习与 DNS 接管已自动让路（不启动）；请关掉对方的 TUN，或只用按 IP 段的规则")
			e.tunBlocked = true
		}
	}
	if e.ruleSet().HasWildcards() && !e.tunBlocked {
		e.startLoop("dnsLoop", e.dnsLoop)
		e.startLoop("dynFilterLoop", e.dynFilterLoop)
		// SNI/Host：应对加密 DNS（DoH/DoT）与自带解析器的客户端 ——
		// 那条路看不了 DNS，但握手是明文的。可在设置里关掉。
		if e.cfg.TLSSniffEnabled() {
			e.startLoop("sniLoop", e.sniLoop)
		}
		// 名字表跨重启保留着（学习结果不清空），但动态过滤器是上一轮关掉的，
		// 这里按当前已覆盖到的 IP 直接建起来，否则得等下一次 DNS 观测才恢复。
		e.rebuildDynFilter()
	}
	// DNS 接管：不再新开“看”的句柄（实测过：再开一只句柄即使只读，也会把整个 DNS
	// 搞熄）——看查询复用上面那只早已跑通的 dnsLoop 嗅探句柄；
	// 这里只新开一只 **filter=false** 的“只塞”句柄（什么也不匹配 → 结构上不可能
	// 影响任何流量），用来把假 IP 应答注进去。
	if e.fake != nil && e.tunBlocked {
		e.bus.Warn("DNS 接管：因本机已被 TUN 模式代理接管，本次不启动（让路）")
		e.fake = nil
	}
	if e.fake != nil {
		dh, derr := divert.Open("false", divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if derr != nil {
			e.bus.Warn("DNS 接管：注入句柄打开失败（%v）—— 退回只读嗅探", derr)
			e.fake = nil
		} else {
			e.mu.Lock()
			if e.run {
				e.injector = dh
			} else {
				dh = nil
			}
			e.mu.Unlock()
			if dh != nil {
				if e.cfg.DNSBlackboxEnabled() {
					e.dnsBox = openDNSBlackbox(dnsBlackboxPath(), 4<<20)
					e.bus.Info("DNS 接管：黑匣子已开启（%s）—— 每个查询/每次回答都记在里面", dnsBlackboxPath())
				}
				e.bus.Info("dns.takeover: started observe=shared-sniff inject=filter-false range=%s", e.fake.Range())
				e.startLoop("dnsTakeoverGuard", e.dnsTakeoverGuard)
			}
		}
	}
	return nil
}

// setFatal 记下“拦截已中断”的原因（nil = 正常）。
func (e *Engine) setFatal(err error) {
	e.fatalMu.Lock()
	e.fatal = err
	e.fatalMu.Unlock()
}

// Fatal 拦截是否已意外中断；中断后界面不该再显示“运行中”。
func (e *Engine) Fatal() error {
	e.fatalMu.Lock()
	defer e.fatalMu.Unlock()
	return e.fatal
}

// Stop 停止拦截：关句柄（让 packetLoop 的 Recv 立刻返回）、关 relay、等协程退完。
//
// 幂等，且 Stop 之后可以再次 Start（状态在 Start 里重置）。
func (e *Engine) Stop() {
	e.startMu.Lock()
	defer e.startMu.Unlock()

	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return // 已经停过了
	}
	e.stopped = true
	h, ln, run := e.handle, e.ln, e.run
	mainStop := e.mainStop
	dyn, dynStop := e.dynHandle, e.dynStop
	inj := e.injector
	done := e.done
	running := make([]net.Conn, 0, len(e.relayConns))
	for c := range e.relayConns {
		running = append(running, c)
	}
	e.handle, e.ln, e.run = nil, nil, false
	e.mainStop = nil
	e.dynHandle, e.dynStop = nil, nil
	e.injector = nil
	e.mu.Unlock()

	e.pool.closeAll() // 池里的会话要主动关，否则退出时留下悬挂连接
	if e.proc != nil {
		e.proc.Stop()
	}

	if done != nil {
		close(done)
	}
	if mainStop != nil {
		close(mainStop) // 同上：让主句柄的循环知道“不是出错，是我们在停”
	}
	if h != nil {
		h.Close() // 让 packetLoop 的 Recv 立刻返回错误
	}
	if inj != nil {
		inj.Close()
	}
	e.dnsBox.Close()
	if dynStop != nil {
		close(dynStop) // 告诉动态句柄的循环“不是出错，是我们在换它”
	}
	if dyn != nil {
		dyn.Close()
	}
	if ln != nil {
		ln.Close()
	}
	// 在途 relay 连接也要关：否则界面/托盘说“拦截与隧道均已关闭”、hosts 也撤了，
	// 实际上这些隧道还在继续转发（现场表现是“停了服务业务还在跑”）。
	// 关完再 wg.Wait，能确保它们真的收尾了。
	for _, c := range running {
		_ = c.Close()
	}
	// 只读噢探句柄也要关：它们阻塞在 Recv 上，不关就永远不返回（wg.Wait 卡住）。
	e.closeSniffHandles()
	e.wg.Wait()
	if run {
		e.bus.Info("engine.stop")
	}
}

// ErrNotRunning 引擎没在跑时拒绝热重载（调用方当作“已落盘、运行实例在用旧规则”处理）。
var ErrNotRunning = errors.New("引擎没有在运行")

// ReloadRules 用新编译好的规则集替换正在跑的规则集（**不重启**引擎）。
//
// 语义（三条都要说清，界面文案也照这个写）：
//   - **新连接**按新规则判定；**已经在跑的连接不受影响** —— 它们的链/动作在建立时
//     就定好了（relay 不会中途改道），所以改规则不会踢掉正在用的业务。
//   - 内核过滤器按新区间重建：先开新句柄、再关旧句柄，中间不丢包（与动态过滤器同法）。
//     过滤器没变时（只改了链/顺序/进程条件）连句柄都不换。
//   - 学到的状态要继承：本机地址、名字表（通配域名靠它命中）。不继承＝通配规则
//     “忘掉”之前学过的名字，表现为“刚还好好的，重载后不通”。
//
// 不在这里处理的东西（改了仍要重启）：relay 端口、DNS 接管开关与假 IP 段、
// 上游拨号参数（预热池按启动时的 tuning 建）。哪些没生效由 App 说清楚。
func (e *Engine) ReloadRules(ns *rules.Set) error {
	if ns == nil {
		return errors.New("规则集为空")
	}
	// 与 Start/Stop 互斥：否则可能在 Stop 的 wg.Wait() 途中 Add(1)，那是错用法。
	e.startMu.Lock()
	defer e.startMu.Unlock()

	// 学习态继承。本机地址先照搬（localNetLoop 下一轮还会再写，这里先给上不留空窗）。
	ns.SetLocalIPs(e.ruleSet().LocalIPs())
	e.applyHostIPsTo(ns) // 名字表 → hostIPs（含通配规则命中的名字）

	rulesN := len(ns.List())
	e.mu.Lock()
	if !e.run {
		e.mu.Unlock()
		return ErrNotRunning
	}
	// 用当前**真实** relay 端口算新过滤器（配置里可能是 0=自动分配）
	newFilter, nrange := e.buildMainFilter(ns, portOf(e.relay))
	changed := newFilter != "" && newFilter != e.mainFilter
	e.mu.Unlock()

	if newFilter == "" {
		// 新规则一条都不需要拦（全改成直连/全停用）：规则换掉，旧句柄留着。
		// 旧句柄上还会来包，但已匹配不到任何规则 → packetLoop 原样放回，不影响流量。
		e.rules.Store(ns)
		e.bus.Info("rules.reload: rules=%d ranges=0 filter=none（不再拦截任何网段）", rulesN)
		return nil
	}
	if !changed {
		e.rules.Store(ns)
		e.bus.Info("rules.reload: rules=%d ranges=%d filter=unchanged", rulesN, nrange)
		return nil
	}

	// 先开新句柄：开不了就当这次重载没发生（绝不半生效 —— 规则换了但包拦不到
	// 是最坏的结果：新网段的流量会静默直连出去）。
	nh, err := openDivert(e.bus, newFilter)
	if err != nil {
		return fmt.Errorf("新过滤器打开失败（规则未生效，仍在用旧规则）: %w", err)
	}

	e.mu.Lock()
	if !e.run { // 刚好在这中间被停了
		e.mu.Unlock()
		nh.Close()
		return ErrNotRunning
	}
	oldH, oldStop := e.handle, e.mainStop
	stop := make(chan struct{})
	e.rules.Store(ns)
	e.handle, e.mainStop, e.mainFilter = nh, stop, newFilter
	e.wg.Add(1) // 在锁内 Add：Stop 要先拿 startMu，所以不会与 wg.Wait() 并发
	e.mu.Unlock()

	go e.guard("packetLoop", func() { e.packetLoop(nh, stop, loopMain) })
	if oldStop != nil {
		close(oldStop)
	}
	if oldH != nil {
		oldH.Close()
	}
	e.bus.Info("rules.reload: rules=%d ranges=%d filter.changed=true", rulesN, nrange)
	return nil
}

// ───────────────────────── relay ─────────────────────────

func (e *Engine) acceptLoop() {
	defer e.wg.Done()
	e.mu.Lock()
	ln := e.ln
	e.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("relay accept: %v", err)
				return
			}
		}
		// 在途 relay 连接登记在册（见 relayConns）：Stop 时要主动关掉它们。
		// 否则进度列表里说“已停止”、hosts 已经撤了，实际上隧道还在转发数据。
		e.mu.Lock()
		if e.relayConns == nil {
			e.relayConns = map[net.Conn]struct{}{}
		}
		e.relayConns[c] = struct{}{}
		e.mu.Unlock()
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer func() {
				e.mu.Lock()
				delete(e.relayConns, c)
				e.mu.Unlock()
			}()
			e.handleConn(c)
		}()
	}
}

// dialUpstream 建立到目标的上游连接。
//
// 一条链可能有多个上游（故障转移/轮询/随机）：按策略拿候选顺序，依次试，
// 第一个成功的就用；每次成/败都记进健康表（被动探测，不靠主动探也能学到东西）。
// dialUpstream 按候选顺序试上游，一个不成马上换下一个。
//
// 两个旋钮（都在 config.tuning 里，默认 5s / 10s）：
//   - 单次超时：一条上游最多等多久。半死上游（TCP 通但不回话）会吃满这个时间，
//     所以它直接决定“业务等多久才换下一条”。老的硬编码 10s 是实测 TTFB 偏高的主因。
//   - 总预算：一整次连接最多花多久，防止候选多时逐个等满。
//     拒绝型失败（端口不通）只花几毫秒，所以不会触发截断；只有超时型才吃预算。
func (e *Engine) dialUpstream(ch config.Chain, dst net.IP, dport uint16) (net.Conn, error) {
	return e.dialUpstreamKeyed(ch, dst, dport, "")
}

// dialUpstreamKeyed 带一个「粘性键」（一般是客户端 IP）：
// 链的策略是 hash 时，同一个键永远落到同一条上游 —— 需要"对方按来源 IP 做白名单/会话"
// 的场景就靠它（A17）。
func (e *Engine) dialUpstreamKeyed(ch config.Chain, dst net.IP, dport uint16, key string) (net.Conn, error) {
	raws := e.cfg.UpstreamsResolved(ch) // A18：还原 DPAPI 保险箱里的口令
	if len(raws) == 0 {
		return nil, fmt.Errorf("链 %s 没有配置上游", ch.Name)
	}
	per, budget := e.cfg.DialTimeoutDur(), e.cfg.DialBudgetDur()
	cands := e.candidatesFor(ch, key)

	// 预热连接池：先看池子里有没有“已握手、只差 CONNECT”的会话（A11）
	if c, ok := e.dialWarm(ch, cands[0], dst, dport); ok {
		e.afterDial(ch, cands[0])
		return c, nil
	}
	// 慢则竞速（A10）：候选有两条以上、且第一条超过 race_after 还没连上时，
	// 把其余的并发拨出去，取先成功的。
	// 为什么不是“总是并发”：平时并发会成倍放大连接数与客户端 IP 的落地请求，
	// 只有在“第一条明显慢”时才值得。实测 etyy 的 CONNECT 阶段要 620ms、sjy 只要 75ms，
	// 这一招能把业务直接拉到快链路。
	if len(cands) > 1 && e.cfg.RaceAfterDur() > 0 {
		c, ok, raced, raceErr := e.dialRacing(ch, raws, cands, dst, dport, per, budget)
		if ok {
			return c, nil
		}
		if raced {
			// 竞速已经把**所有**候选都拨过一遍了，失败就是真失败；
			// 再回退一次顺序试等于把同一批上游拨两遍（白等一个预算）。
			return nil, raceErr
		}
		// 第一条在起跑前就明确失败 → 从第二条开始顺序试（不重复第一条）
		return e.dialSequential(ch, raws, cands[1:], dst, dport, per, budget)
	}
	return e.dialSequential(ch, raws, cands, dst, dport, per, budget)
}

// dialSequential 顺序试（原行为）：一个不成马上换下一个。
func (e *Engine) dialSequential(ch config.Chain, raws []string, cands []int,
	dst net.IP, dport uint16, per, budget time.Duration) (net.Conn, error) {
	start := time.Now()
	var errs []string
	for n, idx := range cands {
		el := time.Since(start)
		// 第一条无论如何都试（否则预算配小了就永远不会拨号）
		if n > 0 && el >= budget {
			msg := fmt.Sprintf("剩余 %d 条上游未尝试（已用 %s，总预算 %s）",
				len(raws)-n, el.Round(time.Millisecond), budget)
			e.bus.Warn("链 %s 拨号：%s", ch.Name, msg)
			errs = append(errs, msg)
			break
		}
		timeout := per
		if left := budget - el; left > 0 && left < timeout {
			timeout = left
		}
		c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, timeout)
		if err == nil {
			e.afterDial(ch, idx) // 用掉一条就要补一条
			return c, nil
		}
		errs = append(errs, msg)
	}
	return nil, fmt.Errorf("%s", strings.Join(errs, "\n"))
}

// tryUpstream 试一条上游，并把结果记进健康表。
//
// 注意业务拨号的失败**只作为参考**，不直接把上游判成 down（见 noteUpstream）：
// 一个坏掉的内网目标也能连着失败两次，那不代表上游挂了。
func (e *Engine) tryUpstream(ch config.Chain, raw string, idx int, dst net.IP, dport uint16,
	timeout time.Duration) (net.Conn, error, string) {
	up, err := upstream.Parse(raw)
	if err != nil {
		e.markUp(ch.Name, idx, false, 0, err.Error())
		return nil, err, fmt.Sprintf("上游 %d: %v", idx+1, err)
	}
	t0 := time.Now()
	c, err := up.Dial(dst, dport, timeout)
	lat := time.Since(t0)
	if err == nil {
		// 真拨通了：这是比探测更硬的证据，可以直接把状态正过来（也顺带消掉假警报）
		e.markUp(ch.Name, idx, true, lat, "")
		return c, nil, ""
	}
	// 失败：只升级“疑似”，等下一次探测确认。否则一条坏业务目标
	// 连续失败两次就能把健康的上游写成 down，随后探测又报一行假的恢复。
	e.noteUpstreamSuspect(ch.Name, idx, err.Error())
	// 每条上游一行、带耗时与本次超时 —— 现场把日志整段复制给 agent 时，
	// “谁、排第几、等了多久、原始报错是什么”都在这一行里。
	// 上游地址用 maskUpstream（保留协议/主机/端口，去掉凭据）。
	return nil, err, fmt.Sprintf("上游 #%d %s（单次超时 %s，已等 %s）：%v",
		idx+1, maskUpstream(up.Raw), timeout, lat.Round(time.Millisecond), err)
}

// dialAttempt 一次拨号尝试的结果（竞速用）。
type dialAttempt struct {
	c   net.Conn
	err error
	msg string
}

// dialRacing 慢则竞速：等 raceAfter，第一条还没好就把剩下的并发拨出去，取先到的。
//
// 返回：conn（成功时）、ok（拿到连接）、raced（是否真的进过竞速阶段）。
// 　　　raced=false 表示第一条在起跑前就明确失败，调用方应从第二条开始顺序试。
func (e *Engine) dialRacing(ch config.Chain, raws []string, cands []int,
	dst net.IP, dport uint16, per, budget time.Duration) (net.Conn, bool, bool, error) {
	race := e.cfg.RaceAfterDur()
	if race <= 0 || race >= per {
		race = per / 2 // 竞速必须早于单次超时，否则没意义
	}
	t0 := time.Now()
	first := make(chan dialAttempt, 1)
	go func(idx int) {
		c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, minDur(per, budget))
		first <- dialAttempt{c, err, msg}
	}(cands[0])

	select {
	case a := <-first:
		if a.err == nil {
			return a.c, true, true, nil
		}
		// 第一条已经明确失败（被拒/解析错）→ 交给顺序试，它从第二条开始
		if a.c != nil {
			a.c.Close()
		}
		return nil, false, false, a.err
	case <-time.After(race):
	}

	// 剩下的并发拨（总超时受剩余预算约束）
	n := len(cands) - 1
	left := budget - time.Since(t0)
	if left <= 0 {
		left = per
	}
	rest := make(chan dialAttempt, n)
	for _, idx := range cands[1:] {
		go func(idx int) {
			c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, minDur(per, left))
			rest <- dialAttempt{c, err, msg}
		}(idx)
	}
	e.bus.Info("链 %s：第一条上游还没连上（等满 %.0fms），并发试其余 %d 条",
		ch.Name, race.Seconds()*1000, n)

	errs := []string{}
	readRest, firstRead := 0, 0
	for readRest < n || firstRead == 0 {
		select {
		case a := <-rest:
			readRest++
			if a.err == nil {
				// 其余候选还在跑：它们的连接成功也来不及用了，收尾时关掉
				go drainAttempts(rest, n-readRest, per)
				go drainAttempts(first, 1-firstRead, per)
				return a.c, true, true, nil
			}
			errs = append(errs, a.msg)
		case a := <-first:
			firstRead = 1
			if a.err == nil {
				go drainAttempts(rest, n-readRest, per)
				return a.c, true, true, nil
			}
			errs = append(errs, a.msg)
		}
	}
	e.bus.Warn("链 %s 竞速全失败：\n%s", ch.Name, strings.Join(errs, "\n"))
	detail := strings.Join(errs, "\n")
	if detail == "" {
		detail = "所有上游都连不上"
	}
	return nil, false, true, fmt.Errorf("链 %s：所有上游都连不上\n%s", ch.Name, detail)
}

// drainAttempts 把竞速里多余的尝试收干净：成功的连接要关掉，不能漏。
func drainAttempts(ch chan dialAttempt, n int, wait time.Duration) {
	deadline := time.After(wait + time.Second)
	for i := 0; i < n; i++ {
		select {
		case a := <-ch:
			if a.c != nil {
				a.c.Close()
			}
		case <-deadline:
			return
		}
	}
}

// minDur 取较小值（给拨号超时用）。
func minDur(a, b time.Duration) time.Duration {
	if a < b || b <= 0 {
		return a
	}
	return b
}

func (e *Engine) handleConn(c net.Conn) {
	defer c.Close()

	_, portStr, _ := net.SplitHostPort(c.RemoteAddr().String())
	var sport uint16
	fmt.Sscanf(portStr, "%d", &sport)

	e.mu.Lock()
	st := e.conns[sport]
	e.mu.Unlock()
	if st == nil {
		e.bus.Warn("relay 收到未知来源连接 sport=%d，丢弃", sport)
		return
	}
	// 看门狗：relay 确实收到了这条连接（这一步以前没有任何记录，
	// 导致“包没到 relay”这种故障在日志里完全看不出来）。
	st.relayed.Store(true)
	// 建链耗时（握手 + 认证 + CONNECT）单独量：一条连接慢到底是“上游慢”
	// 还是“传输慢”，只看总耗时是分不清的 —— 专业日志（HAProxy 的 Tc、squid 的 %tr）也都分开记。
	dialStart := time.Now()

	ch, ok := e.cfg.ChainByName(st.chain)
	if !ok {
		e.bus.Error("链 %s 不存在，丢弃 %s:%d", st.chain, st.dst, st.dport)
		return
	}

	// 域名规则命中时，按配置决定“本机解析”还是“交给上游解析”：
	//
	//	local（默认）   按本机解析出的 IP 连 —— 客户内网域名通常只有本机能解答
	//	upstream        把域名交给上游解析（同一域名两边解析不同时用）
	//	auto            本机优先，连不上再把域名交给上游试一次
	//
	// 实测教训：我们这套环境里 main.his.com 只有客户网内的 DNS 能解答，
	// 上游是公网中转服务器、解析不到（host unreachable）—— 所以不能默认透传。
	host, hasName := e.nameOf(st.dst)
	// 目标是我们发的假 IP：绝不能拿它去连（那是个不存在的地址）。
	// st.dst 保持“应用连的那个地址”（回包改写要用），真实 IP 单独放 st.realDst，
	// 拨号/展示统一走 dialDst。
	if e.isFakeIP(st.dst) {
		name := host
		st.fakeName = name
		if !hasName {
			// 池子里没这个名字：多半是重启前的旧假 IP（映射不落盘）。说清楚，别让人猜。
			e.bus.Warn("DNS 接管：连到未登记的假 IP %s:%d（NetHub 重启前发的旧应答？）—— 这一条连不上",
				st.dst, st.dport)
			st.fail("假 IP 已过期（NetHub 重启过），请重新访问一次")
			e.finish(st)
			return
		}
		real := e.resolveReal(name)
		if real != nil {
			st.realDst.Store(real)
			// 把“名字 → 真实 IP”记进名字表。两个作用：
			//  ① 界面上的通配规则能显示“已覆盖 N 个 IP”（否则接管过的名字永远是空的，
			//     看起来像“这条规则什么都不拦”—— 而它刚刚才拦过）；
			//  ② 应用第二次直接用缓存里的**真实 IP** 连过来时，也能按名字命中这条规则。
			e.noteRealIP(name, real)
			e.bus.Info("DNS 接管：假 IP %s → %s 的真实 IP %s", st.fakeName, name, real)
		} else {
			e.bus.Info("DNS 接管：假 IP %s → %s 本机解不开，交给上游解析", st.dst, name)
		}
	}
	dialDst := st.displayTarget() // 假 IP 已解析则用真实 IP，否则保持原地址

	// 假 IP 阶段只能按“名字”选链，可能把本该按 IP 走的连接选错
	// （宽通配如 main.*.com 抢走 10.100.100.0/24 的连接）。真实 IP 到手后，
	// 用“IP 优先”的匹配再判一次，以其为准 —— 这就是 v0.2.2 / Proxifier 的语义。
	if e.isFakeIP(st.dst) && st.action == rules.ActionChain {
		if real := st.realTarget(); real != nil {
			if chain2, act2, hit := e.ruleSet().MatchName(host, real, st.dport, st.procName); hit && chain2 != st.chain {
				switch act2 {
				case rules.ActionChain:
					e.bus.Info("route.fixup: target=%s real_ip=%s %s → %s（真实 IP 命中更靠前的规则）",
						host, real, st.chain, chain2)
					st.chain = chain2
					if c2, ok2 := e.cfg.ChainByName(chain2); ok2 {
						ch = c2
					}
				default:
					// 真实 IP 命中直连/阻断：目前仍按原链走（罕见；给出可操作提示）
					e.bus.Warn("route.fixup: target=%s real_ip=%s 命中 %s 规则而非链 —— 仍按原链处理；"+
						"如需直连/阻断，请把该网段的规则排到前面", host, real, act2)
				}
			}
		}
	}
	mode := e.cfg.DomainResolveMode()
	var up net.Conn
	var err error
	tryName := func() bool {
		if !hasName {
			return false
		}
		up, err = e.dialViaName(ch, host, st.dport)
		if err == nil {
			e.bus.Info("[%s] 用域名 %s 建隧道（交给上游解析）", st.chain, host)
			return true
		}
		return false
	}
	// 假 IP 且本机解不开：只能交给上游（不能拿假 IP 当目标）。
	// 其余情况保持原有语义：按 DomainResolve 配置走 local / upstream / auto。
	if e.isFakeIP(st.dst) && st.realTarget() == nil {
		e.bus.Info("[%s] 目标 %s 是假 IP（无真实 IP），只能交给上游解析域名 %s", st.chain, st.dst, host)
		tryName()
	} else {
		switch {
		case mode == "upstream" && hasName:
			if !tryName() {
				up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
			}
		case mode == "upstream":
			up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
		default: // local / auto：先用本机解析出的 IP
			up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
			if err != nil && mode == "auto" && hasName {
				e.bus.Info("[%s] 按 IP %s 连不上（%v），改用域名 %s 交给上游再试", st.chain, dialDst, err, host)
				tryName()
			}
		}
	}
	if err != nil {
		// 原始报错一字不改地打出来（现场是把日志整段复制给 agent 看的，
		// 任何“翻译成人话”都会把底层信息抹掉）。这里只补几项我们才知道的上下文：
		// 命中哪条链、谁发起的、以及这条链试过哪些上游。
		//
		// 进程定位不到时（系统服务的短连接、受保护进程、连接已消失）：
		// **不进 ERROR**，只打一行 INFO。两个原因：
		//  ① 对用户可操作的信息 = 0（它多半是系统的后台连接，如 Windows 传递优化连局域网邻居）；
		//  ② 以前这里会打 “PID 0” —— PID 0 在 Windows 上是空闲进程、永远不会拥有 TCP 连接，
		//     那只是我们“查不到”的哨兵值，打在日志里纯属误导（用户以为多了个进程）。
		if st.procName == "" {
			e.bus.Info("tunnel.down: chain=%s target=%s:%d proc=unknown src_port=%d err=%s",
				st.chain, dialDst, st.dport, sport, firstLine(err.Error()))
			st.fail(err.Error())
			e.finish(st)
			return
		}
		e.bus.Error("[%s] 隧道建立失败 %s:%d（进程 %s，PID %d，源端口 %d）",
			st.chain, dialDst, st.dport, st.procName, st.pid, sport)
		for _, line := range strings.Split(err.Error(), "\n") {
			e.bus.Error("    %s", line)
		}
		st.fail(err.Error())
		e.finish(st)
		return
	}
	defer up.Close()

	dialMs := time.Since(dialStart).Milliseconds()

	// 不再单记一行 relay.up：它只是中间态，成功与否看 relay.done（字节数）、
	// 失败看 tunnel.down；每条连接两行（intercept 开始 / relay.done 结束）就够现场用，
	// 也跟 Proxifier “一条连接一行”的粒度对得上，不再把日志刷成三段。

	done := make(chan struct{}, 2)
	go func() { copyAndClose(up, c, &st.up); done <- struct{}{} }()
	go func() { copyAndClose(c, up, &st.down); done <- struct{}{} }()
	<-done

	e.finish(st)
	// 收尾时再补一次进程名：连接刚建那一刻表还没刷新到它（实测的 proc=unknown 根因），
	// 而到收尾时表里通常已经有了（TIME_WAIT 之类的行也在表里）。
	// 每连接一次，不在包路径上。
	if st.procName == "" && e.proc != nil {
		if n, pid, ok := e.proc.ByPort(st.appPort); ok {
			e.mu.Lock()
			st.procName, st.pid = n, pid
			e.mu.Unlock()
		}
	}
	e.bus.Info("relay.done: chain=%s%s target=%s:%d up=%s down=%s tc_ms=%d ms=%d", st.chain,
		connLogCtx(st.ruleNo, st.ruleName, st.procName, st.pid), dialDst, st.dport,
		humanBytes(st.up.Load()), humanBytes(st.down.Load()),
		dialMs, time.Since(st.start).Milliseconds())
}

// copyAndClose 单向拷贝并在结束后关闭写端（半关闭，双向都能正常收尾）。
func copyAndClose(dst, src net.Conn, counter *atomic.Uint64) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				counter.Add(uint64(n))
				break
			}
			counter.Add(uint64(n))
		}
		if err != nil {
			break
		}
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
	src.Close()
}

// ───────────────────────── 包处理 ─────────────────────────

// recoverHandle Recv 出错后的自愈：按退避重建同一只句柄，成则继续收包。
//
// 为什么要它（审计 P0-2）：主句柄一旦不可用，拦截就完全停了，但进程还活着、界面
// 还显示“运行中” —— 内网流量被系统按原路发出去（直连内网 IP，全不通），
// 只有人工重启才能恢复。触发途径实测存在：驱动被卸、安全软件临时拦、句柄失效。
//
// 退避 1s/2s/5s/10s/30s（共 ~48 秒）；期间一旦收到停止信号就立即退出。
// 新句柄先建好、再把旧句柄关掉（防止关完到重建成功这段空窗期里包没人接）。
func (e *Engine) recoverHandle(kind loopKind, stop chan struct{}) (*divert.Handle, error) {
	backoff := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}
	var lastErr error
	for i, wait := range backoff {
		select {
		case <-e.done:
			return nil, fmt.Errorf("引擎已停止")
		default:
		}
		if i > 0 {
			select {
			case <-e.done:
				return nil, fmt.Errorf("引擎已停止")
			case <-time.After(wait):
			}
		}
		filter, ferr := e.handleFilter(kind)
		if ferr != nil {
			return nil, ferr // 过滤器都不在了（停止过程中）→ 不必再试
		}
		nh, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err != nil {
			lastErr = err
			continue
		}
		// 新句柄已经能收包了，才动旧的
		e.mu.Lock()
		var old *divert.Handle
		if kind == loopDyn {
			// 这期间可能有别的路径重建过：那就不用我们这只
			if e.dynHandle != nil {
				nh.Close()
				e.mu.Unlock()
				return nil, fmt.Errorf("动态句柄已被重建")
			}
			e.dynHandle, e.dynFilter = nh, filter
		} else {
			old, e.handle = e.handle, nh
		}
		e.mu.Unlock()
		if old != nil {
			old.Close()
		}
		e.setFatal(nil)
		e.bus.Info("WinDivert: 句柄已重建（第 %d 次尝试）—— 拦截恢复", i+1)
		return nh, nil
	}
	return nil, lastErr
}

// handleFilter 重建句柄时用哪份过滤器：主句柄按当前规则集重算，动态句柄用记着的那份。
func (e *Engine) handleFilter(kind loopKind) (string, error) {
	if kind == loopDyn {
		e.mu.RLock()
		f := e.dynFilter
		e.mu.RUnlock()
		if f == "" {
			return "", fmt.Errorf("动态过滤器没有记录")
		}
		return f, nil
	}
	filter, _ := e.buildMainFilter(e.ruleSet(), portOf(e.RelayAddr()))
	if filter == "" {
		return "", fmt.Errorf("主过滤器为空（规则集为空？）")
	}
	return filter, nil
}

// loopKind 说明这只句柄是谁的 —— 决定 Recv 出错时怎么处理（这两类差别很大，
// 用 stop 是否为 nil 来区分已经不够了：热重载会让**主**句柄也带着 stop）。
type loopKind int

const (
	loopMain loopKind = iota // 主过滤器：出错＝整个引擎“拦截已中断”
	loopDyn                  // 动态过滤器（通配域名）：出错只是这部分不再接管
)

func (e *Engine) packetLoop(h *divert.Handle, stop chan struct{}, kind loopKind) {
	defer e.wg.Done()

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	relayIP := net.ParseIP(hostOf(e.RelayAddr())).To4()
	relayPort := portOf(e.RelayAddr())

	for {
		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-e.done:
				return
			case <-closedCh(stop):
				return // 我们在换句柄（热重载 / 换动态过滤器），不是出错
			default:
			}
			if kind == loopDyn {
				// 动态句柄出错不能把整个引擎置成“已中断”：它只管通配域名那部分流量。
				// 但它也不能就此死掉 —— 先清掉句柄状态（让重建不再被“过滤器没变”挡回去），
				// 再退避重建；不行才放弃。
				e.bus.Warn("域名通配：动态过滤器已中断: %v（正在重建）", err)
				e.mu.Lock()
				e.dynHandle, e.dynStop, e.dynFilter = nil, nil, ""
				e.mu.Unlock()
				if nh, rerr := e.recoverHandle(kind, stop); rerr == nil {
					h = nh
					continue
				}
				return
			}
			// 主句柄：**绝不能就此放弃**。
			//
			// 拦截一停，那些本该走隧道的内网目标就会被系统按原路发出去（直连内网 IP
			// = 全部不通），而进程还活着、界面还是绿的，只有人工重启才能恢复。
			// 实测触发过：驱动被卸、被安全软件拦、句柄失效。
			// 所以按退避重建；连续多次不行才判“已中断”。
			nh, rerr := e.recoverHandle(kind, stop)
			if rerr == nil {
				h = nh
				continue
			}
			e.bus.Error("WinDivert Recv 失败，且重建句柄失败（最后一次: %v）：原错误 %v", rerr, err)
			e.setFatal(err) // 让界面变红「Error」—— 否则状态还说“运行中”，其实一个包都没拦
			if e.Notify != nil {
				e.Notify("拦截已中断", err.Error()+"（请重启服务）", true)
			}
			return
		}
		pkt := buf[:n]

		// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
		// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
		// 只取源端口、不取地址与载荷 —— 每个包都跑这段，udpPayload 会白白分配两块 slice。
		if sport, ok := udpSrcPort(pkt); ok && sport >= dnsProbePortLo && sport <= dnsProbePortHi {
			continue
		}

		src, dst, ihl, proto, ok := parseIPv4(pkt)
		// QUIC（UDP 443）：这条包能到我们手上，说明它的目标落在“该走隧道”的网段里
		// （过滤器只装了那些范围的 UDP 443，直连目标的 QUIC 根本不经过我们）。
		// UDP 走不了隧道 —— 以前是静默直连漏出，现在丢掉并记一行（回 ICMP 是尽力而为）。
		if ok && proto == 17 {
			e.blockQUIC(h, pkt, addr, src, dst, ihl)
			continue
		}
		if !ok || proto != 6 || len(pkt) < ihl+20 {
			_, _ = h.Send(pkt, addr)
			continue
		}
		t := ihl
		sport := be16(pkt, t+offSrcPort)
		dport := be16(pkt, t+offDstPort)
		flags := pkt[t+offFlags]

		// 入方向：源端口 = relay 端口的包，只可能是本机 relay 回来的
		// （应用不可能正好用着 relay 占着的那个端口）。先判它，
		// 否则“只按进程”的规则会把回来的包也当出站命中。
		if sport == relayPort {
			e.rewriteInbound(h, pkt, addr, t, dport)
			continue
		}

		// 出方向：这条连接属于哪个进程（只在规则里写了进程条件时才查表，其余情况零开销）。
		// 优先用连接上缓存的结论，避免每个包都查。
		procName, procPID := e.flowProc(sport)

		// 内置直连：Windows 更新传递优化走 TCP 7680，客户内网里不该进隧道。
		// 以前要在规则里写一条 direct 规则来实现；现在内置，规则列表干净。
		if dport == builtinDirectPort && e.cfg.BuiltinDirectEnabled() {
			// 内置直连（Windows 更新传递优化）：一个文件共享的 peer 一对一行，
			// 刷起来全是噪声且对现场结论无影响 → 归到“详细日志”。
			e.passThrough(h, pkt, addr, t, src, dst, sport, dport, flags, rules.ActionDirect, 0, "", procName, procPID, true)
			continue
		}

		// 方向判定不依赖 addr.Flags 的位布局：目标落在规则内 = 应用发出的包。
		// 名字：通配域名只能靠“这个 IP 是哪个域名”匹配。两个来源：
		//  ① DNS 接管发的假 IP（池子反查）② 嗅探/解析学到的真 IP（名字表）
		// 没写通配规则时不做这次查找（每包一次查找，不该白付）。
		name := ""
		if e.ruleSet().HasWildcards() {
			if n, ok := e.nameOf(dst); ok {
				name = n
			}
		}
		if chain, act, ruleNo, ruleName, hit := e.ruleSet().MatchNameRule(name, dst, dport, procName); hit {
			switch act {
			case rules.ActionDirect, rules.ActionBlock:
				e.passThrough(h, pkt, addr, t, src, dst, sport, dport, flags, act, ruleNo, ruleName, procName, procPID, false)
			default:
				e.rewriteOutbound(h, pkt, addr, t, src, dst, sport, dport, flags, chain, relayIP, relayPort, ruleNo, ruleName, procName, procPID)
			}
			continue
		}
		// 没命中任何规则：要么是“带本机网段条件的规则”**当前不生效**（A16），
		// 要么是“只按进程”的规则拦下的其它程序的包（A20）。
		// 两种都必须原样放回内核，绝不能当入站包改写（会把用户的包改坏）。
		// 直连流量（仅当开了“统计直连流量”才会被拦到这里）：
		// 回来的包也要数上，否则界面上永远只有出方向（A15）。
		if st := e.flow(dport); st != nil && st.action == rules.ActionDirect {
			st.touch()
			st.packets.Add(1)
			st.down.Add(uint64(len(pkt)))
		}
		e.cap.note(pkt)
		if _, err := h.Send(pkt, addr); err != nil {
			e.bus.Throttle("inject.fail", time.Minute, "注入失败: %v（1 分钟内的重复不再逐条记）", err)
		}
	}
}

// ───────────────────────── 域名通配：只读嗅探 DNS ─────────────────────────

// dnsSniffFilter 只读嗅探用的过滤器：只关心 DNS **应答**（源端口 53），UDP 与 TCP 都要。
//
// 用 sniff + recv-only：包照常交给系统与应用，我们只看一份拷贝 —— 这一步出
// 任何问题最多是“没看见”，绝不会把全机 DNS 弄坏（这是选这个方案的前提）。
const dnsSniffFilter = "(inbound and udp and udp.SrcPort == 53) or (inbound and tcp and tcp.SrcPort == 53)" +
	" or (outbound and udp and udp.DstPort == 53)"

// dnsLoop 读 DNS 应答 → 学“名字 ↔ IP” → 按需重建动态过滤器。
func (e *Engine) dnsLoop() {
	defer e.wg.Done()

	h, err := divert.Open(dnsSniffFilter, divert.LayerNetwork, divert.PriorityHighest, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Warn("域名通配：无法只读嗅探 DNS（%v）—— 通配域名只能匹配已经观察到的名字", err)
		return
	}
	defer h.Close()
	if !e.trackSniff(h) {
		return // 已经在停止：直接退出（defer 会关 h）
	}
	e.bus.Info("dns.sniff: started mode=read-only scope=answers+queries")

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	for {
		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("域名通配：DNS 嗅探中断: %v（通配域名将不再学到新 IP）", err)
				return
			}
		}
		pkt := buf[:n]
		// 出方向的查询：DNS 接管（开了才有动作）—— 命中通配规则的名字塞一条假 IP 应答
		if e.fake != nil && e.takeoverQuery(pkt, addr) {
			continue
		}
		// 入方向的应答：学“名字 → IP”
		e.learnDNS(pkt)
	}
}

// takeoverQuery 处理一条**出方向** DNS 查询：命中通配规则就额外塞一条假 IP 应答。
//
// 返回 true 表示“这是查询，已处理”（不必再当应答解析）。
//
// 注意：这是**只读**句柄，我们从头到尾**不消费**这个包 —— 原查询照常发出去，
// 我们只是多塞一条应答。真应答先到的话，应用就用真 IP，而那条路我们能靠
// “名字→IP”嗅探照常接管（两条路都能到，不会因此失效）。
func (e *Engine) takeoverQuery(pkt []byte, addr *divert.Address) bool {
	info, payload, ok := udpPayload(pkt)
	if !ok {
		return false
	}
	// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
	// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
	if info.sport >= dnsProbePortLo && info.sport <= dnsProbePortHi {
		return true
	}
	q, okq := dnssniff.ParseQuery(payload)
	if !okq {
		return false
	}
	// 黑匣子：这是“到底谁弄坏的”唯一的原始事实
	if e.dnsBox != nil {
		e.dnsBox.Writef("查询  %s:%d → %s:%d  id=%#04x %s 类型 %d",
			info.src, info.sport, info.dst, info.dport, q.ID, q.Name, q.Type)
	}
	if !e.ruleSet().WildcardMatch(q.Name) {
		return true // 不命中：什么都不做（原查询照常）
	}
	var ansIP net.IP
	switch q.Type {
	case 1:
		ansIP = e.fake.Assign(q.Name, dnsFakeTTL)
		if ansIP == nil {
			e.bus.Throttle("dns.takeover.poolfull", time.Minute,
				"DNS 接管：假 IP 池已满，本次不接管（1 分钟内的重复不再逐条记）")
			return true
		}
	case 28:
		ansIP = nil // AAAA：答“没有这条记录”，否则应用可能走 IPv6 绕过我们
	default:
		return true
	}
	resp := buildDNSResponse(pkt, info, q, ansIP)
	if resp == nil {
		return true
	}
	inj := e.injectorHandle()
	if inj == nil {
		return true
	}
	addr.Flags &^= 0x02 // 清掉 Outbound：回包是**入方向**的
	divert.CalcChecksums(resp, addr, divert.ChecksumDefault)
	if _, serr := inj.Send(resp, addr); serr != nil {
		e.bus.Throttle("dns.takeover.injectfail", time.Minute,
			"DNS 接管：注入假应答失败: %v（1 分钟内的重复不再逐条记）", serr)
		if e.dnsBox != nil {
			e.dnsBox.Writef("注入失败 %s: %v", q.Name, serr)
		}
		return true
	}
	e.tookOver.Add(1)
	if e.dnsBox != nil {
		e.dnsBox.Writef("已回答 %s → %v（已注入应答）", q.Name, ansIP)
	}
	e.noteTookOver(q.Name)
	return true
}

// injectorHandle 取“只塞”那只句柄（过滤器是 false，什么也不匹配）。
func (e *Engine) injectorHandle() *divert.Handle {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.injector
}

// learnDNS 从一条 DNS 报文里学“名字 → IP”，写进名字表。
//
// 为什么全记（不只是能命中通配规则的名字）：同一个 IP 常被多个名字共用，
// 只记能命中的那些会漏掉“先用另一个名字访问过、然后才轮到通配规则”的情况；
// 表本身按 TTL 过期（见 dnsmap.Expired），不会无限长。
func (e *Engine) learnDNS(pkt []byte) {
	payload := dnsPayload(pkt)
	if len(payload) == 0 {
		return
	}
	res, err := dnssniff.Parse(payload)
	if err != nil || len(res.Pairs) == 0 {
		return
	}
	e.dnsSeen.Add(1)
	byName := map[string][]string{}
	ttl := map[string]time.Duration{}
	for _, p := range res.Pairs {
		byName[p.Name] = append(byName[p.Name], p.IP)
		if cur, ok := ttl[p.Name]; !ok || (p.TTL > 0 && p.TTL < cur) {
			ttl[p.Name] = p.TTL
		}
	}
	// 观测到的名字**封顶**存 10 分钟。
	//
	// 直接用报文里的 TTL（公网域名常见几千到 86400 秒）的后果：一天的观测全留着，
	// 而名字表每次写入都要整表重建索引（持写锁、全表 Snapshot），长跑后包处理会被
	// 这些写操作周期性地挡住（审计 P1-6）。
	// 10 分钟足够覆盖“应用刚解析完就要连”这个真正的用途。
	for name, d := range ttl {
		if d <= 0 || d > maxObservedTTL {
			ttl[name] = maxObservedTTL
		}
	}
	changed := false
	for name, ips := range byName {
		before := e.names.IPsFor(name)
		e.names.SetWithTTL(name, ips, dnsmap.PrioObserved, ttl[name])
		e.dnsLearn.Add(1)
		if !sameStrSet(before, e.names.IPsFor(name)) {
			changed = true
		}
	}
	if changed {
		e.applyHostIPs()
		e.onWildcardsChanged()
	}
}

// tcpPayload 从 IP 包里取出 TCP 负载（不做端口判断，调用方自己判）。
func tcpPayload(pkt []byte) []byte {
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok || proto != 6 {
		return nil
	}
	if len(pkt) < ihl+20 {
		return nil
	}
	hdr := int(pkt[ihl+12]>>4) * 4 // data offset
	if hdr < 20 || ihl+hdr > len(pkt) {
		return nil
	}
	return pkt[ihl+hdr:]
}

// dnsPayload 从 IP 包里取出 UDP/TCP 负载（DNS 报文）。取不到返回 nil。
//
// 只认**源端口 53**（应答）：嗅探过滤器只装了这一个条件，这里再守一道，
// 免得把别的 TCP 流量当成 DNS 报文去解析（解析器再怎么健壮也不该被白喂）。
func dnsPayload(pkt []byte) []byte {
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok {
		return nil
	}
	switch proto {
	case 17: // UDP
		if len(pkt) < ihl+8 {
			return nil
		}
		if be16(pkt, ihl) != 53 {
			return nil
		}
		l := int(be16(pkt, ihl+4)) // UDP 长度（含 8 字节头）
		end := ihl + l
		if l < 8 || end > len(pkt) {
			end = len(pkt)
		}
		return pkt[ihl+8 : end]
	case 6: // TCP
		if be16(pkt, ihl) != 53 {
			return nil
		}
		return tcpPayload(pkt)
	}
	return nil
}

// onWildcardsChanged 发现名字表变了：有必要时立刻重建动态过滤器。
//
// 为什么要“立刻”：应用解析完域名后会马上发起连接，而那个包还没进过滤器。
// 这一小段窗口就是能不能拦住首次连接的关键，所以不能等到下一次 tick。
// 但也不能每个 DNS 应答都重建（重建要开新句柄），所以节流 200 ms，
// 节流期间只置脏标记，由 dynFilterLoop 补上。
func (e *Engine) onWildcardsChanged() {
	if !e.ruleSet().HasWildcards() {
		return
	}
	now := time.Now().UnixMilli()
	last := e.dynLast.Load()
	if now-last >= 200 {
		e.dynLast.Store(now)
		e.rebuildDynFilter()
		return
	}
	select {
	case e.dynDirty <- struct{}{}:
	default: // 已经有人置脏了
	}
}

// dynFilterLoop 把节流期间攒下的“脏”补上（最多滞后 200 ms）。
func (e *Engine) dynFilterLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(200 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			select {
			case <-e.dynDirty:
				e.dynLast.Store(time.Now().UnixMilli())
				e.rebuildDynFilter()
			default:
			}
		}
	}
}

// rebuildDynFilter 重建动态过滤器（第二只句柄，只装通配域名当前覆盖到的 IP）。
//
// 热替换的做法：**先开新句柄、再关旧句柄**，中间不丢包（两只都开着的那一瞬，
// 同一个包只会被其中一只收到，两边的处理逻辑完全一样）。
func (e *Engine) rebuildDynFilter() {
	rs := e.ruleSet().WildcardRanges(e.cfg.CountDirectEnabled())
	filter := ""
	if len(rs) > 0 {
		filter = buildFilter(rs, portOf(e.RelayAddr()))
	}

	e.mu.Lock()
	oldH, oldStop, oldFilter := e.dynHandle, e.dynStop, e.dynFilter
	if filter == oldFilter {
		e.mu.Unlock()
		return // 没变化，不要白白换句柄
	}
	if filter == "" {
		e.dynHandle, e.dynStop, e.dynFilter = nil, nil, ""
		e.mu.Unlock()
		if oldH != nil {
			if oldStop != nil {
				close(oldStop)
			}
			oldH.Close()
			e.bus.Info("wildcard: filter.remove reason=no-matched-ip")
		}
		return
	}

	nh, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		// 把“记住的旧过滤器”清掉：否则下次观测到同一批 IP 时，
		// rebuildDynFilter 会以为“没变”直接返回，这只句柄就永久建立不起来了。
		e.dynFilter = ""
		e.mu.Unlock()
		e.bus.Warn("域名通配：动态过滤器打开失败: %v", err)
		return
	}
	if !e.run {
		// 已经停在停止过程中了：不要把协程加进 WaitGroup（Add 与 Wait 并发是错的）
		e.mu.Unlock()
		nh.Close()
		return
	}
	stop := make(chan struct{})
	e.dynHandle, e.dynStop, e.dynFilter, e.dynAt = nh, stop, filter, time.Now()
	e.wg.Add(1)
	e.mu.Unlock()

	go e.guard("dynPacketLoop", func() { e.packetLoop(nh, stop, loopDyn) })
	if oldH != nil {
		if oldStop != nil {
			close(oldStop)
		}
		oldH.Close()
	}
	e.bus.Detail("wildcard: filter.update ranges=%d filter=%s", len(rs), filter)
}

// WildcardStat 一条通配规则当前的状态（界面/日志看“学到了几个 IP”）。
type WildcardStat struct {
	Pattern  string            `json:"pattern"`
	IPs      []string          `json:"ips"`
	Updated  string            `json:"updated"`
	Takeover bool              `json:"takeover"`
	Names    []string          `json:"names"`
	FakeIPs  map[string]string `json:"fakeIps"`
}

// WildcardStats 通配域名规则当前各覆盖到哪些 IP / 接管过哪些名字。
func (e *Engine) WildcardStats() []WildcardStat {
	var out []WildcardStat
	seen := map[string][]string{}
	for _, r := range e.ruleSet().List() {
		for _, w := range r.WildcardTargets() {
			if _, done := seen[w]; done {
				continue
			}
			var ips []string
			for h, list := range e.names.Snapshot() {
				if dnsmap.MatchWildcard(w, h) {
					ips = append(ips, list...)
				}
			}
			sort.Strings(ips)
			// 接管过哪些名字：假 IP 池里有记录（这是它**真的在干活**的证据）。
			var names []string
			fake := map[string]string{}
			if e.fake != nil {
				for _, n := range e.fake.Names() {
					if !dnsmap.MatchWildcard(w, n) {
						continue
					}
					names = append(names, n)
					if ip, ok := e.fake.IPFor(n); ok {
						fake[n] = ip.String()
					}
				}
			}
			sort.Strings(names)
			seen[w] = ips
			out = append(out, WildcardStat{Pattern: w, IPs: ips, Names: names, FakeIPs: fake,
				Takeover: e.cfg.DNSTakeoverEnabled()})
		}
	}
	if len(out) == 0 {
		return nil
	}
	e.mu.RLock()
	at := e.dynAt
	e.mu.RUnlock()
	age := "—"
	if !at.IsZero() {
		age = humanDur(time.Since(at))
	}
	for i := range out {
		out[i].Updated = age
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pattern < out[j].Pattern })
	return out
}

// DNSStats 只读嗅探的统计（进/出）—— 诊断页用。
func (e *Engine) DNSStats() (seen, learned uint64) {
	return e.dnsSeen.Load(), e.dnsLearn.Load()
}

// closedCh 简单包装：nil 通道永远不关闭。
func closedCh(ch chan struct{}) <-chan struct{} {
	if ch == nil {
		return nil
	}
	return ch
}

// sameStrSet 两个集合是否相等（顺序无关，元素不重复）。
func sameStrSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	return true
}

// ───────────────────── 名字的第二个来源：TLS SNI / HTTP Host ─────────────────────

// sniSniffPorts 只读嗅探的端口：TLS 常见端口 + 明文 HTTP 常见端口。
//
// 为什么要端口白名单：嗅探的代价是“这些包的负载都拷一份到用户态”，
// 范围越小越好；而握手只发生在连接最开始，常见的就这几类端口。
// 内网服务端口不在表里的，可以用通配域名 + 明文 DNS 拿到（不依赖 SNI）。
var sniSniffPorts = []uint16{443, 8443, 9443, 6443, 4443, 10443, 80, 8080, 853} // 853=DoT

// sniSniffFilter 拼出方向 TCP 的嗅探过滤器（只读，不改任何包）。
//
// 加 `ip.Length < 1400` 是为了**开销**，不是为了省事：嗅探的代价在“每个匹配的包
// 都要拷一份到用户态”，而大包体量最大。实测 30MB 下载（全部经 Clash 的 443）
// 开销约 0.7s CPU；加上长度条件后大块数据包直接不进内核过滤，代价降到零头。
//
// 代价：极端大的 ClientHello（≥1400 字节，比如带 ECH 配置的）会被漏掉 ——
// 而 ECH 的名字本来我们也看不到（真名被加密），漏了不亏。
func sniSniffFilter() string {
	var c string
	for i, p := range sniSniffPorts {
		if i > 0 {
			c += " or "
		}
		c += fmt.Sprintf("tcp.DstPort == %d", p)
	}
	return "outbound and tcp and ip.Length < 1400 and (" + c + ")"
}

// sniBuf 一条连接攒起来的“开头几个字节”（连接只靠源端口区分，与拦截路径一致）。
type sniBuf struct {
	dst  net.IP
	data []byte
	at   time.Time
	done bool // 已经得出结论（学到了名字，或者判定不是我们要的）
}

// sniLoop 只读嗅探 TLS ClientHello / 明文 HTTP 请求，从中读出目标域名。
//
// 为什么要有它：名字原本靠“看明文 DNS 应答”学；一旦应用用了加密 DNS
// （DoH/DoT）或自带解析器，DNS 层就什么都看不见了。但握手是明文的 ——
// SNI 里还有名字。这就是“防患于未然”的那一半。
func (e *Engine) sniLoop() {
	defer e.wg.Done()

	filter := sniSniffFilter()
	h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityHighest, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Warn("TLS 嗅探：无法启动（%v）—— 加密 DNS 环境下通配域名将学不到名字", err)
		return
	}
	defer h.Close()
	if !e.trackSniff(h) {
		return // 已经在停止：直接退出（defer 会关 h）
	}
	e.bus.Info("sni.sniff: started mode=read-only ports=%d filter=%s", len(sniSniffPorts), filter)

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	flows := map[uint16]*sniBuf{}
	tk := time.NewTicker(10 * time.Second)
	defer tk.Stop()

	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			// 定期把所有攒着的、没结论的连接丢掉（长连接 + 大流量不能无限攒）
			for k, f := range flows {
				if time.Since(f.at) > 20*time.Second || len(f.data) > 8192 {
					delete(flows, k)
				}
			}
			if len(flows) > 2048 { // 更硬的上限：宁可漏学，不能吃内存
				flows = map[uint16]*sniBuf{}
			}
		default:
		}

		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("TLS 嗅探中断: %v（通配域名将只能靠明文 DNS）", err)
				return
			}
		}
		pkt := buf[:n]

		// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
		// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
		if info, _, ok := udpPayload(pkt); ok && info.sport >= dnsProbePortLo && info.sport <= dnsProbePortHi {
			continue
		}
		src, dst, _, proto, ok := parseIPv4(pkt)
		if !ok || proto != 6 {
			continue
		}
		t := 20
		if _, _, ihl, _, ok2 := parseIPv4(pkt); ok2 {
			t = ihl
		}
		sport := be16(pkt, t+offSrcPort)
		payload := tcpPayload(pkt)
		if len(payload) == 0 {
			continue
		}
		_ = src

		f := flows[sport]
		if f == nil {
			// 只关心“第一条数据”的样子：不像 TLS/HTTP 就不管它（后面也别攒）
			if !tlsname.LooksLikeTLS(payload) && !tlsname.LooksLikeHTTP(payload) {
				continue
			}
			f = &sniBuf{dst: dst, at: time.Now()}
			flows[sport] = f
		}
		if f.done || len(f.data) > 8192 {
			delete(flows, sport)
			continue
		}
		f.data = append(f.data, payload...)
		f.at = time.Now()

		// TLS 要看整条记录；HTTP 只要够一个请求头（通常第一段就够）
		if tlsname.LooksLikeTLS(f.data) && !tlsname.Complete(f.data) {
			continue
		}
		res, okr := tlsname.Name(f.data)
		if !okr {
			// 已经有结论了：不是 TLS 也不是 HTTP（或者没 SNI/Host）→ 别死等
			if len(f.data) > 512 {
				f.done = true
				delete(flows, sport)
			}
			continue
		}
		f.done = true
		delete(flows, sport)
		e.learnFromHandshake(res, dst)
	}
}

// learnFromHandshake 从握手里学到的名字 → 名字表（与 DNS 观察走同一条流水线）。
func (e *Engine) learnFromHandshake(res tlsname.Result, dst net.IP) {
	if res.Name == "" || dst == nil {
		return
	}
	if res.ECH {
		// ECH：SNI 里只是“公开名”，真名被加密了 —— 坦诚地说出来，别让人以为通了。
		// 但同一个域名每次握手都重复说一遍没意义（实测 22 分钟里刷了十几行）：
		// 它是个**稳定属性**，不是“刚发生的事故” —— 每个名字 10 分钟说一次、且降到 INFO。
		if e.noteOnce("ech:"+res.Name, 10*time.Minute) {
			e.bus.Info("TLS 嗅探：%s 用了 ECH（加密的 ClientHello）—— 真实目标名看不见，"+
				"通配域名对它无效（具体域名规则不受影响）", res.Name)
		}
		e.names.Set(res.Name, []string{dst.String()}, dnsmap.PrioObserved)
		return
	}
	before := e.names.IPsFor(res.Name)
	_, wasKnown := e.names.NameFor(dst)
	e.names.Set(res.Name, []string{dst.String()}, dnsmap.PrioObserved)
	e.sniLearn.Add(1)
	if len(before) == 0 && !wasKnown {
		// 这个名字从未在明文 DNS 里出现过 → 基本可以确定这台机器上有人用了
		// 加密 DNS 或自带解析器的客户端。这条日志的价值：让“为什么通配能/不能生效”有据可查。
		e.bus.Detail("sni.learn: name=%s ip=%s dns_seen=false", res.Name, dst)
	}
	e.applyHostIPs()
	e.onWildcardsChanged()
}

// dohHosts 已知的加密 DNS（DoH/DoT）服务名。只用于**报信**，不参与任何匹配。
var dohHosts = []string{
	"dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one",
	"mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
	"doh.pub", "dns.pub", "doh.360.cn", "dns.alidns.com", "doh.alidns.com",
	"dns.quad9.net", "doh.opendns.com", "dns.nextdns.io", "doh.dns.sb",
	"doh.cleanbrowsing.org", "dns.adguard.com",
}

// isDoHEndpoint 这个域名是不是已知的加密 DNS 端点。
func isDoHEndpoint(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, h := range dohHosts {
		if name == h {
			return true
		}
	}
	return false
}

// noteDoH 第一次看到加密 DNS 端点时报一条（同一个端点只报一次，否则刷屏）。
func (e *Engine) noteDoH(name string, dst net.IP) {
	e.mu.Lock()
	if e.dohSeen == nil {
		e.dohSeen = map[string]bool{}
	}
	show := !e.dohSeen[name]
	if show {
		e.dohSeen[name] = true
	}
	e.mu.Unlock()
	if !show {
		return
	}
	e.bus.Warn("doh.detect: host=%s ip=%s impact=first-connect-may-miss", name, dst)
	e.bus.Warn("  影响：这些名字只能从 TLS 握手看到，**首次连接**可能来不及进过滤器（重试起生效）。" +
		"要首次就生效，需打开 DNS 接管或改用明文 DNS")
}

// ───────────────────────── DNS 接管（发假 IP） ─────────────────────────

// 我们自己的 DNS 解析专用源端口段（区间选在这种不常用的高位段）。
//
// 接管查询用的是 dnsLoop 那只**只读嗅探**句柄（dnsSniffFilter 已含
// `outbound and udp and udp.DstPort == 53`）；这里不再单独定义过滤器。
const (
	dnsProbePortLo = 53901
	dnsProbePortHi = 53910
)

// noteTookOver 第一次接管某个名字时说一行（带名字与假 IP），之后静默计数。
func (e *Engine) noteTookOver(name string) {
	e.mu.Lock()
	if e.tookSeen == nil {
		e.tookSeen = map[string]bool{}
	}
	show := !e.tookSeen[name]
	if show {
		e.tookSeen[name] = true
	}
	e.mu.Unlock()
	if !show {
		return
	}
	ip, _ := e.fake.IPFor(name)
	if ip == nil {
		e.bus.Info("dns.takeover: name=%s qtype=AAAA answer=NOERROR/empty", name)
		return
	}
	e.bus.Info("dns.takeover: name=%s fake_ip=%s ttl=%s", name, ip, dnsFakeTTL)
}

// ───────────────────────── 名字反查：假 IP 优先 ─────────────────────────

// nameOf 这个目标属于哪个域名：先查假 IP 池（DNS 接管发的），再查名字表（嗅探/解析来的）。
func (e *Engine) nameOf(ip net.IP) (string, bool) {
	if e.fake != nil {
		if n, ok := e.fake.NameFor(ip); ok {
			return n, true
		}
	}
	if e.names != nil {
		return e.names.NameFor(ip)
	}
	return "", false
}

// isFakeIP 这个地址是不是我们发的假 IP。
func (e *Engine) isFakeIP(ip net.IP) bool {
	return e.fake != nil && e.fake.Range().Contains(ip)
}

// sweepFakeIP 回收过期的假 IP（一个名字过期后地址还给池子）。
func (e *Engine) sweepFakeIP() {
	if e.fake == nil {
		return
	}
	gone := e.fake.Sweep()
	if len(gone) == 0 {
		return
	}
	e.mu.Lock()
	for _, n := range gone {
		delete(e.tookSeen, n)
	}
	e.mu.Unlock()
	e.bus.Detail("fakeip.recycle: count=%d names=%v", len(gone), gone)
}

// udpPayload 从 IP 包里取出 UDP 负载，并返回地址/端口（DNS 接管要互换它们）。
// udpSrcPort 只取 UDP 源端口（不做分配、不取地址/载荷）。
//
// 为什么单独一个：包循环里拿它排掉“我们自己解析器发的查询”，**每个包都要跑**。
// 用 udpPayload 会把两个地址各 copy 一块新 slice（实测每包两次小分配 → GC 压力），
// 而我们只想要那个端口号。
func udpSrcPort(pkt []byte) (uint16, bool) {
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok || proto != 17 || len(pkt) < ihl+4 {
		return 0, false
	}
	return be16(pkt, ihl), true
}

// udpPayload 一个 UDP 包的地址、端口与载荷。
func udpPayload(pkt []byte) (udpInfo, []byte, bool) {
	var u udpInfo
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok || proto != 17 || len(pkt) < ihl+8 {
		return u, nil, false
	}
	u.src = append(net.IP(nil), pkt[12:16]...)
	u.dst = append(net.IP(nil), pkt[16:20]...)
	u.sport = be16(pkt, ihl)
	u.dport = be16(pkt, ihl+2)
	l := int(be16(pkt, ihl+4)) // UDP 长度（含 8 字节头）
	end := ihl + l
	if l < 8 || end > len(pkt) {
		end = len(pkt)
	}
	return u, pkt[ihl+8 : end], true
}

// udpInfo 一个 UDP 包的地址与端口。
type udpInfo struct {
	src, dst     net.IP
	sport, dport uint16
}

// dnsFakeTTL 我们发出的假 A 记录的 TTL。
//
// maxObservedTTL 观测到的名字最多记住多久（见 dnsLoop 里的封顶）：
// 名字表的真实用途是“应用刚解析完就要连”，10 分钟绰绰有余；
// 用它换掉报文里的原始 TTL，避免长跑后表无限变大、每次写入都重建全表索引。
//
// 短一点有三个好处：① 假 IP 回收得快，池子不易满；
// ② 我们重启后应用缓存里的旧假 IP 很快失效（假 IP 映射不落盘）；
// ③ 名字对应的真实 IP 变化时跟着快。
const dnsFakeTTL = 60 * time.Second

// maxObservedTTL 观测到的名字最多记多久（见 dnsLoop 里的封顶）。
const maxObservedTTL = 10 * time.Minute

// buildDNSResponse 造一条 DNS 应答；ip 为 nil 表示“明确告诉它没有这条记录”
// （用于 AAAA：空 NOERROR，防止应用走 IPv6 绕过我们）。
//
// 实测配方（见 KB 决策/2026-09-21-DNS接管已验证可行.md）—— 缺一个就被静默丢弃：
// 新建缓冲区、问题段逐字节搬、ANCOUNT/NSCOUNT/ARCOUNT 写对（丢掉 EDNS0 OPT）、
// QR=1 且 RD 跟查询一致、RA=1、IP 与 UDP 的地址/端口互换、长度改对。
func buildDNSResponse(pkt []byte, u udpInfo, q dnssniff.Query, ip net.IP) []byte {
	payload, ok := udpPayloadOnly(pkt)
	if !ok || q.QEnd > len(payload) || len(payload) < 12 {
		return nil
	}
	dns := make([]byte, 0, 12+(q.QEnd-12)+16)
	hdr := make([]byte, 12)
	copy(hdr, payload[:12])
	hdr[2] = 0x80 | (payload[2] & 0x01) // QR=1，RD 跟查询一致
	hdr[3] = 0x80                       // RA=1，RCODE=0
	if ip != nil {
		putBE16(hdr, 6, 1) // ANCOUNT=1
	} else {
		putBE16(hdr, 6, 0) // 空应答
	}
	putBE16(hdr, 8, 0)  // NSCOUNT=0
	putBE16(hdr, 10, 0) // ARCOUNT=0（丢掉 EDNS0 OPT，否则计数对不上）
	dns = append(dns, hdr...)
	dns = append(dns, payload[12:q.QEnd]...) // 问题段原样

	if ip != nil {
		ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01} // 名字指针 + TYPE=A + CLASS=IN
		ttl := uint32(dnsFakeTTL / time.Second)
		ans = append(ans, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
		ans = append(ans, 0x00, 0x04)
		ans = append(ans, ip.To4()...)
		dns = append(dns, ans...)
	}

	// 套回 IP + UDP（源/目标互换）
	ipLen := 20 + 8 + len(dns)
	resp := make([]byte, 0, ipLen)
	head := append([]byte{}, pkt[:20]...)
	copy(head[12:16], pkt[16:20]) // 源 = 原目标（DNS 服务器）
	copy(head[16:20], pkt[12:16]) // 目标 = 原来源（本机）
	putBE16(head, 2, uint16(ipLen))
	putBE16(head, 10, 0) // IP 校验和交给 CalcChecksums
	resp = append(resp, head...)
	resp = append(resp, byte(u.dport>>8), byte(u.dport))
	resp = append(resp, byte(u.sport>>8), byte(u.sport))
	ul := 8 + len(dns)
	resp = append(resp, byte(ul>>8), byte(ul), 0, 0)
	return append(resp, dns...)
}

// udpPayloadOnly 只取 UDP 负载（不关心地址）。
func udpPayloadOnly(pkt []byte) ([]byte, bool) {
	_, payload, ok := udpPayload(pkt)
	return payload, ok
}

// realResolver **绕开我们自己**的解析器：用专用源端口发查询。
//
// 为什么需要：DNS 接管会“看”到本机所有出方向 DNS 查询（包括我们自己进程发的）——
// 而拿到假 IP 后我们要把它换回**真实 IP**，如果那次解析也被自己塞了假 IP，
// 就是自己骗自己、跳进死循环。所以自己的查询从一个专用端口段发，并在过滤器里排除。
//
// 服务器地址仍然由系统配置决定（Go 的 Resolver 会把服务器地址传进来）。
func (e *Engine) realResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// 端口被占就往后找一个
			for p := dnsProbePortLo; p <= dnsProbePortHi; p++ {
				d := net.Dialer{
					Timeout:   3 * time.Second,
					LocalAddr: &net.UDPAddr{Port: p},
				}
				c, err := d.DialContext(ctx, "udp", address)
				if err == nil {
					return c, nil
				}
			}
			return nil, fmt.Errorf("DNS 探针端口 %d-%d 都被占用", dnsProbePortLo, dnsProbePortHi)
		},
	}
}

// resolveReal 把一个域名在本机解析成**真实 IP**（绕开我们自己的假 IP）。
//
// 拿到后调用方应该把它记进名字表（见 noteRealIP）—— 假 IP 只是为了让包能被拦到，
// 真实 IP 才是“这个名字现在实际用哪个地址”，它同时也是界面统计的数据源。
func (e *Engine) resolveReal(name string) net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := e.realResolver().LookupIP(ctx, "ip4", name)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			return v4
		}
	}
	return nil
}

// noteRealIP 记下“我们代理自己解出来的真实 IP”（DNS 接管路径专用）。
//
// 优先级用 PrioObserved（和嗅到的 DNS 应答同级）：dnsmap 是“只升不降”，所以
// 配置里 hosts/域名规则写死的映射（PrioRule）不会被这里覆盖 —— 那是用户明写的意图。
// TTL 与假 IP 同寿命（dnsFakeTTL）：过期自然回收，不会长期留着旧 IP。
func (e *Engine) noteRealIP(name string, ip net.IP) {
	v4 := ip.To4()
	if v4 == nil || e.names == nil {
		return
	}
	before := e.names.IPsFor(name)
	e.names.SetWithTTL(name, []string{v4.String()}, dnsmap.PrioObserved, dnsFakeTTL)
	if !sameStrSet(before, e.names.IPsFor(name)) {
		// 通了新 IP → 让内核过滤器把目标换进来（否则包到不了我们手里）
		e.applyHostIPs()
		e.onWildcardsChanged()
	}
}

// dnsCanaries 自检用的“不相干名字”（不属于任何通配规则，必须能解析出**真实 IP**）。
//
// 为什么需要：透明拦截工具最不该做的事是“一开就让人上不了网”。DNS 接管只应该
// 改变命中通配规则的名字，其余必须照常 —— 这一条不能靠“我觉得对”，要能验、
// 而且要能自己说出来。
var dnsCanaries = []string{"www.baidu.com", "www.qq.com"}

// dnsTakeoverSelfCheck 验“除指定域名外的解析照常吗”。
//
// **只报警，不自己关**：这个功能就是干这个的，一有问题就自废就没意义了。
// （唯一会自动退让的情形是“本机还有别的程序也在拦 DNS”导致的乒乓，那是真打架，
// 见 dnsTakeoverLoop 里的检测。）
//
// 判据：canary 名字用**系统解析器**（应用走的那条路）解一遍 —— 至少一个解出
// 非假 IP 才算通过；全解不出、或全被答成我们自己的假 IP → 大声报。
func (e *Engine) dnsTakeoverSelfCheck() {
	good, bad := 0, 0
	var detail []string
	for _, name := range dnsCanaries {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
		cancel()
		if err != nil || len(ips) == 0 {
			bad++
			detail = append(detail, fmt.Sprintf("%s 解不出（%v）", name, err))
			continue
		}
		fake := false
		for _, ip := range ips {
			if e.isFakeIP(ip) {
				fake = true
			}
		}
		if fake {
			bad++
			detail = append(detail, fmt.Sprintf("%s 被答成了我们自己的假 IP（%v）", name, ips))
			continue
		}
		good++
	}
	if good > 0 {
		e.bus.Info("dns.selftest: ok canaries=%v", dnsCanaries)
		return
	}
	e.bus.Error("dns.selftest: failed bad=%d total=%d detail=%v", bad, len(dnsCanaries), detail)
	e.bus.Error("  —— 注意：DNS 接管只应该改变**命中通配规则**的名字，其余必须照常。" +
		"这条已经影响别的名字了，请把上面几行日志发回来（功能不会自动关闭，但这个问题得查）")
}

// dnsTakeoverGuard 起来后马上自检一次，之后每 10 分钟复查（环境会变）。
func (e *Engine) dnsTakeoverGuard() {
	defer e.wg.Done()
	// 稍微等一下再查：启动瞬间本地 DNS 栈可能还在忙
	select {
	case <-e.done:
		return
	case <-time.After(3 * time.Second):
	}
	e.dnsTakeoverSelfCheck()
	tk := time.NewTicker(10 * time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			if e.dnsTakeoverRunning() {
				e.dnsTakeoverSelfCheck()
			}
		}
	}
}

// dnsTakeoverRunning DNS 接管句柄还在不在。
func (e *Engine) dnsTakeoverRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.injector != nil
}

// noticeSeen 直连/阻断日志去重用的一条记录。
type noticeSeen struct {
	key  string // 动作 + 目标
	last time.Time
}

// noteAction 同一动作在同一条连接上（同一源端口 + 同一目标）只报一行。
// 源端口被系统复用给另一个目标时，目标变了就再报一行。
func (e *Engine) noteAction(kind string, sport uint16, dst net.IP, dport uint16, note string) {
	e.noticeTick(sport, kind, dst, dport)
	e.bus.Throttle(fmt.Sprintf("action:%s:%s:%d", kind, dst, dport), time.Minute,
		"[%s] %s:%d  %s", kind, dst, dport, note)
}

// noteActionDetail 同 noteAction，但归到“详细日志”（内置直连那类刷屏项用它）。
func (e *Engine) noteActionDetail(kind string, sport uint16, dst net.IP, dport uint16, note string) {
	e.noticeTick(sport, kind, dst, dport)
	if e.bus.Verbose() {
		e.bus.Throttle(fmt.Sprintf("action:%s:%s:%d", kind, dst, dport), time.Minute,
			"[%s] %s:%d  %s", kind, dst, dport, note)
	}
}

// noticeTick 记下“这个源端口最后是什么动作/目标”（连接表与排查用）。
func (e *Engine) noticeTick(sport uint16, kind string, dst net.IP, dport uint16) {
	key := kind + " " + fmt.Sprintf("%s:%d", dst, dport)
	e.mu.Lock()
	if e.notices == nil {
		e.notices = map[uint16]noticeSeen{}
	}
	e.notices[sport] = noticeSeen{key: key, last: time.Now()}
	e.mu.Unlock()
}

// procLookupTries / procRetryEvery 一条连接最多查几次进程表、每次至少隔多久
// （见 connState.procTries）：新连接的头几拍常查不到（表还没刷新到它），
// 所以按时间间隔给它几次机会；短连接只试一次，长会话会被后续包补上。
const (
	procLookupTries = 5
	procRetryEvery  = 200 * time.Millisecond
)

// flowProc 这条连接的进程名 / PID。
//
// 三层次序：① 连接上已经查到过 → 用缓存的；② 试够了还没查到
// → 不再每包重查；③ 查一次表（常见情况只是内存里 map 命中）。
// flowProc 这条连接的进程名 / PID。
//
// 三层次序：① 连接上已经查到过 → 用缓存的；② 这个连接查过一次没查到
// （受保护进程/已消失）→ 不再每包重查；③ 查一次表（常见情况只是内存里 map 命中）。
//
// 为什么现在**总是查**（不再要求“规则里写了进程条件”）：
//   - 后台每 500ms 刷表这件事本来就在跑（resolver 在 New() 里建、Start() 里启），
//     省掉的只是一个 map 查找（实测命中 ~0.1µs，见 local/procbench）；
//   - 换来的是日志与连接列表里都有进程名（实测以前几乎全是 proc=unknown），
//     而“到底是谁在连这个地址”正是现场第一个要问的问题。
func (e *Engine) flowProc(sport uint16) (string, uint32) {
	if e.proc == nil {
		return "", 0
	}
	if st := e.flow(sport); st != nil {
		if st.procName != "" {
			return st.procName, st.pid
		}
		if st.procTries.Load() >= procLookupTries {
			return "", 0 // 试够了还查不到（受保护进程/已消失），别每个包都再查
		}
		now := time.Now().UnixNano()
		if now < st.procNext.Load() {
			return "", 0 // 距上次尝试太近：等下一个包再来
		}
		st.procNext.Store(now + int64(procRetryEvery))
		st.procTries.Add(1)
	}
	name, pid, _ := e.proc.ByPort(sport)
	if name == "" {
		// 只在详细日志里说：查不出进程名到底是“表里没这个端口”还是“打不开这个进程”。
		// 这两个在包路径上完全看不出区别（都表现为 proc=unknown）。
		e.bus.Detail("proc.lookup: port=%d result=unknown pid=%d", sport, pid)
	}
	return name, pid
}

// ProcStats 进程解析器缓存规模（诊断页用）。
func (e *Engine) ProcStats() (ports, pids int) {
	if e.proc == nil {
		return 0, 0
	}
	return e.proc.Stats()
}

// ProcPath 某个 PID 的完整路径（界面看“到底是谁”时用）。
func (e *Engine) ProcPath(pid uint32) string {
	if e.proc == nil {
		return ""
	}
	return e.proc.FullPath(pid)
}

// connLogCtx 给连接级日志拼上“哪条规则、哪个进程”两项（对齐 Proxifier 日志里的 rule/进程）。
//
// 拼成**独立的 key=value**（`rule=3 name="…" proc=chrome.exe pid=1234`），
// 而不是塞进一个字段：日志是给机器和 agent 读的，拆开才能单独 grep。
// 进程查不到就写 `proc=unknown` —— 宁可说不知道，也不要留空让人以为是空字符串。
func connLogCtx(ruleNo int, ruleName, procName string, pid uint32) string {
	var b strings.Builder
	if ruleNo > 0 {
		fmt.Fprintf(&b, " rule=%d", ruleNo)
		if ruleName != "" {
			fmt.Fprintf(&b, " name=%q", ruleName)
		}
	}
	if procName != "" {
		fmt.Fprintf(&b, " proc=%s pid=%d", procName, pid)
	} else {
		b.WriteString(" proc=unknown")
	}
	return b.String()
}

// ruleSuffix 给“直连/阻断”那类行内日志补上规则序号（有就补）。
func ruleSuffix(ruleNo int, ruleName string) string {
	if ruleNo <= 0 {
		return ""
	}
	if ruleName == "" {
		return fmt.Sprintf("（规则 %d）", ruleNo)
	}
	return fmt.Sprintf("（规则 %d %s）", ruleNo, ruleName)
}

// isSyn 只看 SYN（不带 ACK）—— 新连接的第一个包。
func isSyn(flags byte) bool { return flags&0x02 != 0 && flags&0x10 == 0 }

// builtinDirectPort 内置直连端口：Windows 更新传递优化（Delivery Optimization）。
// 这些连接在客户内网里应直连，不该进隧道 —— 以前靠配置里写 direct 规则，现在内置。
const builtinDirectPort = 7680

// rewriteOutbound 把应用发往内网目标的包改成"发给本机 relay"。
func (e *Engine) rewriteOutbound(h *divert.Handle, pkt []byte, addr *divert.Address, t int,
	src, dst net.IP, sport, dport uint16, flags byte, chain string, relayIP net.IP, relayPort uint16,
	ruleNo int, ruleName, procName string, pid uint32) {

	if isSyn(flags) {
		// A14：新建连接时判一次环（目标=上游自己 / 源=目标 / 同目标疯狂重连）
		e.checkLoop(src, dst, dport, chain)
		// A19：抓包写“改写前”的形态（目标还是内网地址）——拿 Wireshark 看就是一段正常会话
		e.cap.note(pkt)
		e.mu.Lock()
		_, existed := e.conns[sport]
		st := &connState{
			dst: dst, dport: dport,
			app: append(net.IP(nil), src...), appPort: sport,
			chain: chain, action: rules.ActionChain, start: time.Now(),
			ruleNo: ruleNo, ruleName: ruleName,
			procName: procName, pid: pid,
			counted: true, // 紧接着（!existed 时）会 statActive++
		}
		// 调用方刚刚查过一次进程表（flowProc）：不额外标记，
		// 让后续几个包还有机会补上（新连接的第一拍常查不到，见 procTries）。
		st.touch()
		e.conns[sport] = st
		if !existed {
			e.statTotal++
			e.statActive++
			e.statPerRule[chain]++
		}
		e.mu.Unlock()
		if !existed {
			ctx := connLogCtx(ruleNo, ruleName, procName, pid)
			// 目标是假 IP 时，日志里要看到**域名**（否则只能看到一个 198.19.x.x 莫明其妙）
			if e.isFakeIP(dst) {
				if n, ok := e.nameOf(dst); ok {
					st.fakeName = n
					e.bus.Info("intercept: chain=%s%s target=%s fake_ip=%s port=%d action=relay", chain, ctx, n, dst, dport)
				} else {
					e.bus.Info("intercept: chain=%s%s target=%s:%d action=relay fake_ip=unmapped", chain, ctx, dst, dport)
				}
			} else {
				e.bus.Info("intercept: chain=%s%s target=%s:%d action=relay", chain, ctx, dst, dport)
			}
		}
	} else if st := e.flow(sport); st != nil {
		st.touch()
	}

	// 目标 → relay；源也改成 relay 的 IP（关键！否则环回口丢包）
	copy(pkt[offDstIP:offDstIP+4], relayIP)
	putBE16(pkt, t+offDstPort, relayPort)
	copy(pkt[offSrcIP:offSrcIP+4], relayIP)

	if flags&0x04 != 0 { // RST：应用主动断了，标结束（条目留着给界面看）
		if st := e.flow(sport); st != nil {
			e.finish(st)
		}
	}

	divert.CalcChecksums(pkt, addr, divert.ChecksumDefault)
	if _, err := h.Send(pkt, addr); err != nil {
		e.bus.Throttle("inject.fail", time.Minute, "注入失败: %v（1 分钟内的重复不再逐条记）", err)
	}
}

// rewriteInbound 把 relay 回来的包改回"来自真正的内网目标"。
func (e *Engine) rewriteInbound(h *divert.Handle, pkt []byte, addr *divert.Address, t int, dport uint16) {
	st := e.flow(dport) // dport = 应用的源端口
	if st == nil {
		_, _ = h.Send(pkt, addr)
		return
	}
	st.touch()
	copy(pkt[offSrcIP:offSrcIP+4], st.dst.To4()) // 源 = 应用实际连的那个地址（假 IP 场景就是假 IP）
	putBE16(pkt, t+offSrcPort, st.dport)
	copy(pkt[offDstIP:offDstIP+4], st.app.To4())
	putBE16(pkt, t+offDstPort, st.appPort)
	divert.CalcChecksums(pkt, addr, divert.ChecksumDefault)
	// A19：入方向写“改写后”的形态（看起来就是从内网目标回来的）
	e.cap.note(pkt)
	if _, err := h.Send(pkt, addr); err != nil {
		e.bus.Throttle("inject.fail", time.Minute, "注入失败: %v（1 分钟内的重复不再逐条记）", err)
	}
}

// flow 按源端口取连接状态（读锁：每个包都要走，不能和写路径抢）。
func (e *Engine) flow(sport uint16) *connState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.conns[sport]
}

// passThrough 处理直连与阻断：计数 + 必要时记一行日志（去重）。
// 直连的包原样放回内核转发；阻断的包丢掉，并在 SYN 上回一个 RST。
func (e *Engine) passThrough(h *divert.Handle, pkt []byte, addr *divert.Address, t int,
	src, dst net.IP, sport, dport uint16, flags byte, act rules.Action, ruleNo int, ruleName, procName string, pid uint32, detail bool) {

	if isSyn(flags) {
		e.mu.Lock()
		if _, ok := e.conns[sport]; !ok {
			st := &connState{dst: dst, dport: dport, app: append(net.IP(nil), src...),
				appPort: sport, action: act, start: time.Now(),
				ruleNo: ruleNo, ruleName: ruleName, procName: procName, pid: pid}
			st.touch()
			e.conns[sport] = st
		}
		e.mu.Unlock()
		if act == rules.ActionDirect {
			if detail {
				e.noteActionDetail("直连", sport, dst, dport, "不走代理"+ruleSuffix(ruleNo, ruleName))
			} else {
				e.noteAction("直连", sport, dst, dport, "不走代理"+ruleSuffix(ruleNo, ruleName))
			}
		} else {
			e.noteAction("阻断", sport, dst, dport, "已丢弃"+ruleSuffix(ruleNo, ruleName))
		}
	}

	if st := e.flow(sport); st != nil {
		st.touch()
		st.packets.Add(1)
		if act == rules.ActionDirect {
			st.up.Add(uint64(len(pkt)))
		}
		if flags&0x05 != 0 { // FIN 或 RST：连接收了
			e.finish(st)
		}
	}

	if act == rules.ActionBlock {
		if isSyn(flags) {
			e.sendReset(h, pkt, addr, t, src, dst, sport, dport)
		}
		return // 阻断：包丢掉
	}
	// A19：直连的包原样写进抓包（能证实“这个目标确实没走隧道”）
	e.cap.note(pkt)
	_, _ = h.Send(pkt, addr)
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
			e.pruneOnce()
			e.bus.FlushThrottled() // 把“噪声停了但还是欠着”的去重计数补出来
			if tick++; tick%5 == 0 {
				e.logStatsSummary()
			}
			e.fillMissingProcs()
			activeCut := time.Now().Add(-10 * time.Minute).UnixNano()
			endedCut := time.Now().Add(-2 * time.Minute).UnixNano()
			e.mu.Lock()
			for k, st := range e.conns {
				cut := activeCut
				if st.ended.Load() {
					cut = endedCut
				}
				if st.last.Load() < cut {
					// 收尾时发现是“没人动的进行中”，把活跃数一起扣回来
					if st.ended.CompareAndSwap(false, true) && e.statActive > 0 {
						e.statActive--
					}
					delete(e.conns, k)
				}
			}
			for k, d := range e.notices {
				if d.last.Before(time.Unix(0, activeCut)) {
					delete(e.notices, k)
				}
			}
			e.mu.Unlock()
		}
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
		"② 安全软件里信任 nethub.exe 与 WinDivert64.sys（含 TUN 类驱动）；③ 确认没有同时开着第二个 nethub。")

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

// ───────────────────────── 过滤器与工具 ─────────────────────────

// buildFilter 拼 WinDivert 过滤器。
//
// 只有“需要隧道”的区间才进来（直连规则的目标不进），带端口的规则会把端口条件
// 一并写进过滤条件 —— 这样未列入的端口在驱动层就被放行，一次用户态都不用来。
// buildMainFilter 用规则集拼主过滤器（含 DNS 接管覆盖的假 IP 段 + QUIC 的 UDP 侧）。
//
// 抽出来是为了让**启动**与**热重载**走同一条装配路径 —— 两处各写一遍必然漂移
// （最典型的漂移就是漏掉假 IP 段，表现为“接管之后应用连不上假 IP”）。
// 返回 (过滤器原文, 区间数)；返回空串表示“没有需要拦截的规则”（调用方决定怎么报）。
func (e *Engine) buildMainFilter(s *rules.Set, relayPort uint16) (string, int) {
	rs := s.FilterRanges(e.cfg.CountDirectEnabled())
	var fake *rules.Range
	if e.fake != nil {
		if r := e.fake.Range(); r != nil {
			first := rules.IP2U(r.IP.To4())
			mask := rules.IP2U(net.IP(r.Mask).To4())
			fr := rules.Range{First: first, Last: first | ^mask}
			rs = append(rs, fr)
			fake = &fr
		}
	}
	if len(rs) == 0 {
		return "", 0
	}
	filter := buildFilter(rs, relayPort)

	// UDP 侧（QUIC 阻断）：只拿“走链 / 阻断”的区间 ——
	// **直连目标不进来**，它们的 QUIC 我们一个包也不该碰；
	// 勾了“不拦 QUIC”（allow_quic）的规则同样不进来（见 rules.QUICFilterRanges）。
	// 假 IP 段要带上：应用拿着假 IP 去连 QUIC，那边根本没人在听，
	// 回个 ICMP 让它回落 TCP（真 IP 由 TCP 那条路换回来）。
	if e.cfg.QuicBlockEnabled() {
		urs := rules.RangesForPort(s.QUICFilterRanges(), quicPort)
		if fake != nil {
			urs = append(urs, *fake)
		}
		if len(urs) > 0 {
			filter += fmt.Sprintf(" or (outbound and udp and udp.DstPort == %d and (%s))",
				quicPort, rangeClause(urs))
		}
	}
	return filter, len(rs)
}

func buildFilter(rs []rules.Range, relayPort uint16) string {
	return fmt.Sprintf("(outbound and tcp and (%s)) or (outbound and tcp and tcp.SrcPort == %d)",
		rangeClause(rs), relayPort)
}

// rangeClause 把规则区间拼成一个布尔表达式（拿掉外层的方向/协议条件）。
// 单独抽出来是因为“先接后判”的过滤器要把它放进 `not (...)` 里。
func rangeClause(rs []rules.Range) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		clause := fmt.Sprintf("ip.DstAddr >= %s and ip.DstAddr <= %s",
			rules.U2IP(r.First), rules.U2IP(r.Last))
		if len(r.Ports) > 0 {
			clause += " and (" + portFilter(r.Ports) + ")"
		}
		parts = append(parts, "("+clause+")")
	}
	return strings.Join(parts, " or ")
}

// portFilter 把端口区间拼成 WinDivert 的端口条件（形如 tcp.DstPort == 443）。
func portFilter(ps []rules.PortRange) string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.First == p.Last {
			out = append(out, fmt.Sprintf("tcp.DstPort == %d", p.First))
			continue
		}
		out = append(out, fmt.Sprintf("(tcp.DstPort >= %d and tcp.DstPort <= %d)", p.First, p.Last))
	}
	return strings.Join(out, " or ")
}

// openDivert 打开 WinDivert；首次安装驱动会失败一次（服务被创建但启动失败，
// 报 ERROR_NO_SYSTEM_RESOURCES），所以这里带重试 + 主动拉起服务。
// driverPathMatches 看驱动服务登记的 .sys 是不是就在当前目录旁边。
// 返回 (路径相符/无法判断, 当前登记的路径)。
func driverPathMatches() (bool, string) {
	exe, err := os.Executable()
	if err != nil {
		return true, "" // 判断不了就不要动它
	}
	want := filepath.Join(filepath.Dir(exe), "WinDivert64.sys")

	out, err := winrun.Command("sc", "qc", "WinDivert").CombinedOutput()
	if err != nil {
		return true, "" // 服务不存在，WinDivert 会自己装
	}
	i := strings.Index(string(out), "BINARY_PATH_NAME")
	if i < 0 {
		return true, ""
	}
	line := string(out)[i:]
	if j := strings.IndexAny(line, "\r\n"); j >= 0 {
		line = line[:j]
	}
	if !strings.Contains(line, ".sys") {
		return true, "" // 解析不出路径就别乱动
	}
	cur := strings.TrimSpace(line[strings.Index(line, ":")+1:])
	cur = strings.TrimSpace(strings.TrimPrefix(cur, `\??\`))
	return strings.EqualFold(cur, want), cur
}

// serviceState 查服务状态（STOPPED / RUNNING / 不存在）。
func serviceState(name string) string {
	out, err := winrun.Command("sc", "query", name).CombinedOutput()
	if err != nil {
		return "MISSING"
	}
	s := string(out)
	for _, st := range []string{"RUNNING", "STOPPED", "START_PENDING", "STOP_PENDING"} {
		if strings.Contains(s, st) {
			return st
		}
	}
	return "UNKNOWN"
}

// rebuildDriverService 把驱动服务重建到当前目录。
//
// **关键（这是踩过的坑）**：不能“停一下马上就删”。驱动还挂在内核里的时候强行删服务，
// 会留下残留状态，之后加载会一直报 1450（Insufficient system resources）——
// 而且这个错误会把人往“杀毒软件拦截”上带，很难查。
// 所以：先 stop，**轮询等它真的 STOPPED**，再 delete，**再等它真的消失**。
func rebuildDriverService(bus *logbus.Bus, oldPath string) {
	exe, _ := os.Executable()
	want := filepath.Join(filepath.Dir(exe), "WinDivert64.sys")
	bus.Warn("驱动服务指向旧路径（%s），重建为 %s", oldPath, want)

	_ = winrun.Command("sc", "stop", "WinDivert").Run()
	if !waitFor(func() bool { return serviceState("WinDivert") != "RUNNING" }, 15*time.Second) {
		bus.Warn("驱动服务 15 秒内没停下来，仍继续尝试重建")
	}
	_ = winrun.Command("sc", "delete", "WinDivert").Run()
	if !waitFor(func() bool { return serviceState("WinDivert") == "MISSING" }, 15*time.Second) {
		bus.Warn("驱动服务 15 秒内没删除干净（可能还有句柄），继续尝试")
	}
}

func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func openDivert(bus *logbus.Bus, filter string) (*divert.Handle, error) {
	var lastErr error
	// 先直接试。【不要】一上来就动驱动服务 —— 服务重建本身有风险，
	// 而且如果服务路径只是“看起来旧”但驱动已经加载着，它其实能用。
	for attempt := 1; attempt <= 6; attempt++ {
		h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err == nil {
			if attempt > 1 {
				bus.Info("WinDivert 第 %d 次尝试成功", attempt)
			}
			return h, nil
		}
		lastErr = err

		// 失败时区分两种情况：只在“路径确实不符”时重建服务，否则只是把服务启起来
		if ok, cur := driverPathMatches(); !ok && attempt == 1 {
			rebuildDriverService(bus, cur)
			continue
		}

		bus.Warn("WinDivert 打开失败(第 %d/6 次): %v", attempt, err)
		out, serr := winrun.Command("sc", "start", "WinDivert").CombinedOutput()
		if serr != nil {
			bus.Info("  sc start WinDivert -> %s", strings.TrimSpace(string(out)))
		} else {
			bus.Info("  已尝试启动 WinDivert 驱动服务")
		}
		time.Sleep(time.Duration(attempt) * 700 * time.Millisecond)
	}

	// 报错要能指向正确方向：1450 在内存池健康时通常不是“真的缺资源”，
	// 而是残留状态或安全软件拦截，别让人去查内存。
	hint := ""
	if strings.Contains(lastErr.Error(), "resources") {
		hint = "\n  提示：内存池健康时出现这个错误，通常不是真的缺资源，而是：\n" +
			"    ① 反复加载/卸载驱动留下的残留状态 → 重启系统即可恢复\n" +
			"    ② 安全软件（火绒/360 等）拦截了驱动加载 → 检查其拦截记录，把 nethub.exe 与 WinDivert 加入信任"
	}
	return nil, fmt.Errorf("重试 6 次仍失败: %w%s", lastErr, hint)
}

func parseIPv4(p []byte) (src, dst net.IP, ihl int, proto uint8, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl = int(p[0]&0x0f) * 4
	if len(p) < ihl {
		return
	}
	src = net.IPv4(p[offSrcIP], p[offSrcIP+1], p[offSrcIP+2], p[offSrcIP+3]).To4()
	dst = net.IPv4(p[offDstIP], p[offDstIP+1], p[offDstIP+2], p[offDstIP+3]).To4()
	proto = p[offProto]
	ok = true
	return
}

func be16(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return uint16(b[off])<<8 | uint16(b[off+1])
}

func putBE16(b []byte, off int, v uint16) {
	if off+2 > len(b) {
		return
	}
	b[off] = byte(v >> 8)
	b[off+1] = byte(v)
}

func hostOf(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return "127.0.0.1"
	}
	return h
}

func portOf(hostport string) uint16 {
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return 0
	}
	var v uint16
	fmt.Sscanf(p, "%d", &v)
	return v
}

// ───────── 本机网络变化（A16：带 LocalNets 条件的规则靠它生效/失效）─────────

// localNetLoop 定期把本机地址告诉规则层。
// 为什么需要循环而不是只做一次：笔记本会在“公司网/家里/热点”之间切换，
// 插拔网线或用 WLAN 都会变地址；规则要跟着变（否则该走隧道的流量会直连）。
func (e *Engine) localNetLoop() {
	defer e.wg.Done()
	last := ""
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		ips := localIPv4s()
		sig := ipsKey(ips)
		if sig != last {
			e.ruleSet().SetLocalIPs(ips)
			if last != "" {
				// 只在真的变了的时候说一句，别刷日志
				e.bus.Info("本机网络变化：现在 %s（带本机网段条件的规则会据此生效/失效）", sig)
			}
			last = sig
		}
		select {
		case <-e.done:
			return
		case <-tick.C:
		}
	}
}

// localIPv4s 本机当前的非回环 IPv4（只取已启用且有地址的网卡）。
func localIPv4s() []net.IP {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, it := range ifs {
		if it.Flags&net.FlagUp == 0 || it.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := it.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					out = append(out, v4)
				}
			}
		}
	}
	return out
}

// ipsKey 给一组地址排个序拼成短字符串（用于“有没有变化”的比较与日志）。
func ipsKey(ips []net.IP) string {
	ss := make([]string, 0, len(ips))
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}
	sort.Strings(ss)
	return strings.Join(ss, ", ")
}

// procNewResolver 供测试直接造一个进程解析器（生产路径由 New 注入）。
func procNewResolver() *proc.Resolver { return proc.NewResolver() }

// ───────────────────────── 域名规则（名字↔IP）─────────────────────────

// resolveHostTargets 把规则里的域名解析成 IP，填进规则集（供匹配与过滤器用）。
//
// 解析不到的域名**不阻断启动**（DNS 一时不可用很常见）：那条规则暂时不匹配任何东西，
// 界面上能看到它没解析出来。warnChange 为真时（定期刷新）把"IP 变了"说出来，
// 因为过滤器在启动时就装配好了，新 IP 要重启服务才生效。
func (e *Engine) resolveHostTargets(warnChange bool) {
	e.seedFromHosts()
	hosts := e.ruleSet().HostTargets()
	if len(hosts) == 0 {
		// 没有具体域名要解析：但可能有通配规则，仍要把观察到的名字交下去
		e.applyHostIPs()
		return
	}
	var unresolved []string
	for _, h := range hosts {
		before := e.names.IPsFor(h)
		ips, err := e.names.Resolve(h, dnsmap.PrioRule)
		if err != nil || len(ips) == 0 {
			unresolved = append(unresolved, h)
			continue
		}
		if warnChange && len(before) > 0 && !sameStrSet(before, ips) {
			e.bus.Warn("域名 %s 的 IP 变了（%v → %v）—— 过滤器在启动时装配，重启服务后新 IP 才生效",
				h, before, ips)
		}
	}
	e.applyHostIPs()
	if len(unresolved) > 0 {
		// 解析不到的域名规则 = **一条也不拦**（不猜、也不退化成拦全部）。
		// 启动时也必须说一声，否则“规则配了、什么都没拦、日志也不说”就是静默失效。
		if warnChange {
			e.bus.Warn("这些域名规则暂时解析不到，暂时不匹配任何流量：%v", unresolved)
		} else {
			e.bus.Warn("域名规则解析不到，这条规则目前不匹配任何流量：%v（本机 DNS 或 hosts 里没有这些名字？）", unresolved)
		}
	}
}

// seedFromHosts 把 hosts 托管里的条目先灌进名字表。
//
// 为什么要这一步：hosts 里的名字**根本不会产生 DNS 报文**（系统直接查文件），
// 而我们学名字靠的是嗅探 DNS 应答 —— 不灌的话，“内网域名全靠 hosts 写死”
// 这种最典型的场景下，通配域名将什么都匹配不到。
// TTL 给长一点（每轮 nameLoop 都会重新灌一遍，过期清理不会误删）。
func (e *Engine) seedFromHosts() {
	if e.cfg == nil {
		return
	}
	hosts := e.cfg.HostsCopy()
	if !hosts.Manage {
		return
	}
	for _, line := range hosts.Entries {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if net.ParseIP(f[0]).To4() == nil {
			continue
		}
		for _, name := range f[1:] {
			if dnsmap.IsHostname(name) && !dnsmap.IsWildcard(name) {
				e.names.SetWithTTL(name, []string{f[0]}, dnsmap.PrioObserved, 12*time.Hour)
			}
		}
	}
}

// applyHostIPs 把“名字表里的全部名字（含观察到的）”交给**当前**规则集。
func (e *Engine) applyHostIPs() { e.applyHostIPsTo(e.ruleSet()) }

// applyHostIPsTo 把“名字表里的全部名字（含观察到的）”交给指定规则集。
//
// 通配域名（*.his.com）就是靠这一步才能命中：规则层从 map 里挑出后缀匹配的名字，
// 把它们当前解析到的 IP 填进 hostIPs —— 这决定了过滤器会不会拦住这些 IP。
//
// 热重载要用它把学到的名字**继承**给新规则集（否则通配规则会“忘掉”已观察到的名字）。
func (e *Engine) applyHostIPsTo(s *rules.Set) {
	byHost := map[string][]*net.IPNet{}
	for h, ips := range e.names.Snapshot() {
		var nets []*net.IPNet
		for _, str := range ips {
			if ip := net.ParseIP(str); ip != nil && ip.To4() != nil {
				nets = append(nets, &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)})
			}
		}
		if len(nets) > 0 {
			byHost[h] = nets
		}
	}
	s.SetHostIPs(byHost)
}

// nameLoop 定期刷新域名解析（内网 DNS 记录会变；不刷新就一直是启动那一份）。
func (e *Engine) nameLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(dnsmap.TTL)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			e.resolveHostTargets(true)
			e.pruneNames()
			e.sweepFakeIP()
		}
	}
}

// pruneNames 掉过期的**观察结果**（规则里写的域名由 resolveHostTargets 重新解析）。
//
// 为什么必须做：观察到的名字对应的 IP 会进动态过滤器，不摘掉的话
// 过滤器只会越滚越大、而且会把早就不用的域名的旧 IP 一直当成“要接管的目标”。
func (e *Engine) pruneNames() {
	exp := e.names.Expired()
	if len(exp) == 0 {
		return
	}
	for _, h := range exp {
		e.names.Remove(h)
	}
	e.bus.Detail("name.expire: count=%d names=%v", len(exp), exp)
	e.applyHostIPs()
	e.onWildcardsChanged()
}

// HostResolveView 域名解析状态（界面/诊断页看"这个域名现在指到哪"）。
type HostResolveView struct {
	Host    string   `json:"host"`
	IPs     []string `json:"ips"`
	Age     string   `json:"age"`
	Stale   bool     `json:"stale"`
	Failed  bool     `json:"failed"`
	LastErr string   `json:"lastErr"`
}

// HostResolves 列出所有域名规则的解析状态。
func (e *Engine) HostResolves() []HostResolveView {
	if e.names == nil {
		return nil
	}
	st := e.names.Status()
	out := make([]HostResolveView, 0, len(st))
	for _, s := range st {
		out = append(out, HostResolveView{
			Host: s.Host, IPs: s.IPs, Age: s.Age.Truncate(time.Second).String(),
			Stale: s.Stale, Failed: s.Failed, LastErr: s.LastErr,
		})
	}
	return out
}

// NameForIP 这个 IP 当前对应哪个域名（界面解释"这条连接为什么走了隧道"用）。
func (e *Engine) NameForIP(ip net.IP) string {
	if e.names == nil {
		return ""
	}
	n, _ := e.names.NameFor(ip)
	return n
}

// dialViaName 把**域名**交给上游解析并连接（而不是本机先解析成 IP）。
//
// 为什么单独一条路（不走预热池/竞速）：那两套是围绕"目标 IP"建的，
// 而这里的目标是名字 —— 混进去只会把两条路径都弄乱；域名规则的连接量本来也小。
func (e *Engine) dialViaName(ch config.Chain, host string, dport uint16) (net.Conn, error) {
	raws := e.cfg.UpstreamsResolved(ch)
	if len(raws) == 0 {
		return nil, fmt.Errorf("链 %s 没有配置上游", ch.Name)
	}
	per := e.cfg.DialTimeoutDur()
	var lastErr error
	for _, raw := range raws {
		u, err := upstream.Parse(raw)
		if err != nil {
			lastErr = err
			continue
		}
		conn, err := u.DialHost(host, dport, per)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用上游")
	}
	return nil, fmt.Errorf("把域名 %s 交给上游解析失败: %w", host, lastErr)
}
