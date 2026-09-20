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
	"fmt"
	"net"
	"nethub/internal/winrun"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/config"
	"nethub/internal/logbus"
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

	last    atomic.Int64  // unix nano：最后一次看到包/数据的时间
	up      atomic.Uint64 // 应用 → 目标 的字节（直连只能统计出方向）
	down    atomic.Uint64 // 目标 → 应用 的字节
	packets atomic.Uint64 // 包数（直连/阻断时用得上）
	ended   atomic.Bool
	errText atomic.Value // string：失败原因（如隧道建立失败）
}

func (st *connState) touch() { st.last.Store(time.Now().UnixNano()) }

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
	Started string `json:"started"`
	Dur     string `json:"dur"`
	Up      uint64 `json:"up"`
	Down    uint64 `json:"down"`
	Packets uint64 `json:"packets"`
	State   string `json:"state"`
	Error   string `json:"error"`
}

// Conns 返回连接表快照：进行中在前，其余按最后活动时间倒序；limit<=0 表示不限。
func (e *Engine) Conns(limit int) []ConnView {
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
		out = append(out, ConnView{
			Target:  fmt.Sprintf("%s:%d", st.dst, st.dport),
			Action:  st.action.String(),
			Chain:   st.chain,
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
	bus   *logbus.Bus
	rules *rules.Set
	cfg   *config.Config

	mu      sync.RWMutex
	handle  *divert.Handle
	ln      net.Listener
	relay   string
	conns   map[uint16]*connState
	notices map[uint16]noticeSeen    // 直连/阻断日志去重：源端口 → 上次报过的动作+目标
	health  map[string][]*upHealth   // 每条链的上游健康（与 Upstreams() 下标对齐）
	targets map[string]*targetHealth // 业务目标巡检结果（按 ip:port 索引）
	round   int                      // 轮询策略的游标
	run     bool

	// 统计
	statTotal   uint64
	statActive  int
	statPerRule map[string]uint64

	stopOnce sync.Once

	// fatalMu/fatal 记下“拦截已中断”的原因（驱动被卸载、句柄被抢等）
	fatalMu sync.Mutex
	fatal   error

	// loop 环路检测（A14）：与其它代理共存时发现自己打转
	loop *loopGuard

	// cap 抓包（A19）：按需把包写成 pcap
	cap *capturer

	// pool 预热连接池（A11）：养着“已握手、只差 CONNECT”的会话
	pool *warmPool
	done chan struct{}
	wg   sync.WaitGroup

	// Notify 由上层（App）注入：把"状态变化"变成应用内提示。
	// 第二个参数为 true 表示是不好的消息。
	Notify func(title, text string, bad bool)
}

func New(bus *logbus.Bus, rs *rules.Set, cfg *config.Config) *Engine {
	return &Engine{
		bus: bus, rules: rs, cfg: cfg,
		conns:       map[uint16]*connState{},
		statPerRule: map[string]uint64{},
		done:        make(chan struct{}),
		pool:        newWarmPool(),
		loop:        newLoopGuard(),
		cap:         newCapturer(),
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

// Stats 返回 (累计连接数, 当前活跃数)。
func (e *Engine) Stats() (uint64, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statTotal, e.statActive
}

// Start 启动拦截。返回后即处于运行状态。
func (e *Engine) Start() error {
	e.setFatal(nil) // 重新启动就清掉“已中断”状态
	e.mu.Lock()
	if e.run {
		e.mu.Unlock()
		return fmt.Errorf("已在运行")
	}
	e.mu.Unlock()

	// 1) 先起 relay，拿到真实端口（端口可能配的是 0=自动分配，过滤器要用它）
	ln, err := net.Listen("tcp", e.cfg.Relay)
	if err != nil {
		return fmt.Errorf("relay 监听 %s 失败: %w", e.cfg.Relay, err)
	}
	relay := ln.Addr().String()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// 2) 用规则区间拼内核过滤器（直连规则的目标不进过滤器，见 rules.FilterRanges）
	rs := e.rules.FilterRanges(e.cfg.CountDirectEnabled())
	if len(rs) == 0 {
		ln.Close()
		return fmt.Errorf("没有需要拦截的规则（只填了直连规则时无事可做）")
	}
	filter := buildFilter(rs, port)
	e.bus.Info("内核过滤器: %s", filter)

	// 3) 打开 WinDivert（含首次安装驱动的重试）
	h, err := openDivert(e.bus, filter)
	if err != nil {
		ln.Close()
		return fmt.Errorf("WinDivert 打开失败: %w", err)
	}

	e.mu.Lock()
	e.ln, e.relay, e.handle, e.run = ln, relay, h, true
	e.mu.Unlock()

	e.bus.Info("✓ 拦截已启动：relay=%s，规则 %d 条", relay, len(e.rules.List()))
	for _, r := range e.rules.List() {
		switch r.Action {
		case rules.ActionDirect:
			e.bus.Info("    %s  →  直连（不走代理）", r.Label())
		case rules.ActionBlock:
			e.bus.Info("    %s  →  阻断（丢弃）", r.Label())
		default:
			e.bus.Info("    %s  →  链 %s", r.Label(), r.Chain)
		}
	}
	for _, ch := range e.cfg.Chains {
		e.bus.Info("    链 %s：%d 个上游，策略 %s，探测 %s",
			ch.Name, len(ch.Upstreams()), ch.StrategyName(), ch.ProbeInterval())
	}

	e.wg.Add(6)
	go e.acceptLoop()
	go e.packetLoop()
	go e.janitor()
	go e.healthLoop()
	go e.targetLoop()
	go e.localNetLoop()
	return nil
}

// Stop 停止拦截并回收资源。
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
func (e *Engine) Stop() {
	e.pool.closeAll() // 池里的会话要主动关，否则退出时留下悬挂连接
	e.stopOnce.Do(func() {
		close(e.done)

		e.mu.Lock()
		h, ln, run := e.handle, e.ln, e.run
		e.handle, e.ln, e.run = nil, nil, false
		e.mu.Unlock()

		if h != nil {
			h.Close() // 让 packetLoop 的 Recv 立刻返回错误
		}
		if ln != nil {
			ln.Close()
		}
		e.wg.Wait()
		if run {
			e.bus.Info("拦截已停止")
		}
	})
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
		go e.handleConn(c)
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
	raws := ch.Upstreams()
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
		c, ok, raced := e.dialRacing(ch, raws, cands, dst, dport, per, budget)
		if ok {
			return c, nil
		}
		if raced {
			// 竞速已经把**所有**候选都拨过一遍了，失败就是真失败；
			// 再回退一次顺序试等于把同一批上游拨两遍（白等一个预算）。
			return nil, fmt.Errorf("链 %s：所有上游都连不上", ch.Name)
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
	return nil, fmt.Errorf("%s", strings.Join(errs, "；"))
}

// tryUpstream 试一条上游，并把结果记进健康表。
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
		e.markUp(ch.Name, idx, true, lat, "")
		return c, nil, ""
	}
	e.markUp(ch.Name, idx, false, lat, err.Error())
	return nil, err, fmt.Sprintf("%s: %v", up.String(), err)
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
	dst net.IP, dport uint16, per, budget time.Duration) (net.Conn, bool, bool) {
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
			return a.c, true, true
		}
		// 第一条已经明确失败（被拒/解析错）→ 交给顺序试，它从第二条开始
		if a.c != nil {
			a.c.Close()
		}
		return nil, false, false
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
				return a.c, true, true
			}
			errs = append(errs, a.msg)
		case a := <-first:
			firstRead = 1
			if a.err == nil {
				go drainAttempts(rest, n-readRest, per)
				return a.c, true, true
			}
			errs = append(errs, a.msg)
		}
	}
	e.bus.Warn("链 %s 竞速全失败：%s", ch.Name, strings.Join(errs, "；"))
	return nil, false, true
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

	ch, ok := e.cfg.ChainByName(st.chain)
	if !ok {
		e.bus.Error("链 %s 不存在，丢弃 %s:%d", st.chain, st.dst, st.dport)
		return
	}

	up, err := e.dialUpstreamKeyed(ch, st.dst, st.dport, st.app.String())
	if err != nil {
		e.bus.Error("[%s] 隧道建立失败 %s:%d — %v", st.chain, st.dst, st.dport, err)
		st.fail(err.Error())
		e.finish(st)
		return
	}
	defer up.Close()

	e.bus.Info("[%s] 已接管 %s:%d  (来源端口 %d)", st.chain, st.dst, st.dport, sport)

	done := make(chan struct{}, 2)
	go func() { copyAndClose(up, c, &st.up); done <- struct{}{} }()
	go func() { copyAndClose(c, up, &st.down); done <- struct{}{} }()
	<-done

	e.finish(st)
	e.bus.Info("[%s] 连接结束 %s:%d  ↑ %s  ↓ %s", st.chain, st.dst, st.dport,
		humanBytes(st.up.Load()), humanBytes(st.down.Load()))
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

func (e *Engine) packetLoop() {
	defer e.wg.Done()

	e.mu.Lock()
	h := e.handle
	e.mu.Unlock()

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
			default:
				e.bus.Error("WinDivert Recv 失败，拦截已中断: %v", err)
				e.setFatal(err) // 让界面变红「Error」—— 否则状态还说“运行中”，其实一个包都没拦
				if e.Notify != nil {
					e.Notify("拦截已中断", err.Error()+"（请重启服务）", true)
				}
				return
			}
		}
		pkt := buf[:n]

		src, dst, ihl, proto, ok := parseIPv4(pkt)
		if !ok || proto != 6 || len(pkt) < ihl+20 {
			_, _ = h.Send(pkt, addr)
			continue
		}
		t := ihl
		sport := be16(pkt, t+offSrcPort)
		dport := be16(pkt, t+offDstPort)
		flags := pkt[t+offFlags]

		// 方向判定不依赖 addr.Flags 的位布局：目标落在规则内 = 应用发出的包。
		if chain, act, hit := e.rules.Match(dst, dport); hit {
			switch act {
			case rules.ActionDirect, rules.ActionBlock:
				e.passThrough(h, pkt, addr, t, src, dst, sport, dport, flags, act)
			default:
				e.rewriteOutbound(h, pkt, addr, t, src, dst, sport, dport, flags, chain, relayIP, relayPort)
			}
			continue
		}
		// 没命中任何规则：要么是 relay 回来的包（源端口 = relay 端口），
		// 要么是“带本机网段条件的规则”**当前不生效**（A16）——
		// 后者必须原样放回内核，绝不能当入站包改写（会把用户的包改坏）。
		if sport == relayPort {
			e.rewriteInbound(h, pkt, addr, t, dport)
			continue
		}
		// 直连流量（仅当开了“统计直连流量”才会被拦到这里）：
		// 回来的包也要数上，否则界面上永远只有出方向（A15）。
		if st := e.flow(dport); st != nil && st.action == rules.ActionDirect {
			st.touch()
			st.packets.Add(1)
			st.down.Add(uint64(len(pkt)))
		}
		e.cap.note(pkt)
		if _, err := h.Send(pkt, addr); err != nil {
			e.bus.Warn("注入失败: %v", err)
		}
	}
}

// noticeSeen 直连/阻断日志去重用的一条记录。
type noticeSeen struct {
	key  string // 动作 + 目标
	last time.Time
}

// noteAction 同一动作在同一条连接上（同一源端口 + 同一目标）只报一行。
// 源端口被系统复用给另一个目标时，目标变了就再报一行。
func (e *Engine) noteAction(kind string, sport uint16, dst net.IP, dport uint16, note string) {
	key := kind + " " + fmt.Sprintf("%s:%d", dst, dport)
	e.mu.Lock()
	if e.notices == nil {
		e.notices = map[uint16]noticeSeen{}
	}
	prev, seen := e.notices[sport]
	e.notices[sport] = noticeSeen{key: key, last: time.Now()}
	e.mu.Unlock()
	if !seen || prev.key != key {
		e.bus.Info("[%s] %s:%d  %s", kind, dst, dport, note)
	}
}

// isSyn 只看 SYN（不带 ACK）—— 新连接的第一个包。
func isSyn(flags byte) bool { return flags&0x02 != 0 && flags&0x10 == 0 }

// rewriteOutbound 把应用发往内网目标的包改成"发给本机 relay"。
func (e *Engine) rewriteOutbound(h *divert.Handle, pkt []byte, addr *divert.Address, t int,
	src, dst net.IP, sport, dport uint16, flags byte, chain string, relayIP net.IP, relayPort uint16) {

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
		}
		st.touch()
		e.conns[sport] = st
		if !existed {
			e.statTotal++
			e.statActive++
			e.statPerRule[chain]++
		}
		e.mu.Unlock()
		if !existed {
			e.bus.Info("[%s] 拦截 %s:%d  → relay", chain, dst, dport)
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
		e.bus.Warn("注入失败: %v", err)
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
	copy(pkt[offSrcIP:offSrcIP+4], st.dst.To4())
	putBE16(pkt, t+offSrcPort, st.dport)
	copy(pkt[offDstIP:offDstIP+4], st.app.To4())
	putBE16(pkt, t+offDstPort, st.appPort)
	divert.CalcChecksums(pkt, addr, divert.ChecksumDefault)
	// A19：入方向写“改写后”的形态（看起来就是从内网目标回来的）
	e.cap.note(pkt)
	if _, err := h.Send(pkt, addr); err != nil {
		e.bus.Warn("注入失败: %v", err)
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
	src, dst net.IP, sport, dport uint16, flags byte, act rules.Action) {

	if isSyn(flags) {
		e.mu.Lock()
		if _, ok := e.conns[sport]; !ok {
			st := &connState{dst: dst, dport: dport, app: append(net.IP(nil), src...),
				appPort: sport, action: act, start: time.Now()}
			st.touch()
			e.conns[sport] = st
		}
		e.mu.Unlock()
		if act == rules.ActionDirect {
			e.noteAction("直连", sport, dst, dport, "不走代理")
		} else {
			e.noteAction("阻断", sport, dst, dport, "已丢弃")
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
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			e.pruneLoops() // A14：清掉过期的环路检测窗口
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

// ───────────────────────── 过滤器与工具 ─────────────────────────

// buildFilter 拼 WinDivert 过滤器。
//
// 只有“需要隧道”的区间才进来（直连规则的目标不进），带端口的规则会把端口条件
// 一并写进过滤条件 —— 这样未列入的端口在驱动层就被放行，一次用户态都不用来。
func buildFilter(rs []rules.Range, relayPort uint16) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		clause := fmt.Sprintf("ip.DstAddr >= %s and ip.DstAddr <= %s",
			rules.U2IP(r.First), rules.U2IP(r.Last))
		if len(r.Ports) > 0 {
			clause += " and (" + portFilter(r.Ports) + ")"
		}
		parts = append(parts, "("+clause+")")
	}
	return fmt.Sprintf("(outbound and tcp and (%s)) or (outbound and tcp and tcp.SrcPort == %d)",
		strings.Join(parts, " or "), relayPort)
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
			e.rules.SetLocalIPs(ips)
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
