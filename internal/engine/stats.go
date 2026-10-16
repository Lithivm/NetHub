package engine

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nethub/internal/rules"
)

// ───────────────────── 统计（界面上「统计」页） ─────────────────────
//
// 回答的问题不是"现在有哪些连接"（那是「连接」页），而是**"这段时间谁在占通道"**：
// 按应用、按目标的累计连接数 / 失败数 / 字节数 / 速率。
//
// 两个口径，界面上一个开关切换（都在内存里，**不落盘**）：
//
//	· 本次运行（run）：引擎这一次 Start 以来 —— Start 时把这些字段清零；
//	· 累计（all）    ：进程活着期间的合计，跨启停；界面上的「清零」把它清掉。
//
// 不落盘的理由：现场要的是"这台机器这一天谁在占带宽"，而重启进程是人为动作
// （换配置、升级）—— 把重启之前的数留着，只会与新的运行混在一起，谁也说不清
// 那个数字是哪一段的。真正的长期账在日志的 5 分钟概览里（logStatsSummary）。
//
// 桶在连接**收尾时**累加（finish / janitor 回收，幂等约定见 noteStatEnd），
// 而**当前还开着的连接**在读的时候实时算进去 —— 否则一个开了 8 小时的 HIS 会话
// 在页面上永远是 0，可"谁在占带宽"问的恰恰是它。
// 口径与「连接」页一致：不算我们自己的探针（selfconn.go：那是仪器不是业务）。
const (
	// StatBucketCap 每个维度（应用 / 目标）最多留几个桶，超出淘汰**最久没活动**的那个。
	//
	// 为什么要上限：目标键来自"应用实际连的地址"，一台机器跑一天能见到几百个
	// （每个 CDN/更新服务器都是一个）。512 足够覆盖真实业务的头部，而尾部那些
	// 只连过一次的键本来也不会有人去看。
	StatBucketCap = 512
	// StatTopN 界面上一张表默认显示几行（其余折起来，见 StatPage.KeysApps）。
	StatTopN = 20
	// statPortsKeep 每个目标桶记几个端口（目标的端口分布是"顺手看一眼"的信息，不是报表）。
	statPortsKeep = 4

	// StatUnknownApp 查不到进程时那一行的名字（与「连接」页"未知"同一个说法）。
	StatUnknownApp = "未知（系统/受保护进程）"

	// StatScopeRun / StatScopeAll 两个口径。
	StatScopeRun = "run"
	StatScopeAll = "all"
)

// statBucket 一个维度键上的累计桶。
//
// 累计与"本次运行"两套数字**放在同一个桶里**（而不是两张表）：这样 Start 时
// 只要把 run* 清零，键的名字、端口、IP 这些展示信息都还在，界面不会"重启一下
// 就把认识的目标名全忘了"。
type statBucket struct {
	// conns/failed/up/down：累计口径。failed 含"拨号失败/未送达中转/**被阻断**"，
	// 因为它们都是"应用想连但没连上"——这正是这一页要回答的第二个问题。
	conns, failed, up, down uint64

	// runConns/runFailed/runUp/runDown：本次运行口径。
	runConns, runFailed, runUp, runDown uint64

	// first/last 这个桶第一次/最后一次活动的时刻（两个口径共用：它只用来算平均速率与
	// "最后活动多久前"，跟口径无关 —— 界面上的时长本来就是给"这一行还在不在动"用的）。
	first, last time.Time

	ports []uint16 // 见过的端口（最多 statPortsKeep 个）
	ip    net.IP   // 目标是域名时，记一个实际解析到的地址（界面上给"实际地址"）
}

func (b *statBucket) beginRun() { b.runConns, b.runFailed, b.runUp, b.runDown = 0, 0, 0, 0 }

func (b *statBucket) addPort(p uint16) {
	for _, x := range b.ports {
		if x == p {
			return
		}
	}
	if len(b.ports) >= statPortsKeep {
		return
	}
	b.ports = append(b.ports, p)
}

// statPortsText 端口列的文字形式（应用维度为空串）。
func statPortsText(ps []uint16) string {
	var sb strings.Builder
	for i, p := range ps {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(int(p)))
	}
	return sb.String()
}

// statBoard 统计板的内部状态。锁是**叶子锁**：绝不可以在持有它的时候再去拿 e.mu
// （读路径的调用方保证先取快照再进这里）。
type statBoard struct {
	mu sync.Mutex
	// app/tgt 两个维度的桶。**同一个连接同时进两个维度**（一张表按应用看，一张按目标看），
	// 所以两边的合计天然相等 —— 界面上两张表可以互相印证。
	app, tgt map[string]*statBucket
	// 合计与桶**分开存**：桶有上限会淘汰，合计不能跟着丢（否则"总数"越跑越小）。
	conns, failed, up, down uint64
	// 按动作分解：走隧道的 / 直连的 / 阻断的。界面上要能把"不走隧道的那些"说清楚 ——
	// 「连接」页的活跃数早就含它们了，统计页要是只报走隧道的那批，两个页面会自相矛盾。
	chain, direct, blocked uint64
	// 本次运行口径
	runConns, runFailed, runUp, runDown uint64
	runChain, runDirect, runBlocked     uint64
	// since/runSince 这两组数字从什么时候开始数（界面上显示"从 14:03 起"）。
	since, runSince time.Time
	// evicted 因为桶上限淘汰过几个键 —— 界面上要说出来（"还有 N 项被挤掉了"），
	// 静默截断会让人以为"就这么点"。
	evicted int
}

func newStatBoard(now time.Time) *statBoard {
	return &statBoard{
		app: map[string]*statBucket{}, tgt: map[string]*statBucket{},
		since: now, runSince: now,
	}
}

// beginRun 引擎每次 Start 调一次：把「本次运行」口径清零（累计口径不动）。
func (b *statBoard) beginRun(now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, m := range []map[string]*statBucket{b.app, b.tgt} {
		for _, bk := range m {
			bk.beginRun()
		}
	}
	b.runConns, b.runFailed, b.runUp, b.runDown = 0, 0, 0, 0
	b.runChain, b.runDirect, b.runBlocked = 0, 0, 0
	b.runSince = now
}

// reset 界面上「清零」：两个口径都从头数。
func (b *statBoard) reset(now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.app, b.tgt = map[string]*statBucket{}, map[string]*statBucket{}
	b.conns, b.failed, b.up, b.down = 0, 0, 0, 0
	b.chain, b.direct, b.blocked = 0, 0, 0
	b.runConns, b.runFailed, b.runUp, b.runDown = 0, 0, 0, 0
	b.runChain, b.runDirect, b.runBlocked = 0, 0, 0
	b.since, b.runSince = now, now
	b.evicted = 0
}

// bucket 取或建一个桶；到上限时淘汰**最久没活动**的那个。
//
// 淘汰按 last 而不是按"最早建的"：一个连了十年的老键今天还在传数据，
// 不应该因为"它很老"被一个只连过一次的新键挤掉。
func (b *statBoard) bucket(m map[string]*statBucket, key string, now time.Time) *statBucket {
	if bk, ok := m[key]; ok {
		return bk
	}
	if len(m) >= StatBucketCap {
		oldKey, oldLast := "", time.Time{}
		for k, v := range m {
			if oldKey == "" || v.last.Before(oldLast) {
				oldKey, oldLast = k, v.last
			}
		}
		delete(m, oldKey)
		b.evicted++
	}
	bk := &statBucket{first: now, last: now}
	m[key] = bk
	return bk
}

// noteEnd 把一条已收尾连接的数字落进桶（全部字段一次锁内改完）。
//
// targetKey/ip 由调用方算（要在锁外查名字表，见 noteStatEnd）。
func (b *statBoard) noteEnd(st *connState, appKey, targetKey string, ip net.IP, now time.Time) {
	if b == nil {
		return
	}
	up, down := st.up.Load(), st.down.Load()
	failed := statConnFailed(st)
	blocked := st.action == rules.ActionBlock
	direct := st.action == rules.ActionDirect

	b.mu.Lock()
	defer b.mu.Unlock()
	b.conns++
	b.up, b.down = b.up+up, b.down+down
	b.runConns++
	b.runUp, b.runDown = b.runUp+up, b.runDown+down
	if failed {
		b.failed++
		b.runFailed++
	}
	switch {
	case blocked:
		b.blocked++
		b.runBlocked++
	case direct:
		b.direct++
		b.runDirect++
	default: // 走隧道
		b.chain++
		b.runChain++
	}
	for _, pair := range []struct {
		m map[string]*statBucket
		k string
	}{{b.app, appKey}, {b.tgt, targetKey}} {
		bk := b.bucket(pair.m, pair.k, now)
		bk.conns++
		bk.up, bk.down = bk.up+up, bk.down+down
		bk.runConns++
		bk.runUp, bk.runDown = bk.runUp+up, bk.runDown+down
		if failed {
			bk.failed++
			bk.runFailed++
		}
		bk.last = now
		if bk.first.IsZero() {
			bk.first = st.start
		}
		bk.addPort(st.dport)
		if bk.ip == nil && ip != nil {
			bk.ip = ip
		}
	}
}

// statConnFailed 这条连接算不算"失败"。
//
// 三个来源，都是"应用想连但没连上"：拨号/隧道建立失败（err）、SYN 改了却没人来接
// （unrelayed，见 relayGrace）、被规则阻断。**不能拿"字节为 0"当判据**：一条干净的
// 短连接（探测、健康检查）也可能一个字节都没有。
func statConnFailed(st *connState) bool {
	return st.err() != "" || st.unrelayed.Load() || st.action == rules.ActionBlock
}

// noteStatEnd 连接收尾时落统计（唯一入口）。
//
// **幂等由调用方保证**：只在 st.ended 的 CAS 成功的那条路径上调用
// （finish 的开头、janitor 回收）。不在这里自己判 —— 那就要在 connState 上
// 再挂一个"统计过了"的标志，多一处永远要维护的状态。
func (e *Engine) noteStatEnd(st *connState) {
	if e == nil || e.stats == nil || st == nil || st.self {
		return // 探针不算业务流量（与「连接」页同一个口径）
	}
	// 进程名是**发布后还会被补上**的（fillMissingProcs），读它要拿读锁。
	e.mu.RLock()
	appKey := st.procName
	e.mu.RUnlock()
	if appKey == "" {
		appKey = StatUnknownApp
	}
	// 目标名优先用**名字**：`nameOf` 同时认识假 IP 与"应用拿真实 IP 连过来"的那种
	// （noteRealIP 把名字→真实 IP 也记进了名字表），所以同一个域名无论应用是拿域名、
	// 假 IP 还是真实 IP 连的，都会并进同一行 —— 这正是"按目标统计"要的效果。
	//
	// ⚠ 不要用 st.fakeName：那个字段在包路径上是**无锁写**的（engine.go 的两处），
	// 读它就是这个仓库里唯一的数据竞争。
	dst := st.displayTarget()
	key, ip := dst.String(), net.IP(nil)
	if name, ok := e.nameOf(dst); ok && name != "" {
		key, ip = name, dst
	}
	e.stats.noteEnd(st, appKey, key, ip, time.Now())
}

// ResetStats 界面上「清零」：两个口径都从头数。
func (e *Engine) ResetStats() {
	if e == nil || e.stats == nil {
		return
	}
	e.stats.reset(time.Now())
	e.bus.Info("统计已清零（连接数/字节数/按应用与按目标的累计都从头数）")
}

// ───────────────────── 界面快照 ─────────────────────

// StatRow 统计表里的一行（应用维度或目标维度，同一套列）。
type StatRow struct {
	Name string `json:"name"`
	// Conns 连接数 = 已收尾的 + **还开着的**（顶上那个总数同理）。
	Conns  uint64 `json:"conns"`
	Active int    `json:"active"`
	Failed uint64 `json:"failed"`
	Up     uint64 `json:"up"`
	Down   uint64 `json:"down"`
	// UpBps/DownBps 只算**当前还开着**的连接（与「连接」页的速率同一口径）。
	UpBps   uint64 `json:"upBps"`
	DownBps uint64 `json:"downBps"`
	// AvgBps 这个键活跃期间的平均速率：(up+down) / (last-first)，下限 1 秒。
	AvgBps  uint64 `json:"avgBps"`
	DurSec  int    `json:"durSec"`  // 第一次活动到最后一次活动的秒数
	LastAgo int    `json:"lastAgo"` // 距今多少秒（快照时才算，存下来会随时间变假）
	Ports   string `json:"ports,omitempty"`
	IP      string `json:"ip,omitempty"` // 名字对应的实际地址（按目标那张表的"实际连到哪"
}

// StatPage 「统计」页的一次快照。
type StatPage struct {
	Scope string `json:"scope"` // run | all
	// Readonly 引擎不在这进程里（界面与引擎分进程，见 AGENTS.md）：给空页，不是崩溃。
	Readonly bool `json:"readonly,omitempty"`

	// 三组累计数字（照 Proxifier 的 Statistics 那三组：连接 / 流量 / 时长）
	Conns  uint64 `json:"conns"`
	Active int    `json:"active"`
	Failed uint64 `json:"failed"`
	Up     uint64 `json:"up"`
	Down   uint64 `json:"down"`
	// 分解：走隧道 / 直连 / 阻断（三者相加 = Conns）
	Chain   uint64 `json:"chain"`
	Direct  uint64 `json:"direct"`
	Blocked uint64 `json:"blocked"`

	// Uptime 引擎本次运行了多久；Since 这组数字从什么时候开始数（都是给人看的字符串）。
	Uptime string `json:"uptime"`
	Since  string `json:"since"`

	Apps    []StatRow `json:"apps"`
	Targets []StatRow `json:"targets"`
	// KeysApps/KeysTargets 桶里一共有几个键（表只显示前 TopN 行）。
	KeysApps    int `json:"keysApps"`
	KeysTargets int `json:"keysTargets"`
	TopN        int `json:"topN"`
	Cap         int `json:"cap"`
	// Evicted 被上限挤掉的键数（>0 时界面上要说出来）。
	Evicted int `json:"evicted"`
	// Note 一句人话的补充（比如"直连统计关着，直连连接看不到"）。
	Note string `json:"note,omitempty"`
}

// statAcc 读快照时用的累加器（桶 + 还开着的连接合并到同一个键上）。
type statAcc struct {
	conns   uint64
	failed  uint64
	up      uint64
	down    uint64
	active  int
	upBps   uint64
	downBps uint64
	first   time.Time
	last    time.Time
	ports   []uint16
	ip      net.IP
}

func (a *statAcc) addPort(p uint16, keep int) {
	for _, x := range a.ports {
		if x == p {
			return
		}
	}
	if len(a.ports) >= keep {
		return
	}
	a.ports = append(a.ports, p)
}

// StatsPage 生成「统计」页快照。scope 为空 / StatScopeRun 时看"本次运行"，StatScopeAll 看累计。
func (e *Engine) StatsPage(scope string, topN int) StatPage {
	if topN <= 0 {
		topN = StatTopN
	}
	now := time.Now()
	run := scope != StatScopeAll
	p := StatPage{Scope: StatScopeAll, TopN: topN, Cap: StatBucketCap}
	if run {
		p.Scope = StatScopeRun
	}
	if e == nil {
		p.Readonly = true
		return p
	}
	if up := now.Sub(e.startedAt); e.startedAt.IsZero() {
		p.Uptime = "—"
	} else {
		p.Uptime = humanDur(up)
	}

	apps := map[string]*statAcc{}
	tgts := map[string]*statAcc{}
	get := func(m map[string]*statAcc, k string) *statAcc {
		a, ok := m[k]
		if !ok {
			a = &statAcc{}
			m[k] = a
		}
		return a
	}

	// ① 已收尾的：从桶里搬（按口径选字段）
	if e.stats != nil {
		b := e.stats
		b.mu.Lock()
		for _, pair := range []struct {
			m map[string]*statBucket
			d map[string]*statAcc
		}{{b.app, apps}, {b.tgt, tgts}} {
			for k, bk := range pair.m {
				a := get(pair.d, k)
				a.conns, a.failed, a.up, a.down = bk.conns, bk.failed, bk.up, bk.down
				a.first, a.last = bk.first, bk.last
				a.ports, a.ip = bk.ports, bk.ip
				if run {
					a.conns, a.failed, a.up, a.down = bk.runConns, bk.runFailed, bk.runUp, bk.runDown
				}
			}
		}
		p.Conns, p.Failed, p.Up, p.Down = b.conns, b.failed, b.up, b.down
		p.Chain, p.Direct, p.Blocked = b.chain, b.direct, b.blocked
		since := b.since
		if run {
			p.Conns, p.Failed, p.Up, p.Down = b.runConns, b.runFailed, b.runUp, b.runDown
			p.Chain, p.Direct, p.Blocked = b.runChain, b.runDirect, b.runBlocked
			since = b.runSince
		}
		p.Evicted = b.evicted
		if !since.IsZero() {
			p.Since = since.Format("15:04:05")
		}
		b.mu.Unlock()
	}

	// ② 还开着的：实时算进去（字节 / 速率 / 活跃数）
	//
	// 先在读锁下**只取指针与进程名**，出锁再查名字表（nameOf 有自己的锁，
	// 混在一起就给自己挖锁序的坑）。
	type liveConn struct {
		st  *connState
		app string
	}
	countDirect := e.cfg.CountDirectEnabled()
	e.mu.RLock()
	live := make([]liveConn, 0, 16)
	for _, st := range e.conns {
		if st.self || st.ended.Load() {
			continue
		}
		if st.statsOnly && !countDirect {
			continue // 直连统计关着：这条连接已经"不被观察"了，不能算（与「连接」页一致）
		}
		app := st.procName
		if app == "" {
			app = StatUnknownApp
		}
		live = append(live, liveConn{st: st, app: app})
	}
	e.mu.RUnlock()

	for _, lc := range live {
		st := lc.st
		up, down := st.up.Load(), st.down.Load()
		upBps, downBps := st.rateUp.Load(), st.rateDown.Load()
		dst := st.displayTarget()
		key, ip := dst.String(), net.IP(nil)
		if name, ok := e.nameOf(dst); ok && name != "" {
			key, ip = name, dst
		}
		if st.action == rules.ActionBlock {
			p.Blocked++
			p.Failed++ // 阻断的连接还没走到"收尾"，但它在应用那边已经是失败了
		} else if st.action == rules.ActionDirect {
			p.Direct++
		} else {
			p.Chain++
		}
		p.Conns++
		p.Up, p.Down = p.Up+up, p.Down+down
		blocked := st.action == rules.ActionBlock
		for _, pair := range []struct {
			k string
			m map[string]*statAcc
		}{{lc.app, apps}, {key, tgts}} {
			a := get(pair.m, pair.k)
			a.conns++
			if blocked {
				a.failed++ // 与上面 p.Failed++ 同一个理由，保持行内与合计一致
			}
			a.up, a.down = a.up+up, a.down+down
			a.active++
			a.upBps, a.downBps = a.upBps+upBps, a.downBps+downBps
			if a.first.IsZero() || st.start.Before(a.first) {
				a.first = st.start
			}
			if a.last.Before(now) {
				a.last = now
			}
			a.addPort(st.dport, statPortsKeep)
			if a.ip == nil && ip != nil {
				a.ip = ip
			}
		}
	}
	p.Active = e.ConnsActive()

	// ③ 排序 + TopN
	conv := func(m map[string]*statAcc) []StatRow {
		rows := make([]StatRow, 0, len(m))
		for k, a := range m {
			// 全零的行不列：引擎重启后「本次运行」口径清零了，但桶还在（它还要给「累计」
			// 口径用）—— 把 a.exe 0/0/0 这种行挂在表上，用户只会以为是显示错了。
			if a.conns == 0 && a.failed == 0 && a.up == 0 && a.down == 0 {
				continue
			}
			last := a.last
			if last.IsZero() {
				last = a.first
			}
			row := StatRow{
				Name: k, Conns: a.conns, Active: a.active, Failed: a.failed,
				Up: a.up, Down: a.down, UpBps: a.upBps, DownBps: a.downBps,
				Ports: statPortsText(a.ports),
			}
			if a.ip != nil {
				row.IP = a.ip.String()
			}
			span := last.Sub(a.first)
			if span < time.Second {
				span = time.Second
			}
			row.DurSec = int(span.Seconds())
			row.AvgBps = (a.up + a.down) / uint64(span.Seconds())
			row.LastAgo = int(now.Sub(last).Seconds())
			if row.LastAgo < 0 {
				row.LastAgo = 0
			}
			rows = append(rows, row)
		}
		// 排序：流量大的在前（这一页是"谁在占通道"，不是按名字排的通讯录）。
		// 流量相等时按连接数，再相等按名字 —— 保证同一份数据每次渲染顺序一致，
		// 否则界面每 1.5 秒刷新一次，行会自己跳（用户没法点）。
		sort.Slice(rows, func(i, j int) bool {
			ti, tj := rows[i].Up+rows[i].Down, rows[j].Up+rows[j].Down
			if ti != tj {
				return ti > tj
			}
			if rows[i].Conns != rows[j].Conns {
				return rows[i].Conns > rows[j].Conns
			}
			return rows[i].Name < rows[j].Name
		})
		return rows
	}
	allApps, allTgts := conv(apps), conv(tgts)
	p.KeysApps, p.KeysTargets = len(allApps), len(allTgts)
	if len(allApps) > topN {
		allApps = allApps[:topN]
	}
	if len(allTgts) > topN {
		allTgts = allTgts[:topN]
	}
	p.Apps, p.Targets = allApps, allTgts

	// ④ 一句人话的补充：把"这个页面上数字的边界"说清楚
	if !countDirect {
		p.Note = "「直连流量统计」关着 —— 直连的连接根本没进内核过滤器，这里看不到（打开那个开关才有）"
	}
	return p
}
