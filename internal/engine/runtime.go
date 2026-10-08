package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"nethub/internal/config"
	"nethub/internal/rules"
)

// ───────────────────────── 接管状态（诊断页那张卡的数据源）─────────────────────────
//
// 这一组类型的定位：**回答“现在是什么样”**，日志回答“发生过什么”。
// 所以字段只放**当前值**（数字 / 在不在 / 条数），不放时间戳流水、不放事件序列 ——
// 否则这张卡就退化成了第二份日志（用户明确要求：它不能看起来像另类的日志）。
//
// 判定好坏的那部分（“需要注意”）单独抽成纯函数 statusWarnings：口径必须能被单测钉住，
// 不然它会随着改动悄悄漂，最后没人说得清“打开诊断页看到红色到底意味着什么”。

// RuntimeStatus 引擎自述的当前状态。
type RuntimeStatus struct {
	Running   bool   `json:"running"`
	Reason    string `json:"reason,omitempty"` // 没在跑的原因（界面直显，不用猜）
	Relay     string `json:"relay"`
	Uptime    string `json:"uptime"`    // 人读时长，如 "6h12m"
	UptimeSec int    `json:"uptimeSec"` // 秒（判据用：刚启动那几十秒的“还没探过”不算异常）

	Kernel KernelFace `json:"kernel"`
	Names  NameFace   `json:"names"`
	Conns  ConnFace   `json:"conns"`
	Rules  RuleFace   `json:"rules"`

	// Warnings 按判据算好的“需要注意”；空数组 = 没发现异常。
	Warnings []StatusWarning `json:"warnings"`
}

// KernelFace 内核面：**包到底有没有到我们手上**。
type KernelFace struct {
	Main    bool     `json:"main"`    // 主过滤器句柄
	Dyn     bool     `json:"dyn"`     // 通配域名的动态过滤器句柄
	Inject  bool     `json:"inject"`  // DNS 接管那只有“只塞”句柄
	Socket  bool     `json:"socket"`  // SOCKET 层（进程名事件驱动）
	Reflect bool     `json:"reflect"` // REFLECT 层（谁在拦我的包）
	Ranges  int      `json:"ranges"`  // 主过滤器里的地址区间数
	Bytes   int      `json:"bytes"`   // 主过滤器原文长度
	Peers   []string `json:"peers"`   // 本机还有谁在用 WinDivert（空 = 只有我们）
	Direct  bool     `json:"direct"`  // 是否把直连网段也纳入统计
	QuicBlk bool     `json:"quicBlock"`
}

// NameFace 名字面：域名通配 / DNS 接管灵不灵。
type NameFace struct {
	Count     int    `json:"count"`     // 名字表里有多少个名字
	Stale     int    `json:"stale"`     // 过期（TTL 到了但还没被刷新）
	Failed    int    `json:"failed"`    // 解析失败
	NewestSec int    `json:"newestSec"` // 最近一次学到名字是几秒前（-1 = 从没学到过）
	Wildcards bool   `json:"wildcards"` // 规则里有没有通配域名（没有的话名字表本该是空的）
	Takeover  bool   `json:"takeover"`  // DNS 接管（发假 IP）开着没
	FakeUsed  int    `json:"fakeUsed"`
	FakeCap   int    `json:"fakeCap"`
	FakeRange string `json:"fakeRange"`
}

// ConnFace 连接面：谁在连、走了哪条链。
type ConnFace struct {
	Total      uint64            `json:"total"`  // 进程生命周期内累计接管
	Active     int               `json:"active"` // 现在活着的
	PerChain   map[string]uint64 `json:"perChain"`
	ProcKnown  int               `json:"procKnown"`   // 活连接里查到进程名的
	ProcUnknow int               `json:"procUnknown"` // 查不到的（受保护进程 / 已消失）
	ProcPorts  int               `json:"procPorts"`   // 进程解析器的端口表规模
	ProcPIDs   int               `json:"procPids"`
}

// RuleFace 规则面。
//
// 为什么不报“哪条规则从未命中”：一条规则没人用是**正常**的（那个环境今天没人访问而已），
// 报它只会持续误报。真正需要看的是“被前面规则盖住”（永远不会生效）—— 那条**配置**层面
// 就算得出来（`Config.ShadowedTargets`），规则页早就在逐条标了；这里只给一句汇总 + 指路，
// 不把同一份事实讲两遍。
type RuleFace struct {
	Total    int      `json:"total"`
	Ranges   int      `json:"ranges"`
	Shadowed []string `json:"shadowed"` // 被前面规则完全覆盖、永远不会生效的目标
}

// StatusWarning 一条“需要注意”。
type StatusWarning struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // warn | error
	Text     string `json:"text"`
}

// KernelDetail 内核层的原始材料 —— **按需取**（过滤器原文三 KB 一行，不能进轮询）。
type KernelDetail struct {
	Ranges    []string `json:"ranges"`    // 覆盖的地址区间（人读）
	DynRanges []string `json:"dynRanges"` // 通配域名当前覆盖到的 IP
	Filter    string   `json:"filter"`    // 主过滤器原文
	DynFilter string   `json:"dynFilter"` // 动态过滤器原文
}

// ChainSummary 链条可用性汇总（从 ChainHealth 折出来，供判据使用）。
type ChainSummary struct {
	Total    int
	Down     []string // 当前不可用
	Untested []string // 还没探过（刚启动时的正常态）
}

// RuntimeStatus 采集当前状态。
func (e *Engine) RuntimeStatus() RuntimeStatus {
	e.mu.RLock()
	running := e.run
	mainOn, dynOn := e.handle != nil, e.dynHandle != nil
	injectOn, sockOn, reflectOn := e.injector != nil, e.sockH != nil, e.reflectH != nil
	mainFilter, mainRanges := e.mainFilter, e.mainRanges
	started := e.startedAt
	relayAddr := e.relay
	e.mu.RUnlock()

	st := RuntimeStatus{
		Running: running,
		Relay:   relayAddr,
		Kernel: KernelFace{
			Main: mainOn, Dyn: dynOn, Inject: injectOn, Socket: sockOn, Reflect: reflectOn,
			Ranges: mainRanges, Bytes: len(mainFilter),
			Peers:  e.DivertPeers(),
			Direct: e.cfg.CountDirectEnabled(), QuicBlk: e.cfg.QuicBlockEnabled(),
		},
	}
	if !started.IsZero() {
		d := time.Since(started)
		st.Uptime, st.UptimeSec = shortDur(d), int(d.Seconds())
	}
	if !running {
		st.Reason = e.ReasonNotRunning()
	}

	// 名字面
	names := e.names.Status()
	st.Names.Wildcards = e.ruleSet().HasWildcards()
	st.Names.Takeover = e.cfg.DNSTakeoverEnabled() && st.Names.Wildcards
	st.Names.NewestSec = -1
	for _, n := range names {
		if n.Failed {
			st.Names.Failed++
			continue
		}
		if n.Stale {
			st.Names.Stale++
		}
		// Age 越小越新
		if st.Names.NewestSec < 0 || n.Age < time.Duration(st.Names.NewestSec)*time.Second {
			st.Names.NewestSec = int(n.Age / time.Second)
		}
	}
	st.Names.Count = len(names)
	if e.fake != nil {
		used, cap := e.fake.Stats()
		st.Names.FakeUsed, st.Names.FakeCap = used, cap
		st.Names.FakeRange = e.fake.Range().String()
	}

	// 连接面
	total, active := e.Stats()
	st.Conns.Total, st.Conns.Active = total, active
	st.Conns.PerChain = e.ChainCounts()
	if e.proc != nil {
		st.Conns.ProcPorts, st.Conns.ProcPIDs = e.proc.Stats()
	}
	for _, c := range e.Conns(5000, false) {
		if c.Proc == "" || c.Proc == "unknown" {
			st.Conns.ProcUnknow++
		} else {
			st.Conns.ProcKnown++
		}
	}

	// 规则面
	st.Rules.Total, st.Rules.Ranges = len(e.ruleSet().List()), mainRanges
	st.Rules.Shadowed = shadowedRules(e.cfg)

	st.Warnings = statusWarnings(st, e.chainSummary())
	return st
}

// KernelDetail 取内核层的原始材料（界面上的折叠区按需调）。
func (e *Engine) KernelDetail() KernelDetail {
	e.mu.RLock()
	mainFilter, dynFilter := e.mainFilter, e.dynFilter
	e.mu.RUnlock()

	d := KernelDetail{Filter: mainFilter, DynFilter: dynFilter}
	for _, r := range e.ruleSet().FilterRanges(e.cfg.CountDirectEnabled()) {
		d.Ranges = append(d.Ranges, rangeLabel(r))
	}
	for _, r := range e.ruleSet().WildcardRanges(false) {
		d.DynRanges = append(d.DynRanges, rangeLabel(r))
	}
	return d
}

// chainSummary 把每条链的上游健康折成“down / 还没探过”两张名单。
func (e *Engine) chainSummary() ChainSummary {
	hs := e.ChainHealth()
	sum := ChainSummary{Total: len(hs)}
	for _, h := range hs {
		if len(h.Upstreams) == 0 {
			sum.Down = append(sum.Down, h.Name+"（没配上游）") // 配错了，也要报
			continue
		}
		known, ok := 0, 0
		for _, u := range h.Upstreams {
			if !u.Known {
				continue
			}
			known++
			if u.OK {
				ok++
			}
		}
		switch {
		case known == 0:
			sum.Untested = append(sum.Untested, h.Name)
		case ok == 0:
			sum.Down = append(sum.Down, h.Name)
		}
	}
	return sum
}

// shadowedRules 被前面规则完全覆盖、永远不会生效的目标（逐规则一行）。
//
// 复用配置层那份判定（规则页也用同一个），不另算一套 —— “一份内容一个出处”。
func shadowedRules(cfg *config.Config) []string {
	routes := cfg.RoutesSnapshot()
	var out []string
	for i := range routes {
		n := len(cfg.ShadowedTargets(i))
		if n == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("第 %d 条「%s」（%d 个目标被覆盖）", i+1, routes[i].Name, n))
	}
	return out
}

// statusWarnings 把状态折成“需要注意”。**纯函数**：判据被单测钉住，口径不会自己漂。
func statusWarnings(st RuntimeStatus, chains ChainSummary) []StatusWarning {
	if !st.Running {
		return []StatusWarning{{Kind: "engine.stopped", Severity: "error",
			Text: "引擎未运行，内核拦截与 DNS 接管均未生效。" + st.Reason}}
	}
	var out []StatusWarning
	add := func(kind, sev, text string) {
		out = append(out, StatusWarning{Kind: kind, Severity: sev, Text: text})
	}

	// 内核面：包到不了我们手上 = 最严重
	if st.Rules.Total > 0 && st.Kernel.Ranges == 0 {
		add("kernel.no-range", "error",
			"内核过滤器没有地址区间，当前不会拦截任何流量。请确认规则是否已全部改为直连或停用")
	}
	if len(st.Kernel.Peers) > 0 {
		add("kernel.peers", "warn",
			"检测到其他进程也在使用 WinDivert："+strings.Join(st.Kernel.Peers, "、")+
				"。数据包可能被其他程序优先处理")
	}
	if !st.Kernel.Main {
		add("kernel.no-main", "error", "主过滤器句柄不可用，内核拦截未生效")
	}

	// 链条
	if len(chains.Down) > 0 {
		add("chain.down", "error", "链路不可用："+strings.Join(chains.Down, "、"))
	}
	// 刚启动那几十秒“还没探过”是正常态，别报
	if len(chains.Untested) > 0 && st.UptimeSec > 90 {
		add("chain.untested", "warn", "链路尚未探测："+strings.Join(chains.Untested, "、"))
	}

	// 规则：被前面盖住的目标永远不会生效（静默失效，现场最难发现）
	if n := len(st.Rules.Shadowed); n > 0 {
		add("rules.shadowed", "warn",
			fmt.Sprintf("%d 条规则存在被前置规则完全覆盖的目标，这些目标不会生效（见「路由规则」页）：%s",
				n, strings.Join(firstN(st.Rules.Shadowed, 2), "、")))
	}

	// 名字面
	if st.Names.Wildcards && !st.Names.Takeover {
		add("names.no-takeover", "warn",
			"存在通配域名规则，但 DNS 接管未开启；首次访问（真实 IP 尚未被观测到）可能不经隧道")
	}
	if st.Names.Wildcards && st.Names.Count == 0 && st.UptimeSec > 90 {
		add("names.empty", "warn",
			"存在通配域名规则，但名字表为空：通配域名当前无法匹配到任何 IP（应用可能使用 DoH 或自带解析器）")
	}
	if st.Names.Failed > 0 {
		add("names.failed", "warn",
			fmt.Sprintf("%d 个域名解析失败，它们不会被通配规则匹配", st.Names.Failed))
	}
	if st.Names.Count >= 10 && st.Names.Stale*2 > st.Names.Count {
		add("names.stale", "warn",
			fmt.Sprintf("名字表过期比例过半（%d/%d），通配域名的匹配能力下降", st.Names.Stale, st.Names.Count))
	}
	if st.Names.FakeCap > 0 && st.Names.FakeUsed*10 > st.Names.FakeCap*9 {
		add("names.pool-full", "warn",
			fmt.Sprintf("假 IP 池即将占满（%d/%d）：占满后新域名不再被接管", st.Names.FakeUsed, st.Names.FakeCap))
	}

	// 连接面：进程名解析率（v0.5.0 把它从 60% unknown 修到 0，这是防回归）
	if seen := st.Conns.ProcKnown + st.Conns.ProcUnknow; seen >= 5 && st.Conns.ProcUnknow*5 > seen {
		add("proc.unknown", "warn",
			fmt.Sprintf("无法解析进程名的连接比例偏高（%d/%d）：端口未在表中，或该进程不可访问",
				st.Conns.ProcUnknow, seen))
	}

	// error 排前面（同一 severity 内保持判据顺序）
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity == "error" && out[j].Severity != "error" })
	return out
}

// firstN 取前 n 个（超出的用“…”收尾）—— 给“需要注意”那一行用的，不写全名单。
func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return append(append([]string{}, list[:n]...), "…")
}

// rangeLabel 把地址区间写成人读的一行（含端口条件）。
func rangeLabel(r rules.Range) string {
	s := fmt.Sprintf("%s - %s", rules.U2IP(r.First), rules.U2IP(r.Last))
	if len(r.Ports) == 0 {
		return s + "（任意端口）"
	}
	ps := make([]string, 0, len(r.Ports))
	for _, p := range r.Ports {
		if p.First == p.Last {
			ps = append(ps, fmt.Sprintf("%d", p.First))
			continue
		}
		ps = append(ps, fmt.Sprintf("%d-%d", p.First, p.Last))
	}
	return s + "（端口 " + strings.Join(ps, ",") + "）"
}

// shortDur 人读时长：1h2m / 3m12s / 45s。
func shortDur(d time.Duration) string {
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}
