package webui

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"nethub/internal/engine"
	"nethub/internal/hostsmgr"
)

// ───────────────────── 连接列表（观测） ─────────────────────

// ConnList 连接页的一次性快照：列表 + 汇总，避免前端分几次拉。
type ConnList struct {
	List     []engine.ConnView `json:"list"`
	Total    uint64            `json:"total"`
	Active   int               `json:"active"`
	PerChain map[string]uint64 `json:"perChain"`
	// RateUp/RateDown：全表速率合计（字节/秒）—— "现在到底有没有在传"。
	RateUp   uint64 `json:"rateUp"`
	RateDown uint64 `json:"rateDown"`
}

// GetConns 返回连接表快照（界面上每 1.5 秒拉一次，只统计当前页可见时）。
func (b *Backend) GetConns() ConnList {
	e := b.a.Engine
	if e == nil { // 只读态（引擎在别的进程/没接上）：给空列表，不是崩溃
		return ConnList{List: nil}
	}
	total, _ := e.Stats()
	rateUp, rateDown := e.Rates()
	return ConnList{
		List:  e.Conns(150, true),
		Total: total,
		// Active 用界面口径（含直连/阻断的进行中行），见 Engine.ConnsActive
		Active:   e.ConnsActive(),
		PerChain: e.ChainCounts(),
		RateUp:   rateUp,
		RateDown: rateDown,
	}
}

// ConnHistList 历史连接快照（界面「历史连接」展开区）。
type ConnHistList struct {
	List []engine.ConnHist `json:"list"`
	// Keep 存档条数上界——界面上要写明“只留最近 N 条”，否则看着像丢数据。
	Keep int `json:"keep"`
}

// GetConnsHistory 已结束连接的存档（新的在前）。
//
// 为什么单独一个接口、不塞进 GetConns：它只在用户展开那个区块时才要看，
// 而 GetConns 每 1.5 秒跑一次 —— 不该把 300 条存档每轮都搬一遍。
func (b *Backend) GetConnsHistory() ConnHistList {
	e := b.a.Engine
	if e == nil {
		return ConnHistList{Keep: engine.ConnHistKeep}
	}
	return ConnHistList{List: e.ConnsHistory(0), Keep: engine.ConnHistKeep}
}

// ClearConnsHistory 清空存档（界面上「清空」：做一次动作后只看新增的）。
func (b *Backend) ClearConnsHistory() {
	if e := b.a.Engine; e != nil {
		e.ClearConnsHistory()
	}
}

// GetStats 「统计」页快照（scope 空/"run" = 本次运行，"all" = 累计）。
//
// 为什么每次都要现算、不给引擎加一层"按秒缓存"：这一页的键来自**此刻正在跑的连接**
// （不然开了一天的会话在页面上永远是 0），缓存一秒就等于把"刚才"当成"现在"。
// 代价是每次遍历一遍连接表 —— 几百条的量级，1.5 秒一次，可以忽略。
func (b *Backend) GetStats(scope string) engine.StatPage {
	e := b.a.Engine
	if e == nil {
		// 只读态（引擎在别的进程/没接上）：给空页，不是崩溃
		if scope == "" {
			scope = engine.StatScopeRun
		}
		return engine.StatPage{Scope: scope, Readonly: true,
			TopN: engine.StatTopN, Cap: engine.StatBucketCap}
	}
	return e.StatsPage(scope, 0)
}

// ResetStats 界面上「清零」：两个口径（本次运行 / 累计）都从头数。
func (b *Backend) ResetStats() {
	if e := b.a.Engine; e != nil {
		e.ResetStats()
	}
}

// ProcPath 某个 PID 的完整路径（连接页点进程名看“到底是谁”）。
// 拿不到时返回空串（受保护进程/已退出）。
func (b *Backend) ProcPath(pid uint32) string {
	if e := b.a.Engine; e != nil {
		return e.ProcPath(pid)
	}
	return ""
}

// ───────────────────── 规则智能 / 体检 / 备份 / 诊断 ─────────────────────

// ExplainRef 解释里提到的“另一条也匹配的规则”。
type ExplainRef struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Action string `json:"action"`
}

// ExplainView “这个目标会怎么走”的完整解释。
type ExplainView struct {
	Input        string                   `json:"input"`
	Matched      bool                     `json:"matched"`
	RuleIndex    int                      `json:"ruleIndex"`
	RuleName     string                   `json:"ruleName"`
	Action       string                   `json:"action"`
	Chain        string                   `json:"chain"`
	PortIgnored  bool                     `json:"portIgnored"`
	Shadowed     []ExplainRef             `json:"shadowed"`
	ChainHealth  *engine.ChainHealthView  `json:"chainHealth"`
	TargetHealth *engine.TargetHealthView `json:"targetHealth"`
}

// ExplainTarget 回答“这个 IP（可选端口）会走哪条链”：命中的规则、被抢先的规则、
// 该链的上游健康、以及上次巡检到的可达性。
func (b *Backend) ExplainTarget(ip, port string) (ExplainView, error) {
	v := ExplainView{Input: strings.TrimSpace(ip), RuleIndex: -1}
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return v, fmt.Errorf("不是合法的 IPv4 地址：%q", ip)
	}

	var pnum uint16
	tp := strings.TrimSpace(port)
	v.PortIgnored = tp == ""
	if !v.PortIgnored {
		n, err := strconv.Atoi(tp)
		if err != nil || n < 1 || n > 65535 {
			return v, fmt.Errorf("端口要在 1-65535：%q", port)
		}
		pnum = uint16(n)
	}
	if v.PortIgnored {
		v.Input = strings.TrimSpace(ip) + "（未填端口 → 只看目标）"
	}

	idx, shadowed, _ := b.a.Rules.Explain(addr, pnum, v.PortIgnored)
	routes := b.a.Cfg.RoutesSnapshot()
	if idx >= 0 && idx < len(routes) {
		r := routes[idx]
		v.Matched, v.RuleIndex, v.RuleName, v.Action, v.Chain = true, idx, r.Name, r.ActionText(), r.Chain
	}
	for _, si := range shadowed {
		if si >= 0 && si < len(routes) {
			r := routes[si]
			v.Shadowed = append(v.Shadowed, ExplainRef{Index: si, Name: r.Name, Action: r.ActionText()})
		}
	}
	if v.Matched && v.Chain != "" {
		for _, ch := range b.a.Engine.ChainHealth() {
			if ch.Name == v.Chain {
				c := ch
				v.ChainHealth = &c
			}
		}
		target := fmt.Sprintf("%s:%d", addr, pnum)
		for _, th := range b.a.Engine.TargetHealth() {
			if th.Target == target {
				t := th
				v.TargetHealth = &t
			}
		}
	}
	return v, nil
}

// SetRouteEnabled 开/关一条规则。
//
// 为什么做成一个独立的小入口（而不是走保存整条规则的表单）：现场要在十几个
// 内网环境之间来回切，开关必须**一下点到位**，不能每次弹出表单改完再存。
func (b *Backend) SetRouteEnabled(index int, on bool) error {
	rt, ok := b.a.Cfg.RouteAt(index)
	if !ok {
		return fmt.Errorf("规则序号超出范围")
	}
	if rt.IsEnabled() == on {
		return nil
	}
	rt.SetEnabled(on)
	if err := b.a.Cfg.UpdateRoute(index, rt); err != nil {
		// 启用时如果链丢了/目标冲了，要当场说清楚，而不是模糊地“保存失败”
		return err
	}
	name := rt.Name
	if strings.TrimSpace(name) == "" {
		name = rt.Describe()
	}
	if on {
		return b.save(fmt.Sprintf("启用规则%s（%d 个目标）", name, len(rt.Targets)))
	}
	return b.save(fmt.Sprintf("停用规则%s —— 停用后不进匹配也不占目标，可与其已启用的规则同时存在", name))
}

// SortRoutes 按“最具体优先”重排规则（等于帮用户点了几十次上下箭头）。
//
// 返回是否真的改动了顺序：已经是目标顺序时返回 (false, nil) —— “本来就是对的”
// 不是错误（以前拿 error 当“无需调整”的信号，前端只好弹一个红色的失败提示）。
func (b *Backend) SortRoutes() (bool, error) {
	if !b.a.Cfg.SortRoutesBySpecificity() {
		return false, nil
	}
	if err := b.save("按最具体优先整理规则顺序"); err != nil {
		return false, err
	}
	return true, nil
}

// PrecheckConfig 配置体检：返回人话报告（不修任何东西）。
func (b *Backend) PrecheckConfig() []string {
	// 隧道探测也放进体检报告里。
	//
	// 为什么：这张卡是**开机自动跑一次**的那份报告（界面文案：“打开设置页时把上次结果补上
	// （开机自动跑过一次）”），但它以前只有配置层面的检查 —— “配置没问题”读起来像
	// “网络没问题”，而某条链上游挂了、口令错了根本看不出来。用户明确要求把隧道探测加上。
	lines := b.a.Cfg.Precheck()
	lines = append(lines, b.tunnelProbeLines()...)
	return lines
}

// ensureSelfTest 拿到“足够新”的自检结果：有现成的就用，没有就跑一轮。
//
// 并发安全：SelfTest 与体检可能同时要结果，用 selfTestGate 保证只跑一轮 ——
// 后来者等前一轮跑完直接拿结果，不会把同一条链探两遍（探活本身是对端可见的动作）。
func (b *Backend) ensureSelfTest(maxAge time.Duration) SelfTestReport {
	if rep, ok := b.freshSelfTest(maxAge); ok {
		return rep
	}
	// 这里只排队（闸在 runSelfTest 里），不能再自己拿一次 —— Go 的 Mutex 不可重入
	b.runSelfTest()
	b.selfTestMu.RLock()
	defer b.selfTestMu.RUnlock()
	return b.selfTestLast
}

func (b *Backend) freshSelfTest(maxAge time.Duration) (SelfTestReport, bool) {
	b.selfTestMu.RLock()
	rep, at := b.selfTestLast, b.selfTestAt
	b.selfTestMu.RUnlock()
	if rep.Total > 0 && !at.IsZero() && time.Since(at) < maxAge {
		return rep, true
	}
	return rep, false
}

// tunnelProbeLines 把自检结果转成体检报告里的一段（逐条链一句）。
func (b *Backend) tunnelProbeLines() []string {
	// 每次体检都要看见**当前**的隧道状态 → 最多认 90 秒内的结果，过期就重探。
	rep := b.ensureSelfTest(90 * time.Second)
	if rep.Total == 0 {
		return []string{"⚠ 隧道探测：没有可探测的链（还没配链路？）"}
	}
	out := []string{fmt.Sprintf("— 隧道探测（%s 实测，逐条链去连其内网目标）—", rep.At)}
	for _, c := range rep.Chains {
		detail := ""
		if len(c.Detail) > 0 {
			detail = c.Detail[0]
		}
		switch {
		case c.OK && strings.Contains(detail, "跳过"):
			// 不是错误：代理段是好的，只是没东西可探（新环境常见）
			out = append(out, "⚠ 隧道 "+c.Name+"："+detail)
			if len(c.Detail) > 1 {
				out = append(out, "    "+c.Detail[1])
			}
		case c.OK:
			out = append(out, "✓ 隧道 "+c.Name+"："+detail)
		default:
			out = append(out, "✗ 隧道 "+c.Name+"："+detail)
			for _, d := range c.Detail[1:] {
				out = append(out, "    "+d)
			}
		}
	}
	if rep.Bad == 0 {
		out = append(out, fmt.Sprintf("✓ %d 条链的隧道探测全部通过", rep.Total))
	} else {
		out = append(out, fmt.Sprintf("✗ %d/%d 条链的隧道探测没通过（详见上面各行）", rep.Bad, rep.Total))
	}
	return out
}

// ListBackups 配置备份列表（新的在前）。
func (b *Backend) ListBackups() []string { return b.a.Cfg.Backups() }

// RestoreBackup 回滚到某个备份：先备当前、再写回、重新载入并重启服务。
func (b *Backend) RestoreBackup(name string) error {
	cur, err := b.a.Cfg.RestoreBackup(name)
	if err != nil {
		return err
	}
	b.a.Cfg.ReplaceFrom(cur)
	// 同一个指针：引擎/规则看到的就是新配置（path 也一并带过来）
	b.a.Bus.Warn("已回滚配置：%s（当前配置已自动备份）", name)
	return b.a.Restart()
}

// GetTargetHealth 业务目标巡检快照。
// TargetProbeView 巡检页的一次性快照：列表 + “正在巡检”（与 ConnList 同一个理由：
// 一次拉完，别让界面分两次问；更重要的是**把“正在巡检”这个状态带出来** —— 空表时
// “正在巡检”与“还没有可巡检的目标”长得一模一样，而前者说“再等一秒”，后者说“去干别的”。
type TargetProbeView struct {
	Probing bool                      `json:"probing"`
	Count   int                       `json:"count"`
	Targets []engine.TargetHealthView `json:"targets"`
}

func (b *Backend) GetTargetHealth() TargetProbeView {
	if b.a.Engine == nil {
		return TargetProbeView{}
	}
	return TargetProbeView{
		Probing: b.a.Engine.TargetsProbing(),
		Count:   b.a.Engine.TargetProbeCount(),
		Targets: b.a.Engine.TargetHealth(),
	}
}

// ProbeTargetsNow 立刻巡检一遍最近用过的业务目标。
func (b *Backend) ProbeTargetsNow() error {
	if b.a.Engine == nil {
		return fmt.Errorf("引擎未初始化")
	}
	// 手动轮在日志里留一行：巡检会向上游与业务发起真实连接，
	// 事后看到一串 target.* 日志时要能对上是“谁点的”。
	// 返回值就是这一轮要巡几个（先看完再写日志：写在前面的会是上一轮的数）。
	n := b.a.Engine.ProbeTargetsAsync()
	b.a.Bus.Info("patrol.now: by=ui targets=%d", n)
	return nil
}

// ── 业务目标巡检的设置（开关 + 间隔，用户自己定） ──

// PatrolView 巡检设置（界面用）。
type PatrolView struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"` // 归一化后的间隔，如 5m0s
	Count    int    `json:"count"`
}

// GetPatrol 当前巡检设置。
func (b *Backend) GetPatrol() PatrolView {
	return PatrolView{
		Enabled:  b.a.Cfg.PatrolEnabled(),
		Interval: humanInterval(b.a.Cfg.PatrolInterval()),
		Count:    b.a.Cfg.PatrolCount(),
	}
}

// humanInterval 把 5m0s 写成 5m（界面里好看点）。
func humanInterval(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return d.String()
}

// SetPatrol 改开关与间隔（即时保存；引擎每 10 秒看一眼配置，自己接上）。
func (b *Backend) SetPatrol(enabled bool, interval string) error {
	if !enabled {
		b.a.Cfg.SetPatrol("off", 0)
		return b.save("关闭业务目标巡检")
	}
	iv := strings.TrimSpace(interval)
	if iv == "" || strings.EqualFold(iv, "off") {
		iv = "5m"
	}
	d, err := time.ParseDuration(iv)
	if err != nil || d <= 0 {
		return fmt.Errorf("间隔要形如 30s / 5m / 1h（当前 %q）", interval)
	}
	if d < 10*time.Second {
		return fmt.Errorf("间隔太短：最少 10s —— 每轮都要经隧道去连客户内网")
	}
	b.a.Cfg.SetPatrol(iv, 0)
	return b.save("业务目标巡检：每 " + iv)
}

func (b *Backend) GetLogs() []LogView {
	src := b.a.Bus.Snapshot()
	out := make([]LogView, 0, len(src))
	for _, l := range src {
		out = append(out, logView(l))
	}
	return out
}

func (b *Backend) GetSettings() SettingsView {
	hosts := b.a.Cfg.HostsCopy()
	entries := hosts.Entries
	if len(entries) == 0 {
		if block, ok, _, err := hostsmgr.Read(); err == nil && ok {
			entries = block
		}
	}
	if len(entries) == 0 {
		entries = defaultHostsEntries()
	}
	return SettingsView{
		HostsManage:        hosts.Manage,
		HostsEntries:       entries,
		Theme:              b.a.Cfg.Theme(),
		TrayTraffic:        b.a.Cfg.TrayTraffic(),
		TrayTrafficMode:    b.a.Cfg.TrayTrafficMode(),
		LogLevel:           b.a.Cfg.LogLevel(),
		LogLevelFile:       b.a.Cfg.LogLevelFile(),
		LogLevelFileSet:    b.a.Cfg.LogLevelFileSet(),
		DialTimeout:        int(b.a.Cfg.DialTimeoutDur() / time.Second),
		DialBudget:         int(b.a.Cfg.DialBudgetDur() / time.Second),
		RaceAfter:          intPtr(int(b.a.Cfg.RaceAfterDur() / time.Millisecond)),
		WarmSessions:       intPtr(b.a.Cfg.WarmTarget()),
		DomainResolveLocal: b.a.Cfg.LocalResolveDomains(),
		AutostartDelay:     intPtr(int(b.a.Cfg.AutostartDelayDur() / time.Second)),
	}
}

// cleanDomainList 清理“强制本机解析”的域名列表：去空白、去空行与 # 注释、去重。
//
// 为什么要清洗：这串是给匹配器逐条跑的，空串会变成“永远不命中”的垃圾项；
// 重复项也不算错但让人以为配了两条。
func cleanDomainList(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		for _, line := range strings.Split(s, "\n") { // 允许前端一次贴多行
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, line)
		}
	}
	return out
}

// KillConn 结束一条连接（连接列表里点「结束」）。
//
// 为什么要从界面做：现场最常见的诉求是“这条卡死了，让它重连”——没这个入口只能
// 等应用自己超时。对直连/阻断的不给结束（那些不经过我们，关了什么也停不了）。
func (b *Backend) KillConn(sport int) error {
	if sport <= 0 || sport > 65535 {
		return fmt.Errorf("端口号不对：%d", sport)
	}
	if b.a.Engine == nil {
		return fmt.Errorf("引擎没在运行")
	}
	return b.a.Engine.KillConn(uint16(sport))
}

// SetTrayTraffic 切换托盘图标：默认图标 / 实时流量图（迷你柱图）。
//
// 即时生效（不用重启）：Tray 里那个开关是个 atomic，下一拍就换图标；
// 关掉时**当场**换回默认图标，不给用户“拨了没反应”的感觉。
func (b *Backend) SetTrayTraffic(on bool) error {
	old := b.a.Cfg.TrayTraffic()
	b.a.Cfg.SetTrayTraffic(on)
	res, err := b.a.SaveConfig()
	if err != nil {
		b.a.Cfg.SetTrayTraffic(old)
		return err
	}
	if b.tray != nil {
		b.tray.SetTraffic(on, b.a.Cfg.TrayTrafficMode())
	}
	b.afterSave(res, "托盘图标")
	if on {
		b.a.Bus.Info("托盘图标已切换为实时流量图（上行/下行两根柱，每秒重绘；空载时只剩一条底线）")
	} else {
		b.a.Bus.Info("托盘图标已恢复为默认图标")
	}
	return nil
}

// SetTrayTrafficMode 切换托盘图显示的量：total（上+下）| up | down。
//
// 只影响图标画哪个量，不动任何统计口径（累计/连接列表/顶栏图都不变）。
func (b *Backend) SetTrayTrafficMode(mode string) error {
	old := b.a.Cfg.TrayTrafficMode()
	b.a.Cfg.SetTrayTrafficMode(mode)
	res, err := b.a.SaveConfig()
	if err != nil {
		b.a.Cfg.SetTrayTrafficMode(old)
		return err
	}
	if b.tray != nil {
		b.tray.SetTraffic(b.a.Cfg.TrayTraffic(), b.a.Cfg.TrayTrafficMode())
	}
	b.afterSave(res, "托盘显示内容")
	b.a.Bus.Info("托盘流量图改为显示：%s", trayModeLabel(b.a.Cfg.TrayTrafficMode()))
	return nil
}

// trayModeLabel 给日志用的中文名。
//
// 刻意不写「上行（出）」这种带解释的写法：上行/下行在运维嘴里就是常识，
// 括号只会把干净的一行搞脏（用户 2026-10-20 明确要求）。
func trayModeLabel(mode string) string {
	switch mode {
	case "up":
		return "上行"
	case "down":
		return "下行"
	default:
		return "总量"
	}
}

// CurrentSeries 最近 n 秒的上行/下行字节序列（每秒一格，旧的在前）—— 托盘画面积/折线用。
//
// 口径与顶栏流量图完全一致：关着“也统计直连流量”时不把直连算进去。
func (b *Backend) CurrentSeries(n int) (up, down []uint64) {
	if b == nil || n <= 0 {
		return nil, nil
	}
	series := b.traffic.snapshot(false, b.a.Running()).Series
	withDirect := b.countDirect()
	if len(series) > n {
		series = series[len(series)-n:]
	}
	up = make([]uint64, len(series))
	down = make([]uint64, len(series))
	for i, pt := range series {
		up[i], down[i] = pt.TunUp, pt.TunDown
		if withDirect {
			up[i] += pt.DirUp
			down[i] += pt.DirDown
		}
	}
	return up, down
}

// CurrentRates 最近一秒的速率（字节/秒，上行、下行）—— 给托盘流量图用。
//
// 口径与顶栏流量图完全一致（那边也是每秒一格）：关着「也统计直连流量」时
// 不把直连算进去，否则托盘上会显示一笔“界面上看不到来源”的流量。
func (b *Backend) CurrentRates() (up, down uint64) {
	if b == nil {
		return 0, 0
	}
	series := b.traffic.snapshot(false, b.a.Running()).Series
	if len(series) == 0 {
		return 0, 0
	}
	p := series[len(series)-1]
	up, down = p.TunUp, p.TunDown
	if b.countDirect() {
		up += p.DirUp
		down += p.DirDown
	}
	return up, down
}

// defaultHostsEntries 不做任何预置：内置默认里绝不能出现真实环境的映射。
// 格式提示由界面上的字段标签负责，这里返回空列表（而非 nil，免得前端拿到 null）。
func defaultHostsEntries() []string {
	return []string{}
}
