// Package webui 是 Wails 的 Go 侧：把 app.App 的能力暴露给前端。
//
// 前端约定（Wails 用 Go 包名 + 结构体名 + 方法名做命名空间，运行时自动生成 bindings，
// **不需要 wails CLI 也不需要 npm**）：
//
//	await window.go.webui.Backend.GetState()
//	await window.go.webui.Backend.AddChain({name, listen, forward, note})
//
// 返回值末尾带 error 的方法，前端 Promise 会 reject（catch 到错误文本）。
package webui

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"nethub/internal/app"
	"nethub/internal/autostart"
	"nethub/internal/config"
	"nethub/internal/engine"
	"nethub/internal/gostbat"
	"nethub/internal/hostsmgr"
	"nethub/internal/logbus"
	"nethub/internal/upstream"
	"nethub/internal/winrun"
)

// Backend 是绑定给前端的对象。
type Backend struct {
	a   *app.App
	ctx context.Context

	mu       sync.Mutex
	logCh    chan logbus.Line
	tray     *Tray
	quitting bool

	// 最近一次链路自检的结果：界面直接看，不用再翻日志（打开设置页也能看到上次的）。
	selfTestMu   sync.RWMutex
	selfTestLast SelfTestReport

	// 自启状态缓存：schtasks 是外部进程，不能在 GetState（前端每 1.5s 调一次）里跑，
	// 否则会不断创建进程；而且 GUI 子系统没控制台，会表现为窗口一直闪、抢焦点。
	autoMu      sync.RWMutex
	autoEnabled bool
	autoDetail  string
}

func New(a *app.App) *Backend {
	return &Backend{a: a, logCh: make(chan logbus.Line, 256)}
}

// OnStartup Wails 启动回调：拿 ctx、接管通知、把日志推给前端、拉起服务。
func (b *Backend) OnStartup(ctx context.Context) {
	b.ctx = ctx
	b.refreshAutostart()
	// 提示只走应用内（前端 toast），不弹 Windows 系统通知：
	// 既不占用户的「操作中心」，也避免窗口收起来时被系统弹窗打断。
	b.a.Notify = func(title, text string, kind app.NotifyKind) {
		b.emit("notify", NotifyView{Title: title, Text: text, Kind: kind.String()})
	}
	sub := b.a.Bus.Subscribe()
	go func() {
		for l := range sub {
			b.emit("log", logView(l))
		}
	}()

	// 后台巡检 Clash 绕过覆盖：内网被交给 Clash 是红线（DNS 外泄/封号风险），
	// 不能只靠用户打开界面才发现 —— 每 60 秒查一次（只读注册表，不发网络请求）
	go b.clashWatch()

	// 起来就把服务拉起（计划任务开机自启靠这个：进程起来 = 隧道就绪）
	go func() {
		time.Sleep(600 * time.Millisecond)
		b.a.Bus.Info("开始自动启动服务…")
		if err := b.a.Start(); err != nil {
			b.a.Bus.Error("自动启动失败（可在界面上手动重试）: %v", err)
			return
		}
		// 启动成功后自动跑一次链路自检：
		// 打开软件就该知道“哪条链能用、哪条不能”，而不是等人去点按钮。
		// 稍等一下再跑，避开引擎刚起来那几秒（过滤器/relay 正在装配）。
		time.Sleep(1200 * time.Millisecond)
		if b.a.Engine == nil || !b.a.Engine.Running() {
			return
		}
		b.SelfTest()
	}()
}

// OnDomReady 页面就绪。
func (b *Backend) OnDomReady(ctx context.Context) {
	b.a.Bus.Info("界面已就绪")
}

// OnShutdown Wails 退出回调：兜底注销托盘图标。
//
// 正常退出（托盘菜单 → 退出）走 Quit()，那里已经 Remove 过了；
// 但窗口被强制关闭、或者别的退出路径不能让图标变成孤儿 ——
// 孤儿图标会堆在托盘折叠面板里，显得像“注册了一堆图标”。
func (b *Backend) OnShutdown(ctx context.Context) {
	if b.tray != nil {
		b.tray.Remove()
		b.tray = nil
	}
}

// OnBeforeClose 点 X → 收进托盘继续跑，返回 true 阻止关闭。
func (b *Backend) OnBeforeClose(ctx context.Context) bool {
	if b.quitting {
		return false
	}
	wruntime.WindowHide(ctx)
	return true
}

func (b *Backend) emit(name string, data any) {
	if b.ctx == nil {
		return
	}
	wruntime.EventsEmit(b.ctx, name, data)
}

// ───────────────────────── 视图类型（与前端 JSON 对齐）─────────────────────────

type StateView struct {
	Running bool   `json:"running"`
	Relay   string `json:"relay"` // 内部中转端口（界面上不再直接显示，只作悬停提示）
	// Error 非空表示当前处于出错态（启动失败 / 拦截中断）。前端用它决定红/绿。
	Error string `json:"error"`
	// 预热连接池近况（A11）
	PoolWarm uint64 `json:"poolWarm"`
	PoolHits uint64 `json:"poolHits"`
	// GostPIDs 已移除：上游为原生实现，不再有子进程。
	TotalConns  uint64 `json:"totalConns"`
	ActiveConns int    `json:"activeConns"`
	ConfigPath  string `json:"configPath"`
	LogPath     string `json:"logPath"`
	Theme       string `json:"theme"`
	HostsPath   string `json:"hostsPath"`
	HostsInFile bool   `json:"hostsInFile"` // hosts 里已存在我们的标记区块
	Autostart   bool   `json:"autostart"`
	AutoDetail  string `json:"autoDetail"`
}

type ChainView struct {
	Name string `json:"name"`
	// Forward / Forwards 只给个**能认出来是哪台机器**的简化地址：
	// 去掉 userinfo 与查询参数（auth=… 里是凭据），尾部带上 “带凭据” 标记。
	// 列表不需要完整细节；要看/改真实地址就去编辑页（那里明文）。
	Forward  string   `json:"forward"`
	Forwards []string `json:"forwards"`
	Strategy string   `json:"strategy"`
	Probe    string   `json:"probe"`
	Note     string   `json:"note"`
	// Auth 这条链有没有凭据（列表上只表达这一件事）
	Auth bool `json:"auth"`
	// CredUser 账号名（只显示账号、不显示口令 —— 列表上用来确认“还是我那个账号”）
	CredUser string `json:"credUser"`
}

type RouteView struct {
	Index    int      `json:"index"`
	Name     string   `json:"name"`
	Targets  []string `json:"targets"`
	Ports    []string `json:"ports"`
	Chain    string   `json:"chain"`
	Direct   bool     `json:"direct"`
	Block    bool     `json:"block"`
	Note     string   `json:"note"`
	Shadowed []string `json:"shadowed"` // 被前面的规则完全覆盖、永远不会生效的目标
	// A16：仅在这些本机网段下生效；Inactive=当前本机网络下这条规则不生效
	LocalNets []string `json:"localNets"`
	Inactive  bool     `json:"inactive"`
	// A20：进程条件（空 = 不看进程）
	Apps []string `json:"apps"`
	// 域名目标：解析到哪、什么时候解析的、解析不到的原因（规则页直接显示）
	HostResolves []engine.HostResolveView `json:"hostResolves"`
	// 规则开关（默认开）；停用的规则不进匹配、不占目标
	Enabled bool `json:"enabled"`
}

type LogView struct {
	Time  string `json:"time"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

type NotifyView struct {
	Title string `json:"title"`
	Text  string `json:"text"`
	Kind  string `json:"kind"` // info | warn | error
}

type SettingsView struct {
	// 注意：没有 relay 字段 —— relay 是内部实现细节（127.0.0.1:0 自动分配端口），
	// 不暴露到界面。前端不再传它，SaveSettings 也就不再覆写它。
	HostsManage  bool     `json:"hostsManage"`
	HostsEntries []string `json:"hostsEntries"`
	Theme        string   `json:"theme"`
	// 上游拨号（秒）。0 表示前端没传 → 保持原值，不当成“设成 0”。
	DialTimeout int `json:"dialTimeout,omitempty"`
	DialBudget  int `json:"dialBudget,omitempty"`
	// RaceAfter 竞速起跑（毫秒）：0 = 关闭竞速。
	// 用指针是为了区分“没传”（nil = 不改）与“明确设成 0”（关）—— 用 int 的话，
	// 前端一旦漏传就会被当成“关闭”，静默把功能关了。
	RaceAfter *int `json:"raceAfter"`
	// WarmSessions 预热会话条数：0 = 关闭（同样用指针区分“没传”）。
	WarmSessions *int `json:"warmSessions"`
}

type ChainInput struct {
	Name     string   `json:"name"`
	_        struct{} `json:"-"`
	Forward  string   `json:"forward"`  // 单上游（老界面）
	Forwards []string `json:"forwards"` // 多上游（新界面：一行一个）
	Strategy string   `json:"strategy"`
	Probe    string   `json:"probe"`
	Note     string   `json:"note"`
}

type BatEntryView struct {
	File    string   `json:"file"`
	_       struct{} `json:"-"`
	Forward string   `json:"forward"`
	Name    string   `json:"name"`
}

type ImportResult struct {
	Added   []string `json:"added"`
	Skipped []string `json:"skipped"`
}

type ProbeView struct {
	Target string `json:"target"`
	Port   int    `json:"port"` // 命中的端口，0 = 没连上
	OK     bool   `json:"ok"`
	Err    string `json:"err"`
}

// SelfTestChain 一条链的自检结果。
// Detail 里是**原始**的报错/说明（一行一条），故意不做“翻译”——现场是把这几行
// 整段复制给 agent 的，翻成人话就把底层信息抹掉了。
type SelfTestChain struct {
	Name   string   `json:"name"`
	OK     bool     `json:"ok"`
	Detail []string `json:"detail"`
}

type SelfTestReport struct {
	At     string          `json:"at"`
	Total  int             `json:"total"`
	Bad    int             `json:"bad"`
	Chains []SelfTestChain `json:"chains"`
}

// LastSelfTest 取最近一次自检结果（空 At = 还没跑过）。
func (b *Backend) LastSelfTest() SelfTestReport {
	b.selfTestMu.RLock()
	defer b.selfTestMu.RUnlock()
	return b.selfTestLast
}

func logView(l logbus.Line) LogView {
	return LogView{Time: l.Time.Format("15:04:05.000"), Level: l.Level, Text: l.Text}
}

// ───────────────────────── 读取 ─────────────────────────

// GetState 一次性拿界面需要的所有状态（前端每秒轮询，比推事件简单可靠）。
func (b *Backend) GetState() StateView {
	total, active := b.a.Engine.Stats()
	relay := b.a.Engine.RelayAddr()
	running, errText := b.a.Status()
	taken, _, warm := b.a.Engine.PoolStats()
	_, hostsInFile, _, _ := hostsmgr.Read()
	return StateView{
		Running:     running,
		Error:       errText,
		PoolWarm:    warm,
		PoolHits:    taken,
		Relay:       relay,
		TotalConns:  total,
		ActiveConns: active,
		ConfigPath:  b.a.Cfg.Path(),
		LogPath:     b.a.Bus.FilePath(),
		Theme:       b.a.Cfg.UI.Theme,
		HostsPath:   hostsmgr.Path(),
		HostsInFile: hostsInFile,
		Autostart:   b.autostartCached(),
		AutoDetail:  b.autostartDetailCached(),
	}
}

// refreshAutostart 跑一次 schtasks 并把结果缓存起来（只在启动、切换自启时调）。
func (b *Backend) refreshAutostart() {
	on := autostart.Enabled()
	detail := ""
	if on {
		detail = autostart.Detail()
	}
	b.autoMu.Lock()
	b.autoEnabled, b.autoDetail = on, detail
	b.autoMu.Unlock()
}

func (b *Backend) autostartCached() bool {
	b.autoMu.RLock()
	defer b.autoMu.RUnlock()
	return b.autoEnabled
}

func (b *Backend) autostartDetailCached() string {
	b.autoMu.RLock()
	defer b.autoMu.RUnlock()
	return b.autoDetail
}

func (b *Backend) GetChains() []ChainView {
	out := make([]ChainView, 0, len(b.a.Cfg.Chains))
	for _, c := range b.a.Cfg.Chains {
		ups := c.Upstreams()
		brief := make([]string, 0, len(ups))
		hasAuth := false
		for _, f := range ups {
			if hasCred(f) {
				hasAuth = true
			}
			brief = append(brief, briefUpstream(f))
		}
		first := ""
		if len(brief) > 0 {
			first = brief[0]
		}
		user := b.a.Cfg.ChainCredUser(c)
		if user == "" {
			user = credUserIn(ups)
		}
		out = append(out, ChainView{
			Name: c.Name, Forward: first, Forwards: brief,
			Strategy: c.StrategyName(), Probe: c.ProbeInterval().String(), Note: c.Note,
			Auth: hasAuth || c.Secret != "", CredUser: user,
		})
	}
	return out
}

// briefUpstream 列表用的简化地址：协议 + 主机:端口 +（有凭据）“带凭据”。
func briefUpstream(raw string) string {
	b := gostbat.Redact(raw)
	if u, err := upstream.Parse(raw); err == nil && u.Addr != "" {
		proto := u.Protocol
		if u.TLS {
			proto += "+tls"
		}
		b = proto + "://" + u.Addr
	}
	if hasCred(raw) {
		b += "（带凭据）"
	}
	return b
}

// hasCred 这个上游地址里到底有没有凭据（userinfo 或 ?auth=）。
func hasCred(raw string) bool {
	if u, err := upstream.Parse(raw); err == nil {
		return u.Creds.User != "" || u.Creds.Pass != ""
	}
	return strings.Contains(raw, "auth=") || strings.Contains(raw, "@")
}

// credUserIn 从一串上游地址里找出账号名（只给界面显示，不泄口令）。
func credUserIn(raws []string) string {
	for _, raw := range raws {
		if u, err := upstream.Parse(raw); err == nil && u.Creds.User != "" {
			return u.Creds.User
		}
	}
	return ""
}

// ChainForwardPlain 取一条链的**真实**上游地址（含凭据），专给编辑页面用。
//
// 为什么不在列表里就明文：列表是拿来一眼扫“哪条链路是什么”的，不需要细节；
// 而编辑页面就是拿来实现/修正凭据的 —— 那里藏起来除了多造麻烦没任何意义。
func (b *Backend) ChainForwardPlain(name string) ([]string, error) {
	ch, ok := b.a.Cfg.ChainByName(name)
	if !ok {
		return nil, fmt.Errorf("没有这条链: %s", name)
	}
	return b.a.Cfg.UpstreamsResolved(ch), nil
}

// GetChainHealth 每条链的上游健康（主动探测 + 真实连接失败都会记进来）。
func (b *Backend) GetChainHealth() []engine.ChainHealthView {
	if b.a.Engine == nil {
		return nil
	}
	return b.a.Engine.ChainHealth()
}

// ProbeChains 立即把所有上游探一遍（界面上的“立即探测”）。
func (b *Backend) ProbeChains() error {
	if b.a.Engine == nil {
		return fmt.Errorf("引擎未初始化")
	}
	go b.a.Engine.ProbeAll()
	return nil
}

func (b *Backend) GetRoutes() []RouteView {
	note := map[string]string{}
	for _, c := range b.a.Cfg.Chains {
		note[c.Name] = c.Note
	}
	out := make([]RouteView, 0, len(b.a.Cfg.Routes))
	for i, r := range b.a.Cfg.Routes {
		note := note[r.Chain]
		switch {
		case r.IsDirect():
			note = "不走代理，直接连（本机网段 / 局域网邻居常用）"
		case r.IsBlock():
			note = "直接丢弃：应用会看到连接被拒"
		}
		resolves := map[string]engine.HostResolveView{}
		for _, hr := range b.a.Engine.HostResolves() {
			resolves[strings.ToLower(hr.Host)] = hr
		}
		var mine []engine.HostResolveView
		for _, t := range r.Targets {
			if hr, ok := resolves[strings.ToLower(strings.TrimSpace(t))]; ok {
				mine = append(mine, hr)
			}
		}
		out = append(out, RouteView{
			Index: i, Name: r.Name, Targets: r.Targets, Ports: r.Ports,
			Chain: r.Chain, Direct: r.IsDirect(), Block: r.IsBlock(), Note: note,
			Shadowed:     b.a.Cfg.ShadowedTargets(i),
			LocalNets:    r.LocalNets,
			Inactive:     !localNetsMatch(r.LocalNets, localIPv4s()),
			Apps:         r.Apps,
			Enabled:      r.IsEnabled(),
			HostResolves: mine,
		})
	}
	return out
}

// localNetsMatch 规则的本机网段条件在当前网络下是否满足（A16）。
// 空条件 = 总是满足（与以前行为一致）。
func localNetsMatch(conds []string, ips []net.IP) bool {
	if len(conds) == 0 {
		return true
	}
	for _, c := range conds {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			if ip := net.ParseIP(c); ip != nil {
				n = &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
			} else {
				continue
			}
		}
		for _, ip := range ips {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// localIPv4s 本机当前的非回环 IPv4（界面上判断“这条规则现在生不生效”用）。
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

// LocalSubnets 本机直接相连的 IPv4 网段（规则里“本地直连”用）。
//
// 只取 up 且非回环接口上的地址：典型就是 192.168.1.0/24 这种内网段。
// 界面上一键填入，省得每次手敲 —— 忘了配本地直连，局域网里的同事机器 /
// 打印机 / 共享盘会被送进隧道而不可达（异地代理到不了你的局域网）。
func (b *Backend) LocalSubnets() []string {
	out := []string{}
	seen := map[string]bool{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil {
				continue
			}
			s := (&net.IPNet{IP: v4.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ───────────────────── 连接列表（观测） ─────────────────────

// ConnList 连接页的一次性快照：列表 + 汇总，避免前端分几次拉。
type ConnList struct {
	List     []engine.ConnView `json:"list"`
	Total    uint64            `json:"total"`
	Active   int               `json:"active"`
	PerChain map[string]uint64 `json:"perChain"`
}

// GetConns 返回连接表快照（界面上每 1.5 秒拉一次，只统计当前页可见时）。
func (b *Backend) GetConns() ConnList {
	total, active := b.a.Engine.Stats()
	return ConnList{
		List:     b.a.Engine.Conns(150, true),
		Total:    total,
		Active:   active,
		PerChain: b.a.Engine.ChainCounts(),
	}
}

// ProcPath 某个 PID 的完整路径（连接页点进程名看“到底是谁”）。
// 拿不到时返回空串（受保护进程/已退出）。
func (b *Backend) ProcPath(pid uint32) string {
	return b.a.Engine.ProcPath(pid)
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
	if idx >= 0 && idx < len(b.a.Cfg.Routes) {
		r := b.a.Cfg.Routes[idx]
		v.Matched, v.RuleIndex, v.RuleName, v.Action, v.Chain = true, idx, r.Name, r.ActionText(), r.Chain
	}
	for _, si := range shadowed {
		if si >= 0 && si < len(b.a.Cfg.Routes) {
			r := b.a.Cfg.Routes[si]
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
	if index < 0 || index >= len(b.a.Cfg.Routes) {
		return fmt.Errorf("规则序号超出范围")
	}
	was := b.a.Cfg.Routes[index].IsEnabled()
	if was == on {
		return nil
	}
	rt := b.a.Cfg.Routes[index]
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
func (b *Backend) SortRoutes() error {
	if !b.a.Cfg.SortRoutesBySpecificity() {
		return fmt.Errorf("顺序已经是“最具体优先”，不需要调整")
	}
	return b.save("按最具体优先整理规则顺序")
}

// PrecheckConfig 配置体检：返回人话报告（不修任何东西）。
func (b *Backend) PrecheckConfig() []string { return b.a.Cfg.Precheck() }

// ListBackups 配置备份列表（新的在前）。
func (b *Backend) ListBackups() []string { return b.a.Cfg.Backups() }

// RestoreBackup 回滚到某个备份：先备当前、再写回、重新载入并重启服务。
func (b *Backend) RestoreBackup(name string) error {
	cur, err := b.a.Cfg.RestoreBackup(name)
	if err != nil {
		return err
	}
	*b.a.Cfg = *cur
	// 同一个指针：引擎/规则看到的就是新配置（path 也一并带过来）
	b.a.Bus.Warn("已回滚配置：%s（当前配置已自动备份）", name)
	return b.a.Restart()
}

// GetTargetHealth 业务目标巡检快照。
func (b *Backend) GetTargetHealth() []engine.TargetHealthView {
	if b.a.Engine == nil {
		return nil
	}
	return b.a.Engine.TargetHealth()
}

// ProbeTargetsNow 立刻巡检一遍最近用过的业务目标。
func (b *Backend) ProbeTargetsNow() error {
	if b.a.Engine == nil {
		return fmt.Errorf("引擎未初始化")
	}
	go b.a.Engine.ProbeTargets()
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
		b.a.Cfg.Patrol.Interval = "off"
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
	b.a.Cfg.Patrol.Interval = iv
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
	entries := b.a.Cfg.Hosts.Entries
	if len(entries) == 0 {
		if block, ok, _, err := hostsmgr.Read(); err == nil && ok {
			entries = block
		}
	}
	if len(entries) == 0 {
		entries = defaultHostsEntries()
	}
	return SettingsView{
		HostsManage:  b.a.Cfg.Hosts.Manage,
		HostsEntries: entries,
		Theme:        b.a.Cfg.UI.Theme,
		DialTimeout:  int(b.a.Cfg.DialTimeoutDur() / time.Second),
		DialBudget:   int(b.a.Cfg.DialBudgetDur() / time.Second),
		RaceAfter:    intPtr(int(b.a.Cfg.RaceAfterDur() / time.Millisecond)),
		WarmSessions: intPtr(b.a.Cfg.WarmTarget()),
	}
}

// defaultHostsEntries 不做任何预置：内置默认里绝不能出现真实环境的映射。
// 格式提示由界面上的字段标签负责，这里返回空列表（而非 nil，免得前端拿到 null）。
func defaultHostsEntries() []string {
	return []string{}
}

// ───────────────────────── 启停 ─────────────────────────

func (b *Backend) Start() error   { return b.a.Start() }
func (b *Backend) Stop()          { b.a.Stop() }
func (b *Backend) Restart() error { return b.a.Restart() }

// Quit 真正退出：先停服务再关窗。
func (b *Backend) Quit() {
	b.quitting = true
	b.a.Stop()
	if b.tray != nil {
		b.tray.Remove()
	}
	wruntime.Quit(b.ctx)
}

// HideToTray 自绘标题栏的"最小化到托盘"按钮。
func (b *Backend) HideToTray() {
	wruntime.WindowHide(b.ctx)
}

// ───────────────────────── 链路（≈ Proxifier 的 Proxy Servers）─────────────────────────

func (b *Backend) AddChain(in ChainInput) error {
	if err := b.a.Cfg.AddChain(in.toChain()); err != nil {
		return err
	}
	return b.save("添加链路 " + in.Name)
}

func (b *Backend) UpdateChain(oldName string, in ChainInput) error {
	if err := b.a.Cfg.UpdateChain(oldName, in.toChain()); err != nil {
		return err
	}
	return b.save("更新链路 " + in.Name)
}

func (b *Backend) DeleteChain(name string) error {
	if err := b.a.Cfg.RemoveChain(name); err != nil {
		return err
	}
	return b.save("删除链路 " + name)
}

func (b *Backend) MoveChain(from, to int) error {
	if err := b.a.Cfg.MoveChain(from, to); err != nil {
		return err
	}
	return b.save("调整链路顺序")
}

func (in ChainInput) toChain() config.Chain {
	fwd := strings.TrimSpace(in.Forward)
	forwards := make([]string, 0, len(in.Forwards))
	for _, f := range in.Forwards {
		if t := strings.TrimSpace(f); t != "" {
			forwards = append(forwards, t)
		}
	}
	if len(forwards) == 0 && fwd != "" {
		forwards = []string{fwd}
	}
	return config.Chain{
		Name:     strings.TrimSpace(in.Name),
		Forwards: forwards,
		Strategy: strings.TrimSpace(in.Strategy),
		Probe:    strings.TrimSpace(in.Probe),
		Note:     strings.TrimSpace(in.Note),
	}
}

// ───────────────────────── 规则（≈ Proxifier 的 Rules）─────────────────────────

// RouteInput 界面上一条规则的完整输入（字段与表单一一对应）。
// 目标/端口/进程都可以一次填多个（换行/逗号/顿号/空格分隔）。
type RouteInput struct {
	Name      string `json:"name"`
	Targets   string `json:"targets"`
	Chain     string `json:"chain"`
	Ports     string `json:"ports"`
	LocalNets string `json:"localNets"`
	Apps      string `json:"apps"`
}

// ruleFromInput 把界面输入整理成 config.Route。
func ruleFromInput(in RouteInput) (config.Route, error) {
	return ruleFrom(in.Name, in.Targets, in.Chain, in.Ports, in.LocalNets, in.Apps)
}

// SaveRoute 保存一条规则：index < 0 = 新增，否则替换第 index 条。
// 这是界面当前用的入口（老方法保留给已有调用方，行为一致）。
func (b *Backend) SaveRoute(index int, in RouteInput) error {
	rt, err := ruleFromInput(in)
	if err != nil {
		return err
	}
	if index < 0 {
		if err := b.a.Cfg.AddRoute(rt); err != nil {
			return err
		}
		return b.save(ruleSaved("添加", rt))
	}
	old := ""
	if rs := b.a.Cfg.Routes; index < len(rs) {
		// 规则开关由列表上的开关控制，不是表单字段 —— 编辑内容时**必须继承原状态**，
		// 否则“改个名字/加个目标”会悳悹把停用的规则重新启用。
		rt.Enabled = rs[index].Enabled
		old = rs[index].Name
		if strings.TrimSpace(old) == "" {
			old = rs[index].Describe()
		}
	}
	if err := b.a.Cfg.UpdateRoute(index, rt); err != nil {
		return err
	}
	if old != "" && strings.TrimSpace(in.Name) != "" && old != in.Name {
		return b.save(fmt.Sprintf("%s→%s（%d 个目标）", old, in.Name, len(rt.Targets)))
	}
	return b.save(ruleSaved("修改", rt))
}

// ruleFrom 把界面传来的"一条规则"整理成 config.Route：目标与端口文本都可以一次填多个
// （换行/逗号/顿号/空格分隔），这里负责拆分 + 归一化。端口留空 = 任意端口。
func ruleFrom(name, targets, chain, ports, localNets, apps string) (config.Route, error) {
	ts, _, err := config.NormalizeTargets(targets)
	if err != nil {
		return config.Route{}, err
	}
	as, err := normalizeApps(apps)
	if err != nil {
		return config.Route{}, err
	}
	if len(ts) == 0 && len(as) == 0 {
		return config.Route{}, fmt.Errorf("至少要填一个目标（或一个进程条件）")
	}
	ps, _, err := config.NormalizePorts(ports)
	if err != nil {
		return config.Route{}, err
	}
	// A16：可选的“仅在这些本机网段下生效”（逗号/分号/空白分隔都行）
	var lns []string
	for _, ln := range strings.FieldsFunc(localNets, func(r rune) bool {
		switch r {
		case ',', '，', ';', '；', ' ', '\t', '\n', '\r':
			return true
		}
		return false
	}) {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(ln); err != nil && net.ParseIP(ln) == nil {
			return config.Route{}, fmt.Errorf("本机网段 %q 不是合法的 IP/网段", ln)
		}
		lns = append(lns, ln)
	}
	return config.Route{Name: name, Targets: ts, Ports: ps, Chain: chain, LocalNets: lns, Apps: as}, nil
}

// normalizeApps 拆分并校验进程条件：进程名（可带 * 通配，也可写完整路径）。
// 这里只挡明显的写法错误，真正的匹配在 rules.MatchAppName。
func normalizeApps(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', '，', '、', ';', '；', ' ', '\t', '\n', '\r':
			return true
		}
		return false
	}) {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		if strings.ToLower(a) != a {
			// 大小写保留原样（匹配时不分大小写）
		}
		if strings.ContainsAny(a, `<>|"`) {
			return nil, fmt.Errorf("进程条件 %q 含非法字符", a)
		}
		// 写完整路径也照原样存（匹配时只比文件名，见 rules.MatchAppName）——
		// 不替用户改写输入，界面显示原形。

		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}

// ruleSaved 保存成功后给日志/界面的回执文案。
func ruleSaved(verb string, rt config.Route) string {
	if len(rt.Targets) == 0 && len(rt.Apps) > 0 {
		return fmt.Sprintf("%s规则%s（进程 %s）", verb, rt.Describe(), strings.Join(rt.Apps, " "))
	}
	if len(rt.Ports) > 0 {
		return fmt.Sprintf("%s规则%s（%d 个目标，端口 %s）", verb, rt.Describe(), len(rt.Targets), config.PortText(rt.Ports))
	}
	return fmt.Sprintf("%s规则%s（%d 个目标）", verb, rt.Describe(), len(rt.Targets))
}

// AddRoute 添加一条规则。名字可留空；目标与端口都可以一次填多个 ——
// 多个目标属于**同一条规则**（对齐 Proxifier：一个动作挂一组目标 + 一组端口）。
func (b *Backend) AddRoute(name, targets, chain, ports, localNets string) error {
	rt, err := ruleFrom(name, targets, chain, ports, localNets, "")
	if err != nil {
		return err
	}
	if err := b.a.Cfg.AddRoute(rt); err != nil {
		return err
	}
	return b.save(ruleSaved("添加", rt))
}

// UpdateRoute 替换第 index 条规则（同样支持多目标 + 端口条件）。
func (b *Backend) UpdateRoute(index int, name, targets, chain, ports, localNets string) error {
	rt, err := ruleFrom(name, targets, chain, ports, localNets, "")
	if err != nil {
		return err
	}
	if err := b.a.Cfg.UpdateRoute(index, rt); err != nil {
		return err
	}
	return b.save(ruleSaved("更新", rt))
}

func (b *Backend) DeleteRoute(index int) error {
	if err := b.a.Cfg.RemoveRoute(index); err != nil {
		return err
	}
	return b.save("删除规则")
}

func (b *Backend) MoveRoute(from, to int) error {
	if err := b.a.Cfg.MoveRoute(from, to); err != nil {
		return err
	}
	return b.save("调整规则顺序")
}

// ───────────────────────── 导入 gost 批处理 ─────────────────────────

// PickBatFile 弹文件框选一个 gost .bat，解析出 -L/-F 回填给表单（不直接写配置）。
func (b *Backend) PickBatFile() (*BatEntryView, error) {
	path, err := wruntime.OpenFileDialog(b.ctx, wruntime.OpenDialogOptions{
		Title: "选择 gost 批处理",
		Filters: []wruntime.FileFilter{
			{DisplayName: "gost 批处理 (*.bat)", Pattern: "*.bat"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil // 用户取消
	}
	be, ok := gostbat.ParseBatFile(path)
	if !ok {
		return nil, fmt.Errorf("这个文件里没找到成对的 -L \"…\" / -F \"…\"：\n%s", path)
	}
	return &BatEntryView{File: be.File, Forward: be.Forward, Name: be.Name()}, nil
}

// ImportBatDir 选一个目录，批量把里面的 gost .bat 加为链（同名则更新上游）。
func (b *Backend) ImportBatDir() (*ImportResult, error) {
	dir, err := wruntime.OpenDirectoryDialog(b.ctx, wruntime.OpenDialogOptions{
		Title: "选择 gost 脚本所在目录",
	})
	if err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, nil
	}
	got := gostbat.ScanBatDir(dir)
	if len(got) == 0 {
		return nil, fmt.Errorf("这个目录里没找到含成对 -L/-F 的 gost 批处理：\n%s", dir)
	}
	res := &ImportResult{}
	for _, be := range got {
		name := be.Name()
		if idx := b.a.Cfg.FindChain(name); idx >= 0 {
			// 同名链已存在 → 只更新 listen/forward（最常见的"换服务器"场景）
			cur := b.a.Cfg.Chains[idx]
			cur.Forward = be.Forward
			if err := b.a.Cfg.UpdateChain(name, cur); err != nil {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s：更新失败（%v）", name, err))
			} else {
				res.Added = append(res.Added, fmt.Sprintf("%s：已更新上游（来自 %s）", name, be.File))
			}
			continue
		}
		err := b.a.Cfg.AddChain(config.Chain{
			Name: name, Forward: be.Forward,
			Note: "从 " + be.File + " 导入",
		})
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s：跳过（%v）", name, err))
		} else {
			res.Added = append(res.Added, fmt.Sprintf("%s：已更新上游（来自 %s）", name, be.File))
		}
	}
	if err := b.save("从 .bat 导入"); err != nil {
		return res, err
	}
	return res, nil
}

// ───────────────────────── 设置 ─────────────────────────

func (b *Backend) SaveSettings(s SettingsView) error {
	cfg := b.a.Cfg
	// 不动 cfg.Relay：界面上没有这个字段，前端不会传。
	// （之前这里写 cfg.Relay = s.Relay，前端不传时会被清成空串，直接校验失败）
	cfg.Hosts.Manage = s.HostsManage
	if len(s.HostsEntries) > 0 {
		cfg.Hosts.Entries = s.HostsEntries
	}
	// 拨号调优：只在界面确实传了值时才改（0 = 没传，保持原样）
	if s.DialTimeout > 0 {
		cfg.Tuning.DialTimeout = fmt.Sprintf("%ds", s.DialTimeout)
	}
	if s.DialBudget > 0 {
		cfg.Tuning.DialBudget = fmt.Sprintf("%ds", s.DialBudget)
	}
	// 竞速起跑 / 预热会话：nil = 前端没传 → 保持原值；0 = 明确关闭
	if s.RaceAfter != nil {
		if *s.RaceAfter == 0 {
			cfg.Tuning.RaceAfter = "off"
		} else {
			cfg.Tuning.RaceAfter = fmt.Sprintf("%dms", *s.RaceAfter)
		}
	}
	if s.WarmSessions != nil {
		if *s.WarmSessions == 0 {
			cfg.Tuning.WarmSessions = "off"
		} else {
			cfg.Tuning.WarmSessions = fmt.Sprintf("%d", *s.WarmSessions)
		}
	}
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("设置已保存（hosts 托管=%v；拨号单次 %s / 总预算 %s / 竞速起跑 %s / 预热 %d 条）",
		cfg.Hosts.Manage, cfg.DialTimeoutDur(), cfg.DialBudgetDur(), cfg.RaceAfterDur(), cfg.WarmTarget())
	return nil
}

// SetTheme 切换深浅色并记住（同时切换窗口标题栏配色）。
func (b *Backend) SetTheme(mode string) error {
	if mode != "dark" {
		mode = "light"
	}
	b.a.Cfg.UI.Theme = mode
	if mode == "dark" {
		wruntime.WindowSetDarkTheme(b.ctx)
		wruntime.WindowSetBackgroundColour(b.ctx, 0x14, 0x13, 0x12, 0xff)
	} else {
		wruntime.WindowSetLightTheme(b.ctx)
		wruntime.WindowSetBackgroundColour(b.ctx, 0xff, 0xff, 0xff, 0xff)
	}
	return b.a.Cfg.Save()
}

// SetAutostart 开关开机自启（立即生效，不等"保存"）。
func (b *Backend) SetAutostart(on bool) error {
	var err error
	if on {
		err = autostart.Enable()
	} else {
		err = autostart.Disable()
	}
	if err != nil {
		return err
	}
	b.refreshAutostart()
	if on {
		b.a.Bus.Info("已设置开机自启（计划任务 %s，最高权限，登录后静默启动）", autostart.TaskName)
	} else {
		b.a.Bus.Info("已取消开机自启")
	}
	return nil
}

// ───────────────────────── hosts ─────────────────────────

// ApplyHosts 立即把编辑框里的条目写进 hosts（同时打开托管开关）。
func (b *Backend) ApplyHosts(entries []string) error {
	clean := make([]string, 0, len(entries))
	for _, e := range entries {
		if s := strings.TrimSpace(e); s != "" && !strings.HasPrefix(s, "#") {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return fmt.Errorf("条目是空的，没什么可写的")
	}
	res, err := hostsmgr.Apply(clean)
	if err != nil {
		return err
	}
	b.a.Cfg.Hosts.Entries = clean
	b.a.Cfg.Hosts.Manage = true
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("hosts 已写入 %d 条内网域名映射（已刷 DNS 缓存）", res.Written)
	for _, t := range res.TakenOver {
		b.a.Bus.Warn("hosts 里原有同名记录，已被 NetHub 接管（否则写进去也不生效）: %s", t)
	}
	if res.FlushError != nil {
		b.a.Bus.Warn("刷 DNS 缓存失败（解析可能要等缓存过期才生效）: %v", res.FlushError)
	}
	return nil
}

// RemoveHosts 从 hosts 移除我们的标记区块。
func (b *Backend) RemoveHosts() error {
	if err := hostsmgr.Remove(); err != nil {
		return err
	}
	b.a.Cfg.Hosts.Manage = false
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("已从 hosts 移除本程序的标记区块")
	return nil
}

// ───────────────────────── 链路自检 ─────────────────────────

// SelfTest 对每条链做端到端探测：本地 socks5 通不通 + 经它能不能真连到内网目标。
// 走 gost 的本地监听，不经过 WinDivert，所以它单独验证"链路"这一段。
func (b *Backend) SelfTest() {
	chains := append([]config.Chain(nil), b.a.Cfg.Chains...)
	_ = b.a.Cfg.Routes // 探针目标改为从 hosts 取真实主机 IP，不再用规则网段
	if len(chains) == 0 {
		b.emit("notify", NotifyView{Title: "无法自检", Text: "还没有配置任何链", Kind: "warn"})
		return
	}

	go func() {
		b.a.Bus.Info("=== 链路自检开始（%d 条链）===", len(chains))
		report := SelfTestReport{Total: len(chains)}
		// 每条链的结果除了写日志，也攒起来给界面：以前只写日志，界面上一句
		// “详见上方日志”——可现场根本不知道去哪里看，等于没回答。
		add := func(name string, ok bool, detail ...string) {
			report.Chains = append(report.Chains, SelfTestChain{Name: name, OK: ok, Detail: detail})
			if !ok {
				report.Bad++
			}
		}
		defer func() {
			report.At = time.Now().Format("15:04:05")
			b.selfTestMu.Lock()
			b.selfTestLast = report
			b.selfTestMu.Unlock()
			b.emit("selftest-report", report)
		}()
		// 最近真的被访问过的目标：自检优先探它们（端口是真的）
		recent := b.a.Engine.RecentTargets(64)
		bad := 0
		for _, ch := range chains {
			// ⓪ 代理段体检（TCP+TLS+**认证**）—— 先回答“这条链还能用吗”，再谈目标。
			//
			// 这里必须用 UpstreamsResolved（含保险箱里的凭据）：以前用 ch.Upstreams()
			// 拿到的是**不带凭据**的地址，于是“口令错了”自检根本发现不了。
			var live []*upstream.Upstream
			var lastProbe upstream.ProbeAuthResult
			for _, raw := range b.a.Cfg.UpstreamsResolved(ch) {
				u, perr := upstream.Parse(raw)
				if perr != nil {
					b.a.Bus.Error("[%s] 上游无法解析，跳过：%v", ch.Name, perr)
					continue
				}
				r := u.ProbeAuth(6 * time.Second)
				if r.AuthOK {
					live = append(live, u)
					lastProbe = r
				} else if r.Err != nil {
					// 失败也要把**原始错误**留着 —— 否则下面只能报一句
					// “连不上上游”，现场把日志发给 agent 时就没信息了。
					lastProbe = r
				}
			}
			if len(live) == 0 {
				errText := "连不上上游"
				if lastProbe.Err != nil {
					errText = lastProbe.Err.Error()
				}
				b.a.Bus.Error("[%s] ✗ 代理段不可用", ch.Name)
				lines := []string{"代理段不可用"}
				for _, line := range strings.Split(errText, "\n") {
					b.a.Bus.Error("    %s", line)
					lines = append(lines, line)
				}
				bad++
				add(ch.Name, false, lines...)
				b.emit("selftest", ProbeView{Target: ch.Name, OK: false, Err: "代理段不可用：" + errText})
				continue
			}
			if !lastProbe.Public {
				b.a.Bus.Info("[%s] 代理段正常（认证通过）；出口没连到公网 —— 很多客户出口就是这样，对内网无影响", ch.Name)
			}
			dial := func(ip net.IP, port uint16) (net.Conn, error) {
				var lastErr error
				for _, u := range live {
					conn, derr := u.Dial(ip, port, 6*time.Second)
					if derr == nil {
						return conn, nil
					}
					lastErr = derr
				}
				return nil, lastErr
			}
			desc := "上游 " + live[0].String()
			if len(live) > 1 {
				desc = fmt.Sprintf("%d 条上游依次试（%s …）", len(live), live[0].String())
			}

			// ① 先用“最近真的访问过的 目标:端口”：端口是真的，
			// 不会因为“常见端口没猜对”而误报“链路不通”
			hit, hitIP := 0, ""
			for _, ref := range recent {
				if ref.Chain != ch.Name {
					continue
				}
				host, portStr, err := net.SplitHostPort(ref.Target)
				if err != nil {
					continue
				}
				rip := net.ParseIP(host)
				var rport uint16
				if _, err := fmt.Sscanf(portStr, "%d", &rport); err != nil || rip == nil {
					continue
				}
				if conn, derr := dial(rip, rport); derr == nil {
					conn.Close()
					hit, hitIP = int(rport), rip.String()
					b.a.Bus.Info("[%s] 用最近访问过的真实目标探测：%s", ch.Name, ref.Target)
					break
				}
			}

			// ② 没有真实目标（新装机器）才退回：hosts 里的主机 + 常见端口。
			//
			// ⚠ 这条路径上的端口是**猜**的，所以“全没连上”**不能说明链路有问题**：
			// 真实事故：172.30.4.217 上的服务在 9054，而猜测列表里没有这个端口 →
			// 六次全灭 → 界面报“链路有问题，上游挂了？”，但其实链路好好的（同端口
			// 用工具直连 3/3 成功）。所以这里只能报 WARN，不能计入“有问题”的链。
			guessed := false
			ip := net.ParseIP(hitIP)
			if hit == 0 {
				guessed = true
				ip = probeIPForChain(b.a.Cfg, ch.Name)
				if ip == nil {
					b.a.Bus.Warn("[%s] 找不到可探测的真实主机（hosts 为空且还没有内网连接），跳过", ch.Name)
					add(ch.Name, true, "跳过：找不到可探测的真实主机（hosts 为空且还没有内网连接）", "代理段本身正常，只是没东西可探")
					continue
				}
				for _, port := range []uint16{443, 80, 5432, 6446, 5000, 9054, 9056} {
					conn, derr := dial(ip, port)
					if derr == nil {
						conn.Close()
						hit = int(port)
						break
					}
				}
			}
			if hit > 0 {
				if guessed {
					b.a.Bus.Info("[%s] ✓ 端到端可达：%s → %s:%d（端口是从常见端口里试出来的，不代表业务端口）", ch.Name, desc, ip, hit)
					add(ch.Name, true, fmt.Sprintf("端到端可达：→ %s:%d（端口是猜的，不代表业务端口）", ip, hit), "上游："+desc)
				} else {
					b.a.Bus.Info("[%s] ✓ 端到端可达：%s → %s:%d", ch.Name, desc, ip, hit)
					add(ch.Name, true, fmt.Sprintf("端到端可达：→ %s:%d（最近真的访问过）", ip, hit), "上游："+desc)
				}
				b.emit("selftest", ProbeView{Target: ip.String(), Port: hit, OK: true})
			} else if guessed {
				// 端口是猜的：不下结论，也不计入“有问题”（以前误报的来源）
				b.a.Bus.Info("[%s] 代理段与认证都正常；%s 的常见端口没通 —— 内网目标要有过访问记录才测得准，现在不下结论",
					ch.Name, ip)
				add(ch.Name, true, "代理段与认证正常；但常见端口都没通", "内网目标要有过访问记录才测得准，现在不下结论")
				b.emit("selftest", ProbeView{Target: ch.Name, OK: true})
			} else {
				b.a.Bus.Error("[%s] ✗ 经该链连不上 %s 的任何端口（上游挂了？上游限制了目标？）", ch.Name, ip)
				bad++
				add(ch.Name, false, fmt.Sprintf("经该链连不上 %s 的任何端口", ip), "上游挂了？还是上游限制了目标？")
				b.emit("selftest", ProbeView{Target: ip.String(), OK: false, Err: "经该链不可达"})
			}
		}
		if bad == 0 {
			b.a.Bus.Info("=== 链路自检通过：%d 条链全部可用 ===", len(chains))
			b.emit("notify", NotifyView{Title: "链路自检通过", Text: fmt.Sprintf("%d 条链全部可用", len(chains)), Kind: "info"})
		} else {
			b.a.Bus.Error("=== 链路自检结束：%d 条链有问题（结果已显示在「链路自检」框里）===", bad)
			b.emit("notify", NotifyView{Title: "链路自检有问题", Text: fmt.Sprintf("%d 条链不可用", bad), Kind: "error"})
		}
	}()
}

func targetIPv4(target string) net.IP {
	if ip, _, err := net.ParseCIDR(target); err == nil {
		return ip.To4()
	}
	if p := net.ParseIP(target); p != nil {
		return p.To4()
	}
	return nil
}

// probeIPForChain 取该链网段内的一个【真实主机 IP】用于探测。
// 不用网段的 .1 —— 那不是真主机，会得到 host unreachable 而误判为“链路不通”。
func probeIPForChain(cfg *config.Config, chainName string) net.IP {
	var nets []*net.IPNet
	for _, rt := range cfg.Routes {
		if rt.Chain != chainName {
			continue
		}
		for _, t := range rt.Targets {
			if _, n, err := net.ParseCIDR(t); err == nil {
				nets = append(nets, n)
			} else if ip := net.ParseIP(t); ip != nil {
				nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			}
		}
	}
	for _, e := range hostsEntriesFrom(cfg) {
		f := strings.Fields(e)
		if len(f) < 2 {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return ip.To4()
			}
		}
	}
	return nil
}

// ───────────────────────── 打开文件/目录 ─────────────────────────

func (b *Backend) OpenConfigFile() { openPath(b.a.Cfg.Path()) }
func (b *Backend) OpenProgramDir() { openPath(dirOf(b.a.Cfg.Path())) }
func (b *Backend) OpenLogDir()     { openPath(dirOf(b.a.Bus.FilePath())) }

func openPath(p string) {
	if p == "" {
		return
	}
	_ = winrun.Command("explorer.exe", p).Start()
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return p
}

// save 落盘 + 记日志（编辑类操作的统一收尾）。
func (b *Backend) save(what string) error {
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("%s（已保存到 config.yaml）", what)
	return nil
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

var _ = runtime.GOOS

// SetTray 由 main 注入托盘（Backend 不自己建，避免依赖倒置）。
func (b *Backend) SetTray(t *Tray) { b.tray = t }

// ShowMainWindow 从托盘/第二实例唤回窗口。
func ShowMainWindow(b *Backend) {
	if b.ctx == nil {
		return
	}
	wruntime.WindowShow(b.ctx)
	wruntime.WindowUnminimise(b.ctx)
}

// ───────────────────────── 导出 / 导入设置 ─────────────────────────

// ExportConfig 把当前配置（链路上游 + 路由规则 + 其它设置）另存为一个 yaml，
// 同事拿到后放在 exe 同目录改名 config.yaml 即可直接用。
//
// ⚠️ 导出内容**包含上游凭据**（forward 里的 auth=），所以：
//   - 界面上的按钮要有明确提示
//   - 日志里不打印导出内容，只打印路径
func (b *Backend) ExportConfig() (string, error) {
	name := "nethub-config.yaml"
	if p := b.a.Cfg.Path(); p != "" {
		dir := dirOf(p)
		name = filepath.Join(dir, "nethub-config.yaml")
	}
	path, err := wruntime.SaveFileDialog(b.ctx, wruntime.SaveDialogOptions{
		Title:           "导出设置（含上游凭据，请通过安全渠道分发）",
		DefaultFilename: name,
		Filters: []wruntime.FileFilter{
			{DisplayName: "配置文件 (*.yaml)", Pattern: "*.yaml"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil // 用户取消
	}
	if !strings.HasSuffix(strings.ToLower(path), ".yaml") && !strings.HasSuffix(strings.ToLower(path), ".yml") {
		path += ".yaml"
	}
	if err := b.a.Cfg.SaveAs(path); err != nil {
		return "", err
	}
	b.a.Bus.Info("设置已导出到 %s（含明文口令，别发到群里/仓库）", path)
	return path, nil
}

// LoopInfo 疑似环路统计（与 Clash 共存那张卡一起显示：最典型的环就是被别的代理绕回来）。
type LoopInfo struct {
	Alerts uint64 `json:"alerts"`
	Last   string `json:"last"`
	At     string `json:"at"`
}

// GetLoopInfo 环路检测结果。
func (b *Backend) GetLoopInfo() LoopInfo {
	if b.a.Engine == nil {
		return LoopInfo{}
	}
	n, last, at := b.a.Engine.LoopAlerts()
	return LoopInfo{Alerts: n, Last: last, At: at}
}

// CountDirectView 直连统计开关（「连接」页上的一个勾）。
type CountDirectView struct {
	On bool `json:"on"`
}

// GetCountDirect 当前是否统计直连流量。
func (b *Backend) GetCountDirect() CountDirectView {
	return CountDirectView{On: b.a.Cfg.CountDirectEnabled()}
}

// SetCountDirect 开关直连统计。改完要重启（过滤器在启动时装配），所以顺手重启一下。
func (b *Backend) SetCountDirect(on bool) error {
	b.a.Cfg.Tuning.CountDirect = on
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	if on {
		b.a.Bus.Info("已开启直连流量统计（直连网段会进内核过滤器，每包有一点开销）")
	} else {
		b.a.Bus.Info("已关闭直连流量统计（直连流量不再经过我们，回到零开销）")
	}
	return b.a.Restart()
}

// CaptureView 抓包状态（界面用）。
type CaptureView struct {
	On      bool   `json:"on"`
	Path    string `json:"path"`
	Bytes   int64  `json:"bytes"`
	Packets uint64 `json:"packets"`
	Reason  string `json:"reason"`
}

// GetCaptureStatus 抓包状态。
func (b *Backend) GetCaptureStatus() CaptureView {
	if b.a.Engine == nil {
		return CaptureView{}
	}
	on, path, n, pkts, reason := b.a.Engine.CaptureStatus()
	return CaptureView{On: on, Path: path, Bytes: n, Packets: pkts, Reason: reason}
}

// StartCapture 开始抓包（写到程序目录的 pcap/nethub-capture.pcap）。
func (b *Backend) StartCapture() (CaptureView, error) {
	if b.a.Engine == nil {
		return CaptureView{}, fmt.Errorf("引擎未初始化")
	}
	dir := dirOf(b.a.Cfg.Path())
	if err := b.a.Engine.StartCapture(dir, 64); err != nil {
		return CaptureView{}, err
	}
	b.a.Bus.Warn("已开始抓包（写 %s/pcap/nethub-capture.pcap，上限 64MB；抓到的东西含内网数据，别随便外发）", dir)
	return b.GetCaptureStatus(), nil
}

// StopCapture 停止抓包。
func (b *Backend) StopCapture() CaptureView {
	if b.a.Engine != nil {
		if reason := b.a.Engine.StopCapture(); reason != "" {
			b.a.Bus.Info("已停止抓包")
		}
	}
	return b.GetCaptureStatus()
}

// OpenCaptureDir 打开抓包所在目录（方便用 Wireshark 打开）。
func (b *Backend) OpenCaptureDir() error {
	dir := dirOf(b.a.Cfg.Path())
	if dir == "" {
		dir = "."
	}
	openPath(filepath.Join(dir, "pcap"))
	return nil
}

// ───────── 规则重叠检查（用户点按钮才跑）─────────

// OverlapView 一处重叠（给人看的）。
type OverlapView struct {
	Kind        string   `json:"kind"` // dead | shadowed | fine
	Earlier     int      `json:"earlier"`
	Later       int      `json:"later"`
	EarlierName string   `json:"earlierName"`
	LaterName   string   `json:"laterName"`
	Targets     []string `json:"targets"`
	Ports       []string `json:"ports"`
	Resolution  string   `json:"resolution"`
	Action      string   `json:"action"`
	LaterAction string   `json:"laterAction"`
}

// OverlapResult 一次重叠检查的结果。
type OverlapResult struct {
	Rows    []OverlapView `json:"rows"`
	Summary string        `json:"summary"`
}

// CheckOverlaps 检查规则重叠。刻意做成"按钮触发"：重叠不一定错
// （宽兜底 + 窄例外是常见写法），我们只摆事实，不替用户改顺序。
func (b *Backend) CheckOverlaps() OverlapResult {
	ov := b.a.Cfg.CheckOverlaps()
	res := OverlapResult{Rows: make([]OverlapView, 0, len(ov)), Summary: config.OverlapSummary(ov)}
	for _, o := range ov {
		res.Rows = append(res.Rows, OverlapView{
			Kind: o.Kind, Earlier: o.Earlier + 1, Later: o.Later + 1,
			EarlierName: o.EarlierName, LaterName: o.LaterName,
			Targets: o.Targets, Ports: o.Ports, Resolution: o.Resolution,
			Action: o.ActionText, LaterAction: o.LaterAction,
		})
	}
	return res
}

// ───────── 凭据加密开关（A18）─────────

// intPtr 取个指针（给"区分没传与传了 0"的字段用）。
func intPtr(v int) *int { return &v }

// ───────── 关于 ─────────

// Version 版本号（发布构建可用 -ldflags -X 覆盖）。
var Version = "dev"

// AboutView 关于卡的信息。
type AboutView struct {
	Version   string `json:"version"`
	Repo      string `json:"repo"`
	Releases  string `json:"releases"`
	Elevated  bool   `json:"elevated"`
	GoVersion string `json:"goVersion"`
	ConfigDir string `json:"configDir"`
}

const (
	repoURL     = "https://github.com/Lithivm/NetHub"
	releasesURL = "https://github.com/Lithivm/NetHub/releases"
)

// GetAbout 版本与项目地址（界面「关于」卡用）。
func (b *Backend) GetAbout() AboutView {
	return AboutView{
		Version:   Version,
		Repo:      repoURL,
		Releases:  releasesURL,
		Elevated:  isElevated(),
		GoVersion: runtime.Version(),
		ConfigDir: dirOf(b.a.Cfg.Path()),
	}
}

// OpenRepo / OpenReleases 打开浏览器。
func (b *Backend) OpenRepo()     { openPath(repoURL) }
func (b *Backend) OpenReleases() { openPath(releasesURL) }
