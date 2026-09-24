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
	"errors"
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
	"nethub/internal/winsvc"
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
	selfTestAt   time.Time  // 上次自检完成时间（体检要知道结果新不新）
	selfTestGate sync.Mutex // 同一时刻只跑一轮（体检与按钮可能撞车）

	// 自启状态缓存：schtasks 是外部进程，不能在 GetState（前端每 1.5s 调一次）里跑，
	// 否则会不断创建进程；而且 GUI 子系统没控制台，会表现为窗口一直闪、抢焦点。
	autoMu      sync.RWMutex
	autoEnabled bool
	autoDetail  string

	// 只读态：引擎锁被别的进程（服务版/另一实例）拿着，本界面**不跑引擎**、
	// 只展示状态，等用户点「接管」再抢回来。
	//
	// 为什么不用“起不来就报错”：两个引擎同时跑会各装一套 WinDivert 过滤器
	// 各自改写到自己的 relay，是静默互相干扰（不是第二个报错退出）——
	// 所以宁可降级成只读，也不能让用户随手就撞上去。
	roMu     sync.RWMutex
	readOnly bool
	roWhy    string
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
			// 引擎锁被别的进程（服务版/另一实例）拿着：降级为只读，不弹错、不退出。
			// 界面上会显示醒目状态 + 「接管」按钮，用户要抢回来只需点一下。
			if errors.Is(err, app.ErrEngineBusy) {
				why := describeEngineHolder()
				b.setReadOnly(why)
				b.a.Bus.Warn("%s —— 界面版以只读方式启动（不会碰流量）；要由界面接管请点顶栏「接管引擎」", why)
				return
			}
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
	// ReadOnly 引擎被别的进程拿着（服务版/另一实例），界面处于只读态；
	// ReadOnlyWhy 是一句人话说明，直接显示给用户。
	ReadOnly    bool   `json:"readOnly"`
	ReadOnlyWhy string `json:"readOnlyWhy"`
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
	// 这条规则放行 QUIC（allow_quic）：它的 UDP 443 不进过滤器、直连出去
	AllowQUIC bool `json:"allowQuic"`
	// 域名目标：解析到哪、什么时候解析的、解析不到的原因（规则页直接显示）
	HostResolves []engine.HostResolveView `json:"hostResolves"`
	// Wildcards 通配域名（*.his.com）当前覆盖到哪些 IP（学习自观察到的 DNS 应答）
	Wildcards []engine.WildcardStat `json:"wildcards"`
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
	// AutostartDelay 开机自启的登录后延迟（秒）；nil = 前端没传 → 不改。
	// 0 是合法值（登录后立即启动），所以用指针。
	AutostartDelay *int `json:"autostartDelay"`
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
	readOnly, why := b.readOnlyState()
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
		Theme:       b.a.Cfg.Theme(),
		HostsPath:   hostsmgr.Path(),
		HostsInFile: hostsInFile,
		Autostart:   b.autostartCached(),
		AutoDetail:  b.autostartDetailCached(),
		ReadOnly:    readOnly,
		ReadOnlyWhy: why,
	}
}

// ───────── 引擎互斥：只读降级 / 接管 / 交棒 ─────────

// setReadOnly / clearReadOnly：界面版的只读态（谁在跑、为什么）。
func (b *Backend) setReadOnly(why string) {
	b.roMu.Lock()
	b.readOnly, b.roWhy = true, why
	b.roMu.Unlock()
}

func (b *Backend) clearReadOnly() {
	b.roMu.Lock()
	b.readOnly, b.roWhy = false, ""
	b.roMu.Unlock()
}

func (b *Backend) readOnlyState() (bool, string) {
	b.roMu.RLock()
	defer b.roMu.RUnlock()
	return b.readOnly, b.roWhy
}

// describeEngineHolder 谁拿着引擎。能确定是服务版就说服务版，不确定就不猜。
func describeEngineHolder() string {
	if winsvc.State() == "running" {
		return "Windows 服务版（headless）正在运行"
	}
	return "另一个 NetHub 实例正在运行（可能是 -headless 模式）"
}

// TakeoverEngine 界面版接管引擎：停掉正在跑的 Windows 服务，然后本进程把引擎拉起来。
// 供只读态下的「接管」按钮调用。
func (b *Backend) TakeoverEngine() (string, error) {
	if b.a.Running() {
		b.clearReadOnly()
		return "引擎已经在界面版里运行", nil
	}
	stoppedService := false
	if winsvc.State() == "running" {
		b.a.Bus.Info("接管：先停止 Windows 服务版…")
		if err := winsvc.Stop(); err != nil {
			return "", fmt.Errorf("停止服务失败，没有接管: %w", err)
		}
		// 等服务真的停稳：它会放开引擎锁，锁没放开就抢不到
		if err := winsvc.WaitStopped(10 * time.Second); err != nil {
			return "", fmt.Errorf("服务没停稳，没有接管: %w", err)
		}
		stoppedService = true
	}
	if err := b.a.Start(); err != nil {
		// 服务已停但锁仍被占 → 是别的实例拿着，说清楚别让人以为是服务的锅
		if errors.Is(err, app.ErrEngineBusy) {
			return "", fmt.Errorf("%s，接管没成功", describeEngineHolder())
		}
		return "", err
	}
	b.clearReadOnly()
	if stoppedService {
		b.a.Bus.Info("接管完成：服务版已停止，引擎现由界面版运行（服务注册还留着，下次开机仍会自己跑）")
		return "已接管：服务版已停止（注册保留，下次开机仍会自启）", nil
	}
	return "已接管引擎", nil
}

// StartServiceHandOver 交棒给服务版：先停本机引擎（释放锁）→ 起服务 →
// 等服务真的 Running 才返回。调用方拿到 nil 错误后再让界面优雅退出。
//
// 顺序必须是“先停自己再起服务”：反过来的话服务抢不到锁，起来也白起。
// 代价是几百毫秒的真空期，TCP 会重传，比两个引擎同时抢流量安全得多。
func (b *Backend) StartServiceHandOver() (string, error) {
	wasRunning := b.a.Running()
	if wasRunning {
		b.a.Bus.Info("交棒：先停止界面版引擎，把互斥让给服务版…")
		b.a.Stop()
	}
	if err := winsvc.Start(); err != nil {
		b.rollbackEngine(wasRunning)
		return "", fmt.Errorf("启动服务失败: %w", err)
	}
	if err := winsvc.WaitRunning(15 * time.Second); err != nil {
		_ = winsvc.Stop()
		b.rollbackEngine(wasRunning)
		return "", fmt.Errorf("服务没起来: %w", err)
	}
	b.a.Bus.Info("交棒完成：服务版已接管（引擎锁现在服务进程里）")
	// 界面自己退出。留 1.5 秒让前端把 toast 画出来（立即退会看起来像崩了）；
	// 走 Quit 而不是 os.Exit —— 它会搞掉托盘图标，避免留下“僵尸图标”。
	go func() {
		time.Sleep(1500 * time.Millisecond)
		b.Quit()
	}()
	return "服务版已接管；界面即将退出（托盘图标会一并移除）", nil
}

// rollbackEngine 交棒失败时把界面版引擎恢复回去 —— 否则会变成
// “原来的停了、新的没起来”，隧道全断还看不到界面。
func (b *Backend) rollbackEngine(wasRunning bool) {
	if !wasRunning {
		return
	}
	b.a.Bus.Warn("交棒失败，正在把界面版引擎恢复回去…")
	if err := b.a.Start(); err != nil {
		b.a.Bus.Error("回滚也失败了，现在没有引擎在跑: %v", err)
		return
	}
	b.a.Bus.Info("已回滚：界面版引擎仍在运行")
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
	chains := b.a.Cfg.ChainsSnapshot()
	out := make([]ChainView, 0, len(chains))
	for _, c := range chains {
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

// briefUpstream 列表用的简化地址：协议 + 主机:端口。
//
// **不带凭据标记** —— 界面上另有一个单独的“带凭据 / 无凭据”标签，
// 这里再拼一个就重复了（实测被用户当成显示两次的 bug）。
func briefUpstream(raw string) string {
	b := gostbat.Redact(raw)
	if u, err := upstream.Parse(raw); err == nil && u.Addr != "" {
		proto := u.Protocol
		if u.TLS {
			proto += "+tls"
		}
		b = proto + "://" + u.Addr
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
	chains := b.a.Cfg.ChainsSnapshot()
	routes := b.a.Cfg.RoutesSnapshot()
	note := map[string]string{}
	for _, c := range chains {
		note[c.Name] = c.Note
	}
	wildcardStats := b.a.Engine.WildcardStats()
	out := make([]RouteView, 0, len(routes))
	for i, r := range routes {
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
		// 通配域名（*.his.com）没有“解析结果”，但有“已经学到哪些 IP”——
		// 不显示的话，界面上看不到它到底覆盖了什么，跟“静默失效”没区别。
		var wild []engine.WildcardStat
		for _, st := range wildcardStats {
			for _, t := range r.Targets {
				if strings.EqualFold(strings.TrimSpace(t), st.Pattern) {
					wild = append(wild, st)
					break
				}
			}
		}
		out = append(out, RouteView{
			Index: i, Name: r.Name, Targets: r.Targets, Ports: r.Ports,
			Chain: r.Chain, Direct: r.IsDirect(), Block: r.IsBlock(), Note: note,
			Shadowed:     b.a.Cfg.ShadowedTargets(i),
			LocalNets:    r.LocalNets,
			Inactive:     !localNetsMatch(r.LocalNets, localIPv4s()),
			Apps:         r.Apps,
			AllowQUIC:    r.AllowQUIC,
			Enabled:      r.IsEnabled(),
			HostResolves: mine,
			Wildcards:    wild,
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
		HostsManage:    hosts.Manage,
		HostsEntries:   entries,
		Theme:          b.a.Cfg.Theme(),
		DialTimeout:    int(b.a.Cfg.DialTimeoutDur() / time.Second),
		DialBudget:     int(b.a.Cfg.DialBudgetDur() / time.Second),
		RaceAfter:      intPtr(int(b.a.Cfg.RaceAfterDur() / time.Millisecond)),
		WarmSessions:   intPtr(b.a.Cfg.WarmTarget()),
		AutostartDelay: intPtr(int(b.a.Cfg.AutostartDelayDur() / time.Second)),
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
	// AllowQUIC 放行 QUIC（allow_quic）：勾上 = 这条规则的目标不拦 UDP 443
	AllowQUIC bool `json:"allowQuic"`
}

// ruleFromInput 把界面输入整理成 config.Route。
func ruleFromInput(in RouteInput) (config.Route, error) {
	return ruleFrom(in.Name, in.Targets, in.Chain, in.Ports, in.LocalNets, in.Apps, in.AllowQUIC)
}

// SaveRoute 保存一条规则：index < 0 = 新增，否则替换第 index 条。
// 这是界面当前用的入口（老方法保留给已有调用方，行为一致）。
func (b *Backend) SaveRoute(index int, in RouteInput) error {
	rt, err := ruleFromInput(in)
	if err != nil {
		return err
	}
	if index < 0 {
		base := b.a.Cfg.RouteCount()
		if err := b.a.Cfg.AddRoute(rt); err != nil {
			return err
		}
		return b.saveHint(base, ruleSaved("添加", rt))
	}
	old := ""
	if cur, ok := b.a.Cfg.RouteAt(index); ok {
		// 规则开关由列表上的开关控制，不是表单字段 —— 编辑内容时**必须继承原状态**，
		// 否则“改个名字/加个目标”会悳悹把停用的规则重新启用。
		rt.Enabled = cur.Enabled
		old = cur.Name
		if strings.TrimSpace(old) == "" {
			old = cur.Describe()
		}
	}
	if err := b.a.Cfg.UpdateRoute(index, rt); err != nil {
		return err
	}
	if old != "" && strings.TrimSpace(in.Name) != "" && old != in.Name {
		return b.saveHint(index, fmt.Sprintf("%s→%s（%d 个目标）", old, in.Name, len(rt.Targets)))
	}
	return b.saveHint(index, ruleSaved("修改", rt))
}

// ruleFrom 把界面传来的"一条规则"整理成 config.Route：目标与端口文本都可以一次填多个
// （换行/逗号/顿号/空格分隔），这里负责拆分 + 归一化。端口留空 = 任意端口。
func ruleFrom(name, targets, chain, ports, localNets, apps string, allowQUIC bool) (config.Route, error) {
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
	return config.Route{Name: name, Targets: ts, Ports: ps, Chain: chain, LocalNets: lns, Apps: as,
		AllowQUIC: allowQUIC}, nil
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
	rt, err := ruleFrom(name, targets, chain, ports, localNets, "", false)
	if err != nil {
		return err
	}
	if err := b.a.Cfg.AddRoute(rt); err != nil {
		return err
	}
	return b.saveHint(b.a.Cfg.RouteCount()-1, ruleSaved("添加", rt))
}

// UpdateRoute 替换第 index 条规则（同样支持多目标 + 端口条件）。
func (b *Backend) UpdateRoute(index int, name, targets, chain, ports, localNets string) error {
	rt, err := ruleFrom(name, targets, chain, ports, localNets, "", false)
	if err != nil {
		return err
	}
	// 这个入口（老 API）不带 allow_quic 参数：像 SaveRoute 对 Enabled 那样**继承原值**，
	// 否则“用老接口改个名字”会静默把“不拦 QUIC”抹掉。
	if cur, ok := b.a.Cfg.RouteAt(index); ok {
		rt.AllowQUIC = cur.AllowQUIC
	}
	if err := b.a.Cfg.UpdateRoute(index, rt); err != nil {
		return err
	}
	return b.saveHint(index, ruleSaved("更新", rt))
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
	res, err := b.applyBatEntries(got)
	if err != nil {
		return res, err
	}
	if err := b.save("从 .bat 导入"); err != nil {
		return res, err
	}
	return res, nil
}

// applyBatEntries 把扫描到的 gost 批处理套到配置上（不落盘，便于测试）。
func (b *Backend) applyBatEntries(got []gostbat.BatEntry) (*ImportResult, error) {
	res := &ImportResult{}
	for _, be := range got {
		name := be.Name()
		if idx := b.a.Cfg.FindChain(name); idx >= 0 {
			// 同名链已存在 → 只更新 upstream（最常见的"换服务器"场景）
			cur, _ := b.a.Cfg.ChainAt(idx)
			cur.SetUpstreams([]string{be.Forward}) // 必须整体替换，不能只写 Forward（见 SetUpstreams 注释）
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
	return res, nil
}

// ───────────────────────── 设置 ─────────────────────────

func (b *Backend) SaveSettings(s SettingsView) error {
	cfg := b.a.Cfg
	// 不动 cfg.Relay：界面上没有这个字段，前端不会传。
	// （之前这里写 cfg.Relay = s.Relay，前端不传时会被清成空串，直接校验失败）
	var entries []string
	if len(s.HostsEntries) > 0 {
		entries = s.HostsEntries
	}
	cfg.SetHosts(s.HostsManage, entries)
	if s.AutostartDelay != nil {
		cfg.SetAutostartDelay(time.Duration(*s.AutostartDelay) * time.Second)
	}
	// 拨号调优：只在界面确实传了值时才改（0 = 没传，保持原样）；
	// 竞速起跑 / 预热会话：nil = 前端没传 → 保持原值；0 = 明确关闭
	cfg.UpdateTuning(func(t *config.Tuning) {
		if s.DialTimeout > 0 {
			t.DialTimeout = fmt.Sprintf("%ds", s.DialTimeout)
		}
		if s.DialBudget > 0 {
			t.DialBudget = fmt.Sprintf("%ds", s.DialBudget)
		}
		if s.RaceAfter != nil {
			if *s.RaceAfter == 0 {
				t.RaceAfter = "off"
			} else {
				t.RaceAfter = fmt.Sprintf("%dms", *s.RaceAfter)
			}
		}
		if s.WarmSessions != nil {
			if *s.WarmSessions == 0 {
				t.WarmSessions = "off"
			} else {
				t.WarmSessions = fmt.Sprintf("%d", *s.WarmSessions)
			}
		}
	})
	res, err := b.a.SaveConfig()
	if err != nil {
		return err
	}
	b.afterSave(res, "设置已保存")
	// 计划任务的“登录后延迟”是写死在任务 XML 里的 —— 已经装了就必须重建任务才生效。
	// 放在 SaveConfig **之后**：配置先落盘，重建任务失败也不会丢掉用户刚改的设置。
	if s.AutostartDelay != nil && autostart.Enabled() {
		if err := autostart.Enable(int(cfg.AutostartDelayDur() / time.Second)); err != nil {
			return err
		}
		b.refreshAutostart()
	}
	b.a.Bus.Info("设置已保存（hosts 托管=%v；拨号单次 %s / 总预算 %s / 竞速起跑 %s / 预热 %d 条；自启延迟 %s）",
		b.a.Cfg.HostsCopy().Manage, cfg.DialTimeoutDur(), cfg.DialBudgetDur(), cfg.RaceAfterDur(), cfg.WarmTarget(),
		cfg.AutostartDelayDur())
	return nil
}

// SetTheme 切换深浅色并记住（同时切换窗口标题栏配色）。
func (b *Backend) SetTheme(mode string) error {
	if mode != "dark" {
		mode = "light"
	}
	b.a.Cfg.SetTheme(mode)
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
	delay := int(b.a.Cfg.AutostartDelayDur() / time.Second)
	var err error
	if on {
		err = autostart.Enable(delay)
	} else {
		err = autostart.Disable()
	}
	if err != nil {
		return err
	}
	b.refreshAutostart()
	if on {
		b.a.Bus.Info("已设置开机自启（计划任务 %s，最高权限，登录后延迟 %d 秒静默启动）", autostart.TaskName, delay)
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
	b.a.Cfg.SetHosts(true, clean)
	if _, err := b.a.SaveConfig(); err != nil {
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
	b.a.Cfg.SetHosts(false, nil)
	if _, err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("已从 hosts 移除本程序的标记区块")
	return nil
}

// ───────────────────────── 链路自检 ─────────────────────────

// SelfTest 对每条链做端到端探测：本地 socks5 通不通 + 经它能不能真连到内网目标。
// 走 gost 的本地监听，不经过 WinDivert，所以它单独验证"链路"这一段。
func (b *Backend) SelfTest() { go b.runSelfTest() }

// runSelfTest 真正跑一轮（同步）。走 selfTestGate 排队：体检与按钮可能同时要结果，
// 排队比重复探测好 —— 探活是对端可见的动作，能少发就少发。
func (b *Backend) runSelfTest() {
	chains := b.a.Cfg.ChainsSnapshot()
	if len(chains) == 0 {
		b.emit("notify", NotifyView{Title: "无法自检", Text: "还没有配置任何链", Kind: "warn"})
		return
	}
	b.selfTestGate.Lock()
	defer b.selfTestGate.Unlock()
	func() {
		b.a.Bus.Info("selftest.start: chains=%d", len(chains))
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
			b.selfTestLast, b.selfTestAt = report, time.Now()
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
				b.a.Bus.Error("selftest.fail: chain=%s scope=upstream", ch.Name)
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
					b.a.Bus.Info("selftest.probe: chain=%s target=%s source=recent", ch.Name, ref.Target)
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
				// 一条链的规则里可能写了多个单 IP，逐个试到底（第一个可能恰好没开）。
				cands := probeIPsForChain(b.a.Cfg, ch.Name)
				if len(cands) == 0 {
					// 不是问题，只是这条链暂时没东西可探 —— 用 INFO，别用 WARN
					// （WARN 在界面日志里是警告色，会让人以为链路有问题）
					b.a.Bus.Info("selftest.skip: chain=%s reason=no-probe-target", ch.Name)
					add(ch.Name, true,
						"跳过：这条链的网段里还没有可探的真实主机",
						"代理段本身正常，只是没东西可探。给它一条 hosts 条目（IP 域名），"+
							"或者先正常访问一次它的内网目标，之后自检就会自动把它纳入探活。")
					continue
				}
				for _, cand := range cands {
					ip = cand
					for _, port := range []uint16{443, 80, 5432, 6446, 5000, 9054, 9056} {
						conn, derr := dial(ip, port)
						if derr == nil {
							conn.Close()
							hit = int(port)
							break
						}
					}
					if hit > 0 {
						break
					}
				}
			}
			if hit > 0 {
				if guessed {
					b.a.Bus.Info("selftest.ok: chain=%s upstream=%s reach=%s:%d port_source=guessed", ch.Name, desc, ip, hit)
					add(ch.Name, true, fmt.Sprintf("端到端可达：→ %s:%d（端口是猜的，不代表业务端口）", ip, hit), "上游："+desc)
				} else {
					b.a.Bus.Info("selftest.ok: chain=%s upstream=%s reach=%s:%d port_source=recent", ch.Name, desc, ip, hit)
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
			b.a.Bus.Error("selftest.done: chains_failed=%d", bad)
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
func probeIPsForChain(cfg *config.Config, chainName string) []net.IP {
	var out []net.IP
	// ① 规则里写死的**单个 IP**（裸 IP 或 /32）就是真实目标，最该拿来探活。
	//
	// 真实例子：xaby-dev 那条规则的网段里全是大网段，但目标里有 172.16.20.172/32、
	// 219.145.88.134/32、39.103.146.155/32 —— 以前只去 hosts 里找，找不到就报“跳过”，
	// 而目标其实就摆在眼前。多个时全部返回（调用方逐个试到底：第一个可能恰好没开）。
	for _, rt := range cfg.RoutesSnapshot() {
		if rt.Chain != chainName {
			continue
		}
		for _, t := range rt.Targets {
			t = strings.TrimSpace(t)
			if ip := net.ParseIP(t); ip != nil && ip.To4() != nil {
				out = append(out, ip.To4())
				continue
			}
			if ip, n, err := net.ParseCIDR(t); err == nil && ip.To4() != nil {
				if ones, _ := n.Mask.Size(); ones == 32 {
					out = append(out, ip.To4())
				}
			}
		}
	}
	if len(out) > 0 {
		return out
	}

	var nets []*net.IPNet
	for _, rt := range cfg.RoutesSnapshot() {
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
				out = append(out, ip.To4())
				break
			}
		}
	}
	return out
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
func (b *Backend) save(what string) error { return b.saveHint(-1, what) }

// saveHint 保存配置，并对第 hintFor 条规则（-1 = 不管）给出“不拦保存”的提示。
//
// 放宽校验（2026-09-21）后，“目标被前面的规则盖住”这类东西不再拦保存 ——
// 但要说一声，否则用户会以为新规则在干活（它可能永远轮不到）。
// 结论与规则页那一列、「重叠检查」按钮同源（config.RouteHints）。
func (b *Backend) saveHint(hintFor int, what string) error {
	res, err := b.a.SaveConfig()
	if err != nil {
		return err
	}
	b.afterSave(res, what)
	if hintFor >= 0 {
		for _, h := range b.a.Cfg.RouteHints(hintFor) {
			b.a.Bus.Warn("提示（不拦保存）: %s", h)
		}
	}
	return nil
}

// afterSave 保存后的统一收尾：说清楚“热生效了没有、还有哪些改动要重启”。
//
// 界面 toast 另有一份（LastApplyHint），这里只写日志 —— 日志是现场排障的第一手材料。
func (b *Backend) afterSave(res app.ApplyResult, what string) {
	if res.Applied {
		b.a.Bus.Info("%s（已保存到 config.yaml，规则 %d 条已热生效；已在跑的连接不受影响）", what, res.Rules)
	} else {
		b.a.Bus.Info("%s（已保存到 config.yaml）", what)
	}
	if res.Note != "" {
		b.a.Bus.Warn("%s：%s", what, res.Note)
	}
	for _, f := range res.RestartNeeded {
		b.a.Bus.Warn("%s：%s 的改动需要重启才生效", what, f)
	}
}

// LastApplyHint 上一次保存的“附加说明”（需要重启才生效的项 / 异常）；空串＝没什么要说的。
//
// 界面每次保存成功后问一句，把结果接在 toast 里 —— 现场最怕“以为生效了其实没生效”。
func (b *Backend) LastApplyHint() string { return b.a.LastApply().Hint() }

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

// SetCountDirect 开关直连统计。
//
// 以前这里要重启（过滤器在启动时装配）；现在规则改动是热的（含直连统计开关引起的
// 过滤器变化），所以**不重启** —— 现场不会因为点个开关就把在跑的连接全断掉。
func (b *Backend) SetCountDirect(on bool) error {
	b.a.Cfg.SetCountDirect(on)
	res, err := b.a.SaveConfig()
	if err != nil {
		return err
	}
	b.afterSave(res, "直连统计开关")
	if on {
		b.a.Bus.Info("已开启直连流量统计（直连网段会进内核过滤器，每包有一点开销）")
	} else {
		b.a.Bus.Info("已关闭直连流量统计（直连流量不再经过我们，回到零开销）")
	}
	return nil
}

// QuicBlockView QUIC 阻断开关（「连接」页上的一个勾）。
type QuicBlockView struct {
	On bool `json:"on"`
}

// GetQuicBlock 当前是否阻断 QUIC（UDP 443）。
func (b *Backend) GetQuicBlock() QuicBlockView {
	return QuicBlockView{On: b.a.Cfg.QuicBlockEnabled()}
}

// SetQuicBlock 开关 QUIC 阻断（tuning.quic_block_disabled 的反面）。
//
// 它是主过滤器的一部分（UDP 子句），所以和规则改动一样是热的：改完立即生效，
// 不重启、不断已有连接。
func (b *Backend) SetQuicBlock(on bool) error {
	b.a.Cfg.SetQuicBlock(on)
	res, err := b.a.SaveConfig()
	if err != nil {
		return err
	}
	b.afterSave(res, "QUIC 阻断开关")
	if on {
		b.a.Bus.Info("已开启 QUIC 阻断（本该走隧道的 UDP 443 会被拦下并记一行，不再直连漏出）")
	} else {
		b.a.Bus.Info("已关闭 QUIC 阻断（UDP 443 不再经过我们）")
	}
	return nil
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
