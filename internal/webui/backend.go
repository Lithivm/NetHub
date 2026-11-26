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
	"errors"
	"sync"
	"time"

	"nethub/internal/app"
	"nethub/internal/engine"
	"nethub/internal/hostsmgr"
	"nethub/internal/logbus"
)

// Backend 是引擎进程那边的"能力面"：引擎进程自己直接调它（托盘、看护），
// 同时也是 ipc 反射派发的目标 —— 界面进程发来的每个方法调用都落在这里。
type Backend struct {
	a  *app.App
	ui UI

	mu       sync.Mutex
	logCh    chan logbus.Line
	tray     *Tray
	quitting bool
	// uiHidden 界面现在是收着的吗（看护重启时按它决定要不要带 -hidden）。
	// 两个来源：后端自己叫它藏（HideToTray），以及界面进程的窗口关闭路径主动上报。
	uiHidden bool
	// starting 引擎正在拉起来（给界面的"启动中"中间态用，见 StateView.Starting）。
	starting bool
	quitOnce sync.Once
	quitHook func() // 引擎进程的收尾钩子（关管道、停看护、落日志）

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

	// 别的代理绕过覆盖的最后**确认**结果（clashWatch 后台刷新，界面只读结论）。
	// 界面不现读的理由：GetState 每 1.5 秒调一次，现读会把注册表重写中的裸值挂成告警条。
	clashMu   sync.Mutex
	clashSeen Coverage

	// notified 已经推过**系统通知**的告警 ID（只对 notifiable 里那两条，见 notices.go）：
	// 从无到有时推一次，恢复后从表里移除（下次再出还会推）。
	notified map[string]bool
	noticeMu sync.Mutex

	// 顶栏实时流量图：每秒一格的 60 秒窗口（trafficWatch 写，GetTraffic 读）。
	traffic trafficRing

	// 只读态：引擎锁被别的进程（服务版/另一实例）拿着，本界面**不跑引擎**、
	// 只展示状态，等用户点「接管」再抢回来。
	//
	// 为什么不用“起不来就报错”：两个引擎同时跑会各装一套 WinDivert 过滤器
	// 各自改写到自己的 relay，是静默互相干扰（不是第二个报错退出）——
	// 所以宁可降级成只读，也不能让用户随手就撞上去。
	roMu     sync.RWMutex
	readOnly bool
	roWhy    string

	// updInfoLast / updInfoMu：最近一次**自动**检查更新的结果（Notices 用它决定挂不挂“有新版本”）。
	// 刻意不叫 upd 开头：包外那个 updMu/updStatus 是“一键更新的进度”，两回事。
	updInfoMu   sync.Mutex
	updInfoLast UpdateInfo
}

func New(a *app.App) *Backend {
	return &Backend{a: a, logCh: make(chan logbus.Line, 256), ui: noUI{}}
}

// SetUI 装上"界面配合"的实现（引擎进程装 remoteUI；测试/无界面时留 noUI）。
func (b *Backend) SetUI(ui UI) { b.ui = ui }

// uiOrNoop 取 UI；没装就用空实现。
//
// 引擎是个长跑进程：哪怕只是测试里手搓出来的 Backend 忘了装 UI，也不能 nil panic ——
// 那会直接在用户机器上把隧道带走（同一个道理见 "绝不静默降级" 那些注释）。
func (b *Backend) uiOrNoop() UI {
	if b.ui == nil {
		return noUI{}
	}
	return b.ui
}

// Bootstrap 拿通知口子、把日志推给前端、拉起服务与各路后台巡检。
//
// **由引擎进程调用**，不再是 Wails 的 OnStartup 回调 —— 界面与引擎拆成两个进程后，
// 这些活的归属是引擎进程（为什么要拆见 internal/ipc 的包注释）。
// 名字不叫 Start：Start 是界面上那个"启动服务"按钮（见下方启停一节）。
func (b *Backend) Bootstrap() {
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

	// 顶栏实时流量图：每秒取一格（引擎侧采样，界面切页/重开都不断），见 traffic.go。
	go b.trafficWatch()

	// 自动检查更新：启动后几秒查一次，之后每 6 小时一次；有新版本就挂**常驻告警条**。
	// 以前只有用户点「关于」那个按钮才查 —— 现场多半不点，于是永远没人知道有新版本。
	b.startUpdateCheck()

	// 起来就把服务拉起（计划任务开机自启靠这个：进程起来 = 隧道就绪）
	go func() {
		// 先标"正在启动"：界面第一帧就显示「启动中」，而不是灰「未启动」直接跳 Ready。
		// 标记点必须在"决定要拉"这一刻，不能等真去 Start 才标 —— 否则界面还没连上
		// 标记就已经结束了，中间态等于不存在（2026-10-14 实测：那个窗口只有 0.9 秒）。
		b.setStarting(true)
		time.Sleep(600 * time.Millisecond)
		b.a.Bus.Info("开始自动启动服务…")
		if err := b.startEngine(); err != nil {
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

// Shutdown 引擎进程退出时的兜底：注销托盘图标。
//
// 正常退出（托盘菜单 → 退出）走 Quit()，那里已经 Remove 过了；但别的退出路径
// 不能让图标变成孤儿 —— 孤儿图标会堆在托盘折叠面板里，显得像"注册了一堆图标"。
func (b *Backend) Shutdown() {
	if b.tray != nil {
		b.tray.Remove()
		b.tray = nil
	}
}

func (b *Backend) emit(name string, data any) { b.uiOrNoop().Emit(name, data) }

// ───────────────────────── 视图类型（与前端 JSON 对齐）─────────────────────────

type StateView struct {
	Running bool `json:"running"`
	// Starting 正在拉起引擎（自动启动 / 手动点启动 / 重启 / 接管都算）。
	//
	// 为什么要单独一个字段：以前界面只有"未启动/Ready"两态，用户点了启动之后
	// 那几秒里胺囊还是"未启动"（只是变成黄色），看着像没反应；自动启动服务时
	// 更是直接从灰"未启动"跳到 Ready。（用户 2026-10-14 明确要求加中间态）
	Starting bool   `json:"starting"`
	Relay    string `json:"relay"` // 内部中转端口（界面上不再直接显示，只作悬停提示）
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
	// ThemePref 主题**偏好**（system | light | dark）：设置页的三段滑块看它。
	// Theme 则是**生效色**（light/dark）—— 两者分开的理由，选了 "system" 时只有后端知道答案。
	ThemePref   string `json:"themePref"`
	HostsPath   string `json:"hostsPath"`
	HostsInFile bool   `json:"hostsInFile"` // hosts 里已存在我们的标记区块
	Autostart   bool   `json:"autostart"`
	AutoDetail  string `json:"autoDetail"`
	// ReadOnly 引擎被别的进程拿着（服务版/另一实例），界面处于只读态；
	// ReadOnlyWhy 是一句人话说明，直接显示给用户。
	ReadOnly    bool   `json:"readOnly"`
	ReadOnlyWhy string `json:"readOnlyWhy"`
	// DriverBlocked 最近一次启动失败是“内核驱动被安全软件拦了”（错误码 1450/1275）。
	// 前端据此挂常驻告警条 —— 那个错误码字面像内存不够，实际基本只有杀软一种原因。
	DriverBlocked bool   `json:"driverBlocked"`
	DriverPath    string `json:"driverPath"` // 驱动文件绝对路径（告警条上「复制驱动路径」用）
	// Notices 该挂的常驻告警（后端出数据、前端只渲染；多条时前端取 Priority 最高的）。
	// 跟着这个 1.5 秒的轮询走，就不用再单开一条 60 秒的横幅轮询。
	Notices []Notice `json:"notices"`
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
	// Wildcards 通配域名（*.example.com）当前覆盖到哪些 IP（学习自观察到的 DNS 应答）
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
	// TrayTraffic 托盘图标是否显示实时流量图（默认关 = 默认图标）
	TrayTraffic bool `json:"trayTraffic"`
	// TrayTrafficMode 托盘图显示哪个量：total | up | down（默认 total）
	TrayTrafficMode string `json:"trayTrafficMode"`
	// LogLevel 日志档位：normal（默认）| verbose | debug。
	// 三档各装什么见 logbus.Level 的注释（照抄 Proxifier）。
	LogLevel string `json:"logLevel"`
	// LogLevelFile / LogLevelFileSet 是**只读**的（SaveSettings 不看它们）：
	// 文件档走 SetLogLevelFile。它与屏幕档分开设是 Proxifier 的做法 ——
	// 屏幕 normal 看着清爽，文件 verbose 让事后查有判定面。
	LogLevelFile    string `json:"logLevelFile"`
	LogLevelFileSet bool   `json:"logLevelFileSet"`
	// 上游拨号（秒）。0 表示前端没传 → 保持原值，不当成“设成 0”。
	DialTimeout int `json:"dialTimeout,omitempty"`
	DialBudget  int `json:"dialBudget,omitempty"`
	// RaceAfter 竞速起跑（毫秒）：0 = 关闭竞速。
	// 用指针是为了区分“没传”（nil = 不改）与“明确设成 0”（关）—— 用 int 的话，
	// 前端一旦漏传就会被当成“关闭”，静默把功能关了。
	RaceAfter *int `json:"raceAfter"`
	// WarmSessions 预热会话条数：0 = 关闭（同样用指针区分“没传”）。
	WarmSessions *int `json:"warmSessions"`
	// DomainResolveLocal 强制本机解析的域名（一行一个，支持 `*.example.com` 通配）。
	// 用切片而不是指针：nil = 前端没传（旧前端，不改）；空切片 = 用户清空了。
	DomainResolveLocal []string `json:"domainResolveLocal"`
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
		Running:       running,
		Starting:      b.startingNow(),
		Error:         errText,
		PoolWarm:      warm,
		PoolHits:      taken,
		Relay:         relay,
		TotalConns:    total,
		ActiveConns:   active,
		ConfigPath:    b.a.Cfg.Path(),
		LogPath:       b.a.Bus.FilePath(),
		Theme:         b.effectiveTheme(),
		ThemePref:     b.a.Cfg.Theme(),
		HostsPath:     hostsmgr.Path(),
		HostsInFile:   hostsInFile,
		Autostart:     b.autostartCached(),
		AutoDetail:    b.autostartDetailCached(),
		ReadOnly:      readOnly,
		ReadOnlyWhy:   why,
		DriverBlocked: b.a.DriverBlocked(),
		DriverPath:    engine.DriverSysPath(),
		Notices:       b.Notices(),
	}
}

// ───────────────────────── 启停 ─────────────────────────

func (b *Backend) Start() error { return b.startEngine() }
func (b *Backend) Stop()        { b.a.Stop() }
func (b *Backend) Restart() error {
	b.setStarting(true)
	defer b.setStarting(false)
	return b.a.Restart()
}

// startEngine 统一的"拉起引擎"入口：顺手把"正在启动"标上，界面好显示「启动中」中间态。
//
// 自动启动服务 / 手动点启动 / 接管都走它 —— 干别的事（比如交棒给服务版）不走。
func (b *Backend) startEngine() error {
	b.setStarting(true)
	defer b.setStarting(false)
	return b.a.Start()
}

// setStarting / startingNow："正在启动"标记（GetState 每秒读一次）。
func (b *Backend) setStarting(v bool) {
	b.mu.Lock()
	b.starting = v
	b.mu.Unlock()
}

func (b *Backend) startingNow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.starting
}

// PushTheme 把当前主题推给界面：界面进程刚起来时窗口主题来自启动参数，
// 连上之后再对齐一次，保证与配置（含“跟随系统”）一致。
func (b *Backend) PushTheme() { b.uiOrNoop().SetTheme(b.effectiveTheme() == "dark") }

// SetQuitHook 装上退出收尾：Quit() 把引擎停完、请界面退出之后调它一次。
//
// 引擎进程靠它结束主循环（界面进程不需要这个 —— 它退出就退出了）。
func (b *Backend) SetQuitHook(fn func()) { b.quitHook = fn }

// Quit 真正退出：先停服务再关窗（并请引擎进程收尾退出）。
func (b *Backend) Quit() {
	b.quitting = true
	b.a.Stop()
	if b.tray != nil {
		b.tray.Remove()
		b.tray = nil
	}
	// 界面那边是通知型的（它收到就退、不回执），所以丢到 goroutine 里发，
	// 绝不阻塞退出流程 —— 否则就是干等超时、被用户当成"点了退出没反应"。
	go b.uiOrNoop().QuitApp()
	b.quitOnce.Do(func() {
		if b.quitHook != nil {
			b.quitHook()
		}
	})
}

// HideToTray 自绘标题栏的"最小化到托盘"按钮。
//
// 顺手记下"界面现在是收着的"：界面被外部程序杀掉再拉回来时得按上次的样子起来 ——
// 人家本来收在托盘里干活，不该让窗口弹到人脸上（见 UIHidden/NoteUIHidden）。
func (b *Backend) HideToTray() {
	b.noteUIHidden(true)
	b.uiOrNoop().HideWindow()
}

// NoteUIHidden 界面自己上报"我收起来了 / 我露出来了"。
//
// 为什么需要它：窗口的**系统关闭路径**（Alt+F4 / 系统菜单 / 任务栏关闭）走的是界面进程的
// OnBeforeClose，后端根本看不见，所以那边要主动报一声。
func (b *Backend) NoteUIHidden(hidden bool) { b.noteUIHidden(hidden) }

// UIHidden 界面现在是不是收着的（看护重启界面时按它决定要不要带 -hidden）。
func (b *Backend) UIHidden() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.uiHidden
}

func (b *Backend) noteUIHidden(hidden bool) {
	b.mu.Lock()
	changed := b.uiHidden != hidden
	b.uiHidden = hidden
	b.mu.Unlock()
	// 只在状态真变了的时候记一行：这条回答的是"待会儿拉起来要不要露窗口"，
	// 现场排障时（“为什么界面自己回来了却不弹出来”）能一眼看到。
	if changed && b.a != nil && b.a.Bus != nil {
		if hidden {
			b.a.Bus.Info("界面已收入托盘（被外部程序杀掉后拉起来时保持收着）")
		} else {
			b.a.Bus.Info("界面已显示（拉回来时会跟着露出来）")
		}
	}
	// 通知界面“该冻结 / 该解冻了”—— 界面收到后停轮询、呙动画、丢推送事件。
	//
	// 为什么由这里发（不让界面自己判断）：收起的路径有三条 —— 托盘菜单、窗口的关闭键、
	// **系统的关闭路径（Alt+F4 / 任务栏关闭，走界面进程的 OnBeforeClose）**；
	// 最后那条界面根本不知道自己是被藏了还是被关了。而三条都收敛到 noteUIHidden，
	// 所以在这一处发最省事也最全。
	//
	// 也**不能**用浏览器的 document.hidden 兜底：实测把宿主窗口隐藏（WindowHide）
	// 并不会让 WebView2 里的页面变成 hidden —— 页面照旧每帧出帧、定时器照旧全速跑
	// （同机同托盘态实测：界面进程树 68.8% 单核）。台架里页面真 hidden 时 Chromium 才节流。
	if changed {
		if hidden {
			b.emit("hidden", nil)
		} else {
			b.emit("shown", nil)
		}
	}
}
