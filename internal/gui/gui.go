// Package gui 是 govcl 写的界面层：主窗口 + 系统托盘 + 系统通知。
//
// 通知走 Windows 原生的托盘气泡（Shell_NotifyIcon NIF_INFO）——
// 在 Win10/11 上它会被系统渲染成标准通知并进操作中心，不需要 WinRT。
//
// 四个标签页对应四块功能：
//
//	运行日志 —— 实时日志
//	隧道链路 —— gost 上游（≈ Proxifier 的 Proxy Servers）
//	路由规则 —— 目标网段 → 走哪条链（≈ Proxifier 的 Rules）
//	设置     —— gost 托管 / hosts 接管 / 开机自启 / 文件位置
package gui

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"

	"netproxy/internal/app"
	"netproxy/internal/autostart"
	"netproxy/internal/config"
	"netproxy/internal/gostproc"
	"netproxy/internal/hostsmgr"
	"netproxy/internal/logbus"
	"netproxy/internal/socks"
)

type TMainForm struct {
	*vcl.TForm

	a      *app.App
	logSub chan logbus.Line

	tray     *vcl.TTrayIcon
	lblStat  *vcl.TLabel
	btnRun   *vcl.TButton
	btnTheme *vcl.TButton
	memo     *vcl.TMemo

	// 自绘标签条（govcl 的 TPageControl/TTabSheet 没有 Color 方法，无法深色化，
	// 所以改成 Panel 做标签 + Panel 存内容，靠 SetVisible 互斥）
	tabBar   *vcl.TPanel
	tabPages []*vcl.TPanel
	tabChips []*vcl.TPanel
	tabNames []string

	gridChain  *vcl.TStringGrid
	gridRule   *vcl.TStringGrid
	activeTab  int
	chipLabels []*vcl.TLabel
	topBar     *vcl.TPanel

	// 设置页
	cbGostOn     *vcl.TCheckBox
	eGostExe     *vcl.TEdit
	eRelay       *vcl.TEdit
	cbHosts      *vcl.TCheckBox
	memoHosts    *vcl.TMemo
	lblHostsInfo *vcl.TLabel
	cbAutostart  *vcl.TCheckBox
	lblAutoInfo  *vcl.TLabel
	lblCfgPath   *vcl.TLabel

	// 需要按主题改前景色的标签（分标题/正文/次要三档）
	hdrLabels   []*vcl.TLabel
	bodyLabels  []*vcl.TLabel
	mutedLabels []*vcl.TLabel

	quitting bool
	lines    int
}

var mainForm *TMainForm

// theApp 必须是包级变量：govcl 的 CreateForm 会用反射新建一个 TMainForm 实例
// 并把 mainForm 指针改指过去（见 vcl/resform.go newGoFormInstance），
// 我们在 Run() 里塞进结构体的字段会被丢掉。所以共享状态一律走包级变量。
var theApp *app.App

// Run 启动界面（阻塞直到退出）。
func Run(a *app.App) {
	theApp = a
	mainForm = &TMainForm{}
	vcl.Application.Initialize()
	vcl.Application.SetMainFormOnTaskBar(true)
	vcl.Application.CreateForm(&mainForm, true)
	vcl.Application.Run()
}

// ───────────────────────── 建界面 ─────────────────────────

func (f *TMainForm) OnFormCreate(sender vcl.IObject) {
	// 界面构建是一长串 FFI 调用，任何一步 nil/参数错都会 panic；
	// 拦下来并记入日志，避免"窗口起了但服务没起"这种诡异状态。
	step := "开始"
	defer func() {
		if r := recover(); r != nil {
			if f.a != nil {
				f.a.Bus.Error("界面初始化在「%s」处崩溃: %v", step, r)
			}
		}
	}()
	mark := func(s string) { step = s; f.a.Bus.Info("界面初始化: %s", s) }

	// 实例是 govcl 反射新建的，字段为空，这里把 app 引用补上（不能依赖 Run 里塞的那个）
	f.a = theApp
	f.a.Bus.Info("界面初始化: 开始（实例 %p）", f)
	f.SetCaption("netproxy · 内网隧道代理")
	f.SetWidth(1000)
	f.SetHeight(780)
	f.SetOnCloseQuery(f.onCloseQuery)
	f.SetOnShow(func(vcl.IObject) { f.applyTheme() })
	mark("窗口属性已设置")

	// ── 顶部工具条 ──
	top := vcl.NewPanel(f)
	top.SetParent(f)
	top.SetAlign(types.AlTop)
	top.SetHeight(52)
	top.SetBevelOuter(types.BvNone)
	f.topBar = top

	f.btnRun = mkButton(top, "启动服务", 12, 11, 110, 30, func() { f.onToggle() })
	mkButton(top, "重启服务", 132, 11, 110, 30, func() { go f.doRestart() })
	mkButton(top, "保存设置", 252, 11, 110, 30, func() { f.onSaveSettings() })
	f.btnTheme = mkButton(top, "深色模式", 372, 11, 100, 30, func() { f.toggleTheme() })

	f.lblStat = vcl.NewLabel(top)
	f.lblStat.SetParent(top)
	f.lblStat.SetLeft(488)
	f.lblStat.SetTop(18)
	f.lblStat.SetWidth(500)
	f.lblStat.SetCaption("状态：未启动")
	mark("顶部工具条")

	// ── 自绘标签条（代替 PageControl）──
	f.tabBar = vcl.NewPanel(f)
	f.tabBar.SetParent(f)
	f.tabBar.SetAlign(types.AlTop)
	f.tabBar.SetHeight(42)
	f.tabBar.SetBevelOuter(types.BvNone)

	// ── 内容容器：所有页面铺满剩余区域，靠 SetVisible 互斥 ──
	content := vcl.NewPanel(f)
	content.SetParent(f)
	content.SetAlign(types.AlClient)
	content.SetBevelOuter(types.BvNone)

	for _, name := range []string{"运行日志", "隧道链路", "路由规则", "设置"} {
		pg := vcl.NewPanel(content)
		pg.SetParent(content)
		pg.SetAlign(types.AlClient)
		pg.SetBevelOuter(types.BvNone)
		pg.SetVisible(false)
		f.tabPages = append(f.tabPages, pg)

		chip := vcl.NewPanel(f.tabBar)
		chip.SetParent(f.tabBar)
		chip.SetHeight(32)
		chip.SetWidth(120)
		chip.SetTop(6)
		chip.SetLeft(8 + int32(len(f.tabChips))*126)
		chip.SetBevelOuter(types.BvNone)
		lbl := vcl.NewLabel(chip)
		lbl.SetParent(chip)
		lbl.SetLeft(16)
		lbl.SetTop(8)
		lbl.SetCaption(name)
		f.chipLabels = append(f.chipLabels, lbl)
		i := len(f.tabChips)
		chip.SetOnClick(func(vcl.IObject) { f.showTab(i) })
		lbl.SetOnClick(func(vcl.IObject) { f.showTab(i) })
		f.tabChips = append(f.tabChips, chip)
		f.tabNames = append(f.tabNames, name)
	}

	f.buildLogTab(f.tabPages[0])
	f.buildChainTab(f.tabPages[1])
	f.buildRuleTab(f.tabPages[2])
	f.buildSettingsTab(f.tabPages[3])
	f.showTab(0)
	mark("四个标签页")

	// ── 托盘 + 系统通知 ──
	f.tray = vcl.NewTrayIcon(f)
	if ic := vcl.Application.Icon(); ic != nil {
		f.tray.SetIcon(ic)
	}
	f.tray.SetHint("netproxy · 内网隧道代理")
	f.tray.SetOnDblClick(func(vcl.IObject) { f.showWindow() })
	mark("托盘图标")

	menu := vcl.NewPopupMenu(f)
	addItem := func(cap string, fn func()) {
		it := vcl.NewMenuItem(f)
		it.SetCaption(cap)
		it.SetOnClick(func(vcl.IObject) { fn() })
		menu.Items().Add(it)
	}
	addItem("显示主界面", func() { f.showWindow() })
	addItem("启动服务", func() { go f.doStart() })
	addItem("停止服务", func() { go f.doStop() })
	addItem("-", func() {})
	addItem("退出", func() { f.quit() })
	f.tray.SetPopupMenu(menu)
	f.tray.SetVisible(true)
	mark("托盘菜单")

	// GUI 起来后接管通知回调
	f.a.Notify = f.Balloon

	// 先灌历史日志，再订阅增量
	for _, l := range f.a.Bus.Snapshot() {
		f.memo.Lines().Add(l.String())
		f.lines++
	}
	f.logSub = f.a.Bus.Subscribe()
	go f.pumpLog()
	go f.pumpStatus()
	mark("日志订阅完成，界面初始化完毕")

	// 起来就自动开始（符合"开机就干活"的预期）
	go func() {
		time.Sleep(600 * time.Millisecond)
		f.a.Bus.Info("开始自动启动服务…")
		f.doStart()
	}()
}

// ───────────────────────── 各标签页 ─────────────────────────

func (f *TMainForm) buildLogTab(ts *vcl.TPanel) {

	bar := vcl.NewPanel(ts)
	bar.SetParent(ts)
	bar.SetAlign(types.AlBottom)
	bar.SetHeight(46)
	bar.SetBevelOuter(types.BvNone)
	mkButton(bar, "清空", 12, 8, 100, 30, func() {
		f.memo.Lines().Clear()
		f.lines = 0
	})
	mkButton(bar, "打开日志文件", 122, 8, 130, 30, func() {
		f.openPath(f.a.Bus.FilePath())
	})
	mkButton(bar, "链路自检", 262, 8, 120, 30, func() { f.chainSelfTest() })
	mkLabel(bar, "日志同时写到程序目录的 netproxy.log", 400, 16)

	f.memo = vcl.NewMemo(ts)
	f.memo.SetParent(ts)
	f.memo.SetAlign(types.AlClient)
	f.memo.SetReadOnly(true)
	f.memo.SetScrollBars(types.SsBoth)
	f.memo.SetWantReturns(false)
}

func (f *TMainForm) buildChainTab(ts *vcl.TPanel) {

	bar := vcl.NewPanel(ts)
	bar.SetParent(ts)
	bar.SetAlign(types.AlBottom)
	bar.SetHeight(46)
	bar.SetBevelOuter(types.BvNone)

	mkButton(bar, "添加", 12, 8, 84, 30, func() { f.chainAdd() })
	mkButton(bar, "编辑", 104, 8, 84, 30, func() { f.chainEdit() })
	mkButton(bar, "删除", 196, 8, 84, 30, func() { f.chainDelete() })
	mkButton(bar, "上移", 288, 8, 72, 30, func() { f.chainMove(-1) })
	mkButton(bar, "下移", 368, 8, 72, 30, func() { f.chainMove(1) })
	mkButton(bar, "从 .bat 批量导入", 448, 8, 150, 30, func() { f.chainImportBats() })
	mkLabel(bar, "一条链 = 一个 gost 子进程（-L 本地监听 + -F 上游）；规则按链名引用它", 610, 16)

	f.gridChain = mkGrid(ts, []colSpec{
		{"链名", 110}, {"上游（凭据已遮蔽）", 340}, {"本地 socks5（可选）", 170}, {"说明", 260},
	})
	f.loadChains()
}

func (f *TMainForm) buildRuleTab(ts *vcl.TPanel) {

	bar := vcl.NewPanel(ts)
	bar.SetParent(ts)
	bar.SetAlign(types.AlBottom)
	bar.SetHeight(46)
	bar.SetBevelOuter(types.BvNone)

	mkButton(bar, "添加", 12, 8, 84, 30, func() { f.ruleAdd() })
	mkButton(bar, "编辑", 104, 8, 84, 30, func() { f.ruleEdit() })
	mkButton(bar, "删除", 196, 8, 84, 30, func() { f.ruleDelete() })
	mkButton(bar, "上移", 288, 8, 72, 30, func() { f.ruleMove(-1) })
	mkButton(bar, "下移", 368, 8, 72, 30, func() { f.ruleMove(1) })
	mkButton(bar, "重新载入", 448, 8, 100, 30, func() { f.loadRules(); f.loadChains() })
	mkLabel(bar, "自上而下匹配，命中即停。改动即时保存，点顶部「重启服务」生效", 560, 16)

	f.gridRule = mkGrid(ts, []colSpec{
		{"#", 50}, {"目标 IP / CIDR", 260}, {"走哪条链", 140}, {"说明（该链备注）", 420},
	})
	f.loadRules()
}

func (f *TMainForm) buildSettingsTab(ts *vcl.TPanel) {

	// 底部按钮条
	bar := vcl.NewPanel(ts)
	bar.SetParent(ts)
	bar.SetAlign(types.AlBottom)
	bar.SetHeight(50)
	bar.SetBevelOuter(types.BvNone)
	mkButton(bar, "保存设置", 12, 10, 110, 30, func() { f.onSaveSettings() })
	mkButton(bar, "保存并重启", 132, 10, 120, 30, func() { go f.saveThenRestart() })
	mkLabel(bar, "gost 托管 / relay 的改动需要重启服务才生效", 270, 18)

	y := int32(14)

	// ── 1. gost 托管 ──
	mkSection(ts, "gost 链路托管", y)
	y += 26
	f.cbGostOn = vcl.NewCheckBox(ts)
	f.cbGostOn.SetParent(ts)
	f.cbGostOn.SetLeft(24)
	f.cbGostOn.SetTop(y)
	f.cbGostOn.SetWidth(660)
	f.cbGostOn.SetCaption("由本程序托管 gost 子进程（关掉则假定外部已有 socks5 在监听）")
	y += 28

	mkLabel2(ts, "gost.exe 路径", 24, y, 110)
	f.eGostExe = mkEdit(ts, 140, y-2, 560)
	mkButton(ts, "浏览…", 712, y-4, 90, 28, func() { f.browseGostExe() })
	y += 34

	mkLabel2(ts, "relay 监听", 24, y, 110)
	f.eRelay = mkEdit(ts, 140, y-2, 200)
	mkLabel(ts, "端口写 0 = 自动分配（推荐）", 352, y+2)
	y += 40

	// ── 2. hosts ──
	mkSection(ts, "系统 hosts 接管", y)
	y += 26
	f.cbHosts = vcl.NewCheckBox(ts)
	f.cbHosts.SetParent(ts)
	f.cbHosts.SetLeft(24)
	f.cbHosts.SetTop(y)
	f.cbHosts.SetWidth(700)
	f.cbHosts.SetCaption("由本程序维护 hosts 里的内网域名映射（写入标记区块，保留你的手写内容）")
	y += 28

	f.memoHosts = vcl.NewMemo(ts)
	f.memoHosts.SetParent(ts)
	f.memoHosts.SetLeft(140)
	f.memoHosts.SetTop(y)
	f.memoHosts.SetWidth(560)
	f.memoHosts.SetHeight(110)
	f.memoHosts.SetScrollBars(types.SsBoth)
	mkLabel2(ts, "映射条目", 24, y, 110)
	mkButton(ts, "立即写入 hosts", 712, y, 130, 28, func() { f.hostsApplyNow() })
	mkButton(ts, "移除标记区块", 712, y+34, 130, 28, func() { f.hostsRemoveNow() })
	mkButton(ts, "从文件重新载入", 712, y+68, 130, 28, func() { f.hostsReload() })
	y += 118

	f.lblHostsInfo = mkLabel(ts, "", 24, y)
	f.lblHostsInfo.SetWidth(820)
	y += 32

	// ── 3. 开机自启 ──
	mkSection(ts, "开机自启", y)
	y += 26
	f.cbAutostart = vcl.NewCheckBox(ts)
	f.cbAutostart.SetParent(ts)
	f.cbAutostart.SetLeft(24)
	f.cbAutostart.SetTop(y)
	f.cbAutostart.SetWidth(820)
	f.cbAutostart.SetCaption("开机自动启动（计划任务 + 最高权限：登录后静默启动，不弹 UAC）")
	y += 28

	f.lblAutoInfo = mkLabel(ts, "", 24, y)
	f.lblAutoInfo.SetWidth(820)
	y += 32

	// ── 4. 文件 ──
	mkSection(ts, "文件位置", y)
	y += 26
	f.lblCfgPath = mkLabel(ts, "", 24, y)
	f.lblCfgPath.SetWidth(820)
	y += 28
	mkButton(ts, "打开配置文件", 24, y, 130, 28, func() { f.openPath(f.a.Cfg.Path()) })
	mkButton(ts, "打开程序目录", 164, y, 130, 28, func() { f.openPath(dirOf(f.a.Cfg.Path())) })
	mkButton(ts, "打开日志目录", 304, y, 130, 28, func() { f.openPath(dirOf(f.a.Bus.FilePath())) })

	// 先把当前状态灌进控件，再绑事件（避免 setter 触发已绑的 OnClick 又回写一遍）
	f.loadSettings()
	f.bindSettingsEvents()
}

// ───────────────────────── 小控件工厂 ─────────────────────────

type colSpec struct {
	title string
	width int32
}

func mkGrid(owner vcl.IWinControl, cols []colSpec) *vcl.TStringGrid {
	g := vcl.NewStringGrid(owner)
	g.SetParent(owner)
	g.SetAlign(types.AlClient)
	g.SetColCount(int32(len(cols)))
	g.SetFixedRows(1)
	g.SetRowCount(2)
	for i, c := range cols {
		g.SetColWidths(int32(i), c.width)
		g.SetCells(int32(i), 0, c.title)
	}
	g.SetOptions(g.Options().Include(types.GoRowSelect).Include(types.GoVertLine).Include(types.GoHorzLine))
	return g
}

func mkButton(owner vcl.IWinControl, caption string, left, top, width, height int32, fn func()) *vcl.TButton {
	b := vcl.NewButton(owner)
	b.SetParent(owner)
	b.SetLeft(left)
	b.SetTop(top)
	b.SetWidth(width)
	b.SetHeight(height)
	b.SetCaption(caption)
	if fn != nil {
		b.SetOnClick(func(vcl.IObject) { fn() })
	}
	return b
}

func mkLabel(owner vcl.IWinControl, text string, left, top int32) *vcl.TLabel {
	l := vcl.NewLabel(owner)
	l.SetParent(owner)
	l.SetLeft(left)
	l.SetTop(top)
	l.SetCaption(text)
	return l
}

// mkLabel2 带固定宽度的字段名标签。
func mkLabel2(owner vcl.IWinControl, text string, left, top, width int32) *vcl.TLabel {
	l := mkLabel(owner, text, left, top)
	l.SetWidth(width)
	return l
}

// mkSection 分组标题。
func mkSection(owner vcl.IWinControl, title string, top int32) {
	l := mkLabel(owner, "── "+title+" ──", 16, top)
	l.SetWidth(870)
}

func mkEdit(owner vcl.IWinControl, left, top, width int32) *vcl.TEdit {
	e := vcl.NewEdit(owner)
	e.SetParent(owner)
	e.SetLeft(left)
	e.SetTop(top)
	e.SetWidth(width)
	e.SetHeight(24)
	return e
}

// ───────────────────────── 日志与状态 ─────────────────────────

func (f *TMainForm) pumpLog() {
	for l := range f.logSub {
		vcl.ThreadSync(func() {
			f.memo.Lines().Add(l.String())
			f.lines++
			if f.lines > 1500 { // 控制内存：超量就清空重来
				f.memo.Lines().Clear()
				f.lines = 0
			}
		})
	}
}

func (f *TMainForm) pumpStatus() {
	for {
		time.Sleep(2 * time.Second)
		vcl.ThreadSync(func() { f.refreshStatus() })
	}
}

func (f *TMainForm) refreshStatus() {
	total, active := f.a.Engine.Stats()
	state := "未启动"
	if f.a.Running() {
		state = "运行中"
	}
	pid := "-"
	if ps := f.a.Gost.PIDs(); len(ps) > 0 {
		ss := make([]string, 0, len(ps))
		for _, p := range ps {
			ss = append(ss, fmt.Sprintf("%d", p))
		}
		pid = strings.Join(ss, ",")
	}
	relay := f.a.Engine.RelayAddr()
	if relay == "" {
		relay = "-"
	}
	f.lblStat.SetCaption(fmt.Sprintf(
		"状态：%s    relay：%s    gost PID：%s    累计连接：%d    活跃：%d",
		state, relay, pid, total, active))
	if f.a.Running() {
		f.btnRun.SetCaption("停止服务")
	} else {
		f.btnRun.SetCaption("启动服务")
	}
}

// ───────────────────────── 启停动作 ─────────────────────────

func (f *TMainForm) onToggle() {
	if f.a.Running() {
		go f.doStop()
	} else {
		go f.doStart()
	}
}

func (f *TMainForm) doStart() {
	if err := f.a.Start(); err != nil {
		f.balloon("启动失败", err.Error(), types.BfError)
	}
}

func (f *TMainForm) doStop() { f.a.Stop() }

func (f *TMainForm) doRestart() {
	if err := f.a.Restart(); err != nil {
		f.balloon("重启失败", err.Error(), types.BfError)
	}
}

// ───────────────────────── 隧道链路：增删改排序 ─────────────────────────

func (f *TMainForm) loadChains() {
	n := int32(len(f.a.Cfg.Chains)) + 1
	if n < 2 {
		n = 2
	}
	f.gridChain.SetRowCount(n)
	for i, c := range f.a.Cfg.Chains {
		r := int32(i) + 1
		f.gridChain.SetCells(0, r, c.Name)
		f.gridChain.SetCells(1, r, c.Listen)
		f.gridChain.SetCells(2, r, gostproc.Redact(c.Forward))
		f.gridChain.SetCells(3, r, c.Note)
	}
	for r := int32(len(f.a.Cfg.Chains)) + 1; r < f.gridChain.RowCount(); r++ {
		for c := int32(0); c < f.gridChain.ColCount(); c++ {
			f.gridChain.SetCells(c, r, "")
		}
	}
}

// selectedChainIdx 当前选中的链路下标，未选中返回 -1。
func (f *TMainForm) selectedChainIdx() int {
	r := int(f.gridChain.Row()) - 1
	if r < 0 || r >= len(f.a.Cfg.Chains) {
		return -1
	}
	return r
}

func (f *TMainForm) selectedRuleIdx() int {
	r := int(f.gridRule.Row()) - 1
	if r < 0 || r >= len(f.a.Cfg.Routes) {
		return -1
	}
	return r
}

func (f *TMainForm) chainAdd() {
	def := config.Chain{Listen: fmt.Sprintf("127.0.0.1:%d", f.freePort(1082))}
	ch, ok := EditChainDialog(true, def, f.a.Cfg.Chains)
	if !ok {
		return
	}
	if err := f.a.Cfg.AddChain(ch); err != nil {
		vcl.ShowMessage("添加失败：\r\n" + err.Error())
		return
	}
	f.afterEdit(fmt.Sprintf("已添加链 %s（%s）", ch.Name, ch.Listen), "隧道链路")
}

func (f *TMainForm) chainEdit() {
	i := f.selectedChainIdx()
	if i < 0 {
		vcl.ShowMessage("请先在列表里选中一条链（第一行是表头）")
		return
	}
	old := f.a.Cfg.Chains[i]
	ch, ok := EditChainDialog(false, old, f.a.Cfg.Chains)
	if !ok {
		return
	}
	if err := f.a.Cfg.UpdateChain(old.Name, ch); err != nil {
		vcl.ShowMessage("保存失败：\r\n" + err.Error())
		return
	}
	f.afterEdit(fmt.Sprintf("已更新链 %s", ch.Name), "隧道链路")
}

func (f *TMainForm) chainDelete() {
	i := f.selectedChainIdx()
	if i < 0 {
		vcl.ShowMessage("请先选中一条链")
		return
	}
	ch := f.a.Cfg.Chains[i]
	if vcl.MessageDlg(fmt.Sprintf("确定删除链 %q 吗？", ch.Name), types.MtConfirmation,
		uint8(types.MbYes), uint8(types.MbNo)) != types.IdYes {
		return
	}
	if err := f.a.Cfg.RemoveChain(ch.Name); err != nil {
		vcl.ShowMessage("删除失败：\r\n" + err.Error())
		return
	}
	f.afterEdit("已删除链 "+ch.Name, "隧道链路")
}

func (f *TMainForm) chainMove(delta int) {
	i := f.selectedChainIdx()
	if i < 0 {
		vcl.ShowMessage("请先选中一条链")
		return
	}
	if err := f.a.Cfg.MoveChain(i, i+delta); err != nil {
		return
	}
	f.afterEdit("已调整链顺序", "隧道链路")
	f.gridChain.SetRow(int32(i + delta + 1))
}

// chainImportBats 选一个目录，把里面所有 gost .bat 批量加为链（已存在同名/同端口的跳过）。
func (f *TMainForm) chainImportBats() {
	dir := f.pickDir()
	if dir == "" {
		return
	}
	got := gostproc.ScanBatDir(dir)
	if len(got) == 0 {
		vcl.ShowMessage("这个目录里没找到含成对 -L/-F 的 gost 批处理：\r\n" + dir)
		return
	}
	added, skipped := 0, 0
	var msgs []string
	for _, be := range got {
		name := chainNameFromBat(be.File)
		if f.a.Cfg.FindChain(name) >= 0 {
			// 同名链已存在：只更新它的上游（这是最常见的"换了服务器"场景）
			idx := f.a.Cfg.FindChain(name)
			old := f.a.Cfg.Chains[idx]
			ch := old
			ch.Listen = be.Listen
			ch.Forward = be.Forward
			if err := f.a.Cfg.UpdateChain(old.Name, ch); err != nil {
				msgs = append(msgs, fmt.Sprintf("%s: 更新失败 %v", name, err))
				skipped++
				continue
			}
			msgs = append(msgs, fmt.Sprintf("%s: 已更新上游（来自 %s）", name, be.File))
			added++
			continue
		}
		if err := f.a.Cfg.AddChain(config.Chain{
			Name: name, Listen: be.Listen, Forward: be.Forward,
			Note: "从 " + be.File + " 导入",
		}); err != nil {
			msgs = append(msgs, fmt.Sprintf("%s: 跳过（%v）", name, err))
			skipped++
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s: 已新增（%s）", name, be.Listen))
		added++
	}
	f.afterEdit(fmt.Sprintf("从 .bat 导入：新增/更新 %d 条，跳过 %d 条", added, skipped), "隧道链路")
	vcl.ShowMessage(strings.Join(msgs, "\r\n"))
}

// pickDir 选目录（govcl 的 SelectDirectory1 参数不好用，这里自己调 SHBrowseForFolder 太麻烦，
// 改用 OpenDialog 让用户进目录随便选个文件再取它的目录）。
func (f *TMainForm) pickDir() string {
	od := vcl.NewOpenDialog(f)
	defer od.Free()
	od.SetTitle("进入 gost 脚本所在目录，随便选一个 .bat 文件即可（只取目录）")
	od.SetFilter("gost 批处理 (*.bat)|*.bat|所有文件 (*.*)|*.*")
	if !od.Execute() {
		return ""
	}
	p := od.FileName()
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return ""
}

// freePort 从 start 开始找一个没被占用的本地端口，给"添加链路"当默认值。
func (f *TMainForm) freePort(start int) int {
	for p := start; p < start+50; p++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			l.Close()
			return p
		}
	}
	return start
}

// ───────────────────────── 路由规则：增删改排序 ─────────────────────────

func (f *TMainForm) loadRules() {
	n := int32(len(f.a.Cfg.Routes)) + 1
	if n < 2 {
		n = 2
	}
	f.gridRule.SetRowCount(n)
	note := map[string]string{}
	for _, c := range f.a.Cfg.Chains {
		note[c.Name] = c.Note
	}
	for i, r := range f.a.Cfg.Routes {
		row := int32(i) + 1
		f.gridRule.SetCells(0, row, fmt.Sprintf("%d", i+1))
		f.gridRule.SetCells(1, row, r.Target)
		f.gridRule.SetCells(2, row, r.Chain)
		f.gridRule.SetCells(3, row, note[r.Chain])
	}
	for row := int32(len(f.a.Cfg.Routes)) + 1; row < f.gridRule.RowCount(); row++ {
		for c := int32(0); c < f.gridRule.ColCount(); c++ {
			f.gridRule.SetCells(c, row, "")
		}
	}
}

// takenTargets 已经被别的规则占用的目标（排除 skip 下标）。
func (f *TMainForm) takenTargets(skip int) []string {
	var out []string
	for i, r := range f.a.Cfg.Routes {
		if i == skip {
			continue
		}
		out = append(out, r.Target)
	}
	return out
}

func (f *TMainForm) ruleAdd() {
	if len(f.a.Cfg.Chains) == 0 {
		vcl.ShowMessage("还没有任何链，请先到「隧道链路」页添加一条")
		return
	}
	rt, ok := EditRouteDialog(true, config.Route{Chain: f.a.Cfg.Chains[0].Name},
		f.a.Cfg.Chains, f.takenTargets(-1))
	if !ok {
		return
	}
	if err := f.a.Cfg.AddRoute(rt); err != nil {
		vcl.ShowMessage("添加失败：\r\n" + err.Error())
		return
	}
	f.afterEdit(fmt.Sprintf("已添加规则 %s → %s", rt.Target, rt.Chain), "路由规则")
}

func (f *TMainForm) ruleEdit() {
	i := f.selectedRuleIdx()
	if i < 0 {
		vcl.ShowMessage("请先在列表里选中一条规则（第一行是表头）")
		return
	}
	rt, ok := EditRouteDialog(false, f.a.Cfg.Routes[i], f.a.Cfg.Chains, f.takenTargets(i))
	if !ok {
		return
	}
	if err := f.a.Cfg.UpdateRoute(i, rt); err != nil {
		vcl.ShowMessage("保存失败：\r\n" + err.Error())
		return
	}
	f.afterEdit(fmt.Sprintf("已更新规则 %s → %s", rt.Target, rt.Chain), "路由规则")
}

func (f *TMainForm) ruleDelete() {
	i := f.selectedRuleIdx()
	if i < 0 {
		vcl.ShowMessage("请先选中一条规则")
		return
	}
	r := f.a.Cfg.Routes[i]
	if vcl.MessageDlg(fmt.Sprintf("确定删除规则 %s → %s 吗？", r.Target, r.Chain), types.MtConfirmation,
		uint8(types.MbYes), uint8(types.MbNo)) != types.IdYes {
		return
	}
	if err := f.a.Cfg.RemoveRoute(i); err != nil {
		vcl.ShowMessage("删除失败：\r\n" + err.Error())
		return
	}
	f.afterEdit("已删除规则 "+r.Target, "路由规则")
}

func (f *TMainForm) ruleMove(delta int) {
	i := f.selectedRuleIdx()
	if i < 0 {
		vcl.ShowMessage("请先选中一条规则")
		return
	}
	if err := f.a.Cfg.MoveRoute(i, i+delta); err != nil {
		return
	}
	f.afterEdit("已调整规则顺序", "路由规则")
	f.gridRule.SetRow(int32(i + delta + 1))
}

// ───────────────────────── 设置 ─────────────────────────

func (f *TMainForm) loadSettings() {
	f.cbGostOn.SetChecked(f.a.Cfg.Gost.Enabled)
	f.eGostExe.SetText(f.a.Cfg.Gost.Exe)
	f.eRelay.SetText(f.a.Cfg.Relay)

	f.cbHosts.SetChecked(f.a.Cfg.Hosts.Manage)
	f.hostsReload()

	f.cbAutostart.SetChecked(autostart.Enabled())
	f.refreshAutoInfo()
	f.lblCfgPath.SetCaption("配置文件：" + f.a.Cfg.Path())
}

func (f *TMainForm) bindSettingsEvents() {
	f.cbAutostart.SetOnClick(func(vcl.IObject) { f.applyAutostart() })
}

func (f *TMainForm) refreshAutoInfo() {
	if autostart.Enabled() {
		f.lblAutoInfo.SetCaption("当前：已安装计划任务「" + autostart.TaskName + "」" + autostart.Detail())
	} else {
		f.lblAutoInfo.SetCaption("当前：未设置开机自启")
	}
}

// applyAutostart 勾选框一变就立即生效（这是系统级设置，不该等"保存"）。
func (f *TMainForm) applyAutostart() {
	want := f.cbAutostart.Checked()
	var err error
	if want {
		err = autostart.Enable()
	} else {
		err = autostart.Disable()
	}
	if err != nil {
		vcl.ShowMessage("设置开机自启失败：\r\n" + err.Error())
		f.cbAutostart.SetChecked(!want) // 回滚勾选状态
		f.refreshAutoInfo()
		return
	}
	f.refreshAutoInfo()
	if want {
		f.a.Bus.Info("已设置开机自启（计划任务 %s，最高权限）", autostart.TaskName)
		f.balloon("已设置开机自启", "下次登录后延迟 20 秒静默启动，不会弹 UAC", types.BfInfo)
	} else {
		f.a.Bus.Info("已取消开机自启")
	}
}

// hostsReload 把当前 hosts 里的标记区块（没有就填内置默认）灌进编辑框。
func (f *TMainForm) hostsReload() {
	block, exists, _, err := hostsmgr.Read()
	if err != nil {
		f.lblHostsInfo.SetCaption("读取 hosts 失败：" + err.Error())
		return
	}
	entries := f.a.Cfg.Hosts.Entries
	if len(entries) == 0 {
		entries = block
	}
	if len(entries) == 0 {
		entries = defaultHostsEntries
	}
	f.memoHosts.Lines().SetText(strings.Join(entries, "\r\n"))
	f.refreshHostsInfo(exists)
}

func (f *TMainForm) refreshHostsInfo(managed bool) {
	st := "未写入标记区块"
	if managed {
		st = "标记区块已存在"
	}
	f.lblHostsInfo.SetCaption(fmt.Sprintf("%s        当前状态：%s        托管开关：%s",
		hostsmgr.Path(), st, onOff(f.a.Cfg.Hosts.Manage)))
}

func (f *TMainForm) memoHostsEntries() []string {
	var out []string
	for _, l := range strings.Split(f.memoHosts.Lines().Text(), "\n") {
		l = strings.TrimSpace(strings.TrimRight(l, "\r"))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func (f *TMainForm) hostsApplyNow() {
	entries := f.memoHostsEntries()
	if len(entries) == 0 {
		vcl.ShowMessage("条目是空的，没什么可写的")
		return
	}
	if err := hostsmgr.Apply(entries); err != nil {
		vcl.ShowMessage("写 hosts 失败：\r\n" + err.Error())
		return
	}
	f.a.Cfg.Hosts.Entries = entries
	f.a.Cfg.Hosts.Manage = true
	f.cbHosts.SetChecked(true)
	_ = f.a.SaveConfig()
	f.a.Bus.Info("hosts 已写入 %d 条映射", len(entries))
	f.refreshHostsInfo(true)
	f.balloon("hosts 已更新", fmt.Sprintf("%d 条内网域名映射已写入", len(entries)), types.BfInfo)
}

func (f *TMainForm) hostsRemoveNow() {
	if err := hostsmgr.Remove(); err != nil {
		vcl.ShowMessage("移除失败：\r\n" + err.Error())
		return
	}
	f.a.Cfg.Hosts.Manage = false
	f.cbHosts.SetChecked(false)
	_ = f.a.SaveConfig()
	f.a.Bus.Info("已从 hosts 移除本程序的标记区块")
	f.refreshHostsInfo(false)
}

// onSaveSettings 把设置页的输入写进配置并落盘。
func (f *TMainForm) onSaveSettings() {
	cfg := f.a.Cfg
	oldGost, oldRelay, oldHosts := cfg.Gost.Enabled, cfg.Relay, cfg.Hosts.Manage

	cfg.Gost.Enabled = f.cbGostOn.Checked()
	cfg.Gost.Exe = strings.TrimSpace(f.eGostExe.Text())
	cfg.Relay = strings.TrimSpace(f.eRelay.Text())
	cfg.Hosts.Manage = f.cbHosts.Checked()
	if e := f.memoHostsEntries(); len(e) > 0 {
		cfg.Hosts.Entries = e
	}

	if err := f.a.SaveConfig(); err != nil {
		cfg.Gost.Enabled, cfg.Relay, cfg.Hosts.Manage = oldGost, oldRelay, oldHosts
		vcl.ShowMessage("保存失败：\r\n" + err.Error())
		return
	}
	f.a.Bus.Info("设置已保存（gost 托管=%v，relay=%s，hosts 托管=%v）",
		cfg.Gost.Enabled, cfg.Relay, cfg.Hosts.Manage)
	f.balloon("设置已保存", "gost 托管 / relay 的改动需要重启服务才生效", types.BfInfo)
}

func (f *TMainForm) saveThenRestart() {
	f.onSaveSettings()
	f.doRestart()
}

func (f *TMainForm) browseGostExe() {
	od := vcl.NewOpenDialog(f)
	defer od.Free()
	od.SetTitle("选择 gost.exe")
	od.SetFilter("gost.exe|gost.exe|可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*")
	if !od.Execute() {
		return
	}
	f.eGostExe.SetText(od.FileName())
}

// ───────────────────────── 链路自检 ─────────────────────────

// chainSelfTest 对每条链做端到端探测：本地 socks5 通不通 + 经它能不能真的连到内网目标。
// 走的是 gost 的本地监听（不经过 WinDivert），所以它能单独验证"链路"这一段。
func (f *TMainForm) chainSelfTest() {
	chains := append([]config.Chain(nil), f.a.Cfg.Chains...)
	routes := append([]config.Route(nil), f.a.Cfg.Routes...)
	if len(chains) == 0 {
		vcl.ShowMessage("还没有配置任何链")
		return
	}
	go func() {
		f.a.Bus.Info("=== 链路自检开始（%d 条链）===", len(chains))
		bad := 0
		for _, ch := range chains {
			c, err := net.DialTimeout("tcp", ch.Listen, 2*time.Second)
			if err != nil {
				f.a.Bus.Error("[%s] 本地 socks5 %s 连不上：%v", ch.Name, ch.Listen, err)
				bad++
				continue
			}
			c.Close()
			f.a.Bus.Info("[%s] 本地 socks5 %s 正常", ch.Name, ch.Listen)

			target := ""
			for _, r := range routes {
				if r.Chain == ch.Name {
					target = r.Target
					break
				}
			}
			if target == "" {
				f.a.Bus.Warn("[%s] 没有规则指向它，跳过端到端探测", ch.Name)
				continue
			}
			ip, _, err := net.ParseCIDR(target)
			var v4 net.IP
			if err == nil {
				v4 = ip.To4()
			} else if p := net.ParseIP(target); p != nil {
				v4 = p.To4()
			}
			if v4 == nil {
				f.a.Bus.Warn("[%s] 规则目标 %s 解析不出 IPv4，跳过", ch.Name, target)
				continue
			}

			hit := 0
			for _, port := range []uint16{443, 80, 5432, 6446, 5000, 9056} {
				conn, derr := socks.Dial(ch.Listen, v4, port, 2500*time.Millisecond)
				if derr == nil {
					conn.Close()
					hit = int(port)
					break
				}
			}
			if hit > 0 {
				f.a.Bus.Info("[%s] ✓ 端到端可达：经 %s 到 %s:%d", ch.Name, ch.Listen, v4, hit)
			} else {
				f.a.Bus.Error("[%s] ✗ 本地端口通，但经该链连不上 %s 的任何常见端口（上游挂了？上游限制了目标？）",
					ch.Name, v4)
				bad++
			}
		}
		if bad == 0 {
			f.a.Bus.Info("=== 链路自检通过：%d 条链全部可用 ===", len(chains))
			f.balloon("链路自检通过", fmt.Sprintf("%d 条链全部可用", len(chains)), types.BfInfo)
		} else {
			f.a.Bus.Error("=== 链路自检结束：%d 条链有问题（详见上方日志）===", bad)
			f.balloon("链路自检有问题", fmt.Sprintf("%d 条链不可用，请看日志", bad), types.BfError)
		}
	}()
}

// ───────────────────────── 通用 ─────────────────────────

// afterEdit 编辑完成后的统一收尾：落盘 + 刷新界面 + 提示重启。
func (f *TMainForm) afterEdit(what string, page string) {
	if err := f.a.SaveConfig(); err != nil {
		vcl.ShowMessage("保存配置失败：\r\n" + err.Error())
		return
	}
	f.loadChains()
	f.loadRules()
	f.a.Bus.Info("%s（改动已保存到 %s）", what, page)
	if f.a.Running() {
		f.balloon(what, "已保存。内核拦截用的是启动时的规则，点「重启服务」生效。", types.BfWarning)
	}
}

// ───────────────────────── 主题 ─────────────────────────

// showTab 切换标签页。
func (f *TMainForm) showTab(idx int) {
	if len(f.tabPages) == 0 || idx < 0 || idx >= len(f.tabPages) {
		return
	}
	f.activeTab = idx
	for i, pg := range f.tabPages {
		pg.SetVisible(i == idx)
	}
	f.applyTheme()
}

// toggleTheme 深浅切换，并记住选择（写回 config.yaml 的 ui.theme）。
func (f *TMainForm) toggleTheme() {
	if f.a.Cfg.UI.Theme == "dark" {
		f.a.Cfg.UI.Theme = "light"
	} else {
		f.a.Cfg.UI.Theme = "dark"
	}
	if err := f.a.Cfg.Save(); err != nil {
		vcl.ShowMessage("主题偏好保存失败（不影响本次切换）：\r\n" + err.Error())
	}
	f.applyTheme()
}

// applyTheme 把当前主题刷到整棵控件树；标签条的选中态、文字层级在这里手动分档。
func (f *TMainForm) applyTheme() {
	th := ByName(f.a.Cfg.UI.Theme)
	CurrentTheme = th

	applyTheme(f.TForm, th) // 递归：底色 + 字体 + 网格线 + 深色标题栏

	// 工具条与标签条用次级底色，跟内容区分开
	if f.topBar != nil {
		f.topBar.SetColor(th.CanvasSoft)
	}
	if f.tabBar != nil {
		f.tabBar.SetColor(th.CanvasSoft)
	}

	// 标签条：选中 = 主色块 + 白字；未选中 = 次级底 + 次要字色
	for i, chip := range f.tabChips {
		if i >= len(f.chipLabels) {
			break
		}
		lbl := f.chipLabels[i]
		if i == f.activeTab {
			chip.SetColor(th.Primary)
			setFont(lbl.Font(), th, th.OnPrimary, false, false)
		} else {
			chip.SetColor(th.CanvasSoft)
			setFont(lbl.Font(), th, th.Muted, false, false)
		}
	}

	// 文字层级：分组标题用主墨色，其余正文；次要信息显式压暗
	var labels []*vcl.TLabel
	collectLabels(vcl.AsWinControl(f), &labels)
	for _, l := range labels {
		if strings.HasPrefix(l.Caption(), "── ") {
			setFont(l.Font(), th, th.Ink, false, true) // 分组标题用字重拉开层级
		}
	}
	for _, l := range []*vcl.TLabel{f.lblStat, f.lblHostsInfo, f.lblAutoInfo, f.lblCfgPath} {
		if l != nil {
			setFont(l.Font(), th, th.Muted, false, false)
		}
	}

	if f.btnTheme != nil {
		if th.Dark {
			f.btnTheme.SetCaption("浅色模式")
		} else {
			f.btnTheme.SetCaption("深色模式")
		}
	}
}

func collectLabels(w vcl.IWinControl, out *[]*vcl.TLabel) {
	if w == nil {
		return
	}
	for i := int32(0); i < w.ControlCount(); i++ {
		c := w.Controls(i)
		if l := vcl.AsLabel(c); l != nil {
			*out = append(*out, l)
		}
		if cw := vcl.AsWinControl(c); cw != nil {
			collectLabels(cw, out)
		}
	}
}

func (f *TMainForm) openPath(p string) {
	if p == "" {
		return
	}
	if err := exec.Command("explorer.exe", p).Start(); err != nil {
		vcl.ShowMessage("打开失败：" + err.Error())
	}
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return p
}

func onOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

// defaultHostsEntries 首次使用时的内置默认映射（与现网 hosts 一致）。
var defaultHostsEntries = []string{
	"10.0.0.10 app.example.com",
	"10.0.0.10 opm.example.com",
	"192.168.100.10 site-b.example.com",
	"192.168.100.10 site-c.example.com",
}

// ───────────────────────── 托盘与窗口 ─────────────────────────

// Balloon 弹系统通知（app.Notify 的回调实现）。
func (f *TMainForm) Balloon(title, text string, kind app.NotifyKind) {
	var fl types.TBalloonFlags = types.BfInfo
	switch kind {
	case app.NotifyWarn:
		fl = types.BfWarning
	case app.NotifyError:
		fl = types.BfError
	}
	f.balloon(title, text, fl)
}

func (f *TMainForm) balloon(title, text string, flags types.TBalloonFlags) {
	vcl.ThreadSync(func() {
		f.tray.SetBalloonTitle(title)
		f.tray.SetBalloonHint(text)
		f.tray.SetBalloonFlags(flags)
		f.tray.SetBalloonTimeout(8000)
		f.tray.ShowBalloonHint()
	})
}

func (f *TMainForm) showWindow() {
	vcl.ThreadSync(func() {
		f.SetVisible(true)
		f.Show()
		f.BringToFront()
	})
}

func (f *TMainForm) onCloseQuery(sender vcl.IObject, canClose *bool) {
	// 点关闭 = 收进托盘，服务继续跑；真退出走托盘菜单
	if !f.quitting {
		*canClose = false
		f.SetVisible(false)
		f.balloon("netproxy 仍在运行", "已最小化到托盘，双击托盘图标恢复窗口", types.BfInfo)
	}
}

func (f *TMainForm) quit() {
	f.quitting = true
	go func() {
		f.a.Stop()
		vcl.ThreadSync(func() {
			f.tray.SetVisible(false)
			vcl.Application.Terminate()
		})
	}()
}
