// Package gui 是 govcl 写的界面层：主窗口 + 系统托盘 + 系统通知。
//
// 通知走 Windows 原生的托盘气泡（Shell_NotifyIcon NIF_INFO）——
// 在 Win10/11 上它会被系统渲染成标准通知并进操作中心，不需要 WinRT。
package gui

import (
	"fmt"
	"strings"
	"time"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"

	"netproxy/internal/app"
	"netproxy/internal/config"
	"netproxy/internal/logbus"
)

type TMainForm struct {
	*vcl.TForm

	a       *app.App
	logSub  chan logbus.Line
	tray    *vcl.TTrayIcon
	lblStat *vcl.TLabel
	btnRun  *vcl.TButton
	memo    *vcl.TMemo
	grid    *vcl.TStringGrid // 规则
	gridCh  *vcl.TStringGrid // 链路

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
	f.SetWidth(940)
	f.SetHeight(640)
	f.SetOnCloseQuery(f.onCloseQuery)
	mark("窗口属性已设置")

	// 顶部工具条
	top := vcl.NewPanel(f)
	top.SetParent(f)
	top.SetAlign(types.AlTop)
	top.SetHeight(52)
	top.SetBevelOuter(types.BvNone)

	f.btnRun = vcl.NewButton(top)
	f.btnRun.SetParent(top)
	f.btnRun.SetLeft(12)
	f.btnRun.SetTop(11)
	f.btnRun.SetWidth(110)
	f.btnRun.SetHeight(30)
	f.btnRun.SetCaption("启动服务")
	f.btnRun.SetOnClick(func(vcl.IObject) { f.onToggle() })

	btnRe := vcl.NewButton(top)
	btnRe.SetParent(top)
	btnRe.SetLeft(132)
	btnRe.SetTop(11)
	btnRe.SetWidth(110)
	btnRe.SetHeight(30)
	btnRe.SetCaption("重启服务")
	btnRe.SetOnClick(func(vcl.IObject) { go f.doRestart() })

	btnSave := vcl.NewButton(top)
	btnSave.SetParent(top)
	btnSave.SetLeft(252)
	btnSave.SetTop(11)
	btnSave.SetWidth(110)
	btnSave.SetHeight(30)
	btnSave.SetCaption("保存配置")
	btnSave.SetOnClick(func(vcl.IObject) { f.onSave() })

	f.lblStat = vcl.NewLabel(top)
	f.lblStat.SetParent(top)
	f.lblStat.SetLeft(378)
	f.lblStat.SetTop(18)
	f.lblStat.SetWidth(540)
	f.lblStat.SetCaption("状态：未启动")
	mark("顶部工具条")

	// 主体
	pc := vcl.NewPageControl(f)
	pc.SetParent(f)
	pc.SetAlign(types.AlClient)

	// —— 日志页 ——
	tsLog := pc.AddTabSheet()
	tsLog.SetCaption("运行日志")
	f.memo = vcl.NewMemo(tsLog)
	f.memo.SetParent(tsLog)
	f.memo.SetAlign(types.AlClient)
	f.memo.SetReadOnly(true)
	f.memo.SetScrollBars(types.SsBoth)
	f.memo.SetWantReturns(false)

	// —— 规则页 ——
	tsRule := pc.AddTabSheet()
	tsRule.SetCaption("路由规则")
	pnl := vcl.NewPanel(tsRule)
	pnl.SetParent(tsRule)
	pnl.SetAlign(types.AlBottom)
	pnl.SetHeight(46)
	pnl.SetBevelOuter(types.BvNone)

	mkBtn := func(left int32, cap string, fn func()) {
		b := vcl.NewButton(pnl)
		b.SetParent(pnl)
		b.SetLeft(left)
		b.SetTop(8)
		b.SetWidth(120)
		b.SetHeight(30)
		b.SetCaption(cap)
		b.SetOnClick(func(vcl.IObject) { fn() })
	}
	mkBtn(12, "添加一行", func() { f.addRuleRow() })
	mkBtn(142, "删除选中行", func() { f.deleteSelectedRow() })
	mkBtn(272, "保存并生效", func() { f.onSave() })

	hint := vcl.NewLabel(pnl)
	hint.SetParent(pnl)
	hint.SetLeft(408)
	hint.SetTop(16)
	hint.SetWidth(500)
	hint.SetCaption("目标支持 IP 或 CIDR；自上而下匹配，命中即停。改完点「保存并生效」。")

	f.grid = vcl.NewStringGrid(tsRule)
	f.grid.SetParent(tsRule)
	f.grid.SetAlign(types.AlClient)
	f.grid.SetColCount(2)
	f.grid.SetFixedRows(1)
	f.grid.SetRowCount(2)
	f.grid.SetColWidths(0, 340)
	f.grid.SetColWidths(1, 200)
	f.grid.SetCells(0, 0, "目标 IP / CIDR")
	f.grid.SetCells(1, 0, "走哪条链")
	f.loadRules()

	// —— 链路页 ——
	tsCh := pc.AddTabSheet()
	tsCh.SetCaption("隧道链路")
	f.gridCh = vcl.NewStringGrid(tsCh)
	f.gridCh.SetParent(tsCh)
	f.gridCh.SetAlign(types.AlClient)
	f.gridCh.SetColCount(4)
	f.gridCh.SetFixedRows(1)
	f.gridCh.SetRowCount(2)
	f.gridCh.SetColWidths(0, 110)
	f.gridCh.SetColWidths(1, 180)
	f.gridCh.SetColWidths(2, 300)
	f.gridCh.SetColWidths(3, 320)
	f.gridCh.SetCells(0, 0, "链名")
	f.gridCh.SetCells(1, 0, "本地 socks5")
	f.gridCh.SetCells(2, 0, "上游转发（凭据已遮蔽）")
	f.gridCh.SetCells(3, 0, "说明")
	f.loadChains()

	pc.SetActivePageIndex(0)
	mark("日志页/规则页/链路页")

	// 托盘 + 系统通知
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
	if p := f.a.Gost.PID(); p > 0 {
		pid = fmt.Sprintf("%d", p)
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

// ───────────────────────── 动作 ─────────────────────────

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

func (f *TMainForm) onSave() {
	var rows []config.Route
	for r := int32(1); r < f.grid.RowCount(); r++ {
		t := strings.TrimSpace(f.grid.Cells(0, r))
		c := strings.TrimSpace(f.grid.Cells(1, r))
		if t == "" && c == "" {
			continue
		}
		rows = append(rows, config.Route{Target: t, Chain: c})
	}
	saved := append([]config.Route(nil), f.a.Cfg.Routes...)
	f.a.Cfg.Routes = rows
	if err := f.a.SaveConfig(); err != nil {
		f.a.Cfg.Routes = saved // 回滚
		f.balloon("配置保存失败", err.Error(), types.BfError)
		return
	}
	f.a.Bus.Info("配置已保存并生效（%d 条规则）", len(f.a.Cfg.Routes))
	f.balloon("配置已保存",
		fmt.Sprintf("%d 条规则已生效；内核过滤器需重启服务才更新", len(f.a.Cfg.Routes)), types.BfInfo)
}

func (f *TMainForm) addRuleRow() {
	r := f.grid.RowCount()
	f.grid.SetRowCount(r + 1)
	f.grid.SetCells(0, r, "10.0.0.0/8")
	f.grid.SetCells(1, r, f.firstChain())
}

func (f *TMainForm) deleteSelectedRow() {
	r := f.grid.Row()
	if r < 1 {
		f.balloon("无法删除", "请先选中一行数据行（第一行是表头）", types.BfWarning)
		return
	}
	for i := r; i < f.grid.RowCount()-1; i++ {
		f.grid.SetCells(0, i, f.grid.Cells(0, i+1))
		f.grid.SetCells(1, i, f.grid.Cells(1, i+1))
	}
	f.grid.SetRowCount(f.grid.RowCount() - 1)
}

func (f *TMainForm) loadRules() {
	n := int32(len(f.a.Cfg.Routes)) + 1
	if n < 2 {
		n = 2
	}
	f.grid.SetRowCount(n)
	for i, r := range f.a.Cfg.Routes {
		f.grid.SetCells(0, int32(i)+1, r.Target)
		f.grid.SetCells(1, int32(i)+1, r.Chain)
	}
}

func (f *TMainForm) loadChains() {
	n := int32(len(f.a.Cfg.Chains)) + 1
	if n < 2 {
		n = 2
	}
	f.gridCh.SetRowCount(n)
	for i, c := range f.a.Cfg.Chains {
		r := int32(i) + 1
		f.gridCh.SetCells(0, r, c.Name)
		f.gridCh.SetCells(1, r, c.Listen)
		f.gridCh.SetCells(2, r, redact(c.Forward))
		f.gridCh.SetCells(3, r, c.Note)
	}
}

func (f *TMainForm) firstChain() string {
	if len(f.a.Cfg.Chains) > 0 {
		return f.a.Cfg.Chains[0].Name
	}
	return ""
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

// redact 遮蔽上游 URL 里的凭据，界面上只显示到域名/端口。
func redact(s string) string {
	if s == "" {
		return "(未配置)"
	}
	if i := strings.Index(s, "auth="); i >= 0 {
		return s[:i] + "auth=***"
	}
	if at := strings.Index(s, "@"); at >= 0 {
		if sl := strings.Index(s, "://"); sl >= 0 && sl+3 < at {
			return s[:sl+3] + "***@" + s[at+1:]
		}
	}
	return s
}
