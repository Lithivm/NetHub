package webui

import ()

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
