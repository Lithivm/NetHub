package main

// 界面进程（-frontend）与它的看护者。
//
// 为什么要拆：现场机器上装着的 HIS/医保客户端启动器，在清理自己 WebView2 缓存时会
// **按进程名杀掉全系统所有 msedgewebview2.exe**（反编译 DF.HIS.Launcher.exe 的
// WebMainForm.DelectCache 实证），而界面就是 Wails/WebView2 应用 —— 首当其冲；
// 更糟的是 Wails 在浏览器进程消失后直接 os.Exit(-1)、跳过所有收尾。界面只要跟引擎
// 同进程，引擎就被连坐（现场表现：NetHub 整个静默消失、hosts 段留在系统里没人兑付）。
//
// 拆开之后：被杀的只有界面进程。引擎照跑、隧道不断、hosts 一直有效（它还在兑付），
// 而看护循环会在几秒内把界面重新拉起来。详见 internal/ipc 的包注释。

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wopts "github.com/wailsapp/wails/v2/pkg/options/windows"

	"nethub/internal/ipc"
	"nethub/internal/logbus"
	"nethub/internal/proc"
	"nethub/internal/webui"
)

// uiPipeTag 是界面通道的名字后缀（同一来源，两端都用它，见 ipc.PipeName）。
const uiPipeTag = "ui"

// webviewProcessName 是 WebView2 运行时给宿主进程起的固定名字。
// 现场那个 HIS 启动器就是按**这个名字**杀进程的（它清自己 WebView2 缓存时删不动文件，
// 兜底动作是全系统 KillProcessByName("msedgewebview2")），所以我们拿它当存活判据。
const webviewProcessName = "msedgewebview2.exe"

func uiPipeName() string { return ipc.PipeName(uiPipeTag) }

// redirectStderrTo 把 panic / 运行时诊断落到 logs\stderr.log。
//
// windowsgui 子系统没有控制台：不接走就整个丢掉，现场只能看到"它自己突然没了"
// （2026-10-13 排查 HIS 启动器杀 WebView2 时踩过 —— 连一行堆栈都没留下）。
// 提权重启走 ShellExecuteW、不传句柄，所以新进程里也要再重定向一次。
func redirectStderrTo(logDir string) {
	_ = os.MkdirAll(logDir, 0o755)
	f, err := os.OpenFile(filepath.Join(logDir, "stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	os.Stderr = f // 只接 stderr：panic 走它；stdout 留给 -status/-check 这些控制面
}

// runFrontend 跑界面进程：连引擎的管道、画界面。
//
// **刻意只收一个日志目录、不收配置路径**：界面不该读也不该写配置（那里有上游凭据），
// 所有配置读写都归引擎进程一条路 —— 前端连路径都不知道，就不存在"两头写配置文件"的风险。
//
// startHidden：上次界面就是收在托盘里的（被杀之前），这次起来也别露出来。
// parentPID：拉起我的那个引擎进程。非 0 就盯着它 —— 它没了我也退出（见 watchParent）。
func runFrontend(logDir, themeMode string, startHidden bool, parentPID uint32) {
	redirectStderrTo(logDir)
	if parentPID != 0 {
		go watchParent(parentPID)
	}

	theme := wopts.Light
	bg := uint32(0xffffffff)
	if themeMode == "dark" {
		theme = wopts.Dark
		bg = 0xff121314 // ABGR
	}

	br := webui.NewBridge(uiPipeName(), themeMode)
	// 自己的浏览器子进程被外部程序按名字杀干净了就立刻退出 ——
	// 别等 Wails 那个模态报错框被点（它会一直等，界面进程就卡成"活着但没用"）。
	go watchOwnWebview2()
	err := wails.Run(&options.App{
		Title:  "NetHub · 内网隧道代理",
		Width:  1120,
		Height: 720,
		// 与 DESIGN.md 的表格一节一致：窗口再窄就会把「速率」列挤到截断
		MinWidth:    980,
		MinHeight:   560,
		Frameless:   true, // 自绘标题栏（Win10 原生标题栏是"Win7 味"的主要来源）
		StartHidden: startHidden,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: uint8(bg & 0xff), G: uint8((bg >> 8) & 0xff), B: uint8((bg >> 16) & 0xff), A: 255},
		Bind:             []interface{}{br},
		Windows: &wopts.Options{
			Theme:        theme,
			BackdropType: wopts.None, // Mica 需要 Win11 22621+，Win10 上只能 None
			// 浏览器子进程被杀时 Wails 会弹这个框（而且**等人点确定**才退出，
			// 所以我们也自己判定并退出，见 watchOwnWebview2）。
			// 文案换成能跟客户解释的一句话：至少闪那一下是可读的。
			Messages: &wopts.Messages{
				WebView2ProcessCrash: "界面被外部程序结束了（常见：HIS/医保客户端清理 WebView2 缓存时会结束所有 msedgewebview2）。正在自动恢复…",
			},
		},
		OnStartup: br.OnStartup,
		OnBeforeClose: func(ctx context.Context) bool {
			// 点 X = 收进托盘继续跑：托盘在引擎进程里（另一个进程，不受界面死活影响），
			// 它能把窗口再叫回来。顺手告诉后端"我现在是收着的"（重启时照上次的样子起来）。
			br.HideToTrayNow(ctx)
			return true
		},
		OnShutdown: func(context.Context) { br.Close() },
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "NetHub-frontend",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				br.ShowWindowSelf()
			},
		},
	})
	if err != nil {
		// 界面起不来最常见的原因就是被外部程序杀了：Wails 这时会 os.Exit(-1)，
		// 所以走到这里的多半是别的错（WebView2 运行时缺失等）。
		os.Stderr.WriteString("界面退出: " + err.Error() + "\n")
	}
	br.Close()
}

// ───────────────────────── 界面进程的看护者 ─────────────────────────

// frontendSupervisor 拉起并看护界面进程。
//
// 由引擎进程持有：引擎的寿命约等于"用户想让 NetHub 跑多久"，而界面随时可能被别的
// 程序按名字连坐杀掉。引擎活着，界面就能几秒内自己回来 —— 用户什么都不用做。
type frontendSupervisor struct {
	b      *webui.Backend
	bus    *logbus.Bus
	exe    string
	logDir string

	nudge chan struct{} // "现在就拉起"（托盘点了显示界面、或第二次双击）

	mu       sync.Mutex
	proc     *os.Process
	stopping bool
	deaths   []time.Time // 最近的被杀时间，用来识别"反复被杀"
}

func newFrontendSupervisor(b *webui.Backend, bus *logbus.Bus, logDir string) *frontendSupervisor {
	exe, err := os.Executable()
	if err != nil {
		exe = "nethub.exe"
	}
	return &frontendSupervisor{
		b: b, bus: bus, exe: exe, logDir: logDir,
		nudge: make(chan struct{}, 1),
	}
}

// Start 起看护循环（它会先把界面拉起来）。
func (f *frontendSupervisor) Start() { go f.loop() }

// Stop 停止看护并结束界面进程（引擎进程退出时用）。
func (f *frontendSupervisor) Stop() {
	f.mu.Lock()
	f.stopping = true
	p := f.proc
	f.mu.Unlock()
	f.wake()
	if p != nil {
		_ = p.Kill()
	}
}

// Show 托盘点「显示主界面」：在跑就把窗口叫到前面，不在跑就立刻拉起。
func (f *frontendSupervisor) Show() {
	// ① 已经有界面接着（**不管它是不是我亲手拉起来的那一个**）：请它把窗口露出来。
	// 必须试这一步，否则会退化成"界面明明活着、管道明明通着，点托盘却一点反应没有"：
	// 看护在"另一个界面实例占着单实例锁"时会进待命（见 loop 里退出码 0 那段），那时 f.proc
	// 是 nil；只按"我有没有拉起过进程"判断就等于把活着的那一个当空气（2026-10-19 现场）。
	if err := webui.ShowMainWindow(f.b); err == nil {
		return
	}
	// ② 没有界面接着 / 叫不动：叫看护现在就拉一个（待命状态也会被这一声叫起来）。
	f.wake()
}

func (f *frontendSupervisor) stoppingNow() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopping
}

func (f *frontendSupervisor) wake() {
	select {
	case f.nudge <- struct{}{}:
	default: // 已经有人叫过了
	}
}

// loop 是唯一拉起界面的地方：拉起来 → 等它退出 → 决定要不要再拉。
func (f *frontendSupervisor) loop() {
	// standby = 上一轮是"让位"（退出码 0）而不是死了：不自己反复拉（那会每 1.5 秒起一个
	// 立刻退出的进程），等下一次有人要界面（托盘 / 再次双击）再试。
	standby := false
	for {
		if f.stoppingNow() {
			return
		}
		if standby && !f.waitNudge() {
			return
		}
		p, err := f.launch()
		if err != nil {
			f.bus.Error("界面进程起不来：%v（引擎与隧道不受影响，只是没界面看）", err)
			if !f.nap(5 * time.Second) {
				return
			}
			continue
		}
		started := time.Now()
		code, known := f.superviseProcess(p)
		f.mu.Lock()
		f.proc = nil
		f.mu.Unlock()
		if f.stoppingNow() {
			return
		}
		if known && code == 0 {
			// 退出码 0 ≠ 用户要我们收摊。托盘退出那条路会先把引擎一起收掉（stopping 已经为真，
			// 上面就 return 了）。真正常见的是 Wails 的单实例锁：**另一个界面进程已经把窗口占着了**
			// （典型：引擎被强杀过一次，旧界面变成孤儿活了下来，single_instance.go 里是
			// SendMessage 之后 os.Exit(0)）。以前这里直接 return，从此再也没有界面 ——
			// 托盘点了没反应、重启引擎也没界面，现场只能手工杀进程（2026-10-19 就是这么坏的）。
			f.bus.Warn("界面进程一启动就退出了（退出码 0，跑了 %s）：多半是另一个界面实例占着单实例锁"+
				"（Wails 单实例会让位给它，孤儿界面常见于引擎被强杀过）。看护进入待命 —— 点托盘会再拉一次；"+
				"引擎与隧道不受影响。", time.Since(started).Round(time.Second))
			standby = true
			continue
		}
		standby = false
		if known {
			f.bus.Warn("界面进程被外部程序结束（退出码 %d）。已知原因之一：HIS/医保客户端启动器清理 "+
				"WebView2 缓存时会按名字杀掉全系统所有 msedgewebview2；引擎与隧道不受影响，正在把界面拉回来。", code)
		} else {
			f.bus.Warn("界面进程结束了（拿不到退出码）。已知原因之一：HIS/医保客户端启动器清理 WebView2 " +
				"缓存时会按名字杀掉全系统所有 msedgewebview2；引擎与隧道不受影响，正在把界面拉回来。")
		}
		f.backoff()
	}
}

// watchParent 盯着发起我的那个引擎进程：它没了就自己也退出。
//
// 为什么必须做：引擎被外部强杀时（任务管理器 / 计划任务重启 / 崩溃）界面不会跟着死，
// 它会变成**孤儿** —— 还连着管道、还占着 Wails 的单实例锁。之后的每一次拉起，新界面
// 都会"让位"给这个孤儿然后退出 0，那就等于**永久**没有界面（而引擎照跑、隧道照通，
// 现场看到的就是「双击托盘没反应」）。加这一个监视，孤儿在 2 秒内自己走人，锁就放开了。
func watchParent(pid uint32) {
	for {
		time.Sleep(2 * time.Second)
		if proc.Alive(pid) {
			continue
		}
		os.Stderr.WriteString("引擎进程 " + strconv.Itoa(int(pid)) + " 已不在 —— 界面自己退出" +
			"（不然会变成占着单实例锁的孤儿，下一次界面就永远起不来了）\n")
		os.Exit(0)
	}
}

// watchOwnWebview2 盯着自己的 msedgewebview2 子进程：从"有"掉到"没有"就立刻退出。
//
// 为什么不等 Wails：浏览器进程消失时 Wails 是 `弹模态框 → os.Exit(-1)`，
// 那个框**要人点确定**才返回 —— 现场就变成"窗口没了、进程还活着、看护以为一切正常"，
// 界面永远回不来（2026-10-13 实测）。自己判定，退出后由引擎进程的看护循环重启界面。
func watchOwnWebview2() {
	pid := uint32(os.Getpid())
	sawAny := false
	for {
		time.Sleep(250 * time.Millisecond)
		n := proc.ChildrenByName(pid, webviewProcessName)
		if n > 0 {
			sawAny = true
			continue
		}
		if n < 0 || !sawAny {
			continue // 拿不到快照 / 浏览器子进程还没起来过：不误判
		}
		os.Stderr.WriteString("界面子进程 " + webviewProcessName + " 全部消失 —— 多半被外部程序按名字杀掉了" +
			"（如 HIS 启动器清 WebView2 缓存）。立刻退出，等引擎进程把界面拉回来。\n")
		os.Exit(3)
	}
}

// superviseProcess 等界面进程结束；途中发现它"半死"就动手结束它。
//
// 半死 = 进程还在，但 WebView2 子进程已经长时间为空（典型：卡在系统报错框上等人点）。
// 这时等是等不来的，结束它才能走正常的重启路径。返回退出码。
func (f *frontendSupervisor) superviseProcess(p *os.Process) (int, bool) {
	type exit struct {
		code  int
		known bool
	}
	done := make(chan exit, 1)
	go func() {
		st, err := p.Wait()
		// 坑（本机实测踩过两次）：**os.Process.Wait() 对非零退出码返回的 error 是 nil** ——
		// 退出码在 ProcessState 里（把非零退出码变成 error 的是 exec.Cmd.Wait，两者不是一回事）。
		// 想靠 errors.As 认 *exec.ExitError 会把"被杀"读成"正常退出 0"，
		// 后果是界面被外部程序杀掉后**永远不重启**。
		if st == nil {
			done <- exit{code: -1, known: err == nil}
			return
		}
		done <- exit{code: st.ExitCode(), known: true}
	}()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	sawChildren, emptyStreak := false, 0
	for {
		select {
		case e := <-done:
			return e.code, e.known
		case <-tick.C:
			n := proc.ChildrenByName(uint32(p.Pid), webviewProcessName)
			if n > 0 {
				sawChildren, emptyStreak = true, 0
				continue
			}
			if n < 0 || !sawChildren {
				continue // 拿不到快照 / 界面刚起来还没拉出 WebView2
			}
			emptyStreak++
			if emptyStreak >= 3 { // 连续 6 秒没有浏览器子进程
				f.bus.Warn("界面进程还活着但已经没有 WebView2 子进程了（多半卡在系统的报错框上）—— 结束它并重新拉起")
				_ = p.Kill()
				e := <-done
				return e.code, e.known
			}
		}
	}
}

// waitNudge 挂起直到有人要界面（托盘点了 / 又双击了一次）。返回 false = 看护该停了。
//
// Stop 也会 wake 一下，所以挂在这里不会漏掉退出信号。
func (f *frontendSupervisor) waitNudge() bool {
	<-f.nudge
	return !f.stoppingNow()
}

// nap 等一会儿；中途有人要界面（wake）就提前结束。返回 false = 看护该停了。
func (f *frontendSupervisor) nap(d time.Duration) bool {
	select {
	case <-f.nudge:
		return !f.stoppingNow()
	case <-time.After(d):
		return !f.stoppingNow()
	}
}

// backoff 决定"再拉起来之前等多久"。
//
// 平时只等 1.5 秒（一次性的清理动作，杀掉那一下就过去了）；但一分钟内反复被杀
// 说明外面那个程序还在持续动手，就退避到 30 秒 —— 免得变成"杀-起"死循环把 CPU 打满。
func (f *frontendSupervisor) backoff() {
	now := time.Now()
	f.mu.Lock()
	cut := now.Add(-time.Minute)
	keep := make([]time.Time, 0, len(f.deaths)+1)
	for _, t := range f.deaths {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	f.deaths = keep
	n := len(keep)
	f.mu.Unlock()
	if n >= 5 {
		f.bus.Error("界面在一分钟内已被结束 %d 次：外面那个程序可能还在反复杀 WebView2。先退避 30 秒再拉。", n)
		f.nap(30 * time.Second)
		return
	}
	f.nap(1500 * time.Millisecond)
}

func (f *frontendSupervisor) launch() (*os.Process, error) {
	// -theme 是"窗口刚出现那一下"的主题（连上引擎后后端还会再对齐一次，见 PushTheme）。
	// **每次拉起都重新读配置** —— 不能在后端启动时抓一份留着用：用户中途切了主题，
	// 下一次拉起来的窗口就会用旧主题（看着就像"没记住"）。
	// -parent：引擎的 pid。引擎被强杀时界面不会跟着死，会变成占着 Wails 单实例锁的孤儿 ——
	// 之后的每次拉起都会"让位"给孤儿然后退出 0（见 loop 里那段），界面就永久消失。
	args := []string{"-frontend", "-logdir", f.logDir, "-parent", strconv.Itoa(os.Getpid())}
	if theme := f.b.CurrentTheme(); theme != "" {
		args = append(args, "-theme", theme)
	}
	// 上次界面是收在托盘里的（被杀之前）：这次也别露出来 —— 人家本来在专心干别的，
	// 不该因为"外面的程序把我的界面杀了"就弹个窗口打断他。托盘图标一直在，点它就能显示。
	if f.b.UIHidden() {
		args = append(args, "-hidden")
	}
	cmd := exec.Command(f.exe, args...)
	cmd.Dir = filepath.Dir(f.exe)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.proc = cmd.Process
	f.mu.Unlock()
	f.bus.Info("界面进程已拉起（pid=%d，主题 %s）", cmd.Process.Pid, f.b.CurrentTheme())
	return cmd.Process, nil
}
