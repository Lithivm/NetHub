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
func runFrontend(logDir, themeMode string) {
	redirectStderrTo(logDir)

	theme := wopts.Light
	bg := uint32(0xffffffff)
	if themeMode == "dark" {
		theme = wopts.Dark
		bg = 0xff121314 // ABGR
	}

	br := webui.NewBridge(uiPipeName())
	// 自己的浏览器子进程被外部程序按名字杀干净了就立刻退出 ——
	// 别等 Wails 那个模态报错框被点（它会一直等，界面进程就卡成"活着但没用"）。
	go watchOwnWebview2()
	err := wails.Run(&options.App{
		Title:  "NetHub · 内网隧道代理",
		Width:  1120,
		Height: 720,
		// 与 DESIGN.md 的表格一节一致：窗口再窄就会把「速率」列挤到截断
		MinWidth:  980,
		MinHeight: 560,
		Frameless: true, // 自绘标题栏（Win10 原生标题栏是"Win7 味"的主要来源）
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
			// 它能把窗口再叫回来。
			webui.HideWindowNow(ctx)
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
	theme  string

	nudge chan struct{} // "现在就拉起"（托盘点了显示界面、或第二次双击）

	mu       sync.Mutex
	proc     *os.Process
	stopping bool
	deaths   []time.Time // 最近的被杀时间，用来识别"反复被杀"
}

func newFrontendSupervisor(b *webui.Backend, bus *logbus.Bus, logDir, theme string) *frontendSupervisor {
	exe, err := os.Executable()
	if err != nil {
		exe = "nethub.exe"
	}
	return &frontendSupervisor{
		b: b, bus: bus, exe: exe, logDir: logDir, theme: theme,
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
	if f.running() {
		webui.ShowMainWindow(f.b)
		return
	}
	f.wake()
}

func (f *frontendSupervisor) running() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.proc != nil
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
	for {
		if f.stoppingNow() {
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
		code, known := f.superviseProcess(p)
		f.mu.Lock()
		f.proc = nil
		f.mu.Unlock()
		if f.stoppingNow() {
			return
		}
		if known && code == 0 {
			// 正常退出 = 用户主动退出（托盘退出那条路会先把引擎一起收掉），不再拉起
			f.bus.Info("界面进程正常退出，不再拉起")
			return
		}
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
	// -theme 只是"窗口刚出现那一下"的主题，避免深色用户看到一闪的浅色；
	// 连上引擎之后后端还会再对齐一次（Backend.PushTheme）。
	args := []string{"-frontend", "-logdir", f.logDir}
	if f.theme != "" {
		args = append(args, "-theme", f.theme)
	}
	cmd := exec.Command(f.exe, args...)
	cmd.Dir = filepath.Dir(f.exe)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.proc = cmd.Process
	f.mu.Unlock()
	f.bus.Info("界面进程已拉起（pid=%d）", cmd.Process.Pid)
	return cmd.Process, nil
}
