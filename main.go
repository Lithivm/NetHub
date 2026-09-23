// NetHub —— 内网隧道透明代理（Wails/WebView2 界面）。
//
// 替代 Proxifier + 两个 gost .bat：一个进程管链路、一个驱动管拦截、一个界面管规则。
//
// 界面栈选择（见 DESIGN.md 的说明）：
//
//	驱动级拦截 + gost 托管在 internal/ 里，与界面无关；
//	界面用 Wails v2 + 手写 HTML/CSS/JS —— 因为设计系统本身是 CSS 设计系统，
//	用 Web 技术实现是照抄，用原生控件实现是翻译加走形（govcl 版保留在 cmd/govcl-gui）。
//
// 构建（**必须带 production 标签**，否则 Wails 会弹 "will not build without the correct build tags"）：
//
//	go build -tags production -ldflags "-H=windowsgui -s -w" -o nethub.exe .
//
// 不需要 wails CLI，也不需要 npm：bindings 由 Wails 在运行时从 options.Bind 自动生成。
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wopts "github.com/wailsapp/wails/v2/pkg/options/windows"
	"golang.org/x/sys/windows"

	"nethub/internal/app"
	"nethub/internal/autostart"
	"nethub/internal/config"
	"nethub/internal/gostbat"
	"nethub/internal/logbus"
	"nethub/internal/selfupdate"
	"nethub/internal/webui"
	"nethub/internal/winsvc"
)

//go:embed all:frontend
var assets embed.FS

func main() {
	cfgPath := flag.String("config", "", "配置文件路径（默认 exe 同目录 config.yaml）")
	headless := flag.Bool("headless", false, "无界面模式：只跑引擎（自动化测试用）")
	importBats := flag.String("import-bats", "", "从 gost 的 .bat 目录导入链路配置（含凭据），随后退出")
	doAutostart := flag.Bool("autostart", false, "把本程序加入开机启动（计划任务，最高权限），随后退出")
	noAutostart := flag.Bool("no-autostart", false, "从开机启动中移除，随后退出")
	noElevate := flag.Bool("no-elevate", false, "不要自动提权（调试用）")
	serviceMode := flag.Bool("service", false, "以 Windows 服务方式运行（由 SCM 拉起，无界面）")
	svcInstall := flag.Bool("service-install", false, "安装为 Windows 服务（自动启动，需管理员），随后退出")
	svcUninstall := flag.Bool("service-uninstall", false, "卸载 Windows 服务，随后退出")
	svcState := flag.Bool("service-state", false, "打印 Windows 服务状态，随后退出")
	doQuit := flag.Bool("quit", false, "请已在运行的界面版优雅退出（会先停服务、移除托盘图标），随后退出")
	verFlag := flag.Bool("version", false, "打印版本号，随后退出")
	rollbackFlag := flag.Bool("rollback", false, "回滚到上一版本并重启（一键更新出问题时用），随后退出")
	afterUpdate := flag.Bool("after-update", false, "更新收尾：先等旧进程退出，再替换被占用的文件（由一键更新自动拉起）")
	clashCheck := flag.Bool("clash-check", false, "只检测系统代理/Clash 会不会把内网送进代理，然后退出（不需管理员）")
	upTest := flag.Bool("test-upstream", false, "直接实测原生上游链路（不经 gost），然后退出（不需管理员）")
	checkFlag := flag.Bool("check", false, "只校验配置文件（逐条列错误，不启动、不改任何东西），随后退出（不需管理员）")
	statusFlag := flag.Bool("status", false, "打印机器可读的 JSON 现状（版本/服务/链路/规则/开关），随后退出（不需管理员）")
	flag.Parse()

	if *verFlag {
		fmt.Println(webui.Version)
		return
	}

	// -rollback：一键更新出问题时回到上一版本（把 nethub.exe.old 换回来）
	if *rollbackFlag {
		progDir := filepath.Dir(exePath())
		if !selfupdate.HasRollback(progDir) {
			fmt.Println("没有可回滚的上一版本（nethub.exe.old 不存在）")
			return
		}
		if err := selfupdate.Rollback(progDir); err != nil {
			fatal("回滚失败: %v", err)
		}
		fmt.Println("已回滚上一版本，请手动启动 nethub.exe（或等开机自启）")
		return
	}

	// -after-update：一键更新的收尾。必须放在**任何东西之前** ——
	// 因为要替换的 WinDivert.dll 一旦被本进程加载就换不掉了。
	if *afterUpdate {
		progDir := filepath.Dir(exePath())
		done, err := selfupdate.ApplyPending(progDir, waitProcGone)
		selfupdate.CleanupStale(progDir)
		if len(done) > 0 {
			fmt.Println("更新收尾完成：" + selfupdate.Describe(done))
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "更新收尾未完成："+err.Error())
		}
		// 继续正常启动
	}

	// -quit：请运行中的界面版优雅退出（重启脚本用）。
	// 强杀进程会让托盘图标变成“僵尸”，鼠标扫过才会消失；走这条路就没有。
	if *doQuit {
		if webui.RequestQuit() {
			fmt.Println("已请求正在运行的 NetHub 退出（等服务真正停稳再启动下一个）")
		} else if winsvc.State() == "RUNNING" {
			fmt.Println("没有界面版在跑；Windows 服务正在运行，请用 nethub.exe -service-stop 或 net stop " + winsvc.Name)
		} else {
			fmt.Println("没有在运行的 NetHub")
		}
		return
	}

	// 服务安装/卸载/查状态：不需要配置，也不需要界面
	if *svcInstall || *svcUninstall || *svcState {
		if *svcState {
			fmt.Println("NetHub 服务状态：" + winsvc.State())
			return
		}
		exe, err := os.Executable()
		if err != nil {
			fatal("拿不到自身路径: %v", err)
		}
		cfgPath := *cfgPath
		if cfgPath == "" {
			cfgPath = filepath.Join(filepath.Dir(exe), "config.yaml")
		}
		if *svcUninstall {
			if err := winsvc.Uninstall(); err != nil {
				fatal("%v", err)
			}
			fmt.Println("已卸载 Windows 服务 " + winsvc.Name)
			return
		}
		if err := winsvc.Install(exe, cfgPath); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("已安装 Windows 服务 %s（自动启动，无界面）\n用 net start %s 启动，或去服务管理器里操作。\n", winsvc.Name, winsvc.Name)
		return
	}

	// -test-upstream 直接连上游，不需管理员
	if *upTest {
		if *cfgPath == "" {
			*cfgPath = config.DefaultPath()
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fatal("%v", err)
		}
		webui.TestUpstream(cfg)
		return
	}

	// -clash-check 只读系统代理设置，不需管理员，所以放在提权之前
	if *clashCheck {
		if *cfgPath == "" {
			*cfgPath = config.DefaultPath()
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fatal("%v", err)
		}
		webui.PrintClashCheck(cfg)
		return
	}

	// -check / -status：只读，不改任何状态、不需管理员，供脚本与 agent 用
	if *checkFlag {
		os.Exit(cmdCheck(configPathFor(*cfgPath)))
	}
	if *statusFlag {
		os.Exit(cmdStatus(configPathFor(*cfgPath)))
	}

	// 需要管理员：装 WinDivert 驱动、改 hosts、起驱动服务
	if !*noElevate && !isElevated() {
		if err := relaunchElevated(); err != nil {
			fatal("需要管理员权限才能加载网络驱动、修改 hosts。自动提权失败: %v", err)
		}
		return // 新进程接管
	}

	p := *cfgPath
	if p == "" {
		p = config.DefaultPath()
	}

	if *importBats != "" {
		if err := doImportBats(p, *importBats); err != nil {
			fatal("%v", err)
		}
		fmt.Println("已写入:", p)
		return
	}
	if *doAutostart {
		if err := autostart.Enable(); err != nil {
			fatal("设置开机启动失败: %v", err)
		}
		fmt.Println("已加入开机启动（计划任务 " + autostart.TaskName + "）")
		return
	}
	if *noAutostart {
		if err := autostart.Disable(); err != nil {
			fatal("移除开机启动失败: %v", err)
		}
		fmt.Println("已从开机启动移除")
		return
	}

	bus := logbus.New(3000)
	// 日志单独放 logs\ —— 运行期产物不跟 exe/config 混在一个目录里
	logDir := filepath.Join(filepath.Dir(p), "logs")
	_ = bus.SetFile(filepath.Join(logDir, "nethub.log"))
	bus.Info("NetHub 启动，配置 %s", p)
	if !isElevated() {
		bus.Warn("当前不是管理员权限，驱动加载可能失败")
	}

	cfg, err := config.Load(p)
	if err != nil {
		// 配置坏了以前是“静默不启动”（连日志都没有）—— 这条实测踩过：
		// 配置里写重复键 → 进程直接退出 → 用户只看到“点了没反应”。
		// 所以这里要：① 原始错误整段打进日志 ② 弹窗说清楚 ③ 退出码非 0。
		bus.Error("配置无法载入：%v", err)
		for _, line := range strings.Split(err.Error(), "\n") {
			bus.Error("    %s", line)
		}
		bus.Error("  修好后再启动；可用 `nethub.exe -check` 逐条看错误（不需管理员）")
		// 服务模式下没有交互桌面，弹窗没人看得到（也不该弹）
		if !*serviceMode && !winsvc.IsService() {
			msgBox("NetHub 无法启动",
				"配置文件有问题，程序没有启动（日志在 logs\\nethub.log）：\n\n"+err.Error()+
					"\n\n提示：命令行跑 `nethub.exe -check` 可以只看错误、不启动。")
		}
		os.Exit(2)
	}
	bus.Info("配置载入：%d 条链，%d 条规则", len(cfg.Chains), len(cfg.Routes))

	a := app.New(cfg, bus)

	// 服务模式（SCM 拉起或手动 -service）：没有窗口、没有托盘，只跑引擎
	if *serviceMode || winsvc.IsService() {
		err := winsvc.Run(func(ctx context.Context) error {
			if err := a.Start(); err != nil {
				bus.Error("服务模式启动失败: %v", err)
				return err
			}
			bus.Info("服务模式：引擎已就绪（无界面）")
			<-ctx.Done()
			bus.Info("服务收到停止请求，正在收尾…")
			a.Stop()
			return nil
		})
		if err != nil {
			fatal("服务运行失败: %v", err)
		}
		return
	}

	if *headless {
		runHeadless(a, bus)
		return
	}
	runGUI(a, bus, p)
}

// runGUI 启动 Wails 界面（阻塞到退出）。
func runGUI(a *app.App, bus *logbus.Bus, cfgPath string) {
	b := webui.New(a)

	// 托盘：先建好，点 X 才有地方可去
	tray := webui.NewTray(filepath.Join(filepath.Dir(cfgPath), "nethub.ico"),
		func() { webui.ShowMainWindow(b) }, // 显示主界面
		func() { go func() { _ = a.Start() }() },
		func() { a.Stop() },
		func() { b.Quit() },
		func(m string) { a.Bus.Info("托盘: %s", m) },
	)
	b.SetTray(tray)
	// 优雅退出通道：重启脚本用 `nethub.exe -quit` 通知旧实例走正常退出（摘掉托盘图标），
	// 而不是强杀 —— 强杀会留下“僵尸图标”。
	stopWatch := webui.WatchQuitSignal(func() {
		a.Bus.Info("收到外部退出请求（-quit），正在优雅退出")
		b.Quit()
	})
	defer stopWatch()

	theme := wopts.Light
	bg := uint32(0xffffffff)
	if a.Cfg.UI.Theme == "dark" {
		theme = wopts.Dark
		bg = 0xff121314 // ABGR
	}

	err := wails.Run(&options.App{
		Title:     "NetHub · 内网隧道代理",
		Width:     1120,
		Height:    720,
		MinWidth:  880,
		MinHeight: 560,
		Frameless: true, // 自绘标题栏（Win10 原生标题栏是"Win7 味"的主要来源）
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: uint8(bg & 0xff), G: uint8((bg >> 8) & 0xff), B: uint8((bg >> 16) & 0xff), A: 255},
		Bind:             []interface{}{b},
		Windows: &wopts.Options{
			Theme:        theme,
			BackdropType: wopts.None, // Mica 需要 Win11 22621+，Win10 上只能 None
		},
		OnStartup:     b.OnStartup,
		OnDomReady:    b.OnDomReady,
		OnBeforeClose: b.OnBeforeClose,
		OnShutdown:    b.OnShutdown,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "NetHub-single-instance",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				webui.ShowMainWindow(b)
			},
		},
	})
	if err != nil {
		bus.Error("界面退出: %v", err)
	}
	a.Stop()
	bus.Info("已退出")
	bus.Close()
}

// runHeadless 无界面运行，Ctrl+C / 杀进程时清理子进程。
func runHeadless(a *app.App, bus *logbus.Bus) {
	if err := a.Start(); err != nil {
		bus.Error("启动失败: %v", err)
		os.Exit(1)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	bus.Info("收到退出信号")
	a.Stop()
	bus.Close()
}

// ───────────────────────── 提权 ─────────────────────────

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchElevated 用 ShellExecuteW 的 "runas" 动词重启自己（会弹一次 UAC）。
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args, _ := syscall.UTF16PtrFromString(strings.Join(os.Args[1:], " "))

	shell32 := windows.NewLazySystemDLL("shell32.dll")
	se := shell32.NewProc("ShellExecuteW")
	r, _, e := se.Call(0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(args)),
		0, 1 /* SW_SHOWNORMAL */)
	if r <= 32 {
		return fmt.Errorf("ShellExecuteW 返回 %d (%v)", r, e)
	}
	return nil
}

// ───────────────────────── 开机启动管理（命令行）─────────────────────────

func doImportBats(cfgPath, dir string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	got := gostbat.ScanBatDir(dir)
	if len(got) == 0 {
		return fmt.Errorf("在 %s 里没找到含 -L/-F 的 gost 批处理", dir)
	}
	// 按顺序覆盖现有链的上游（链名与规则保持不动）。
	// 只取 -F：上游能力已内置，脚本里的 -L 不再需要。
	for i := range cfg.Chains {
		if i >= len(got) {
			break
		}
		cfg.Chains[i].SetUpstreams([]string{got[i].Forward})
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	fmt.Printf("导入 %d 条链路（凭据已写入配置文件，未在终端回显）\n", len(got))
	return nil
}

func fatal(format string, a ...any) {
	log.SetFlags(0)
	log.Fatalf(format, a...)
}

// exePath 自身路径（拿不到就用相对名兜底）。
func exePath() string {
	if p, err := os.Executable(); err == nil && p != "" {
		return p
	}
	return "nethub.exe"
}

// waitProcGone 等某个 PID 消失（更新收尾用：旧进程不退，文件就换不掉）。
func waitProcGone(pid int, max time.Duration) bool {
	if pid <= 0 {
		return true
	}
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if !procAlive(pid) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// procAlive 这个 PID 还在不在（用 FindProcess + OpenProcess 判活）。
func procAlive(pid int) bool {
	const processQueryLimitedInformation = 0x1000
	k := windows.NewLazySystemDLL("kernel32.dll")
	open := k.NewProc("OpenProcess")
	h, _, _ := open.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return false
	}
	closeH := k.NewProc("CloseHandle")
	closeH.Call(h)
	return true
}
