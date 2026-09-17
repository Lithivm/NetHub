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
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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
	"nethub/internal/webui"
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
	clashCheck := flag.Bool("clash-check", false, "只检测系统代理/Clash 会不会把内网送进代理，然后退出（不需管理员）")
	upTest := flag.Bool("test-upstream", false, "直接实测原生上游链路（不经 gost），然后退出（不需管理员）")
	flag.Parse()

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
	logDir := filepath.Dir(p)
	_ = bus.SetFile(filepath.Join(logDir, "nethub.log"))
	bus.Info("NetHub 启动，配置 %s", p)
	if !isElevated() {
		bus.Warn("当前不是管理员权限，驱动加载可能失败")
	}

	cfg, err := config.Load(p)
	if err != nil {
		fatal("%v", err)
	}
	bus.Info("配置载入：%d 条链，%d 条规则", len(cfg.Chains), len(cfg.Routes))

	a := app.New(cfg, bus)

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
	)
	b.SetTray(tray)

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
		cfg.Chains[i].Forward = got[i].Forward
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
