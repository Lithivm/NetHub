// netproxy —— 内网隧道透明代理。
//
// 替代 Proxifier + 两个 gost .bat：一个进程管链路、一个驱动管拦截、一个界面管规则。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	_ "github.com/ying32/govcl/pkgs/winappres"
	"golang.org/x/sys/windows"

	"netproxy/internal/app"
	"netproxy/internal/autostart"
	"netproxy/internal/config"
	"netproxy/internal/gostproc"
	"netproxy/internal/gui"
	"netproxy/internal/logbus"
)

func main() {
	cfgPath := flag.String("config", "", "配置文件路径（默认 exe 同目录 config.yaml）")
	headless := flag.Bool("headless", false, "无界面模式：只跑引擎（自动化测试用）")
	importBats := flag.String("import-bats", "", "从 gost 的 .bat 目录导入链路配置（含凭据），随后退出")
	doAutostart := flag.Bool("autostart", false, "把本程序加入开机启动（计划任务，最高权限），随后退出")
	noAutostart := flag.Bool("no-autostart", false, "从开机启动中移除，随后退出")
	noElevate := flag.Bool("no-elevate", false, "不要自动提权（调试用）")
	flag.Parse()

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
	_ = bus.SetFile(filepath.Join(logDir, "netproxy.log"))
	bus.Info("netproxy 启动，配置 %s", p)
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
	gui.Run(a)
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
	shellExecuteW := shell32.NewProc("ShellExecuteW")
	const swShowNormal = 1
	r, _, e := shellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(args)),
		0, swShowNormal)
	if r <= 32 { // ShellExecute 成功时返回值 > 32
		if e != nil {
			return fmt.Errorf("ShellExecuteW 返回 %d: %v", r, e)
		}
		return fmt.Errorf("ShellExecuteW 返回 %d（用户可能取消了 UAC）", r)
	}
	return nil
}

// ───────────────────────── 从 bat 导入 ─────────────────────────

// doImportBats 解析 gost 的 .bat，把凭据搬进配置文件（凭据只落盘、不打印）。
// doImportBats 从旧 gost .bat 目录导入链路上游（解析已在 gostproc 里，GUI 复用同一套）。
func doImportBats(cfgPath, dir string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	got := gostproc.ScanBatDir(dir)
	if len(got) == 0 {
		return fmt.Errorf("在 %s 里没找到含 -L/-F 的 gost 批处理", dir)
	}
	// 按顺序覆盖现有链的 listen/forward（链名与规则保持不动）
	for i := range cfg.Chains {
		if i >= len(got) {
			break
		}
		cfg.Chains[i].Listen = got[i].Listen
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
