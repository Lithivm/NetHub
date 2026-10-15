package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// ───────────────────────── 报错去哪：GUI 程序的三条去向 ─────────────────────────
//
// 为什么不能只 `log.Fatalf` 一句：这是个 **GUI 子系统**程序（`-H=windowsgui`），
// 双击运行、或由脚本拉起时，**都没有自己的控制台** —— 一行 stderr 常常谁也没接到。
// 现场的表现就是"点了没反应，什么也不说"；脚本里的表现是**静默挂死**。

const (
	fatalLogName = "fatal.log"

	// GetFileType 的返回值（FILE_TYPE_DISK=1 / FILE_TYPE_PIPE=3）
	fileTypeDisk = 1
	fileTypePipe = 3

	// MessageBox 标志（不依赖 x/sys 里有没有导出这些名字）
	mbOK      = 0x00000000
	mbIconErr = 0x00000010
	mbSetFg   = 0x00010000
)

// fatal 打印错误并退出（退出码 1）。三条去向，按场景自动选：
//
//  1. stderr          —— 脚本 / 管道（`2>&1`、`| Out-String`）能收到
//  2. logs/fatal.log  —— **双击运行时唯一的事后线索**（没人接 stderr 时）
//  3. MessageBox      —— **只在 stderr 没人接**时才弹：
//     脚本场景弹框会把自动化静默挂死（2026-10-15 实验脚本就这么挂了 11 分钟，
//     桌面上一个没人看见的框）；
//     而双击场景不弹框，用户就完全不知道发生了什么。
func fatal(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, msg)
	writeFatalLog(msg)
	if !stderrHasReceiver() {
		showFatalBox(msg)
	}
	os.Exit(1)
}

// stderrHasReceiver stderr 是不是接在管道/文件上（= 有人在读）。
//
// 判据用 GetFileType，而不是"有没有控制台"：GUI 程序被脚本拉起时**没有**控制台，
// 但 stderr 被重定向了、输出收得到 —— 那种情况**不该**弹框。
func stderrHasReceiver() bool {
	h, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if err != nil || h == 0 || h == windows.InvalidHandle {
		return false
	}
	t, err := windows.GetFileType(h)
	if err != nil {
		return false
	}
	return t == fileTypePipe || t == fileTypeDisk
}

// writeFatalLog 追一行到 <程序目录>/logs/fatal.log。
// 拿不到目录/写不进去就算了 —— 报错路径上不能再炸一次。
func writeFatalLog(msg string) {
	dir := filepath.Join(filepath.Dir(exePath()), "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, fatalLogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s [FATAL] %s（argv: %v）\n",
		time.Now().Format("2006-01-02 15:04:05"), msg, os.Args[1:])
}

// showFatalBox 弹一个模态框（只有"确定"），等用户点完再退出。
func showFatalBox(msg string) {
	title, _ := windows.UTF16PtrFromString("NetHub")
	text, _ := windows.UTF16PtrFromString(msg)
	_, _ = windows.MessageBox(0, text, title, mbOK|mbIconErr|mbSetFg)
}
