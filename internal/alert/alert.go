// Package alert 把**告警级**事件送出界面之外：没人在看前端时也必须留痕、也尽量被看见。
//
// 为什么需要它（2026-10-15 用户提的）：界面里那条常驻告警条只在"有人开着界面"时有用，
// 而现场最常见的状态是**界面收在托盘**、或者**压根没人开界面**（服务模式跑引擎）。
// 项目文档一直写着"通知走 NIF_INFO 气泡、Win10/11 会渲染成标准通知并进操作中心"，
// 但代码里从来没发过系统通知（`Backend` 只把 Notify 转成前端 toast）—— 这里把它补上。
//
// ⚠ 只在 **error 级**调用（见 App.notify）：info/warn 不进系统通知 ——
// 项目原来那句"不占用户的操作中心"是对的，我们要的是"**出事**时别让人错过"。
//
// 出口按"最可能被看见 → 一定能留痕"排：
//  1. Windows 通知（Toast，非模态、进操作中心；人不在也能事后看到）
//  2. logs/alert.log（永远写得出去；界面打开时至少能查）
//  3. 界面告警条（webui.Notices，已有）
//
// **已知边界**：Windows 服务模式跑在 Session 0，那里的进程**弹不出用户可见的 Toast**
// —— 那种场景真正能指望的是 alert.log + "用户下次开界面时看到的告警条"。
// 要主动推到用户桌面得做会话注入（WTSQueryUserToken + CreateProcessAsUser），
// 属于另一件事，没做。
package alert

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"nethub/internal/winrun"
)

const (
	logName = "alert.log"
	// toastTimeout 起 powershell 弹通知的兜底等待（它自己很快退出；这里只防僵尸）。
	toastTimeout = 8 * time.Second
)

// progDir 由上层注入（main 启动时调 SetProgDir），或退化成 exe 所在目录。
var (
	mu      sync.Mutex
	progDir string
	// 同一内容在去重窗口内只弹一次（告警循环可能连续触发）。
	lastKey string
	lastAt  time.Time
)

// 去重窗口：同一标题+正文在这段时间内只弹一次系统通知（alert.log 仍然每条都写）。
const dedupWindow = 10 * time.Minute

// SetProgDir 指定程序目录（alert.log 落在 <程序目录>/logs/）。
func SetProgDir(dir string) {
	mu.Lock()
	progDir = dir
	mu.Unlock()
}

// Error 送一条告警级事件：写日志（每次都写）+ 弹 Windows 通知（同内容去重）。
func Error(title, text string) {
	writeLog(title, text)

	key := title + "\x00" + text
	mu.Lock()
	if key == lastKey && time.Since(lastAt) < dedupWindow {
		mu.Unlock()
		return
	}
	lastKey, lastAt = key, time.Now()
	mu.Unlock()

	showToast(title, text)
}

// writeLog 追一行到 logs/alert.log。
//
// 为什么单独一个文件而不是写进 nethub.log：告警是"必须被看到"的那一类，
// 混在几千行运行日志里会被淹掉；这个文件小、只写告警，出问题时直接看它。
func writeLog(title, text string) {
	mu.Lock()
	dir := progDir
	mu.Unlock()
	if dir == "" {
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Dir(exe)
		} else {
			dir = "."
		}
	}
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(logDir, logName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s [ALERT] %s —— %s\n", time.Now().Format("2006-01-02 15:04:05"), title, text)
}

// showToast 弹一条 Windows 通知（Toast）。
//
// 为什么走 powershell 子进程而不是直接调 WinRT：Go 里调 WinRT 要手写 COM 激活，
// 代价与风险都不小；而告警是**低频**事件（去重之后更少），起一个短命进程完全可以接受。
// 命令一律经 internal/winrun —— 这是个 GUI 子系统程序，直接 exec 会**闪一个黑框**
// 抢走焦点（项目里踩过，见 DESIGN.md 的"实现要点"）。
func showToast(title, text string) {
	script := toastScript(title, text)
	cmd := winrun.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encodeUTF16LE(script))
	if err := cmd.Start(); err != nil {
		return // 弹不出来就算了：alert.log 已经写下去了
	}
	go func() {
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(toastTimeout):
			_ = cmd.Process.Kill() // 防僵尸
		}
	}()
}

// toastScript 生成弹 Toast 的 PowerShell。
//
// XML 用 here-string 包（`@" ... "@`）：这样 XML 属性里的单引号不会和 PowerShell
// 的引号打架，不用做两套转义。标题/正文里的 & < > 仍然要转义 —— 一个 & 就会让
// 整个 XML 解析失败，通知静默不出现。
func toastScript(title, text string) string {
	esc := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;",
		`"`, "&quot;", "'", "&apos;",
	)
	return `$ErrorActionPreference = 'Stop'
` + `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null
` + `[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType=WindowsRuntime] > $null
` + `$xmlText = @"
<toast><visual><binding template='ToastGeneric'><text>` + esc.Replace(title) + `</text><text>` + esc.Replace(text) + `</text></binding></visual></toast>
"@
` + `$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
` + `$xml.LoadXml($xmlText)
` + `$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
` + `[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('NetHub').Show($toast)
`
}

// encodeUTF16LE 把脚本编成 -EncodedCommand 需要的 base64(UTF-16LE)。
// 走这条路而不是写临时文件：不留垃圾、也没有"临时文件被安全软件拦"的可能。
func encodeUTF16LE(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, v := range u {
		b = append(b, byte(v), byte(v>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}
