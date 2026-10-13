package webui

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// UI 是 Backend 需要"界面配合"的那几件事。
//
// 界面与引擎拆成两个进程之后（为什么要拆见 internal/ipc 的包注释），引擎进程里
// 没有窗口、也没有 Wails 上下文，这些动作只能请界面进程替它做 —— 走 ipc 的反向请求。
//
// 抽成接口还有一个用处：没有界面时（界面正被外部程序杀掉、还没被拉起来的空窗期，
// 或者测试里）换成 noUI —— 引擎照跑，不 panic、不报错。
type UI interface {
	Emit(event string, data any)
	ShowWindow()
	HideWindow()
	SetTheme(dark bool)
	QuitApp()
	OpenFile(opts wruntime.OpenDialogOptions) (string, error)
	OpenDir(opts wruntime.OpenDialogOptions) (string, error)
	SaveFile(opts wruntime.SaveDialogOptions) (string, error)
}

// 反向操作名（引擎 → 界面）。两端共用同一份常量，改名不会只改一半。
const (
	uiOpShowWindow = "showWindow"
	uiOpHideWindow = "hideWindow"
	uiOpSetTheme   = "setTheme"
	uiOpQuitApp    = "quitApp"
	uiOpOpenFile   = "openFile"
	uiOpOpenDir    = "openDir"
	uiOpSaveFile   = "saveFile"
)

const (
	uiOpTimeout     = 30 * time.Second // 窗口操作这类"立刻就该有回执"的
	uiDialogTimeout = 10 * time.Minute // 弹文件框：用户翻半天目录是正常的，别掐他
)

// ErrUIDetached 界面不在（没连上 / 已经断开）。引擎遇到它不是故障。
var ErrUIDetached = errors.New("界面进程不在（引擎照常运行；界面会自己回来）")

// uiRequester 是 remoteUI 需要的极小能力面（*ipc.Server 满足它）。
// 刻意不直接依赖 ipc 包：webui 不该知道管道长什么样。
type uiRequester interface {
	Emit(event string, data any) error
	Request(ctx context.Context, op string, args ...any) (json.RawMessage, error)
}

// remoteUI 把 UI 动作转成给界面进程的反向请求。
type remoteUI struct{ r uiRequester }

// NewRemoteUI 造一个"请界面进程代做"的 UI 实现。
func NewRemoteUI(r uiRequester) UI { return &remoteUI{r: r} }

func (u *remoteUI) Emit(event string, data any) { _ = u.r.Emit(event, data) }

func (u *remoteUI) do(timeout time.Duration, op string, args ...any) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return u.r.Request(ctx, op, args...)
}

func (u *remoteUI) ShowWindow()     { _, _ = u.do(uiOpTimeout, uiOpShowWindow) }
func (u *remoteUI) HideWindow()     { _, _ = u.do(uiOpTimeout, uiOpHideWindow) }
func (u *remoteUI) SetTheme(d bool) { _, _ = u.do(uiOpTimeout, uiOpSetTheme, d) }
func (u *remoteUI) QuitApp()        { _, _ = u.do(2*time.Second, uiOpQuitApp) } // 通知型：不等回执，见下

// QuitApp 是**通知型**命令：界面收到就退了，不会回执 —— 等回执就等于干等超时
// （验收门禁里表现为"优雅退出超时，被强杀"）。所以短超时发出去就算了，
// 界面进程的生死由看护循环操心。

func (u *remoteUI) OpenFile(opts wruntime.OpenDialogOptions) (string, error) {
	return u.stringOp(uiOpOpenFile, opts)
}

func (u *remoteUI) OpenDir(opts wruntime.OpenDialogOptions) (string, error) {
	return u.stringOp(uiOpOpenDir, opts)
}

func (u *remoteUI) SaveFile(opts wruntime.SaveDialogOptions) (string, error) {
	return u.stringOp(uiOpSaveFile, opts)
}

func (u *remoteUI) stringOp(op string, opts any) (string, error) {
	res, err := u.do(uiDialogTimeout, op, opts)
	if err != nil {
		return "", err
	}
	var s string
	if len(res) > 0 {
		if err := json.Unmarshal(res, &s); err != nil {
			return "", errors.New("界面回的内容看不懂: " + err.Error())
		}
	}
	return s, nil
}

// noUI 是没有界面时用的空实现：事件丢掉，窗口操作当没发生，需要用户选的直接报错。
type noUI struct{}

func (noUI) Emit(string, any) {}
func (noUI) ShowWindow()      {}
func (noUI) HideWindow()      {}
func (noUI) SetTheme(bool)    {}
func (noUI) QuitApp()         {}

func (noUI) OpenFile(wruntime.OpenDialogOptions) (string, error) { return "", ErrUIDetached }
func (noUI) OpenDir(wruntime.OpenDialogOptions) (string, error)  { return "", ErrUIDetached }
func (noUI) SaveFile(wruntime.SaveDialogOptions) (string, error) { return "", ErrUIDetached }
