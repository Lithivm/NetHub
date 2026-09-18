// 系统托盘：直接调原生 Shell_NotifyIconW。
//
// 为什么不用现成的托盘库：systray 那类库会起自己的消息循环，
// 跟 Wails 自己的 UI 线程/消息泵抢，已知会互相干扰。
// 这里自己开一条锁定的 OS 线程 + 独立窗口 + 消息循环，完全隔离。
//
// 这里只管图标本身，不发系统通知：NIF_INFO 气泡会被 Win10/11 渲染成标准通知
// 并进「操作中心」，等于占用户的系统通知位。所有提示一律走应用内
// （后端 emit("notify") → 前端 toast），窗口收起时不打扰任何人。
package webui

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmApp           = 0x8000 // WM_APP
	wmTrayMsg       = wmApp + 1
	wmRButtonUp     = 0x0205
	wmLButtonDBLCLK = 0x0203
	wmCommand       = 0x0111
	wmDestroy       = 0x0002
	wmClose         = 0x0010

	nimAdd    = 0x00000000
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	mfString       = 0x00000000
	mfSeparator    = 0x00000800
	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020
)

// 菜单命令 id
const (
	idShow = 1001 + iota
	idStart
	idStop
	idQuit
)

type notifyIconData struct {
	cbSize           uint32
	hWnd             windows.Handle
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	// 下面几个字段（含气泡通知用的 szInfo/szInfoTitle）虽然用不上了也必须留着：
	// cbSize 要等于整个结构体大小，少一个字段结构体就“缩水”，
	// Windows 会按 cbSize 判定布局。
	szInfo       [256]uint16
	uVersion     uint32
	szInfoTitle  [64]uint16
	dwInfoFlags  uint32
	guidItem     windows.GUID
	hBalloonIcon windows.Handle
}

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassExW   = user32.NewProc("RegisterClassExW")
	pCreateWindowExW    = user32.NewProc("CreateWindowExW")
	pDefWindowProcW     = user32.NewProc("DefWindowProcW")
	pDestroyWindow      = user32.NewProc("DestroyWindow")
	pGetMessageW        = user32.NewProc("GetMessageW")
	pTranslateMessage   = user32.NewProc("TranslateMessage")
	pDispatchMessageW   = user32.NewProc("DispatchMessageW")
	pPostQuitMessage    = user32.NewProc("PostQuitMessage")
	pCreatePopupMenu    = user32.NewProc("CreatePopupMenu")
	pAppendMenuW        = user32.NewProc("AppendMenuW")
	pDestroyMenu        = user32.NewProc("DestroyMenu")
	pTrackPopupMenu     = user32.NewProc("TrackPopupMenu")
	pGetCursorPos       = user32.NewProc("GetCursorPos")
	pSetForegroundWnd   = user32.NewProc("SetForegroundWindow")
	pLoadImageW         = user32.NewProc("LoadImageW")
	pPostMessageW       = user32.NewProc("PostMessageW")
	pShellNotifyIconW   = shell32.NewProc("Shell_NotifyIconW")
	pGetModuleHandleW   = kernel32.NewProc("GetModuleHandleW")
	pGetCurrentThreadID = kernel32.NewProc("GetCurrentThreadId")

	pRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
)

// wmTaskbarCreated：Explorer（任务栏）启动/重启时向所有顶层窗口广播的消息。
//
// 任务栏重启后，**所有托盘图标都会被清空**，应用必须收到这条消息后重新 NIM_ADD，
// 否则图标就永久消失了（直到进程重启）。这是托盘应用的标准做法。
// 消息号由 RegisterWindowMessage 动态分配，不能写死。
var wmTaskbarCreated uint32

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type point struct{ X, Y int32 }

type msgStruct struct {
	hwnd    windows.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

// Tray 托盘图标。生命周期与主程序一致。
type Tray struct {
	hwnd    windows.Handle
	nid     notifyIconData
	ready   chan struct{}
	onShow  func()
	onStart func()
	onStop  func()
	onQuit  func()
	// onEvent 上报托盘生命周期事件（注册成功、任务栏重启后重注册…），
	// 不然托盘出问题完全不可观测——只能靠盯屏幕猜。
	onEvent func(string)
}

// NewTray 创建托盘。回调必须传进来（避免 Tray 反向依赖 Backend）。
func NewTray(iconPath string, onShow, onStart, onStop, onQuit func(), onEvent func(string)) *Tray {
	t := &Tray{ready: make(chan struct{}), onShow: onShow, onStart: onStart, onStop: onStop, onQuit: onQuit, onEvent: onEvent}
	go t.run(iconPath)
	<-t.ready
	return t
}

func (t *Tray) run(iconPath string) {
	// 窗口 + 消息循环必须在同一条被锁定的 OS 线程上
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInst, _, _ := pGetModuleHandleW.Call(0)
	className, _ := syscall.UTF16PtrFromString("nethubTrayWnd")

	// 动态取 "TaskbarCreated" 的消息号（用于任务栏重启后重新注册图标）
	if name, err := syscall.UTF16PtrFromString("TaskbarCreated"); err == nil {
		if r, _, _ := pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(name))); r != 0 {
			wmTaskbarCreated = uint32(r)
		}
	}

	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   syscall.NewCallback(t.wndProc),
		hInstance:     windows.Handle(hInst),
		lpszClassName: className,
	}
	if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		// 类已注册（第二次启动同一进程内）也走这里，不致命
		_ = err
	}

	hwnd, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(className)), 0, 0, 0, 0, 0, 0, 0, hInst, 0)
	if hwnd == 0 {
		close(t.ready)
		return
	}
	t.hwnd = windows.Handle(hwnd)

	// 图标：优先用 exe 同目录的 .ico，拿不到就用系统默认图标
	var hIcon windows.Handle
	if iconPath != "" {
		p, _ := syscall.UTF16PtrFromString(iconPath)
		const imageIcon, lrLoadFromFile = 1, 0x0010
		if h, _, _ := pLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), imageIcon, 16, 16, lrLoadFromFile); h != 0 {
			hIcon = windows.Handle(h)
		}
	}
	if hIcon == 0 {
		if h, _, _ := pLoadImageW.Call(0, 32512, 1, 0, 0, 0x8000); h != 0 { // IDI_APPLICATION via MAKEINTRESOURCE
			hIcon = windows.Handle(h)
		}
	}

	t.nid = notifyIconData{
		cbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		hWnd:             t.hwnd,
		uID:              1,
		uFlags:           nifIcon | nifMessage | nifTip,
		uCallbackMessage: wmTrayMsg,
		hIcon:            hIcon,
	}
	copyUTF16(t.nid.szTip[:], "NetHub · 内网隧道代理（双击图标打开窗口）")
	if r, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid))); r == 0 {
		t.event("托盘图标注册失败（Shell_NotifyIconW 返回 0）")
	} else {
		t.event("托盘图标已注册")
	}

	close(t.ready)

	var m msgStruct
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (t *Tray) event(msg string) {
	if t != nil && t.onEvent != nil {
		t.onEvent(msg)
	}
}

func (t *Tray) wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	// 任务栏重启 → 重新挂上图标（此时旧图标已经被系统清掉了）
	if wmTaskbarCreated != 0 && msg == wmTaskbarCreated {
		if r, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid))); r != 0 {
			t.event("任务栏(Explorer)重启，已重新注册托盘图标")
		} else {
			t.event("任务栏(Explorer)重启，重新注册托盘图标失败")
		}
		return 0
	}

	switch msg {
	case wmTrayMsg:
		switch uint32(lParam) & 0xffff {
		case wmRButtonUp:
			t.popupMenu()
		case wmLButtonDBLCLK:
			if t.onShow != nil {
				t.onShow()
			}
		}
		return 0
	case wmCommand:
		switch wParam & 0xffff {
		case idShow:
			if t.onShow != nil {
				t.onShow()
			}
		case idStart:
			if t.onStart != nil {
				t.onStart()
			}
		case idStop:
			if t.onStop != nil {
				t.onStop()
			}
		case idQuit:
			if t.onQuit != nil {
				t.onQuit()
			}
		}
		return 0
	case wmClose:
		pDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func (t *Tray) popupMenu() {
	hMenu, _, _ := pCreatePopupMenu.Call()
	defer pDestroyMenu.Call(hMenu)

	add := func(flags uintptr, id uintptr, text string) {
		var p *uint16
		if text != "" {
			p, _ = syscall.UTF16PtrFromString(text)
		}
		pAppendMenuW.Call(hMenu, flags, id, uintptr(unsafe.Pointer(p)))
	}
	add(mfString, idShow, "显示主界面")
	add(mfSeparator, 0, "")
	add(mfString, idStart, "启动服务")
	add(mfString, idStop, "停止服务")
	add(mfSeparator, 0, "")
	add(mfString, idQuit, "退出")

	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// 必须先把窗口设成前台，否则点菜单外部时菜单不消失
	pSetForegroundWnd.Call(uintptr(t.hwnd))
	pTrackPopupMenu.Call(hMenu, tpmRightButton|tpmBottomAlign, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0)
}

// Remove 注销托盘图标（退出前调用，否则图标会残留到鼠标划过）。
func (t *Tray) Remove() {
	if t == nil || t.hwnd == 0 {
		return
	}
	pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
	// 关掉消息循环
	pPostMessageW.Call(uintptr(t.hwnd), wmClose, 0, 0)
}

func copyUTF16(dst []uint16, s string) {
	src := syscall.StringToUTF16(s)
	n := len(src)
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst[:n], src[:n])
	if n > 0 {
		dst[n-1] = 0
	}
}
