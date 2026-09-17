// 深色标题栏（Windows 10 20H1+ / Windows 11）。
//
// 不走这个 API 的话，深色界面顶上是条白色标题栏，非常突兀。
// 属性号在不同版本上不一样（19 = 早期内部版，20 = 正式），两个都试一遍。
package gui

import (
	"unsafe"

	"github.com/ying32/govcl/vcl"
	"golang.org/x/sys/windows"
)

const (
	dwmwaUseImmersiveDarkMode    = 20
	dwmwaUseImmersiveDarkModeOld = 19
)

func setDarkTitleBar(f *vcl.TForm, dark bool) {
	if f == nil || !f.HandleAllocated() {
		return
	}
	hwnd := f.Handle()
	if hwnd == 0 {
		return
	}
	var v int32
	if dark {
		v = 1
	}
	dwm := windows.NewLazySystemDLL("dwmapi.dll")
	proc := dwm.NewProc("DwmSetWindowAttribute")
	for _, attr := range []uintptr{dwmwaUseImmersiveDarkMode, dwmwaUseImmersiveDarkModeOld} {
		r, _, _ := proc.Call(hwnd, attr, uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v))
		if r == 0 { // S_OK
			break
		}
	}
}
