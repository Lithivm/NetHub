//go:build windows

package webui

import "golang.org/x/sys/windows/registry"

// systemPrefersDark 读 Windows 的「应用使用浅色主题」设置。
//
// 位置：HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize
//
//	AppsUseLightTheme = 1 → 浅色；0 → 深色
//
// 为什么读注册表而不是 `prefers-color-scheme`：
//
//	媒体查询的结果只有**渲染进程**知道，而"界面该是什么色"这件事还要在
//	后端说得清（启动界面进程时要把窗口标题栏配色一起定下来、看护重启界面也要用同一个值）。
//	注册表这一处就能同时服务两边，不必让两套判定各说各话。
//
// 读不到（键不存在/权限）就按浅色 —— 与 Windows 自己的默认值一致。
func systemPrefersDark() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return false
	}
	return v == 0
}
