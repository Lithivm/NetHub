package proc

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Alive 判断某个 pid 还活着没。
//
// 现在只有一个用处：界面进程启动时拿到引擎进程的 pid（-parent），拿它当"靠山还在不在"
// 的判据 —— 引擎没了就自己也退出。为什么要这样：引擎被外部强杀时（任务管理器 / 计划任务
// 重启 / 崩溃），界面进程**不会**跟着死，它会变成孤儿：还连着管道、还占着 Wails 的单实例锁
// （wails-app-NetHub-frontendsim）。此后引擎每次拉起新界面，新界面都会"让位"给这个孤儿
// （wails 单实例是发个消息然后 os.Exit(0)），看护循环再把退出码 0 当成"用户主动退出"……
// 结果是托盘点了没反应、重启引擎也没有界面。2026-10-19 现场就是这么坏的：孤儿活了三天。
//
// 判法用进程句柄 + WaitForSingleObject(0)：
//   - 等到了（WAIT_OBJECT_0）= 已退出；
//   - 等到超时（WAIT_TIMEOUT）= 还活着；
//   - 打不开句柄：ERROR_INVALID_PARAMETER 才是"没这个 pid"；**别的错误一律当活着**
//     （拒绝访问之类只是查不了，不能据此让人自杀）。
func Alive(pid uint32) bool {
	if pid == 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(h)
	ev, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return true // 查不了就当活着
	}
	return ev == uint32(windows.WAIT_TIMEOUT)
}
