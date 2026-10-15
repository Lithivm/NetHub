//go:build windows

package app

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// waitTimeout WAIT_TIMEOUT：等一个句柄等到超时了（说明它还没被激发）。
const waitTimeout = 0x102

// processAlive 进程是否还活着。
//
// 为什么不用 os.FindProcess：Windows 上它总会成功（不像 Unix 会去探信号），
// 判不出来。这里 OpenProcess + WaitForSingleObject 两步：打不开＝进程没了；
// 打得开也可能是“已退出的僵尸句柄”，所以要再问一句退没退。
//
// 用途：运行态文件（runtime.json）是进程写的，被强杀时会停在“运行中”，
// 外部（-status / -apply）据此判断它到底还在不在。
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	// ⚠ 权限位要**按实际要做的事**选：WaitForSingleObject 需要 SYNCHRONIZE，
	// 只开 PROCESS_QUERY_LIMITED_INFORMATION 会得到 "Access is denied"（实测踩过），
	// QUERY_INFORMATION 对高完整性级的进程则直接被拒 —— 只有这两个位一起给才既能开又能等。
	const access = 0x1000 | 0x00100000 // PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
	h, err := syscall.OpenProcess(access, false, uint32(pid))
	if err != nil || h == 0 {
		// ⚠ **“打不开”不等于“没了”**（2026-10-15 实测踩到）：服务是 LocalSystem 跑的，
		// 普通用户（非提权）跑 -status 时 OpenProcess 会回 ERROR_ACCESS_DENIED ——
		// 旧代码据此判定“进程已退出”，于是在最常見的「服务模式 + 普通用户」下，
		// -status 一直说没实例在跑（而日志、runtime.json 都还在更新）。
		//
		// 判据：只有 ERROR_INVALID_PARAMETER（pid 不存在）才是真没了；
		// 权限不足一律按“活着”处理 —— 两边的代价不对称：
		//   误报“死” → 用户以为没实例在跑 → 再起一个 → 两个引擎抢过滤器（静默出错）
		//   误报“活” → -apply 少做一次热更（看得见，重跑一次就行）
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return true
		}
		return false
	}
	defer syscall.CloseHandle(h)
	ev, err := syscall.WaitForSingleObject(h, 0)
	if err != nil {
		return false
	}
	return ev == waitTimeout
}
