//go:build windows

package app

import "syscall"

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
		return false
	}
	defer syscall.CloseHandle(h)
	ev, err := syscall.WaitForSingleObject(h, 0)
	if err != nil {
		return false
	}
	return ev == waitTimeout
}
