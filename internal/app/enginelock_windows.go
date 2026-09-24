package app

import (
	"errors"

	"golang.org/x/sys/windows"
)

// 引擎互斥：同一时刻只允许**一个进程**跑引擎 —— 界面版 / Windows 服务版 / -headless
// 三者互斥。以前没有这道保护，两边会各装一套 WinDivert 过滤器去拦同一批包、
// 各自改写到自己的 relay，结果是静默互相干扰（不是"第二个报错退出"）。
//
// 判据是**命名对象存不存在**，而不是 WaitForSingleObject + ReleaseMutex：
// Windows 互斥是**按线程**持有的，而 Start/Stop 会被不同线程调用
// （界面线程点启动、退出流程/托盘线程点停止），跨线程 Release 会 ERROR_NOT_OWNER。
// 只把"对象存在"当锁用，句柄一关就释放；进程无论怎么死，内核都会收掉它的句柄
// —— 所以不存在"上次崩溃留下死锁"的问题。
const engineLockName = `Global\NetHubEngineLock`

// ErrEngineBusy 另一个进程正在跑引擎（服务版、或另一个界面版/headless 实例）。
var ErrEngineBusy = errors.New("引擎已在另一个进程中运行（服务版或另一个实例）")

// engineLock 本进程持有的引擎锁；非 nil 即"我们在跑引擎"。
type engineLock struct{ h windows.Handle }

// acquireEngineLock 抢引擎锁（名字固定，见上）。
//
//	(lock, "", nil)          —— 抢到了
//	(nil, "", ErrEngineBusy) —— 别人在跑
//	(nil, reason, nil)       —— 环境拿不到这个锁（极少见，如策略不给
//	                            SeCreateGlobalPrivilege）：**降级为没有互斥**，
//	                            reason 是要打给用户看的警告。宁可少一道保护，
//	                            也不能因为锁建不出来就让引擎整个起不来。
func acquireEngineLock() (*engineLock, string, error) {
	return acquireNamedLock(engineLockName)
}

func acquireNamedLock(name string) (*engineLock, string, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err.Error(), nil
	}

	// 先**只读探测**一次："有人拿着吗？"
	//
	// 为什么不用 CreateMutex 的 ERROR_ALREADY_EXISTS 直接判定：CreateMutex 要的是
	// MUTEX_ALL_ACCESS，而 Windows 服务跑在 **System 完整性级别**、界面版是 **High** ——
	// 高完整性对象对较低完整性进程是"不可写"的，于是拿不到 ALL_ACCESS，
	// CreateMutex 回的是 ACCESS_DENIED 而不是"已存在"，我们会误判成"环境不支持"而裸奔。
	// SYNCHRONIZE 不属于写权限，跨完整性级别能打开，所以先用它判存在。
	if h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, p); err == nil {
		_ = windows.CloseHandle(h)
		return nil, "", ErrEngineBusy
	}

	h, err := windows.CreateMutex(nil, false, p)
	if h == 0 {
		// 建不出来：极少见（策略不给 SeCreateGlobalPrivilege）；也可能是刚探测完、
		// 高完整性进程抢先建了（窗口是微秒级）。两者都按"没有互斥"降级处理 ——
		// 宁可少一道保护，也不能因为锁建不出来就让引擎整个起不来。
		return nil, err.Error(), nil
	}
	// 竟争输了的那个：CreateMutex 依旧返回一个有效句柄，必须自己关掉 ——
	// 否则我们等于也"持有着"，对方退出后锁会一直留到本进程结束。
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(h)
		return nil, "", ErrEngineBusy
	}
	return &engineLock{h: h}, "", nil
}

// release 放开引擎锁。最后一刻才调（引擎真正停掉之后），
// 否则新进程可能在我们过滤器还没拆掉时就认定"空闲"。
func (l *engineLock) release() {
	if l == nil || l.h == 0 {
		return
	}
	_ = windows.CloseHandle(l.h)
	l.h = 0
}
