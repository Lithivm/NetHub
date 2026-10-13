package app

// 入口进程（用户双击的那个 nethub.exe）要判断"我该当后端还是当界面"：
// 抢到这把锁 = 本进程当后端（跑引擎 + 托盘 + 拉起并看护界面）；
// 抢不到 = 已经有一个后端在跑，本次启动只把它的界面唤回来（见 main.go 的 runEntry）。
//
// 为什么另开一把锁、不复用引擎锁：引擎锁表达的是"谁在跑引擎"（服务版、-headless
// 也拿着它），而且它建不出来时会降级为"没有互斥"。角色归角色 —— 后端只有一个，
// 界面可以有 0 个（被 HIS 启动器杀掉、或还没起来）。
const backendLockName = `Global\NetHubBackendLock`

// AcquireBackendLock 抢"我是后端"这道锁。
//
//	release 非 nil —— 抢到了；进程退出时调它
//	busy = true    —— 别的进程已经是后端
//	warn 非空      —— 环境建不出这把锁（极少见，如策略不给 SeCreateGlobalPrivilege）：
//	                  降级为"当前进程就是后端"。宁可少一道保护，也不能因为锁建不出来
//	                  就整个起不来（沿用引擎锁的同一取舍）。
func AcquireBackendLock() (release func(), busy bool, warn string) {
	l, warn, err := acquireNamedLock(backendLockName)
	if err != nil {
		return nil, true, "" // 别人在跑
	}
	if l == nil {
		return func() {}, false, warn
	}
	return l.release, false, ""
}
