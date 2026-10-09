package engine

import (
	"net"
	"strings"
	"time"
)

// ───────────────────── “这是我们自己发的连接” ─────────────────────
//
// 背景（2026-10-09 用户报的）：每次刚启动，连接列表里都会冒出几条 `nethub.exe` 的连接，
// 看着像应用流量 —— 用户原话「纯误导」。它们确实是真的连接，来源是**本进程自己的探针**：
// 自检 / 与 Clash 共存检测会**直接 dial** 内网目标（走系统栈、拿真实 TLS 响应来判断通不通），
// 而那些目标本来就在我们的接管网段里 → 被自己的内核过滤器接住 → 变成一条 nethub.exe 的连接。
//
// 处理原则：探针该走真实系统路径（那正是它要测的东西），但它**不该冒充应用流量** ——
// 所以：不显示在连接列表、不计入累计/各链累计、也不进进程名解析率。
//
// 实现要点：在 **connect 之前** 把本地端口登记进来（DialSelf 里的 Control 回调），
// 这样建条目那一刻就能认出它 —— 不能等 dial 返回再标（失败的那些连接根本拿不到端口，
// 而启动时恰恰有一批失败探测）。

// MarkSelfPort 登记一个“这是我们自己发起的连接”的本地端口。
func (e *Engine) MarkSelfPort(port uint16) {
	if port == 0 {
		return
	}
	e.mu.Lock()
	if e.selfPorts == nil {
		e.selfPorts = map[uint16]time.Time{}
	}
	e.selfPorts[port] = time.Now()
	e.mu.Unlock()
}

// UnmarkSelfPort 取消登记（挑好的端口被别人抢走时用）。
func (e *Engine) UnmarkSelfPort(port uint16) {
	e.mu.Lock()
	delete(e.selfPorts, port)
	e.mu.Unlock()
}

// SelfPortCount 当前登记为“自己人”的本地端口数（供 debug 转储说明用）。
func (e *Engine) SelfPortCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.selfPorts)
}

// DialSelf 本进程去连一个**可能被我们自己接管**的地址（自检、共存检测等探针用）。
//
// 与 net.DialTimeout 的差别只有一处：在 connect 之前把本地端口登记为“自己人”，
// 于是这条连接被我们的过滤器接住时不会被当成应用流量（见本文件顶部）。
// 探针本身仍然走真实的系统路径。
//
// 为什么是自己挑端口（而不是等系统分）：Windows 上对**未连接**的 socket 调 getsockname
// 直接报 WSAEINVAL（实测 2026-10-09，连 bind 先占一个端口也被拒）——
// 所以反过来：先用 Listen 拿一个空闲端口、关掉、登记，再带 LocalAddr 去连。
// 中间那个“可能被抢”的窗口极小，抢到就换一个重试。
func (e *Engine) DialSelf(network, addr string, timeout time.Duration) (net.Conn, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		port, err := freeLocalPort()
		if err != nil {
			return nil, err
		}
		e.MarkSelfPort(port)
		d := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{Port: int(port)}}
		conn, err := d.Dial(network, addr)
		if err == nil {
			return conn, nil
		}
		e.UnmarkSelfPort(port)
		lastErr = err
		// 只有“挑的端口被人抢了”才值得重试；其他错误（拒绝/超时）直接退回去
		if !strings.Contains(err.Error(), "bind") {
			return nil, err
		}
	}
	return nil, lastErr
}

// freeLocalPort 让系统给一个空闲的本地端口（拿完立刻释放）。
func freeLocalPort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return uint16(port), nil
}

// pruneSelfPorts 丢掉登记过久的端口（端口会被系统复用，留太久会误判应用连接）。
// 只由 janitor 调用。
func (e *Engine) pruneSelfPorts() {
	e.mu.Lock()
	for p, t := range e.selfPorts {
		if time.Since(t) > 2*time.Minute {
			delete(e.selfPorts, p)
		}
	}
	e.mu.Unlock()
}
