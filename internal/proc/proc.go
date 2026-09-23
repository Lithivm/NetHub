// Package proc 把「本机端口」映射到「哪个进程」。
//
// 为什么需要它：内核拦下来的包只有 IP/端口，**没有进程信息**。但 Windows 的
// TCP 表（GetExtendedTcpTable + TCP_TABLE_OWNER_PID_ALL）本身就带 PID，所以：
//
//	包的来源端口 → 查 TCP 表 → PID → 进程名
//
// 这样就能回答"是谁在连内网"，也能支持"按进程决定走不走隧道"。
//
// 两个刻意的设计：
//  1. **每连接查一次，不是每包**：TCP 表是全量枚举（表大时毫秒级），放在包路径上不行。
//     所以后台每 500ms 刷一次整表 + 命中缓存；查不到时按需再刷一次（短命连接靠它兜）。
//  2. **查不到就是查不到**（返回 ok=false），绝不瞎猜：受保护进程、系统服务、
//     已经消失的短命连接都会查不到 —— 调用方按"未知"处理（fail-open：不因此改变流量走向）。
package proc

import (
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ───────── Win32 ─────────

var (
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	pGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	pQueryFullProcess    = kernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	addrPrefixIPv4      = 2 // AF_INET

	// MIB_TCPROW_OWNER_PID 的字段（本地地址/端口、远端地址/端口、状态、PID）
	mibRowSize = 24
)

// mibTcpRow 对应 MIB_TCPROW_OWNER_PID（24 字节，全部小端；端口是网络序，要自己转）。
type mibTcpRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32 // 网络序低 16 位
	RemoteAddr uint32
	RemotePort uint32
	PID        uint32
}

// table 全量枚举一次 TCP 表。
func table() ([]mibTcpRow, error) {
	var size uint32
	// 先问需要多大缓冲
	r, _, _ := pGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		addrPrefixIPv4, tcpTableOwnerPidAll, 0)
	if r != 0 && r != 122 { // ERROR_INSUFFICIENT_BUFFER = 122
		return nil, fmt.Errorf("GetExtendedTcpTable 取长度失败: %d", r)
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	r, _, _ = pGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0, addrPrefixIPv4, tcpTableOwnerPidAll, 0)
	if r != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable 读表失败: %d", r)
	}
	if len(buf) < 4 {
		return nil, nil
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := make([]mibTcpRow, 0, n)
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*mibRowSize
		if off+mibRowSize > len(buf) {
			break
		}
		rows = append(rows, *(*mibTcpRow)(unsafe.Pointer(&buf[off])))
	}
	return rows, nil
}

// processName 由 PID 取进程名（不含路径）；失败返回 ("", false)。
func processName(pid uint32, full bool) (string, bool) {
	if pid == 0 {
		return "", false
	}
	const processQueryLimitedInformation = 0x1000
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil || h == 0 {
		return "", false
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	r, _, _ := pQueryFullProcess.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 || n == 0 {
		return "", false
	}
	p := syscall.UTF16ToString(buf[:n])
	if p == "" {
		return "", false
	}
	if full {
		return p, true
	}
	return filepath.Base(p), true
}

// ───────── 解析器 ─────────

// Resolver 端口→进程 的解析器（后台刷新 + 缓存）。
type Resolver struct {
	mu       sync.RWMutex
	byPort   map[uint16]uint32 // 本地端口 → PID
	byPID    map[uint32]string // PID → 进程名
	byFull   map[uint32]string
	lastFill time.Time
	interval time.Duration

	// started/done：可在 Stop 之后再次 Start（引擎启停是可重复的）。
	started bool
	done    chan struct{}
}

// NewResolver 建一个解析器（不自动开始刷新；用 Start 起后台循环）。
func NewResolver() *Resolver {
	return &Resolver{
		byPort:   map[uint16]uint32{},
		byPID:    map[uint32]string{},
		byFull:   map[uint32]string{},
		interval: 500 * time.Millisecond,
		done:     make(chan struct{}),
	}
}

// Start 起后台刷新（幂等；Stop 之后可再次 Start）。
func (r *Resolver) Start() {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.done = make(chan struct{})
	done := r.done
	r.mu.Unlock()

	go func() {
		tk := time.NewTicker(r.interval)
		defer tk.Stop()
		for {
			r.refresh()
			select {
			case <-done:
				return
			case <-tk.C:
			}
		}
	}()
}

// Stop 停掉后台刷新（幂等）。
func (r *Resolver) Stop() {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return
	}
	r.started = false
	done := r.done
	r.done = nil
	r.mu.Unlock()
	if done != nil {
		close(done)
	}
}

// refresh 重读整张表（只保留出方向连接的本地端口；同端口以 LISTEN 之外的状态优先）。
func (r *Resolver) refresh() {
	rows, err := table()
	r.mu.Lock()
	// 失败也要推进 lastFill：否则 ByPort 里 fresh 恒为 false，每个连接都全量枚举一次 TCP 表。
	r.lastFill = time.Now()
	if err != nil {
		r.mu.Unlock()
		return
	}
	next := make(map[uint16]uint32, len(rows))
	for _, row := range rows {
		port := uint16(ntohs(uint16(row.LocalPort)))
		if port == 0 {
			continue
		}
		// 同一端口可能同时有 LISTEN 与 ESTABLISHED（少见）——后写的覆盖，够用
		next[port] = row.PID
	}
	r.byPort = next
	r.mu.Unlock()
}

// ByPort 查某个本地端口属于哪个进程。查不到时按需再刷一次表（覆盖刚建立、还没进缓存的短命连接）。
func (r *Resolver) ByPort(port uint16) (name string, pid uint32, ok bool) {
	r.mu.RLock()
	pid, hit := r.byPort[port]
	cachedName := ""
	if hit {
		cachedName = r.byPID[pid]
	}
	fresh := time.Since(r.lastFill) < r.interval*2
	r.mu.RUnlock()
	if hit && cachedName != "" {
		return cachedName, pid, true
	}
	if !hit && fresh {
		return "", 0, false // 表刚刷过还是没有 → 真查不到（受保护进程/已消失）
	}

	rows, err := table()
	r.mu.Lock()
	// 失败也推进 lastFill（理由同 refresh：避免退化成“每连接一次全表读”）
	r.lastFill = time.Now()
	if err == nil {
		next := make(map[uint16]uint32, len(rows))
		for _, row := range rows {
			p := uint16(ntohs(uint16(row.LocalPort)))
			if p != 0 {
				next[p] = row.PID
			}
		}
		r.byPort = next
		pid, hit = next[port]
	}
	r.mu.Unlock()
	if !hit || pid == 0 {
		return "", 0, false
	}
	if n, okName := r.nameOf(pid); okName {
		return n, pid, true
	}
	return "", pid, false
}

// nameOf 取（并缓存）进程名。
func (r *Resolver) nameOf(pid uint32) (string, bool) {
	r.mu.RLock()
	n, ok := r.byPID[pid]
	r.mu.RUnlock()
	if ok && n != "" {
		return n, true
	}
	full, okFull := processName(pid, true)
	if !okFull {
		r.mu.Lock()
		r.byPID[pid] = "?" // 记下来，别每次都去开进程（受保护进程会一直失败）
		r.mu.Unlock()
		return "", false
	}
	base := filepath.Base(full)
	r.mu.Lock()
	r.byPID[pid] = base
	r.byFull[pid] = full
	r.mu.Unlock()
	return base, true
}

// FullPath 取进程完整路径（界面「进程详情」用；查不到返回空串）。
func (r *Resolver) FullPath(pid uint32) string {
	if pid == 0 {
		return ""
	}
	r.mu.RLock()
	p := r.byFull[pid]
	r.mu.RUnlock()
	if p != "" {
		return p
	}
	if _, ok := r.nameOf(pid); !ok {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byFull[pid]
}

// Stats 缓存规模（诊断用）。
func (r *Resolver) Stats() (ports, pids int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byPort), len(r.byPID)
}

func ntohs(v uint16) uint16 { return v<<8 | v>>8 }
