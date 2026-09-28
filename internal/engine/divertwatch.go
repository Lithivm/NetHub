package engine

// WinDivert 的**非 NETWORK 层**：SOCKET 与 REFLECT。
//
// 为什么加这两个（2026-09-28）：两件事以前都做得很绕。
//
//	SOCKET  —— socket 操作事件（bind/connect/listen/accept/close）里**直接带 ProcessID**。
//	           以前只能靠「每 500ms 全量枚举 TCP 表」反查端口→PID，于是 `intercept:` 那行
//	           日志（连接建立那一刻写的）实测 **60.7% 是 proc=unknown**，而连接结束的
//	           `relay.done:` 大多已经有名字 —— 名字晚到几百毫秒，可运维要回答"谁连的"
//	           读的正是第一行。现在 connect() 那一刻就把 PID 写进同一张表。
//	REFLECT —— WinDivert **自身**的事件：谁开了/关了句柄，**包括我们启动之前就存在的**。
//	           以前遇到《拦截成功但没到中转是静默失败》只能猜（安全软件？Clash 的 TUN？
//	           还是别的程序在抢管）。现在能把"本机还有谁在用 WinDivert"变成一句确定的话。
//	           （注意它**看不到** Clash 的 TUN 与杀软的驱动 —— 那些不是 WinDivert。）
//
// **为什么用 SOCKET 而不是 FLOW**（两个都试过，探针 local/flowprobe 有原始数据）：
// FLOW 的 "建立" 事件要等**握手完成**才报，而我们是在 **SYN** 那一刻改写并写 intercept 日志的 ——
// FLOW 天然晚一拍，补不上那个洞。SOCKET 的 `connect()` 是应用调 connect 时就报，
// 与 SYN 同一刻，实测 `pid=9448 local=192.168.31.85:52443 remote=10.10.10.237:5432`：
// **端口与 PID 都在**，正是我们需要的那一条。
//
// 三条**实测**出来的硬约束（别照文档或源码猜）：
//
//  1. **FILTER 只能用 `true`/`false`**：这个 DLL 不认 `event == connect`（也不认 FLOW 的
//     `event == established`），一律报 87。所以只好接全部 socket 事件、在用户态自己筛
//     （socket 事件是按**操作**计的，不是按包 —— 量很小，多接几种无所谓）。
//  2. **flags 必须是 FlagSniff|FlagRecvOnly**：传 0 或单个 SNIFF 一律 87。语义上也说得通：
//     这几层本来就不能拦、不能注，DLL 要求你显式声明"只看"。而 divert-go 自带的
//     windivert.c 源码里没有这两条限制 —— 说明**库里那份源码与我们手上的 DLL 不是同一份**。
//  3. **地址是 `UINT32 Addr[4]`（主机序）**，所以 IPv4 在内存里是**小端**存的；按正序切字节
//     会得到倒过来的地址（10.10.10.237 显示成 237.10.10.10）。端口不受影响（实测与 relay 端口对得上）。
//  4. divert-go 把 `Address` 的联合体做成了**未导出字段**，包外够不到，所以这里按偏移取
//     （Timestamp 8 + Layer/Event/Flags/Reserved 4 + Length 4 = 16）。官方头文件里也有静态断言
//     钉着这个偏移；下面再用 init 把结构体大小钉一遍 —— 不成立的话取出来的全是垃圾。

import (
	"fmt"
	"net"
	"os"
	"sort"
	"time"
	"unsafe"

	"github.com/imgk/divert-go"
)

// addrUnionOffset 是 WINDIVERT_ADDRESS 里联合体的偏移。
const addrUnionOffset = 16

func init() {
	if unsafe.Sizeof(divert.Address{}) != 80 {
		panic("divert.Address 布局变了（期望 80 字节）—— addrUnionOffset 要重算")
	}
}

func socketOf(a *divert.Address) *divert.Socket {
	return (*divert.Socket)(unsafe.Add(unsafe.Pointer(a), addrUnionOffset))
}

func reflectOf(a *divert.Address) *divert.Reflect {
	return (*divert.Reflect)(unsafe.Add(unsafe.Pointer(a), addrUnionOffset))
}

// ipOf 从 WinDivert 的地址数组里取 IPv4（倒着取，理由见文件头的实测第 3 条）。
func ipOf(b [16]uint8) net.IP {
	return net.IPv4(b[3], b[2], b[1], b[0])
}

// divertPeer 另一个在用 WinDivert 的进程（按 PID 去重，留最近一次看到的参数）。
type divertPeer struct {
	layer    string
	priority int16
	flags    uint64
}

// startDivertNameFeed 开 SOCKET 层，把 connect() 事件里的 PID 喂给端口解析器。
//
// 为什么在用户态筛而不是写在过滤里：这个 DLL 不认 `event == connect`（见文件头实测第 1 条）。
// socket 事件按**操作**计，不是按包 —— 多接几种的量可以忽略。
//
// 失败不影响主流程：进程名继续走原来「500ms 刷表」那条路，只是会晚几百毫秒。
func (e *Engine) startDivertNameFeed() {
	if e.proc == nil {
		return
	}
	h, err := divert.Open("true", divert.LayerSocket, divert.PriorityDefault,
		divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Detail("socketwatch: 打不开 SOCKET 层（%v）—— 进程名继续走 500ms 刷表那条路", err)
		return
	}
	e.mu.Lock()
	e.sockH = h
	e.mu.Unlock()

	go func() {
		var buf [64]byte // SOCKET 的"包"是空的（pktlen=0），事件在地址里
		var addr divert.Address
		n := 0
		for {
			if _, err := h.Recv(buf[:], &addr); err != nil {
				e.bus.Detail("socketwatch: 结束（本轮记了 %d 条 connect）", n)
				return
			}
			if addr.Event() != divert.EventSocketConnect {
				continue // bind/listen/accept/close 我们不关心
			}
			s := socketOf(&addr)
			if s.ProcessID == 0 || s.LocalPort == 0 {
				continue
			}
			e.proc.Record(s.LocalPort, s.ProcessID)
			n++
		}
	}()
	e.bus.Detail("socketwatch: 已开 SOCKET 层（进程名改为事件驱动；刷表那条仍作兜底）")
}

// startDivertReflect 开 REFLECT 层，盯"谁在用 WinDivert"。
//
// REFLECT 会把**我们打开之前就存在的句柄**也重放一遍，所以启动两秒后就能给出一句确定的话：
// "本机只有本进程在用"或者"还有这些进程在用"。后者值得 Warn —— 那正是
// 《拦截成功但没到中转是静默失败》的候选原因之一（安全软件与 Clash 的 TUN **不**在此列）。
func (e *Engine) startDivertReflect() {
	h, err := divert.Open("true", divert.LayerReflect, divert.PriorityDefault,
		divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Detail("reflectwatch: 打不开 REFLECT 层（%v）—— 少了\"谁在拦我的包\"这条线索", err)
		return
	}
	e.mu.Lock()
	e.reflectH = h
	e.mu.Unlock()

	self := uint32(os.Getpid())
	// 启动时那批"已有句柄"由这里汇总。
	//
	// ⚠ 必须**单独一个 goroutine**，不能放在下面那个 for 里：REFLECT 把已有句柄重放完就安静了，
	// 而 `Recv` 是阻塞的 —— 把定时检查写在 Recv 之后，就永远不会执行（实测：一行都打不出来）。
	go func() {
		time.Sleep(2 * time.Second)
		e.mu.Lock()
		e.peersReported = true
		e.mu.Unlock()
		e.reportDivertPeers()
	}()

	go func() {
		var buf [64]byte
		var addr divert.Address
		for {
			if _, err := h.Recv(buf[:], &addr); err != nil {
				return
			}
			r := reflectOf(&addr)
			if r.ProcessID == 0 {
				continue
			}
			e.mu.Lock()
			if e.divertPeers == nil {
				e.divertPeers = map[uint32]divertPeer{}
			}
			var appeared bool
			switch addr.Event() {
			case divert.EventReflectOpen:
				_, known := e.divertPeers[r.ProcessID]
				e.divertPeers[r.ProcessID] = divertPeer{
					layer: r.Layer().String(), priority: r.Priority, flags: r.Flags,
				}
				appeared = !known && e.peersReported
			case divert.EventReflectClose:
				delete(e.divertPeers, r.ProcessID)
			}
			e.mu.Unlock()

			// 汇总之后新出现的（且不是我们自己）才值得单独说一句。
			if appeared && r.ProcessID != self {
				e.bus.Warn("别的进程也开始用 WinDivert 拦包了：pid=%d 层=%v 优先级=%d flags=%#x —— "+
					"出现\"改写的包没到中转\"时先排查它（另一个代理 / 安全软件 / 第二个本程序）",
					r.ProcessID, r.Layer(), r.Priority, r.Flags)
			}
		}
	}()
}

// reportDivertPeers 汇总一次"本机还有谁在用 WinDivert"。
func (e *Engine) reportDivertPeers() {
	peers := e.DivertPeers()
	if len(peers) == 0 {
		e.bus.Detail("reflectwatch: 本机只有本进程在用 WinDivert 过滤器")
		return
	}
	e.bus.Warn("reflectwatch: 本机还有 %d 个进程在用 WinDivert 过滤器：%v", len(peers), peers)
	e.bus.Warn("  它们可能抢走本该由我们处理的包，出现\"改写没到中转\"先排查它们" +
		"（Clash 的 TUN 模式与杀软的驱动**不**在这里显示 —— 那些不是 WinDivert）")
}

// DivertPeers 当前**除本进程之外**在用 WinDivert 的进程（每进程一行；诊断报告与日志用）。
func (e *Engine) DivertPeers() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.divertPeersLocked()
}

func (e *Engine) divertPeersLocked() []string {
	self := uint32(os.Getpid())
	out := make([]string, 0, len(e.divertPeers))
	for pid, p := range e.divertPeers {
		if pid == self {
			continue
		}
		out = append(out, fmt.Sprintf("pid=%d 层=%s 优先级=%d flags=%#x", pid, p.layer, p.priority, p.flags))
	}
	sort.Strings(out)
	return out
}
