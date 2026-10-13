package proc

import (
	"strings"
	"syscall"
	"unsafe"
)

// 工具：数某个进程名下的子进程还剩几个。
//
// 为什么界面/引擎两边都需要它：界面的浏览器子进程（msedgewebview2.exe）被外部程序
// 按名字杀干净之后，Wails 会弹一个模态报错框、**等用户点确定**才 os.Exit ——
// 界面进程就卡在那儿（实测：进程活着、窗口没了、看护以为它还正常，永远不会重启）。
// 所以两边都拿"孩子还在不在"当存活判据：
//   - 界面进程：孩子全没了就立刻自己退出（别等那个框被点）；
//   - 引擎进程：界面进程活着但孩子长时间为空 = 半死，动手结束它走正常重启。
//
// 返回 -1 表示拿不到进程快照（极少数情况）：调用方要按"不知道"处理，
// 绝不能当成 0 —— 那会把健康进程误判成死掉的。

const th32csSnapProcess = 0x00000002

var (
	pCreateToolhelpSnapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	pProcess32First         = kernel32.NewProc("Process32FirstW")
	pProcess32Next          = kernel32.NewProc("Process32NextW")
)

// processEntry32 对应 PROCESSENTRY32W（字段顺序/宽度必须一致，
// 特别是 th32DefaultHeapID 是 ULONG_PTR —— 64 位下 8 字节）。
type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// ChildrenByName 数 pid 的子进程里、映像名等于 name 的有几个（忽略大小写）。
func ChildrenByName(pid uint32, name string) int {
	h, _, _ := pCreateToolhelpSnapshot.Call(uintptr(th32csSnapProcess), 0)
	if h == 0 || h == uintptr(^uintptr(0)) {
		return -1
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	var e processEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	r, _, _ := pProcess32First.Call(h, uintptr(unsafe.Pointer(&e)))
	n := 0
	for r != 0 {
		if e.ParentProcessID == pid && strings.EqualFold(syscall.UTF16ToString(e.ExeFile[:]), name) {
			n++
		}
		e.Size = uint32(unsafe.Sizeof(e)) // 每次调用都要重新填 dwSize
		r, _, _ = pProcess32Next.Call(h, uintptr(unsafe.Pointer(&e)))
	}
	return n
}
