package engine

import (
	"testing"
	"unsafe"

	"github.com/imgk/divert-go"
)

// 地址的字节序：WinDivert 把地址声明成 `UINT32 Addr[4]`（主机序），所以 IPv4 在内存里是
// **小端**存的。本地探针实测按正序切字节会把 10.10.10.237 显示成 237.10.10.10 ——
// 这种"看着像 IP、其实反了"的错最容易被当成网络问题去查，所以钉住。
func TestIPOfLittleEndian(t *testing.T) {
	// 内存里的样子：10.10.10.237 作为 uint32 小端存下来就是 ED 0A 0A 0A
	b := [16]uint8{0xED, 0x0A, 0x0A, 0x0A}
	if got := ipOf(b).String(); got != "10.10.10.237" {
		t.Errorf("ipOf = %s，期望 10.10.10.237（字节序搞反了？）", got)
	}
	// 顺带确认没把后面 12 个零字节当地址的一部分
	if got := ipOf([16]uint8{0x01, 0, 0, 0x7F}).String(); got != "127.0.0.1" {
		t.Errorf("ipOf = %s，期望 127.0.0.1", got)
	}
}

// 布局自检：从 Address 里按偏移取联合体，是 SOCKET/REFLECT 那两层的**前提**。
// 官方 windivert.c 里也有一组静态断言钉着同样的数字（sizeof(WINDIVERT_ADDRESS)==80、
// offsetof(WINDIVERT_DATA_SOCKET, Protocol)==56）—— 这里用 Go 侧再钉一遍，绑定一升级就会红。
func TestDivertAddressLayout(t *testing.T) {
	if sz := unsafe.Sizeof(divert.Address{}); sz != 80 {
		t.Errorf("divert.Address 大小 = %d，期望 80（addrUnionOffset 要重算）", sz)
	}
	// Socket 结构里 Protocol 的偏移：8(EndpointID)+8(ParentEndpointID)+4(ProcessID)
	// +16(LocalAddr)+16(RemoteAddr)+2(LocalPort)+2(RemotePort) = 56
	if off := unsafe.Offsetof(divert.Socket{}.Protocol); off != 56 {
		t.Errorf("divert.Socket.Protocol 偏移 = %d，期望 56 —— 结构布局变了", off)
	}
	// 联合体确实落在 16：socketOf 必须正好指到 union 的起点
	var a divert.Address
	if got, want := uintptr(unsafe.Pointer(socketOf(&a))), uintptr(unsafe.Pointer(&a))+addrUnionOffset; got != want {
		t.Errorf("socketOf 指到 %#x，期望 %#x", got, want)
	}
	// ProcessID 在 union 内的偏移是 16 → 从 Address 起算共 32
	if got, want := uintptr(unsafe.Pointer(&socketOf(&a).ProcessID)), uintptr(unsafe.Pointer(&a))+addrUnionOffset+16; got != want {
		t.Errorf("ProcessID 落在 %#x，期望 %#x", got, want)
	}
}
