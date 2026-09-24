// 启动时读一次 Windows DNS 客户端缓存，把“NetHub 启动之前就解析过的名字”灌进名字表。
//
// 为什么要这一步：
//  1. 只读嗅探只能看到“我们启动之后”的查询 —— 启动前应用已经解析过的名字，
//     第一次连接会被我们漏掉；
//  2. 系统级 DoH（Windows 原生）虽然看不到明文报文，但**仍会写这份缓存**，
//     所以这一步顺带覆盖了那种场景。
//
// 实现走 dnsapi.dll 的两个老 API（WinDivert 那套本来就是 Windows 专用，这里一致）：
//
//	DnsGetCacheDataTable      列出缓存里的名字
//	DnsQuery_A(NO_WIRE_QUERY) 对每个名字只查本地缓存，取 A 记录
//
// 任何一步失败都只是“没灌成”，打一条日志就完 —— 绝不能影响主流程。
package engine

import (
	"net"
	"time"
	"unsafe"

	"nethub/internal/dnsmap"

	"golang.org/x/sys/windows"
)

// DNS 查询类型与标志（winDNS.h）
const (
	dnsTypeA          = 0x0001
	dnsQueryNoWire    = 0x00000001 // 只用缓存，不发网络请求
	dnsQueryNoNetwork = 0x00000002
)

// dnsCacheEntry 对应 DNS_CACHE_ENTRY（只取前几个字段，够用）。
type dnsCacheEntry struct {
	Next     *dnsCacheEntry
	Name     *uint16
	Type     uint16
	DataLen  uint16
	Flags    uint32
	_padding uint32
}

// dnsRecord 只需要名字/类型/数据这几个字段的布局（完整的结构体很长）。
type dnsRecord struct {
	Next     *dnsRecord
	Name     *uint16
	Type     uint16
	DataLen  uint16
	Flags    uint32
	TTL      uint32
	Reserved uint32
	Data     [1]byte // 后面跟 A 记录的 4 字节
}

var (
	dnsapiDLL             = windows.NewLazySystemDLL("dnsapi.dll")
	procGetCacheDataTable = dnsapiDLL.NewProc("DnsGetCacheDataTable")
	procQueryA            = dnsapiDLL.NewProc("DnsQuery_A")
	procRecordListFree    = dnsapiDLL.NewProc("DnsRecordListFree")
)

// dnsCacheSeed 读缓存并把 A 记录灌进名字表。返回灌进去的名字数。
func (e *Engine) dnsCacheSeed() int {
	if e.names == nil {
		return 0
	}
	var head *dnsCacheEntry
	ret, _, _ := procGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if ret == 0 || head == nil {
		return 0
	}

	ttl := 12 * time.Hour // 缓存里的表项没有可靠的剩余 TTL；给长一点，靠定期复查兜底
	n := 0
	seen := map[string]bool{}
	for p := head; p != nil; p = p.Next {
		if p.Name == nil || seen[windows.UTF16PtrToString(p.Name)] {
			continue
		}
		name := windows.UTF16PtrToString(p.Name)
		seen[name] = true
		if len(name) == 0 || len(name) > 253 {
			continue
		}
		ips := dnsCacheLookupA(name)
		if len(ips) == 0 {
			continue
		}
		e.names.SetWithTTL(name, ips, dnsmap.PrioObserved, ttl)
		n++
	}
	if n > 0 {
		e.applyHostIPs()
	}
	return n
}

// seedDNSCache 后台读一次 Windows DNS 缓存并灌进名字表。
//
// 为什么不直接在 Start 里同步做：本机实测这一步要 16.3 秒（缓存条目多 +
// 逐条 DnsQuery_A），而它只补“按名字匹配的覆盖面”—— 旧实现把“服务已就绪”
// 噎在它后面十几秒，代价远大于收益。
func (e *Engine) seedDNSCache() {
	t0 := time.Now()
	n := e.dnsCacheSeed()
	e.bus.Detail("dns.seed: names=%d source=windows-dns-cache ms=%d", n, time.Since(t0).Milliseconds())
}

// dnsCacheLookupA 只从缓存里取这个名字的 A 记录（不发网络请求）。
func dnsCacheLookupA(name string) []string {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil
	}
	var res *dnsRecord
	ret, _, _ := procQueryA.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(dnsTypeA),
		uintptr(dnsQueryNoWire|dnsQueryNoNetwork),
		0, // pExtra
		uintptr(unsafe.Pointer(&res)),
		0, // pReserved
	)
	if ret != 0 || res == nil {
		return nil
	}
	defer procRecordListFree.Call(uintptr(unsafe.Pointer(res)), 0) // DNS_FREE_TYPE_FLAT

	var out []string
	for r := res; r != nil; r = r.Next {
		if r.Type != dnsTypeA || r.DataLen < 4 {
			continue
		}
		data := (*[4]byte)(unsafe.Pointer(&r.Data[0]))
		out = append(out, net.IPv4(data[0], data[1], data[2], data[3]).String())
	}
	return out
}
