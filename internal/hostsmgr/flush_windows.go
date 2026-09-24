//go:build windows

package hostsmgr

import (
	"sync"
	"syscall"

	"nethub/internal/winrun"
)

var (
	dnsProcOnce sync.Once
	dnsProc     *syscall.LazyProc
)

// flushDNS 让系统重新读 hosts：不改这一步，改完 hosts 之后系统可能继续用缓存里的旧地址
// （表现成"改了没反应/一会儿才生效"）。
// DnsFlushResolverCache 是 dnsapi.dll 里的公开接口，比起一个 ipconfig 进程便宜得多。
func flushDNS() error {
	dnsProcOnce.Do(func() {
		dnsProc = syscall.NewLazyDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")
	})
	if err := dnsProc.Find(); err == nil {
		if r, _, err := dnsProc.Call(); r != 0 {
			return nil
		} else if err == nil {
			return nil // 返回 0 但没报错：也算刷过了（该接口不保证返回值）
		}
	}
	// 退路：老办法起一个 ipconfig。**必须走 winrun**：本程序是 GUI 子系统、自己没有
	// 控制台，裸 exec 一个控制台程序会弹出一个黑框（同包内 winrun 的注释里写了这个坑，
	// 这里曾经是唯一漏网的一处）。
	_, err := winrun.Command("ipconfig", "/flushdns").CombinedOutput()
	return err
}
