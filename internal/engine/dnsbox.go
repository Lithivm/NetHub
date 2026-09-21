package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// dnsBlackbox 把 DNS 接管“看到的原始事实”写进独立小文件。
//
// 为什么要有它：排查“DNS 到底是谁弄坏的”时，靠推理没用 —— 必须看到：
//
//	应用发出的查询到底有没有到我们手里？（没到 = 问题在更上层）
//	我们有没有回答它？回答了什么？（答了不该答的 = 我们弄坏的）
//
// 黑匣子的价值在于“事后”：断网时人手忙脚乱，事后再看这几行就知道真相。
// 所以它默认**关闭**（tuning.dns_blackbox: true 才开），并且自带上限轮转。
type dnsBlackbox struct {
	mu      sync.Mutex
	f       *os.File
	path    string
	size    int
	maxSize int
}

func openDNSBlackbox(path string, maxSize int) *dnsBlackbox {
	if maxSize <= 0 {
		maxSize = 4 << 20
	}
	b := &dnsBlackbox{path: path, maxSize: maxSize}
	b.rotateIfNeeded()
	b.Writef("=== DNS 黑匣子开启 %s ===", time.Now().Format("2006-01-02 15:04:05"))
	return b
}

// Writef 追加一行（带时间戳）。写不进就算了 —— 排查工具绝不能影响主功能。
func (b *dnsBlackbox) Writef(format string, a ...any) {
	if b == nil {
		return
	}
	line := fmt.Sprintf("%s %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, a...))
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.f == nil || b.size+len(line) > b.maxSize {
		b.rotateLocked()
	}
	if b.f == nil {
		return
	}
	n, _ := b.f.WriteString(line)
	b.size += n
}

func (b *dnsBlackbox) rotateIfNeeded() {
	st, err := os.Stat(b.path)
	if err == nil && st.Size() > int64(b.maxSize) {
		_ = os.Remove(b.path + ".1")
		_ = os.Rename(b.path, b.path+".1")
	}
}

func (b *dnsBlackbox) rotateLocked() {
	if b.f != nil {
		_ = b.f.Close()
		b.f = nil
	}
	_ = os.Remove(b.path + ".1")
	_ = os.Rename(b.path, b.path+".1")
	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	b.f = f
	b.size = 0
}

func (b *dnsBlackbox) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.f != nil {
		_ = b.f.Close()
		b.f = nil
	}
}

// dnsBlackboxPath 黑匣子放在程序目录（和日志同级），名字一眼能认出来。
func dnsBlackboxPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "dns-blackbox.log"
	}
	return filepath.Join(filepath.Dir(exe), "logs", "dns-blackbox.log")
}
