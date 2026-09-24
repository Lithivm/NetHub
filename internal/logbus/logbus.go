// Package logbus 是一个极简的日志广播器：
// 引擎/子进程/UI 都往这里写，订阅者（GUI 日志窗口、文件）各自收。
package logbus

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Line 是一条日志。
type Line struct {
	Time  time.Time
	Level string // INFO / WARN / ERROR
	Text  string
}

func (l Line) String() string {
	return fmt.Sprintf("%s [%s] %s", l.Time.Format("15:04:05.000"), l.Level, l.Text)
}

type Bus struct {
	mu       sync.RWMutex
	ring     []Line
	max      int
	subs     []chan Line
	file     *os.File
	filePath string
	fileSize int64 // 当前文件已写字节数（用于轮转）
	maxBytes int64 // 单文件上限，超过就轮转
	keep     int   // 保留几个历史文件（nethub.log.1 … .keep）
}

// 日志文件默认策略：单文件 8 MB、保留 2 份历史 → 磁盘占用最多约 24 MB。
//
// 为什么要限：客户机会连跑几个月，出问题时（比如“每 36 秒重试一次”那种坏法）
// 一天就能写出几百 MB；而日志又没人看没人删，不能任它涨。
const (
	DefaultMaxBytes = 8 << 20
	// DefaultKeep 保留几份。
	//
	// 2 份 = 总共只留 16MB：现场出事时日志很可能已经被刷走（一次贴给 agent 的就是
	// 当时那一段，没有上一段就没法对比“之前是不是也这样”）。参考 squid 默认留 10 份、
	// Proxifier 根本不轮转；这里取 5 份（共 40MB）兼顾可回查与占盘。
	DefaultKeep = 5
)

func New(max int) *Bus {
	if max <= 0 {
		max = 2000
	}
	return &Bus{max: max}
}

// SetFile 额外把日志写到文件（失败不致命，只报告一次）。
func (b *Bus) SetFile(path string) error {
	return b.SetFileLimit(path, DefaultMaxBytes, DefaultKeep)
}

// SetFileLimit 同 SetFile，但可指定单文件上限与保留份数（测试用小数）。
func (b *Bus) SetFileLimit(path string, maxBytes int64, keep int) error {
	// 目录不存在就建（日志默认落在 <程序目录>\logs\）
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if keep < 0 {
		keep = 0
	}
	// 已经超过上限（旧版本留下的、或轮转前被强杀） → 先轮转一次再接着写
	var size int64
	if st, err := os.Stat(path); err == nil && st.Size() >= maxBytes {
		rotate(path, keep)
	} else if err == nil {
		size = st.Size()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	b.mu.Lock()
	if b.file != nil {
		b.file.Close()
	}
	b.file, b.filePath, b.fileSize = f, path, size
	b.maxBytes, b.keep = maxBytes, keep
	b.mu.Unlock()
	return nil
}

// rotate 把 log 滚成 log.1（旧的依次后移，超出 keep 份的丢掉）。
// Windows 上 os.Rename 不接受目标已存在，所以先删目标。
func rotate(path string, keep int) {
	if keep > 0 {
		for i := keep; i >= 1; i-- {
			src, dst := path, path+".1"
			if i > 1 {
				src = fmt.Sprintf("%s.%d", path, i-1)
				dst = fmt.Sprintf("%s.%d", path, i)
			}
			_ = os.Remove(dst)
			_ = os.Rename(src, dst)
		}
		return
	}
	_ = os.Remove(path)
}

// FilePath 返回当前日志文件路径（未设置时为空）。
func (b *Bus) FilePath() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.filePath
}

// Subscribe 返回一个通道，收到后续日志。缓冲满时丢弃最旧的，绝不阻塞调用方。
func (b *Bus) Subscribe() chan Line {
	ch := make(chan Line, 512)
	b.mu.Lock()
	b.subs = append(b.subs, ch)
	b.mu.Unlock()
	return ch
}

func (b *Bus) Unsubscribe(ch chan Line) {
	b.mu.Lock()
	for i, s := range b.subs {
		if s == ch {
			b.subs = append(b.subs[:i], b.subs[i+1:]...)
			close(ch)
			break
		}
	}
	b.mu.Unlock()
}

// Snapshot 返回环形缓冲里的历史日志。
func (b *Bus) Snapshot() []Line {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Line, len(b.ring))
	copy(out, b.ring)
	return out
}

func (b *Bus) log(level, format string, args ...any) {
	l := Line{Time: time.Now(), Level: level, Text: fmt.Sprintf(format, args...)}

	b.mu.Lock()
	b.ring = append(b.ring, l)
	if len(b.ring) > b.max {
		b.ring = b.ring[len(b.ring)-b.max:]
	}
	f := b.file
	b.mu.Unlock()

	if f != nil {
		b.writeFile(l)
	}
	// 在 RLock 下发送：Unsubscribe（持写锁）要么在发送前把通道摘掉，
	// 要么等发送完才关 —— 否则往已关闭的通道发送会直接 panic。
	// 发送是非阻塞的，不会把写锁饿死。
	b.mu.RLock()
	for _, s := range b.subs {
		select {
		case s <- l:
		default: // 订阅者跟不上，丢这一条，不要卡住引擎
		}
	}
	b.mu.RUnlock()
}

func (b *Bus) Info(format string, a ...any)  { b.log("INFO", format, a...) }
func (b *Bus) Warn(format string, a ...any)  { b.log("WARN", format, a...) }
func (b *Bus) Error(format string, a ...any) { b.log("ERROR", format, a...) }

// writeFile 写一行到日志文件，超上限就轮转。
// 单独成函数是为了让轮转逻辑只在一处、并且拿到自己那把锁。
func (b *Bus) writeFile(l Line) {
	line := l.String() + "\n"

	b.mu.Lock()
	f := b.file
	if f == nil {
		b.mu.Unlock()
		return
	}
	if b.maxBytes > 0 && b.fileSize+int64(len(line)) > b.maxBytes {
		path, keep := b.filePath, b.keep
		f.Close()
		rotate(path, keep)
		if nf, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			b.file, b.fileSize = nf, 0
			f = nf
			// 轮转这件事本身要留个痕：现场看到上下文断了会以为是程序重启
			sizeText := fmt.Sprintf("%d KB", b.maxBytes>>10)
			if b.maxBytes >= 1<<20 {
				sizeText = fmt.Sprintf("%d MB", b.maxBytes>>20)
			}
			notice := fmt.Sprintf("%s [INFO] 日志已轮转：%s → %s.1（单文件上限 %s，保留 %d 份）\n",
				time.Now().Format("15:04:05.000"), filepath.Base(path), filepath.Base(path), sizeText, keep)
			if _, err := f.WriteString(notice); err == nil {
				b.fileSize += int64(len(notice))
			}
		} else {
			b.file = nil // 轮转后开不回来就别再往里写了
			b.mu.Unlock()
			return
		}
	}
	if n, err := f.WriteString(line); err == nil {
		b.fileSize += int64(n)
	}
	b.mu.Unlock()
}

// Close 关闭文件。
func (b *Bus) Close() {
	b.mu.Lock()
	if b.file != nil {
		b.file.Close()
		b.file = nil
	}
	b.mu.Unlock()
}

// Indent 给多行文本加前缀（GUI 展示子进程输出用）。
func Indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + strings.TrimRight(l, "\r")
	}
	return strings.Join(lines, "\n")
}
