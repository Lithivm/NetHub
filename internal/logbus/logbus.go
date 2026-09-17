// Package logbus 是一个极简的日志广播器：
// 引擎/子进程/UI 都往这里写，订阅者（GUI 日志窗口、文件）各自收。
package logbus

import (
	"fmt"
	"os"
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
}

func New(max int) *Bus {
	if max <= 0 {
		max = 2000
	}
	return &Bus{max: max}
}

// SetFile 额外把日志写到文件（失败不致命，只报告一次）。
func (b *Bus) SetFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.file, b.filePath = f, path
	b.mu.Unlock()
	return nil
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
	subs := b.subs
	f := b.file
	b.mu.Unlock()

	if f != nil {
		fmt.Fprintln(f, l.String())
	}
	for _, s := range subs {
		select {
		case s <- l:
		default: // 订阅者跟不上，丢这一条，不要卡住引擎
		}
	}
}

func (b *Bus) Info(format string, a ...any)  { b.log("INFO", format, a...) }
func (b *Bus) Warn(format string, a ...any)  { b.log("WARN", format, a...) }
func (b *Bus) Error(format string, a ...any) { b.log("ERROR", format, a...) }

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
