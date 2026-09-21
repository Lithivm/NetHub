package engine

import (
	"fmt"
	"strings"
	"time"
)

// humanBytes 1024 进制的人类可读字节数（日志/界面用）。
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// humanDur 时长的短写法：12s / 3m12s / 1h02m。
func humanDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d.Seconds())
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm%02ds", s/60, s%60)
	default:
		return fmt.Sprintf("%dh%02dm", s/3600, (s%3600)/60)
	}
}

// firstLine 取多行错误的第一行 —— 只给“不打 ERROR”的降级日志用
// （那条日志是 INFO，塞多行会把 INFO 的形态破坏掉；完整报错在别处照常打）。
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
