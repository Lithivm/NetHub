package logbus

import (
	"strings"
	"testing"
	"time"
)

// 回归：订阅者一边退订（关通道）、一边还有日志在广播时，不能往已关闭的通道发送。
// 旧实现把 subs 切片拷出来后在锁外发送，Unsubscribe 关通道后发送方会 panic。
func TestUnsubscribeDuringLogDoesNotPanic(t *testing.T) {
	b := New(100)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 20000; i++ {
			b.Info("x %d", i)
		}
		close(done)
	}()

	for i := 0; i < 500; i++ {
		ch := b.Subscribe()
		// 拿一两条（也可能一条没拿到），然后退订
		select {
		case <-ch:
		default:
		}
		b.Unsubscribe(ch)
	}
	<-done
}

// Throttle：同一 key 窗口内只放行一次，放行时把“上一窗口吞了多少”补出来。
//
// 为什么要这条断言：去重本身很好测，但“吞掉的条数必须说出来”才是关键 ——
// 少了它就是日志在骗人（看起来只发生过一次）。
func TestThrottleReportsSuppressed(t *testing.T) {
	b := New(50)
	// 第一次一定放行，且没有 suppressed 行
	if !b.Throttle("k", 0, "evt: n=%d", 1) {
		t.Fatal("第一次应当放行")
	}
	if got := drain(b); got != "evt: n=1" {
		t.Fatalf("第一次的输出不对: %q", got)
	}
	// 窗口内重复：全被吞掉
	for i := 0; i < 5; i++ {
		if b.Throttle("k", time.Hour, "evt: n=%d", i) {
			t.Fatal("窗口内不该放行")
		}
	}
	if got := drain(b); got != "" {
		t.Fatalf("窗口内不该输出任何东西，得到 %q", got)
	}
	// 窗口过了：先补 suppressed，再写本条
	if !b.Throttle("k", 0, "evt: n=9") {
		t.Fatal("窗口过后应当放行")
	}
	got := drain(b)
	if !strings.Contains(got, "suppressed: key=k count=5") {
		t.Errorf("必须补出被吞掉的条数: %q", got)
	}
	if !strings.Contains(got, "evt: n=9") {
		t.Errorf("补完计数后要写这一条: %q", got)
	}
	if strings.Index(got, "suppressed") > strings.Index(got, "evt: n=9") {
		t.Errorf("suppressed 应当在本条之前: %q", got)
	}
}

// FlushThrottled：窗口里最后那一串重复，必须由巡检补出来（否则凭空消失）。
func TestFlushThrottled(t *testing.T) {
	b := New(50)
	b.Throttle("k", time.Millisecond, "evt")
	for i := 0; i < 3; i++ {
		b.Throttle("k", time.Millisecond, "evt")
	}
	_ = drain(b)
	time.Sleep(5 * time.Millisecond)
	b.FlushThrottled()
	if got := drain(b); !strings.Contains(got, "suppressed: key=k count=3") {
		t.Errorf("巡检应当把尾巴补出来: %q", got)
	}
	// 补过就不再重复补
	b.FlushThrottled()
	if got := drain(b); got != "" {
		t.Errorf("不能重复补同一批计数: %q", got)
	}
}

// 三档：Detail 只在 verbose 以上写，Debug 只在 debug 写（级别仍是 INFO，
// 脚本按级别过滤不会漏）。
func TestLevels(t *testing.T) {
	b := New(50)
	b.Detail("verbose-only: n=%d", 1)
	b.Debug("debug-only: n=%d", 1)
	if got := drain(b); got != "" {
		t.Fatalf("默认（normal）不该输出 Detail/Debug: %q", got)
	}
	if b.Level() != LevelNormal || b.Verbose() || b.IsDebug() {
		t.Fatalf("默认档位应当是 normal，得到 %v", b.Level())
	}

	b.SetLevel(LevelVerbose)
	if !b.Verbose() || b.IsDebug() {
		t.Fatalf("verbose 档：Verbose=true IsDebug=false，得到 %v", b.Level())
	}
	b.Detail("verbose-only: n=%d", 2)
	b.Debug("debug-only: n=%d", 2)
	if got := drain(b); !strings.Contains(got, "verbose-only: n=2") || strings.Contains(got, "debug-only") {
		t.Errorf("verbose 档应当只输出 Detail: %q", got)
	}

	b.SetLevel(LevelDebug)
	if !b.Verbose() || !b.IsDebug() {
		t.Fatalf("debug 档：两个都得为 true，得到 %v", b.Level())
	}
	b.Detail("verbose-only: n=%d", 3)
	b.Debug("debug-only: n=%d", 3)
	got := drain(b)
	if !strings.Contains(got, "verbose-only: n=3") || !strings.Contains(got, "debug-only: n=3") {
		t.Errorf("debug 档应当两个都输出: %q", got)
	}
}

// 配置里的字面量 ↔ 档位：认不出的（含空、旧值）一律 normal ——
// 宁可少写，不要因错一个字把日志刷爆。
func TestParseLevel(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Level
	}{
		{"", LevelNormal}, {"normal", LevelNormal}, {"NORMAL", LevelNormal},
		{" verbose ", LevelVerbose}, {"debug", LevelDebug}, {"Debug", LevelDebug},
		{"true", LevelNormal}, {"off", LevelNormal},
	} {
		if got := ParseLevel(c.in); got != c.want {
			t.Errorf("ParseLevel(%q) = %v，想要 %v", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		in   Level
		want string
	}{
		{LevelNormal, "normal"}, {LevelVerbose, "verbose"}, {LevelDebug, "debug"},
	} {
		if got := c.in.String(); got != c.want {
			t.Errorf("Level(%d).String() = %q，想要 %q", c.in, got, c.want)
		}
	}
}

// drain 把当前环形缓冲里的内容拼起来并清空（只看文本，不关心时间戳）。
func drain(b *Bus) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.ring))
	for _, l := range b.ring {
		out = append(out, l.Text)
	}
	b.ring = nil
	return strings.Join(out, "\n")
}
