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

// Detail：只有打开详细模式才输出（级别仍是 INFO，脚本按级别过滤不会漏）。
func TestDetailOnlyWhenVerbose(t *testing.T) {
	b := New(50)
	b.Detail("noisy: n=%d", 1)
	if got := drain(b); got != "" {
		t.Fatalf("默认不该输出 Detail: %q", got)
	}
	b.SetVerbose(true)
	if !b.Verbose() {
		t.Fatal("SetVerbose(true) 之后应当是详细模式")
	}
	b.Detail("noisy: n=%d", 2)
	if got := drain(b); !strings.Contains(got, "noisy: n=2") {
		t.Errorf("详细模式下应当输出: %q", got)
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
