package logbus

import "testing"

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
