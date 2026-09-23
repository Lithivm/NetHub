package engine

import (
	"testing"
	"time"

	"nethub/internal/config"
	"nethub/internal/logbus"
	"nethub/internal/rules"
)

// 回归（#9）：Stop 必须幂等，且不能在一次都没 Start 过的引擎上卡住。
// 顺便守住 stopOnce/一次性 done 被重新引入。
func TestStopIsIdempotent(t *testing.T) {
	e := New(logbus.New(50), rules.New(), &config.Config{})

	done := make(chan struct{})
	go func() {
		e.Stop()
		e.Stop() // 第二次必须立刻返回
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop 卡住了（幂等性被破坏？）")
	}
	if !e.stopped {
		t.Fatal("Stop 之后 stopped 应为 true")
	}
}
