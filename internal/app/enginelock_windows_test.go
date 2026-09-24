package app

import (
	"errors"
	"testing"
)

// 引擎互斥的语义。用 Local\ 名字而不是真名 Global\NetHubEngineLock：
// 显式避免与**正在运行的 NetHub** 抢锁（本机跑测试时那个进程正拿着真锁，
// 用真名会让测试红）。
func TestEngineLockSemantics(t *testing.T) {
	name := `Local\NetHubEngineLock__test`

	// 没人拿着 → 抢得到
	l1, degraded, err := acquireNamedLock(name)
	if err != nil {
		t.Fatalf("第一次抢锁不该失败: %v", err)
	}
	if l1 == nil {
		t.Fatalf("抢到了却是 nil lock（degraded=%q）", degraded)
	}

	// 再抢一次：命名对象已存在 → 必须判"别人在跑"。
	// 同进程走的是同一条路径，等价于"另一个进程"的场景。
	l2, _, err := acquireNamedLock(name)
	if !errors.Is(err, ErrEngineBusy) {
		t.Fatalf("第二次抢锁应当返回 ErrEngineBusy，得到 %v", err)
	}
	if l2 != nil {
		t.Error("抢失败时不该返回 lock")
	}

	// 释放之后又能抢到（证明 release 真的放开了，而不是只把句柄存起来）
	l1.release()
	l3, degraded3, err := acquireNamedLock(name)
	if err != nil || l3 == nil {
		t.Fatalf("释放后应当能再抢到: err=%v degraded=%q", err, degraded3)
	}
	l3.release()
	l3.release() // 幂等：重复释放不能炸（Stop 可能被调多次）
}

// 锁建不出来时**降级**而不是报错：宁可少一道保护，也不能因为锁的问题
// 让引擎整个起不来（打开前本来就没有这道保护）。
func TestEngineLockDegradesInsteadOfFailing(t *testing.T) {
	l, reason, err := acquireNamedLock("bad\x00name")
	if err != nil {
		t.Fatalf("环境问题不该返回错误: %v", err)
	}
	if l != nil {
		t.Error("拿不到锁时应当返回 nil lock")
	}
	if reason == "" {
		t.Error("降级时要给出原因（会打成警告日志）")
	}
}
