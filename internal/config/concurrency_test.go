package config

import (
	"sync"
	"testing"
)

// 回归（#7）：引擎会在后台 goroutine 里持续读配置，界面线程会改配置。
// 这个测试并发跑「读快照/体检」与「增删改规则」，用于抓：
//   - 重入死锁（sync.RWMutex 不可重入，一旦某处持锁又调加锁方法就会卡死）；
//   - 配合 -race 时暴露真正的数据竞争。
//
// 本机现在没有 CGO 工具链、跑不了 -race，但死锁在这个测试里会直接超时。
func TestConcurrentConfigReadWrite(t *testing.T) {
	c := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "a", Forward: "socks5://1.2.3.4:1080"}},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.ChainsSnapshot()
				_ = c.RoutesSnapshot()
				_, _ = c.ChainByName("a")
				_ = c.UpstreamsResolved(Chain{Name: "a", Forward: "socks5://1.2.3.4:1080"})
				_ = c.Precheck()
				_ = c.Validate()
			}
		}()
	}

	for i := 0; i < 300; i++ {
		rt := Route{Name: "r", Targets: []string{"10.0.0.0/24"}, Chain: "a"}
		if err := c.AddRoute(rt); err != nil {
			t.Fatalf("AddRoute: %v", err)
		}
		rt.Ports = []string{"443"}
		if err := c.UpdateRoute(0, rt); err != nil {
			t.Fatalf("UpdateRoute: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	if n := c.RouteCount(); n != 300 {
		t.Fatalf("规则数 = %d，期望 300", n)
	}

	// ReplaceFrom（导入/回滚路径）也并发跑一遍
	src := &Config{Relay: "127.0.0.1:0", Chains: []Chain{{Name: "b", Forward: "socks5://5.6.7.8:1080"}}}
	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		for i := 0; i < 100; i++ {
			c.ReplaceFrom(src)
			_ = c.ChainsSnapshot()
		}
	}()
	for i := 0; i < 100; i++ {
		_ = c.Snapshot()
	}
	wg2.Wait()
}
