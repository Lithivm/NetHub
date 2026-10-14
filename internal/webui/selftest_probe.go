package webui

import (
	"net"
	"sync"
	"time"
)

// guessedProbePorts 自检在"没有真实访问记录"时猜的常见端口。
//
// ⚠ 这条路上的端口是**猜**的：全没通不能说明链路有问题（见 runSelfTest 里那段注释，
// 真实事故：服务在 9054，而列表里没有这个端口 → 误报"链路有问题"）。
var guessedProbePorts = []uint16{443, 80, 5432, 6446, 5000, 9054, 9056}

// probeGuessedParallel 并发试 (候选 IP × 常见端口)，谁先通就用谁；整轮有总上限。
//
// 为什么要并发（2026-10-13 实测）：每条失败的尝试要等满上游连接超时（6 秒），
// 而这里是**串行**扫"候选 IP × 7 个端口"，一条链就能吃 20~40 秒；更糟的是
// **整轮自检本身也是串行的**，于是它把后面所有链一起拖住 —— 实测整轮 25 秒里
// 有 22.5 秒全耗在这一条链的猜端口扫描上（拆分前一样，不是那次改动引入的）。
// 探测量不变（该发的还是那些 ip:port），只是不再一个等一个。
//
// 两个上限：
//   - 并发 8：一条链的规则里可能写一排单 IP，不限流会一次冒出几百条连接；
//   - 总上限 budget：到点就收手返回 false。猜端口这条路本来就"不下结论"，
//     与其慢慢试完，不如按时收手、如实说"没试出来"（调用处已按这个语义处理）。
func probeGuessedParallel(dial func(net.IP, uint16) (net.Conn, error), cands []net.IP, ports []uint16, budget time.Duration) (net.IP, uint16, bool) {
	type pair struct {
		ip   net.IP
		port uint16
	}
	if len(cands) == 0 || len(ports) == 0 {
		return nil, 0, false
	}

	const maxWorkers = 8
	jobs := make(chan pair)
	res := make(chan pair, 1)
	done := make(chan struct{})
	var once sync.Once // res 只写一次、done 只关一次（成功与超时两条路都走它）
	var wg sync.WaitGroup

	workers := maxWorkers
	if n := len(cands) * len(ports); n < workers {
		workers = n
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				conn, err := dial(p.ip, p.port)
				if err != nil {
					continue
				}
				conn.Close()
				once.Do(func() {
					res <- p
					close(done)
				})
				return // 已经有人试通了，这个 worker 收工
			}
		}()
	}

	// 派活：有人试通就停（剩下的活不发了）
	go func() {
		defer close(jobs)
		for _, cand := range cands {
			for _, port := range ports {
				select {
				case jobs <- pair{cand, port}:
				case <-done:
					return
				}
			}
		}
	}()

	select {
	case p := <-res:
		return p.ip, p.port, true
	case <-time.After(budget):
		// 超时也要让派活的 goroutine 退出（否则它会永远堵在 jobs 上）
		once.Do(func() { close(done) })
		// 还没跑完的探测不用等：它们各自带 6 秒超时，到点自己结束
		//（成功的话会把连接关掉，不会漏 fd）
		return nil, 0, false
	}
}
