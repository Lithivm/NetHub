package engine

import (
	"net"
	"sync"
	"time"

	"nethub/internal/config"
	"nethub/internal/upstream"
)

// 预热连接池（A11）。
//
// 为什么要它：一次"到上游"的完整握手分四段 ——
//
//	TCP + TLS + SOCKS 招呼（与目标无关，实测 193～258ms，etyy 甚至 700ms+）
//	CONNECT 目标                （必须知道目标才能发）
//
// 前三段可以提前做好养着，业务来了只发 CONNECT（1 个 RTT）。
// 关键区别（别搞混）：它省的是**等的时间**，不是连接数 —— 后台补货照样要建连接，
// 但那段时间业务不用等。
//
// 策略（刻意做得很谨慎）：
//   - 只有"用过"的链才补货（用完顺手补一条），不主动去连一堆；
//   - 每条上游最多 warm 条（默认 2，可配 0=关）；
//   - 池里的会话有寿命（warmTTL），过期丢弃 —— 上游多半会掐闲置连接；
//   - 取出来的会话如果 CONNECT 失败，整条丢掉并回落到现拨，不重试已坏的；
//   - 已知不可用的上游不补货（省得白连）。
const (
	warmTTL      = 25 * time.Second // 池内会话寿命
	warmRefillTO = 8 * time.Second  // 补货拨号超时上限
)

type warmConn struct {
	conn    net.Conn
	up      *upstream.Upstream
	created time.Time
}

type warmPool struct {
	mu    sync.Mutex
	byKey map[string][]*warmConn // key = 上游 URL（原文，含凭据）
	taken uint64                 // 命中次数（供界面显示）
	made  uint64                 // 补货建了多条
}

func newWarmPool() *warmPool {
	return &warmPool{byKey: map[string][]*warmConn{}}
}

// take 取一条该上游的预热会话；取不到返回 nil。
// 注意：列表里可能有不属于我们的 nil 占位（后台正在拨），不能当成会话。
func (p *warmPool) take(key string) *warmConn {
	if p == nil {
		return nil
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.byKey[key]
	var chosen *warmConn
	keep := make([]*warmConn, 0, len(list))
	for i := len(list) - 1; i >= 0; i-- { // 后进先出：最新鲜的先走
		w := list[i]
		if w == nil {
			keep = append(keep, nil) // 正在拨的占位：留着
			continue
		}
		if now.Sub(w.created) > warmTTL {
			w.conn.Close() // 过期：丢掉（上游多半已掐掉闲置连接）
			continue
		}
		if chosen == nil {
			chosen = w
			continue
		}
		keep = append(keep, w)
	}
	if len(keep) == 0 {
		delete(p.byKey, key)
	} else {
		p.byKey[key] = keep
	}
	if chosen != nil {
		p.taken++
	}
	return chosen
}

// refill 在后台把某条上游的池子补到 target 条。
// 已有会话数（含正在拨的）达到 target 就直接返回。
func (p *warmPool) refill(ch config.Chain, idx int, target int, cfg *config.Config, healthy bool) {
	if p == nil || target <= 0 || !healthy {
		return
	}
	raws := cfg.UpstreamsResolved(ch)
	if idx < 0 || idx >= len(raws) {
		return
	}
	key := raws[idx]
	p.mu.Lock()
	have := len(p.byKey[key])
	if have >= target {
		p.mu.Unlock()
		return
	}
	// 占位：先塞一个 nil 表示"正在拨"，防止同一上游被并发补成一堆
	for i := have; i < target; i++ {
		p.byKey[key] = append(p.byKey[key], nil)
	}
	p.mu.Unlock()

	go func() {
		up, err := upstream.Parse(key)
		if err != nil {
			p.dropPlaceholders(key)
			return
		}
		for i := have; i < target; i++ {
			to := cfg.DialTimeoutDur()
			if to > warmRefillTO {
				to = warmRefillTO
			}
			conn, err := up.Prepare(to)
			if err != nil {
				continue // 补不到就算了，业务走现拨
			}
			p.mu.Lock()
			// 把占位替换成真会话（保持长度不变）
			replaced := false
			list := p.byKey[key]
			for j := range list {
				if list[j] == nil {
					list[j] = &warmConn{conn: conn, up: up, created: time.Now()}
					replaced = true
					break
				}
			}
			if replaced {
				p.made++
			}
			p.mu.Unlock()
			if !replaced {
				conn.Close()
			}
		}
		p.sweep()
	}()
}

func (p *warmPool) dropPlaceholders(key string) {
	p.mu.Lock()
	list := p.byKey[key]
	out := list[:0]
	for _, w := range list {
		if w != nil {
			out = append(out, w)
		}
	}
	p.byKey[key] = out
	p.mu.Unlock()
}

// sweep 清掉过期会话（顺手在补货之后跑）。
func (p *warmPool) sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, list := range p.byKey {
		out := list[:0]
		for _, w := range list {
			if w == nil {
				out = append(out, w) // 正在拨的占位留着
				continue
			}
			if now.Sub(w.created) > warmTTL {
				w.conn.Close()
				continue
			}
			out = append(out, w)
		}
		if len(out) == 0 {
			delete(p.byKey, k)
		} else {
			p.byKey[k] = out
		}
	}
}

// closeAll 引擎停止时清干净（否则退出时会留下悬挂连接）。
func (p *warmPool) closeAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, list := range p.byKey {
		for _, w := range list {
			if w != nil {
				w.conn.Close()
			}
		}
		delete(p.byKey, k)
	}
}

// stats 给界面看：命中次数 / 建了多少 / 当前养着几条。
func (p *warmPool) stats() (taken, made, warm uint64) {
	if p == nil {
		return 0, 0, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, list := range p.byKey {
		for _, w := range list {
			if w != nil {
				warm++
			}
		}
	}
	return p.taken, p.made, warm
}

// dialWarm 先试池子：拿到会话就只发 CONNECT。成功返回连接；失败返回 ok=false
// （调用方回落到现拨，池里那条已被丢弃）。
func (e *Engine) dialWarm(ch config.Chain, idx int, dst net.IP, dport uint16) (net.Conn, bool) {
	if e.pool == nil || e.cfg.WarmTarget() <= 0 {
		return nil, false
	}
	raws := e.cfg.UpstreamsResolved(ch)
	if idx < 0 || idx >= len(raws) {
		return nil, false
	}
	w := e.pool.take(raws[idx])
	if w == nil {
		return nil, false
	}
	to := e.cfg.DialTimeoutDur()
	if err := w.up.ConnectOn(w.conn, dst, dport, to); err != nil {
		// 会话坏了（上游掐了闲置连接等）→ 丢掉，回落到现拨
		w.conn.Close()
		e.bus.Warn("链 %s 预热会话打通失败（%v），改为现拨", ch.Name, err)
		e.markUp(ch.Name, idx, false, 0, err.Error())
		return nil, false
	}
	e.markUp(ch.Name, idx, true, 0, "")
	return w.conn, true
}

// afterDial 一次成功的现拨之后顺手补货，让池子始终"刚好够下一次用"。
// 为什么不在启动时就把池子灌满：那会平白无故往上游连一堆连接（客户内网专家会问）。
func (e *Engine) afterDial(ch config.Chain, idx int) {
	target := e.cfg.WarmTarget()
	if target <= 0 {
		return
	}
	// 只给"看起来健康"的上游补货（刚成功过，一定是健康的）
	e.pool.refill(ch, idx, target, e.cfg, true)
}
