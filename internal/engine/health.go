package engine

import (
	"fmt"
	"math/rand"
	"time"

	"nethub/internal/config"
	"nethub/internal/upstream"
)

// upHealth 一条上游的观测结果：主动探测与被动失败（真实连接拨不通）都往这里写。
type upHealth struct {
	raw     string
	ok      bool
	latency time.Duration
	err     string
	checked time.Time
}

// UpHealthView 给界面看的上游健康快照。
type UpHealthView struct {
	URL     string `json:"url"`     // 已遮蔽凭据
	OK      bool   `json:"ok"`      //
	Latency string `json:"latency"` // "12 ms"，没探过就是空
	Error   string `json:"error"`   //
	Checked string `json:"checked"` // HH:MM:SS，没探过就是空
	Known   bool   `json:"known"`   // 是否已有观测结果
}

// ChainHealthView 给界面看的一条链的健康快照。
type ChainHealthView struct {
	Name      string         `json:"name"`
	Strategy  string         `json:"strategy"`
	Probe     string         `json:"probe"`
	Upstreams []UpHealthView `json:"upstreams"`
}

// healthOf 取某条链的健康表（下标与 Upstreams() 对齐）。
// 上游列表变过（用户改了配置）就重建，旧的观测作废。
func (e *Engine) healthOf(ch config.Chain) []*upHealth {
	ups := ch.Upstreams()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.health == nil {
		e.health = map[string][]*upHealth{}
	}
	cur := e.health[ch.Name]
	rebuild := len(cur) != len(ups)
	if !rebuild {
		for i, raw := range ups {
			if cur[i] == nil || cur[i].raw != raw {
				rebuild = true
				break
			}
		}
	}
	if rebuild {
		cur = make([]*upHealth, len(ups))
		for i, raw := range ups {
			cur[i] = &upHealth{raw: raw}
		}
		e.health[ch.Name] = cur
	}
	return cur
}

// markUp 记一次观测。返回是否发生"可用性翻转"（供只报变化的日志用）与上游原文。
func (e *Engine) markUp(chain string, idx int, ok bool, latency time.Duration, errText string) (flipped bool, raw string) {
	e.mu.Lock()
	ups := e.health[chain]
	if idx < 0 || idx >= len(ups) || ups[idx] == nil {
		e.mu.Unlock()
		return false, ""
	}
	h := ups[idx]
	flipped = h.checked.IsZero() || h.ok != ok
	h.ok, h.latency, h.err, h.checked = ok, latency, errText, time.Now()
	raw = h.raw
	e.mu.Unlock()
	return flipped, raw
}

// candidates 按策略给出候选上游的下标顺序：可用的在前、已知坏的垫后
// （全坏时照样逐个试 —— 宁可试一次，也不要因为探测结论而拒绝可能已经恢复的链路）。
func (e *Engine) candidates(ch config.Chain) []int {
	n := len(ch.Upstreams())
	if n == 0 {
		return nil
	}
	start := 0
	switch ch.StrategyName() {
	case config.StrategyRound: // 轮询：每次从下一个开始，天然均摊
		e.mu.Lock()
		e.round++
		start = e.round % n
		e.mu.Unlock()
	case config.StrategyRandom:
		start = rand.Intn(n)
	}

	hs := e.healthOf(ch)
	good := make([]int, 0, n)
	bad := make([]int, 0, n)
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		h := (*upHealth)(nil)
		if idx < len(hs) {
			h = hs[idx]
		}
		if h != nil && !h.checked.IsZero() && !h.ok {
			bad = append(bad, idx)
			continue
		}
		good = append(good, idx)
	}
	return append(good, bad...)
}

// probeChain 探一条链的所有上游（顺序做；只测到代理这一段，不碰业务目标）。
func (e *Engine) probeChain(ch config.Chain) {
	e.healthOf(ch) // 先确保健康表存在（markUp 依赖它）
	for i, raw := range ch.Upstreams() {
		u, err := upstream.Parse(raw)
		if err != nil {
			e.markUp(ch.Name, i, false, 0, err.Error())
			continue
		}
		lat, perr := u.Probe(6 * time.Second)
		msg := ""
		if perr != nil {
			msg = perr.Error()
		}
		if flipped, upRaw := e.markUp(ch.Name, i, perr == nil, lat, msg); flipped {
			if perr == nil {
				// 恢复只写日志（链路会不时抖一下，弹窗太吵）
				e.bus.Info("链路 %s 上游 %s 可用（%d ms）", ch.Name, maskUpstream(upRaw), lat.Milliseconds())
			} else {
				e.bus.Warn("链路 %s 上游 %s 不可用：%s", ch.Name, maskUpstream(upRaw), msg)
				if e.Notify != nil {
					e.Notify("链路 "+ch.Name+" 上游不可用", maskUpstream(upRaw)+"："+msg, true)
				}
			}
		}
	}
}

// ProbeAll 立刻把所有链的所有上游探一遍（界面上的"立即探测"）。
func (e *Engine) ProbeAll() {
	for _, ch := range e.cfg.Chains {
		e.probeChain(ch)
	}
}

// healthLoop 定时探活。一条链的间隔由它自己的 probe 决定；这里用 5 秒的粗粒度
// ticker 统一调度，免得每条链起一堆定时器。
func (e *Engine) healthLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	e.bus.Info("健康探测已启动：%d 条链，粒度 5s", len(e.cfg.Chains))
	last := map[string]time.Time{}
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			for _, ch := range e.cfg.Chains {
				iv := ch.ProbeInterval()
				if iv == 0 {
					continue
				}
				if t, ok := last[ch.Name]; ok && time.Since(t) < iv {
					continue
				}
				last[ch.Name] = time.Now()
				e.probeChain(ch)
			}
		}
	}
}

// ChainHealth 所有链的健康快照（界面用）。
func (e *Engine) ChainHealth() []ChainHealthView {
	out := make([]ChainHealthView, 0, len(e.cfg.Chains))
	for _, ch := range e.cfg.Chains {
		v := ChainHealthView{
			Name:     ch.Name,
			Strategy: ch.StrategyName(),
			Probe:    ch.ProbeInterval().String(),
		}
		hs := e.healthOf(ch)
		for i, raw := range ch.Upstreams() {
			uv := UpHealthView{URL: maskUpstream(raw)}
			if i < len(hs) && hs[i] != nil && !hs[i].checked.IsZero() {
				uv.Known = true
				uv.OK = hs[i].ok
				uv.Error = hs[i].err
				uv.Checked = hs[i].checked.Format("15:04:05")
				if hs[i].ok {
					uv.Latency = fmt.Sprintf("%d ms", hs[i].latency.Milliseconds())
				}
			}
			v.Upstreams = append(v.Upstreams, uv)
		}
		out = append(out, v)
	}
	return out
}

// maskUpstream 日志/界面里遮蔽凭据。
func maskUpstream(raw string) string {
	if u, err := upstream.Parse(raw); err == nil {
		return u.String()
	}
	return "（无法解析的上游）"
}
