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

	// okStreak / failStreak：连续同向结果的次数（防抖）。
	//
	// 为什么要防抖：探测每 30s 一次，现网上游偶发抖一下（实测 22 分钟里 5 条链共抖了
	// 15 次）—— 每次都算“挂了 / 好了”，日志被刷成一串 upstream.down/up、界面红绿跳，
	// 现场看到的是“这软件老是报错”，而不是“上游偶尔抖一下”。
	okStreak   int
	failStreak int
	// downAt 上一次置为“不可用”的时刻（恢复时报“断了多久”用）。
	downAt time.Time

	// suspect 业务拨号连续失败的次数（**不是**探测结论，见 noteUpstreamSuspect）。
	// 成功一次（拨通或探测通过）就清零。
	suspect int
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
	ups := e.cfg.UpstreamsResolved(ch)
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
// noteUpstreamSuspect 记一次“业务拨号失败”。
//
// 为什么它**不直接改状态**：探测与真实拨号不是一回事 —— 一个坏掉的内网目标也能
// 连着失败好几次，那不代表上游挂了。以前两者共用一套状态机，于是一条坏业务目标
// 连续失败两次就把健康的上游写成 down，下一次探测又写一行“恢复”：日志里看着像
// 链路在反复抖，现场会以为网络不稳。
//
// 现在：业务失败只算“疑似”（累计 3 次才按 5 分钟节流报一行），
// 真正改状态由探测（连续两次同向）决定；拨通一次就把疑似清零。
func (e *Engine) noteUpstreamSuspect(chain string, idx int, errText string) {
	e.mu.Lock()
	ups := e.health[chain]
	suspect := 0
	if idx >= 0 && idx < len(ups) && ups[idx] != nil {
		ups[idx].suspect++
		suspect = ups[idx].suspect
	}
	e.mu.Unlock()
	if suspect < 3 {
		return // 前几次多半是那个目标自己的问题，不值得说
	}
	e.bus.Throttle(fmt.Sprintf("upstream.suspect:%s:%d", chain, idx), 5*time.Minute,
		"upstream.suspect: chain=%s upstream_no=%d 业务拨号连续失败 %d 次（未改状态，等探测确认）：%s",
		chain, idx+1, suspect, firstLine(errText))
}

// healthFlipStreak 连续几次同向的探测结果才允许改状态（防抖）。
const healthFlipStreak = 2

// markUp 记一次探测结果，返回 flipped=**状态真的变了**（只有这时才该写日志/发通知）。
//
// 单次结果不直接改状态（第一次探测除外，它必须有结论）：
// 偶发抖动只会把 streak 清零，不会把界面刷成红色，也不会往日志里塞一行 upstream.down。
func (e *Engine) markUp(chain string, idx int, ok bool, latency time.Duration, errText string) (flipped bool, raw string) {
	e.mu.Lock()
	ups := e.health[chain]
	if idx < 0 || idx >= len(ups) || ups[idx] == nil {
		e.mu.Unlock()
		return false, ""
	}
	h := ups[idx]
	first := h.checked.IsZero()
	h.checked = time.Now()
	if ok {
		h.suspect = 0 // 通了就把“疑似”清掉
	}
	if ok {
		h.okStreak++
		h.failStreak = 0
	} else {
		h.failStreak++
		h.okStreak = 0
	}
	switch {
	case first || h.ok == ok:
		flipped, h.ok = first, ok
		h.latency, h.err = latency, errText
	case (ok && h.okStreak >= healthFlipStreak) || (!ok && h.failStreak >= healthFlipStreak):
		flipped, h.ok = true, ok
		h.latency, h.err = latency, errText
	default:
		// 想翻但还没连续够次数：维持旧状态，也不动明细（否则界面会出现“绿点亮着 + 红字错误”）
	}
	if flipped {
		if ok {
			h.downAt = time.Time{}
		} else {
			h.downAt = time.Now()
		}
	}
	raw = h.raw
	e.mu.Unlock()
	return flipped, raw
}

// downFor 这个上游上一次置为“不可用”距现在多久（没记录就是 0）。
func (e *Engine) downFor(chain string, idx int) time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ups := e.health[chain]
	if idx < 0 || idx >= len(ups) || ups[idx] == nil || ups[idx].downAt.IsZero() {
		return 0
	}
	return time.Since(ups[idx].downAt)
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
	case config.StrategyHash:
		// hash 策略的起点由键决定，见 candidatesFor；这里保持配置顺序，
		// 以便没有键（巡检等）时行为可预期。
	}

	hs := e.healthOf(ch)
	good := make([]int, 0, n)
	bad := make([]int, 0, n)
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if e.upKnownBad(hs, idx) {
			bad = append(bad, idx)
			continue
		}
		good = append(good, idx)
	}
	return append(good, bad...)
}

// candidatesFor 带粘性键的候选顺序（hash 策略用）。
// key 为空（如目标巡检自己拨号）时就退回配置顺序。
func (e *Engine) candidatesFor(ch config.Chain, key string) []int {
	if ch.StrategyName() != config.StrategyHash || key == "" {
		return e.candidates(ch)
	}
	n := len(ch.Upstreams())
	if n == 0 {
		return nil
	}
	// 一致性哈希（FNV-1a，稳定不依赖进程内随机种子）：
	// 同一个客户端 IP 永远从同一条上游出去；上游增删时只影响少量映射。
	h := fnv32a(key)
	start := int(h % uint32(n))

	hs := e.healthOf(ch)
	good := make([]int, 0, n)
	bad := make([]int, 0, n)
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if e.upKnownBad(hs, idx) {
			bad = append(bad, idx)
			continue
		}
		good = append(good, idx)
	}
	return append(good, bad...)
}

// upKnownBad 一条上游是否“已知坏”。
//
// 必须在锁下读 hs[idx] 的字段：markUp 会在后台探活协程里写它们。
func (e *Engine) upKnownBad(hs []*upHealth, idx int) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if idx < 0 || idx >= len(hs) || hs[idx] == nil {
		return false
	}
	h := hs[idx]
	return !h.checked.IsZero() && !h.ok
}

// fnv32a FNV-1a 32 位哈希（标准库 hash/fnv 的实现，自己写一份免得多一个依赖）。
func fnv32a(s string) uint32 {
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return h
}

// probeChain 探一条链的所有上游（顺序做）。
//
// 探到什么程度：TCP+TLS+**认证**，再 CONNECT 一个公网地址确认它真能转发。
//
// 为什么必须带上认证：旧版只做 TCP+TLS，于是**口令错了也报“可用（96ms）”** ——
// 真实事故里 sjy 的口令被上游间歇性拒掉，界面一直绿着，靠外部工具才查出来。
// 公网探针（223.5.5.5:443）不涉及客户内网的任何服务器，所以“不打扰内网”这条仍然成立。
func (e *Engine) probeChain(ch config.Chain) {
	e.healthOf(ch) // 先确保健康表存在（markUp 依赖它）
	for i, raw := range e.cfg.UpstreamsResolved(ch) {
		u, err := upstream.Parse(raw)
		if err != nil {
			e.markUp(ch.Name, i, false, 0, err.Error())
			continue
		}
		r := u.ProbeAuth(6 * time.Second)
		msg := ""
		if !r.AuthOK {
			msg = r.Err.Error()
		}
		wasDown := e.downFor(ch.Name, i)
		if flipped, upRaw := e.markUp(ch.Name, i, r.AuthOK, r.Latency, msg); flipped {
			if r.AuthOK {
				// 恢复只写日志（链路会不时抖一下，弹窗太吵）
				down := ""
				if wasDown > 0 {
					down = fmt.Sprintf(" down_ms=%d", wasDown.Milliseconds())
				}
				if r.Public {
					e.bus.Info("upstream.up: chain=%s upstream=%s rtt_ms=%d auth=ok%s", ch.Name, maskUpstream(upRaw), r.Latency.Milliseconds(), down)
				} else {
					// 很多客户出口就是不让自己出公网 —— 对“访问内网”而言这不算故障
					e.bus.Info("链路 %s 上游 %s 可用（%d ms，认证通过；出口未连到公网，对内网访问无影响）",
						ch.Name, maskUpstream(upRaw), r.Latency.Milliseconds())
				}
			} else {
				e.bus.Warn("upstream.down: chain=%s upstream=%s err=%s", ch.Name, maskUpstream(upRaw), msg)
				if e.Notify != nil {
					e.Notify("链路 "+ch.Name+" 上游不可用", maskUpstream(upRaw)+"："+msg, true)
				}
			}
		}
	}
}

// ProbeAll 立刻把所有链的所有上游探一遍（界面上的"立即探测"）。
func (e *Engine) ProbeAll() {
	for _, ch := range e.cfg.ChainsSnapshot() {
		e.probeChain(ch)
	}
}

// healthLoop 定时探活。一条链的间隔由它自己的 probe 决定；这里用 5 秒的粗粒度
// ticker 统一调度，免得每条链起一堆定时器。
func (e *Engine) healthLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	e.bus.Info("health.start: chains=%d interval=5s", len(e.cfg.ChainsSnapshot()))
	last := map[string]time.Time{}
	// 先立即探一轮：否则刚打开界面的那几十秒里，链路页全是“未探过”的灰点，
	// 用户会以为没生效（实际只是还在等第一个 tick）。
	for _, ch := range e.cfg.ChainsSnapshot() {
		if ch.ProbeInterval() == 0 {
			continue
		}
		last[ch.Name] = time.Now()
		e.probeChain(ch)
	}
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			for _, ch := range e.cfg.ChainsSnapshot() {
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
	out := make([]ChainHealthView, 0, len(e.cfg.ChainsSnapshot()))
	for _, ch := range e.cfg.ChainsSnapshot() {
		v := ChainHealthView{
			Name:     ch.Name,
			Strategy: ch.StrategyName(),
			Probe:    ch.ProbeInterval().String(),
		}
		hs := e.healthOf(ch)
		ups := e.cfg.UpstreamsResolved(ch)
		for i, raw := range ups {
			uv := UpHealthView{URL: maskUpstream(raw)}
			// 在锁下拷贝一条观测记录：markUp 会在探活协程里并发写它。
			e.mu.RLock()
			var h upHealth
			have := i < len(hs) && hs[i] != nil
			if have {
				h = *hs[i]
			}
			e.mu.RUnlock()
			if have && !h.checked.IsZero() {
				uv.Known = true
				uv.OK = h.ok
				uv.Error = h.err
				uv.Checked = h.checked.Format("15:04:05")
				if h.ok {
					uv.Latency = fmt.Sprintf("%d ms", h.latency.Milliseconds())
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
