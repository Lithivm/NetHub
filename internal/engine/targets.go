package engine

import (
	"fmt"
	"net"
	"time"

	"nethub/internal/rules"
)

// 业务目标巡检：只看"最近真的被访问过"的内网目标（从连接表里来），
// 经隧道连一次（只建连、立刻断开），回答"今天这套业务通不通"。
//
// 为什么不用配置里的网段去挨个探：一个 /24 有 254 个地址，全探是骚扰；
// 而连接表里的目标天然就是"有人在用的业务"，探它们才有意义。
const (
	targetProbeRecent  = 60 * time.Minute // 多久内被访问过才算“最近”
	targetProbeTimeout = 5 * time.Second
)

// targetHealth 一个业务目标的巡检结果。
type targetHealth struct {
	target  string
	chain   string
	ok      bool
	latency time.Duration
	err     string
	checked time.Time
}

// TargetHealthView 给界面看的业务目标健康快照。
type TargetHealthView struct {
	Target  string `json:"target"`
	Chain   string `json:"chain"`
	OK      bool   `json:"ok"`
	Latency string `json:"latency"`
	Error   string `json:"error"`
	Checked string `json:"checked"`
}

// targetRef 连接表里的业务目标。
type targetRef struct {
	target string
	chain  string
}

// recentTargets 挑出最近被访问过的业务目标（隧道命中的那些，按最后活动时间倒序）。
func (e *Engine) recentTargets(limit int) []targetRef {
	cut := time.Now().Add(-targetProbeRecent).UnixNano()
	e.mu.RLock()
	type row struct {
		ref  targetRef
		last int64
	}
	rows := make([]row, 0, len(e.conns))
	seen := map[string]bool{}
	for _, st := range e.conns {
		if st.action != rules.ActionChain || st.last.Load() < cut {
			continue
		}
		key := fmt.Sprintf("%s:%d", st.dst, st.dport)
		if seen[key] {
			continue
		}
		seen[key] = true
		rows = append(rows, row{targetRef{target: key, chain: st.chain}, st.last.Load()})
	}
	e.mu.RUnlock()

	// 最近活动的排前面
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j].last > rows[j-1].last; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	out := make([]targetRef, 0, limit)
	for _, r := range rows {
		if len(out) >= limit {
			break
		}
		out = append(out, r.ref)
	}
	return out
}

// ProbeTargets 巡检最近访问过的业务目标。只建连、不发数据、立刻断开。
func (e *Engine) ProbeTargets() {
	for _, ref := range e.recentTargets(e.cfg.PatrolCount()) {
		e.probeOneTarget(ref)
	}
}

func (e *Engine) probeOneTarget(ref targetRef) {
	ch, ok := e.cfg.ChainByName(ref.chain)
	if !ok {
		return
	}
	host, portStr, err := splitTarget(ref.target)
	if err != nil {
		return
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return
	}

	start := time.Now()
	conn, derr := e.dialUpstream(ch, ip, port)
	lat := time.Since(start)
	msg := ""
	if derr != nil {
		msg = derr.Error()
	} else {
		conn.Close()
	}
	flipped, bad := e.markTarget(ref.target, ref.chain, derr == nil, lat, msg)
	if flipped && bad {
		// 只报坏事：通了就写日志（巡检本身会不时地好一下坏一下，弹窗太吵）
		e.bus.Warn("内网目标不通：%s —— 经链 %s 连不上：%s", ref.target, ref.chain, msg)
		if e.Notify != nil {
			e.Notify("内网目标不通："+ref.target, "经链 "+ref.chain+" 连不上："+msg, true)
		}
		return
	}
	if flipped {
		e.bus.Info("内网目标恢复：%s —— 经链 %s 已通（%s）", ref.target, ref.chain, lat.Round(time.Millisecond))
	}
}

// TargetRef 一个“最近用过”的业务目标（导出给链路自检用）。
type TargetRef struct {
	Target string // ip:port
	Chain  string
}

// RecentTargets 最近用过的业务目标（按最后活动时间倒序，最多 limit 个）。
func (e *Engine) RecentTargets(limit int) []TargetRef {
	refs := e.recentTargets(limit)
	out := make([]TargetRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, TargetRef{Target: r.target, Chain: r.chain})
	}
	return out
}

// markTarget 写巡检结果；返回是否发生状态翻转、以及现在是不是"不好"。
func (e *Engine) markTarget(target, chain string, ok bool, latency time.Duration, errText string) (flipped, bad bool) {
	e.mu.Lock()
	if e.targets == nil {
		e.targets = map[string]*targetHealth{}
	}
	h := e.targets[target]
	if h == nil {
		h = &targetHealth{target: target, chain: chain}
		e.targets[target] = h
	}
	flipped = h.checked.IsZero() || h.ok != ok
	h.chain, h.ok, h.latency, h.err, h.checked = chain, ok, latency, errText, time.Now()
	e.mu.Unlock()
	return flipped, !ok
}

// targetLoop 常规巡检：间隔由配置给（patrol.interval），改配置即时生效；off 则不跑。
func (e *Engine) targetLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(10 * time.Second) // 粗粒度调度：每 10 秒看一眼该不该巡检
	defer tk.Stop()
	var last time.Time
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			iv := e.cfg.PatrolInterval()
			if iv == 0 {
				continue // 关了
			}
			if !last.IsZero() && time.Since(last) < iv {
				continue
			}
			last = time.Now()
			e.ProbeTargets()
		}
	}
}

// TargetHealth 业务目标巡检快照（按目标名排序，界面用）。
func (e *Engine) TargetHealth() []TargetHealthView {
	e.mu.RLock()
	out := make([]TargetHealthView, 0, len(e.targets))
	for _, h := range e.targets {
		v := TargetHealthView{
			Target: h.target, Chain: h.chain, OK: h.ok, Error: h.err,
			Checked: h.checked.Format("15:04:05"),
		}
		if h.ok {
			v.Latency = fmt.Sprintf("%d ms", h.latency.Milliseconds())
		}
		out = append(out, v)
	}
	e.mu.RUnlock()
	for i := 1; i < len(out); i++ { // 不通的排前面
		for j := i; j > 0 && out[j].OK == false && out[j-1].OK; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// alert 已经不需要了：巡检只报坏事，且直接用 bus+Notify 写清楚（保留此注释以防误加回来）

// splitTarget 把 "10.0.0.5:5432" 拆成 host/port。
func splitTarget(s string) (host, port string, err error) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("不是 host:port: %q", s)
}
