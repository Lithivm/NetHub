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
	targetProbeCount    = 8                // 一轮最多探几个目标
	targetProbeInterval = 5 * time.Minute  // 常规巡检间隔
	targetProbeRecent   = 60 * time.Minute // 多久内被访问过才算"最近"
	targetProbeTimeout  = 5 * time.Second
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
	for _, ref := range e.recentTargets(targetProbeCount) {
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
	if flipped {
		if bad {
			e.alert(fmt.Sprintf("内网目标不通：%s", ref.target),
				"经链 "+ref.chain+" 连不上："+msg, true)
		} else {
			e.alert(fmt.Sprintf("内网目标恢复：%s", ref.target),
				"经链 "+ref.chain+" 已通（"+lat.Round(time.Millisecond).String()+"）", false)
		}
	}
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

// targetLoop 常规巡检：每 5 分钟把最近用过的业务目标扫一遍。
func (e *Engine) targetLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(targetProbeInterval)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
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

// alert 状态变化的提示：接到 App 的通知回调（应用内 toast）。
func (e *Engine) alert(title, text string, bad bool) {
	if bad {
		e.bus.Warn("%s —— %s", title, text)
	} else {
		e.bus.Info("%s —— %s", title, text)
	}
	if e.Notify != nil {
		e.Notify(title, text, bad)
	}
}

// splitTarget 把 "10.0.0.5:5432" 拆成 host/port。
func splitTarget(s string) (host, port string, err error) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("不是 host:port: %q", s)
}
