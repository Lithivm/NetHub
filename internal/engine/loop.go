package engine

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"nethub/internal/upstream"
)

// 环路检测（A14）。
//
// 为什么需要它：我们只拦"命中了规则的目标"，而另一个代理（Clash / 另一个网关 / 一台
// 设了系统代理的机器）可能把我们送出去的包再送回来 —— 于是流量在我们自己（或两个代理）
// 之间打转：表现为"内网特别慢、日志里同一个目标疯狂重连、上游流量计费暴涨"。
// 这种问题**看一眼连接表很难看出来**（每条连接看起来都正常），所以我们主动判。
//
// 判据只取"确定性高、不会误报"的三种：
//  1. 目标就是这条链自己的上游地址 —— 包绕回上游，铁定是环（比如规则把上游 IP 也圈进去了）；
//  2. 源地址 == 目标地址 —— 正常流量不会这样；
//  3. 同一个目标在短窗口内被极高频率新建连接（默认 5 秒内 40 次）—— 只有环或死循环客户端才这样。
//
// 注意：判据 3 会漏（真有软件疯狂重连也长这样），所以告警文案写的是"疑似"，
// 并把数字摆出来让人自己判断，而不是替人下定论。
const (
	loopWindow   = 5 * time.Second
	loopSynLimit = 40               // 窗口内同目标新建连接数上限
	loopAlertGap = 60 * time.Second // 同一目标最多多久提醒一次
)

type loopRec struct {
	start time.Time
	n     int
	alert time.Time
}

type loopGuard struct {
	mu     sync.Mutex
	recs   map[string]*loopRec
	alerts uint64
	last   string
	lastAt time.Time

	// 上游地址缓存：链名 → 地址集合（配置变了会重建，见 upstreamAddrs）
	upMu    sync.Mutex
	upCache map[string]string // 链名 → 签名字符串
	upAddrs map[string]map[string]bool
}

func newLoopGuard() *loopGuard {
	return &loopGuard{
		recs:    map[string]*loopRec{},
		upCache: map[string]string{},
		upAddrs: map[string]map[string]bool{},
	}
}

// check 在新建连接（SYN）时判一次环。返回是否新报了警（用于通知）。
func (e *Engine) checkLoop(src, dst net.IP, dport uint16, chain string) bool {
	if e.loop == nil {
		return false
	}
	key := fmt.Sprintf("%s:%d", dst, dport)
	now := time.Now()

	// 判据 1：目标就是上游自己
	if raws := e.chainUpstreams(chain); len(raws) > 0 && e.loop.isUpstreamAddr(raws, dst.String(), dport) {
		return e.loop.alert(e, key, fmt.Sprintf(
			"目标 %s:%d 就是链 %s 的上游自己 —— 规则把上游地址也圈进来了，流量会在上游那里打转",
			dst, dport, chain), true)
	}

	// 判据 2：源 == 目标
	if dst.Equal(src) {
		return e.loop.alert(e, key, fmt.Sprintf("源和目标是同一个地址 %s —— 正常流量不会这样", dst), true)
	}

	// 判据 3：同目标高频新建连接
	e.loop.mu.Lock()
	r := e.loop.recs[key]
	if r == nil || now.Sub(r.start) > loopWindow {
		r = &loopRec{start: now}
		e.loop.recs[key] = r
	}
	r.n++
	n := r.n
	e.loop.mu.Unlock()

	// 注意：节流交给 alert() 统一管（这里不能再自己动 r.alert，
	// 否则会把紧接着的那次告警当成“刚报过”而吞掉）
	if n == loopSynLimit {
		return e.loop.alert(e, key, fmt.Sprintf(
			"目标 %s 在 %s 内新建了 %d 次连接 —— 疑似环路（另一个代理把流量绕回来了？）",
			key, loopWindow, n), false)
	}
	return false
}

// alert 记一次告警并写日志（同一 key 有节流）。
func (g *loopGuard) alert(e *Engine, key, msg string, certain bool) bool {
	g.mu.Lock()
	r := g.recs[key]
	if r == nil {
		r = &loopRec{start: time.Now()}
		g.recs[key] = r
	}
	if !r.alert.IsZero() && time.Since(r.alert) < loopAlertGap {
		g.mu.Unlock()
		return false
	}
	r.alert = time.Now()
	g.alerts++
	g.last, g.lastAt = msg, time.Now()
	g.mu.Unlock()

	prefix := "疑似环路"
	if certain {
		prefix = "检测到环路"
	}
	e.bus.Warn("%s：%s", prefix, msg)
	if e.Notify != nil {
		e.Notify(prefix, msg+"（请检查规则与其它代理的绕过设置）", true)
	}
	return true
}

// isUpstreamAddr 目标地址是不是这条链的上游地址（含端口）。
func (g *loopGuard) isUpstreamAddr(raws []string, dst string, dport uint16) bool {
	if len(raws) == 0 {
		return false
	}
	sig := strings.Join(raws, "|")
	g.upMu.Lock()
	defer g.upMu.Unlock()
	// 链的上游变了就重建（简单签名比较，配置改动不频繁）
	if g.upCache[sig] == "" {
		set := map[string]bool{}
		for _, raw := range raws {
			u, err := upstream.Parse(raw)
			if err != nil {
				continue
			}
			set[u.Addr] = true // host:port
		}
		key := fmt.Sprintf("chain-%d", len(g.upAddrs))
		g.upCache[sig] = key
		g.upAddrs[key] = set
	}
	set := g.upAddrs[g.upCache[sig]]
	return set[net.JoinHostPort(dst, fmt.Sprint(dport))]
}

// LoopAlerts 至今发现的疑似环路次数与最近一条（给界面显示）。
func (e *Engine) LoopAlerts() (uint64, string, string) {
	if e.loop == nil {
		return 0, "", ""
	}
	e.loop.mu.Lock()
	defer e.loop.mu.Unlock()
	if e.loop.lastAt.IsZero() {
		return e.loop.alerts, "", ""
	}
	return e.loop.alerts, e.loop.last, e.loop.lastAt.Format("15:04:05")
}

// pruneLoops 清掉过期记录（janitor 里顺手调，避免窗口记录无限涨）。
func (e *Engine) pruneLoops() {
	if e.loop == nil {
		return
	}
	now := time.Now()
	e.loop.mu.Lock()
	for k, r := range e.loop.recs {
		if now.Sub(r.start) > loopWindow && now.Sub(r.alert) > loopAlertGap {
			delete(e.loop.recs, k)
		}
	}
	e.loop.mu.Unlock()
}

// chainUpstreams 取一条链的上游原文（找不到就空）。
func (e *Engine) chainUpstreams(name string) []string {
	if name == "" {
		return nil
	}
	if ch, ok := e.cfg.ChainByName(name); ok {
		return e.cfg.UpstreamsResolved(ch)
	}
	return nil
}
