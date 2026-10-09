package engine

import (
	"fmt"
	"sort"
	"strings"

	"nethub/internal/rules"
)

// dumpMaxNames 状态转储里最多列几条名字（剩下的只报数量）。
//
// 为什么要封顶：名字表长跑后会攒到几百上千条（客户机上见过 700+），
// 一次转储全倒进日志会把 8 MB 的轮转冲掉一大截 —— 而转储的用途是"看一眼现在什么状态"，
// 不是"把表搬进日志"。要全量自己去名字表/连接页看。
const dumpMaxNames = 40

// DumpState 把当前内部状态写一份（debug 档）。
//
// 为什么需要它：debug 档原有的内容（过滤器原文、内核层开关、规则表编译结果、名字表播种）
// **几乎全是启动那一刻写的** —— 于是"切到 debug 档"在一台已经跑了三天的机器上等于什么都没发生，
// 想看点东西只能重启（而重启会断掉现场正在跑的业务连接）。转储把"当时的内部状态"变成
// 随时要得到的东西：Proxifier 的 Debug 档也是这个意图（all messages + debug messages）。
//
// 调用时机：切档到 debug 时（App.SetLogLevel）、以及启动时档位已经是 debug（Start）。
// 只读快照 + 写日志，不改任何状态；锁只用来把几个字段抄出来，日志在锁外写
// （避免拿包路径的锁去等文件 IO）。
func (e *Engine) DumpState(reason string) {
	if !e.bus.IsDebug() {
		return
	}

	// ① 锁内抄快照（未启动的引擎字段可能还没建，所以先看跑没跑，再取其它东西）
	e.mu.RLock()
	running := e.run
	mainOn, dynOn := e.handle != nil, e.dynHandle != nil
	dnsInjectOn, sockOn, reflectOn := e.injector != nil, e.sockH != nil, e.reflectH != nil
	mainFilter, dynFilter := e.mainFilter, e.dynFilter
	perRule := make(map[string]uint64, len(e.statPerRule))
	for k, v := range e.statPerRule {
		perRule[k] = v
	}
	e.mu.RUnlock()

	if !running {
		e.bus.Debug("dump.state: reason=%s —— 引擎没在跑（只读或未启动），没有内部状态可转储", reason)
		return
	}

	total, active := e.Stats()
	ruleList := e.ruleSet().List()
	names := e.names.Status()
	chainList := e.cfg.ChainsSnapshot()

	// ② 锁外写日志
	e.bus.Debug("dump.state: reason=%s（这一档的多数内容本来只在启动时写，所以切档时补一份当前状态）", reason)

	e.bus.Debug("dump.routes: rules=%d", len(ruleList))
	for _, r := range ruleList {
		switch r.Action {
		case rules.ActionDirect:
			e.bus.Debug("route: %s action=direct", r.Label())
		case rules.ActionBlock:
			e.bus.Debug("route: %s action=block", r.Label())
		default:
			e.bus.Debug("route: %s action=chain/%s", r.Label(), r.Chain)
		}
	}
	for _, ch := range chainList {
		e.bus.Debug("    链 %s：%d 个上游，策略 %s，探测 %s",
			ch.Name, len(ch.Upstreams()), ch.StrategyName(), ch.ProbeInterval())
	}

	if mainFilter != "" {
		// 三 KB 一行的条件串：只在 debug 档写（现场读不下去，但"包到底有没有被内核送过来"
		// 只有它能回答）。也进不了诊断包了 —— 那个功能已删，所以这里更要写全。
		e.bus.Debug("filter.main: %s", mainFilter)
	}
	if dynOn {
		e.bus.Debug("dump.dynfilter: filter_bytes=%d %s", len(dynFilter), dynFilter)
	}

	e.bus.Debug("dump.names: count=%d（只列前 %d 条）", len(names), dumpMaxNames)
	for i, n := range names {
		if i >= dumpMaxNames {
			e.bus.Debug("dump.names: 其余 %d 条省略", len(names)-dumpMaxNames)
			break
		}
		mark := ""
		switch {
		case n.Failed:
			mark = " failed=" + n.LastErr
		case n.Stale:
			mark = " stale"
		}
		e.bus.Debug("names: %s → %s age=%s%s", n.Host, strings.Join(n.IPs, ","), n.Age.Round(1e9), mark)
	}

	if e.fake != nil {
		used, cap := e.fake.Stats()
		e.bus.Debug("dump.fakeip: used=%d cap=%d range=%v names=%v", used, cap, e.fake.Range(), e.fake.Names())
	} else {
		e.bus.Debug("dump.fakeip: 未启用（DNS 接管关着或规则里没有通配域名）")
	}

	e.bus.Debug("dump.conns: total=%d active=%d perChain=%s", total, active, chainCountsText(perRule))
	// 顺带说一句自己人的探针：否则看转储的人会问“刚才那次链路自检怎么不在连接数里”
	if n := e.SelfPortCount(); n > 0 {
		e.bus.Debug("dump.self: 本进程探针登记了 %d 个本地端口（不计入上面的连接数，也不进界面列表）", n)
	}
	if e.proc != nil {
		ports, pids := e.proc.Stats()
		e.bus.Debug("dump.proc: 进程表 ports=%d pids=%d", ports, pids)
	}

	if peers := e.DivertPeers(); len(peers) > 0 {
		e.bus.Debug("dump.kernel: main=%v dyn=%v dns_inject=%v socket_layer=%v reflect_layer=%v peers=%v",
			mainOn, dynOn, dnsInjectOn, sockOn, reflectOn, peers)
	} else {
		e.bus.Debug("dump.kernel: main=%v dyn=%v dns_inject=%v socket_layer=%v reflect_layer=%v peers=none",
			mainOn, dynOn, dnsInjectOn, sockOn, reflectOn)
	}
	e.bus.Debug("dump.state: 转储结束（规则 %d 条 · 名字 %d 个 · 连接 %d/%d）",
		len(ruleList), len(names), active, total)
}

// chainCountsText 把「每条链累计接管多少条」拼成一行（稳定顺序，便于对比两次转储）。
func chainCountsText(m map[string]uint64) string {
	if len(m) == 0 {
		return "无"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%s:%d", k, m[k])
	}
	return b.String()
}
