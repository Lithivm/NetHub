package engine

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"nethub/internal/config"
	"nethub/internal/rules"
	"nethub/internal/upstream"
)

// ───────────────────────── relay ─────────────────────────

func (e *Engine) acceptLoop() {
	defer e.wg.Done()
	e.mu.Lock()
	ln := e.ln
	e.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("relay accept: %v", err)
				return
			}
		}
		// 在途 relay 连接登记在册（见 relayConns）：Stop 时要主动关掉它们。
		// 否则进度列表里说“已停止”、hosts 已经撤了，实际上隧道还在转发数据。
		e.mu.Lock()
		if e.relayConns == nil {
			e.relayConns = map[net.Conn]struct{}{}
		}
		e.relayConns[c] = struct{}{}
		e.mu.Unlock()
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer func() {
				e.mu.Lock()
				delete(e.relayConns, c)
				e.mu.Unlock()
			}()
			e.handleConn(c)
		}()
	}
}

// resolveModeFor 决定一条连接的解析策略：全局 domain_resolve + domain_resolve_local 白名单。
//
// 抽成函数是为了能单测（它决定“域名是本机解还是交给上游解”，现场最容易配错的地方）：
//   - 白名单命中 → 一律 local（压过全局策略）
//   - 例外：没有域名（直接按 IP 连）时白名单无意义
//   - 假 IP 且本机解不出真实 IP 的情况不在这里 —— 那种只能交给上游（调用方另有分支）
func (e *Engine) resolveModeFor(host string, hasName bool) string {
	mode := e.cfg.DomainResolveMode()
	if hasName && e.cfg.ForceLocalResolve(host) {
		if mode != "local" {
			e.bus.Detail("resolve.force_local: name=%s（命中 domain_resolve_local，按本机解析；全局策略是 %s）", host, mode)
		}
		return "local"
	}
	return mode
}

// dialUpstream 建立到目标的上游连接。
//
// 一条链可能有多个上游（故障转移/轮询/随机）：按策略拿候选顺序，依次试，
// 第一个成功的就用；每次成/败都记进健康表（被动探测，不靠主动探也能学到东西）。
// dialUpstream 按候选顺序试上游，一个不成马上换下一个。
//
// 两个旋钮（都在 config.tuning 里，默认 5s / 10s）：
//   - 单次超时：一条上游最多等多久。半死上游（TCP 通但不回话）会吃满这个时间，
//     所以它直接决定“业务等多久才换下一条”。老的硬编码 10s 是实测 TTFB 偏高的主因。
//   - 总预算：一整次连接最多花多久，防止候选多时逐个等满。
//     拒绝型失败（端口不通）只花几毫秒，所以不会触发截断；只有超时型才吃预算。
//
// logUpstreamPick 记一行“这条连接实际用了哪个上游”（verbose 档）。
//
// 以前这一片完全是空白：链里配了多条上游、又开着故障转移/竞速/预热池时，
// 事后没有人知道流量到底走了谁 —— “两条上游都是通的，为什么这条特别慢”无从查起。
// 地址用 maskUpstream（保留协议/主机/端口、去掉凭据），日志可以往外发。
func (e *Engine) logUpstreamPick(ch config.Chain, idx int, warm bool, lat time.Duration) {
	if !e.bus.Verbose() {
		return
	}
	raws := e.cfg.UpstreamsResolved(ch)
	raw := "?"
	if idx >= 0 && idx < len(raws) {
		raw = maskUpstream(raws[idx])
	}
	how := "现拨"
	if warm {
		how = "预热会话"
	}
	e.bus.Detail("upstream.pick: chain=%s upstream=#%d/%d %s %s lat_ms=%d",
		ch.Name, idx+1, len(raws), raw, how, lat.Milliseconds())
}

func (e *Engine) dialUpstream(ch config.Chain, dst net.IP, dport uint16) (net.Conn, error) {
	return e.dialUpstreamKeyed(ch, dst, dport, "")
}

// dialUpstreamKeyed 带一个「粘性键」（一般是客户端 IP）：
// 链的策略是 hash 时，同一个键永远落到同一条上游 —— 需要"对方按来源 IP 做白名单/会话"
// 的场景就靠它（A17）。
func (e *Engine) dialUpstreamKeyed(ch config.Chain, dst net.IP, dport uint16, key string) (net.Conn, error) {
	raws := e.cfg.UpstreamsResolved(ch) // A18：还原 DPAPI 保险箱里的口令
	if len(raws) == 0 {
		return nil, fmt.Errorf("链 %s 没有配置上游", ch.Name)
	}
	per, budget := e.cfg.DialTimeoutDur(), e.cfg.DialBudgetDur()
	cands := e.candidatesFor(ch, key)

	// 预热连接池：先看池子里有没有“已握手、只差 CONNECT”的会话（A11）
	if c, ok := e.dialWarm(ch, cands[0], dst, dport); ok {
		e.afterDial(ch, cands[0])
		return c, nil
	}
	// 慢则竞速（A10）：候选有两条以上、且第一条超过 race_after 还没连上时，
	// 把其余的并发拨出去，取先成功的。
	// 为什么不是“总是并发”：平时并发会成倍放大连接数与客户端 IP 的落地请求，
	// 只有在“第一条明显慢”时才值得。实测 site-a 的 CONNECT 阶段要 620ms、site-b 只要 75ms，
	// 这一招能把业务直接拉到快链路。
	if len(cands) > 1 && e.cfg.RaceAfterDur() > 0 {
		c, ok, raced, raceErr := e.dialRacing(ch, raws, cands, dst, dport, per, budget)
		if ok {
			return c, nil
		}
		if raced {
			// 竞速已经把**所有**候选都拨过一遍了，失败就是真失败；
			// 再回退一次顺序试等于把同一批上游拨两遍（白等一个预算）。
			return nil, raceErr
		}
		// 第一条在起跑前就明确失败 → 从第二条开始顺序试（不重复第一条）
		return e.dialSequential(ch, raws, cands[1:], dst, dport, per, budget)
	}
	return e.dialSequential(ch, raws, cands, dst, dport, per, budget)
}

// dialSequential 顺序试（原行为）：一个不成马上换下一个。
func (e *Engine) dialSequential(ch config.Chain, raws []string, cands []int,
	dst net.IP, dport uint16, per, budget time.Duration) (net.Conn, error) {
	start := time.Now()
	var errs []string
	for n, idx := range cands {
		el := time.Since(start)
		// 第一条无论如何都试（否则预算配小了就永远不会拨号）
		if n > 0 && el >= budget {
			msg := fmt.Sprintf("剩余 %d 条上游未尝试（已用 %s，总预算 %s）",
				len(raws)-n, el.Round(time.Millisecond), budget)
			e.bus.Warn("链 %s 拨号：%s", ch.Name, msg)
			errs = append(errs, msg)
			break
		}
		timeout := per
		if left := budget - el; left > 0 && left < timeout {
			timeout = left
		}
		c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, timeout)
		if err == nil {
			e.afterDial(ch, idx) // 用掉一条就要补一条
			return c, nil
		}
		errs = append(errs, msg)
	}
	return nil, fmt.Errorf("%s", strings.Join(errs, "\n"))
}

// tryUpstream 试一条上游，并把结果记进健康表。
//
// 注意业务拨号的失败**只作为参考**，不直接把上游判成 down（见 noteUpstream）：
// 一个坏掉的内网目标也能连着失败两次，那不代表上游挂了。
func (e *Engine) tryUpstream(ch config.Chain, raw string, idx int, dst net.IP, dport uint16,
	timeout time.Duration) (net.Conn, error, string) {
	up, err := upstream.Parse(raw)
	if err != nil {
		// 被动失败分不出"凭据被拒"与"连不上"（这里的 err 已经是包装过的文案）：
		// 不猜，统一记 false —— 真凭据被拒时探测（30s 一轮）会把它认出来。
		e.markUp(ch.Name, idx, false, 0, err.Error(), false)
		return nil, err, fmt.Sprintf("上游 %d: %v", idx+1, err)
	}
	t0 := time.Now()
	c, err := up.Dial(dst, dport, timeout)
	lat := time.Since(t0)
	if err == nil {
		// 真拨通了：这是比探测更硬的证据，可以直接把状态正过来（也顺带消掉假警报）
		e.markUp(ch.Name, idx, true, lat, "", false)
		e.logUpstreamPick(ch, idx, false, lat)
		return c, nil, ""
	}
	// 失败：只升级“疑似”，等下一次探测确认。否则一条坏业务目标
	// 连续失败两次就能把健康的上游写成 down，随后探测又报一行假的恢复。
	e.noteUpstreamSuspect(ch.Name, idx, err.Error())
	// 每条上游一行、带耗时与本次超时 —— 现场把日志整段复制给 agent 时，
	// “谁、排第几、等了多久、原始报错是什么”都在这一行里。
	// 上游地址用 maskUpstream（保留协议/主机/端口，去掉凭据）。
	return nil, err, fmt.Sprintf("上游 #%d %s（单次超时 %s，已等 %s）：%v",
		idx+1, maskUpstream(up.Raw), timeout, lat.Round(time.Millisecond), err)
}

// dialAttempt 一次拨号尝试的结果（竞速用）。
type dialAttempt struct {
	c   net.Conn
	err error
	msg string
}

// dialRacing 慢则竞速：等 raceAfter，第一条还没好就把剩下的并发拨出去，取先到的。
//
// 返回：conn（成功时）、ok（拿到连接）、raced（是否真的进过竞速阶段）。
// 　　　raced=false 表示第一条在起跑前就明确失败，调用方应从第二条开始顺序试。
func (e *Engine) dialRacing(ch config.Chain, raws []string, cands []int,
	dst net.IP, dport uint16, per, budget time.Duration) (net.Conn, bool, bool, error) {
	race := e.cfg.RaceAfterDur()
	if race <= 0 || race >= per {
		race = per / 2 // 竞速必须早于单次超时，否则没意义
	}
	t0 := time.Now()
	first := make(chan dialAttempt, 1)
	go func(idx int) {
		c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, minDur(per, budget))
		first <- dialAttempt{c, err, msg}
	}(cands[0])

	select {
	case a := <-first:
		if a.err == nil {
			return a.c, true, true, nil
		}
		// 第一条已经明确失败（被拒/解析错）→ 交给顺序试，它从第二条开始
		if a.c != nil {
			a.c.Close()
		}
		return nil, false, false, a.err
	case <-time.After(race):
	}

	// 剩下的并发拨（总超时受剩余预算约束）
	n := len(cands) - 1
	left := budget - time.Since(t0)
	if left <= 0 {
		left = per
	}
	rest := make(chan dialAttempt, n)
	for _, idx := range cands[1:] {
		go func(idx int) {
			c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, minDur(per, left))
			rest <- dialAttempt{c, err, msg}
		}(idx)
	}
	e.bus.Detail("链 %s：第一条上游还没连上（等满 %.0fms），并发试其余 %d 条",
		ch.Name, race.Seconds()*1000, n)

	errs := []string{}
	readRest, firstRead := 0, 0
	for readRest < n || firstRead == 0 {
		select {
		case a := <-rest:
			readRest++
			if a.err == nil {
				// 其余候选还在跑：它们的连接成功也来不及用了，收尾时关掉
				go drainAttempts(rest, n-readRest, per)
				go drainAttempts(first, 1-firstRead, per)
				return a.c, true, true, nil
			}
			errs = append(errs, a.msg)
		case a := <-first:
			firstRead = 1
			if a.err == nil {
				go drainAttempts(rest, n-readRest, per)
				return a.c, true, true, nil
			}
			errs = append(errs, a.msg)
		}
	}
	e.bus.Warn("链 %s 竞速全失败：\n%s", ch.Name, strings.Join(errs, "\n"))
	detail := strings.Join(errs, "\n")
	if detail == "" {
		detail = "所有上游都连不上"
	}
	return nil, false, true, fmt.Errorf("链 %s：所有上游都连不上\n%s", ch.Name, detail)
}

// drainAttempts 把竞速里多余的尝试收干净：成功的连接要关掉，不能漏。
func drainAttempts(ch chan dialAttempt, n int, wait time.Duration) {
	deadline := time.After(wait + time.Second)
	for i := 0; i < n; i++ {
		select {
		case a := <-ch:
			if a.c != nil {
				a.c.Close()
			}
		case <-deadline:
			return
		}
	}
}

// minDur 取较小值（给拨号超时用）。
func minDur(a, b time.Duration) time.Duration {
	if a < b || b <= 0 {
		return a
	}
	return b
}

func (e *Engine) handleConn(c net.Conn) {
	defer c.Close()

	_, portStr, _ := net.SplitHostPort(c.RemoteAddr().String())
	var sport uint16
	fmt.Sscanf(portStr, "%d", &sport)

	e.mu.Lock()
	st := e.conns[sport]
	e.mu.Unlock()
	if st == nil {
		e.bus.Warn("relay 收到未知来源连接 sport=%d，丢弃", sport)
		return
	}
	// 看门狗：relay 确实收到了这条连接（这一步以前没有任何记录，
	// 导致“包没到 relay”这种故障在日志里完全看不出来）。
	st.relayed.Store(true)
	// 登记应用侧连接：用户在连接列表里点「结束」时要能把它关掉。
	st.setClient(c)
	// 建链耗时（握手 + 认证 + CONNECT）单独量：一条连接慢到底是“上游慢”
	// 还是“传输慢”，只看总耗时是分不清的 —— 专业日志（HAProxy 的 Tc、squid 的 %tr）也都分开记。
	dialStart := time.Now()

	ch, ok := e.cfg.ChainByName(st.chain)
	if !ok {
		e.bus.Error("链 %s 不存在，丢弃 %s:%d", st.chain, st.dst, st.dport)
		return
	}

	// 域名规则命中时，按配置决定“本机解析”还是“交给上游解析”：
	//
	//	local（默认）   按本机解析出的 IP 连 —— 客户内网域名通常只有本机能解答
	//	upstream        把域名交给上游解析（同一域名两边解析不同时用）
	//	auto            本机优先，连不上再把域名交给上游试一次
	//
	// 实测教训：我们这套环境里 main.example.com 只有客户网内的 DNS 能解答，
	// 上游是公网中转服务器、解析不到（host unreachable）—— 所以不能默认透传。
	host, hasName := e.nameOf(st.dst)
	// 目标是我们发的假 IP：绝不能拿它去连（那是个不存在的地址）。
	// st.dst 保持“应用连的那个地址”（回包改写要用），真实 IP 单独放 st.realDst，
	// 拨号/展示统一走 dialDst。
	if e.isFakeIP(st.dst) {
		name := host
		st.fakeName = name
		if !hasName {
			// 池子里没这个名字：多半是重启前的旧假 IP（映射不落盘）。说清楚，别让人猜。
			e.bus.Warn("DNS 接管：连到未登记的假 IP %s:%d（NetHub 重启前发的旧应答？）—— 这一条连不上",
				st.dst, st.dport)
			st.fail("假 IP 已过期（NetHub 重启过），请重新访问一次")
			e.finish(st)
			return
		}
		real := e.resolveReal(name)
		if real != nil {
			st.realDst.Store(real)
			// 把“名字 → 真实 IP”记进名字表。两个作用：
			//  ① 界面上的通配规则能显示“已覆盖 N 个 IP”（否则接管过的名字永远是空的，
			//     看起来像“这条规则什么都不拦”—— 而它刚刚才拦过）；
			//  ② 应用第二次直接用缓存里的**真实 IP** 连过来时，也能按名字命中这条规则。
			e.noteRealIP(name, real)
			e.bus.Detail("DNS 接管：假 IP %s → %s 的真实 IP %s", st.fakeName, name, real)
		} else {
			e.bus.Detail("DNS 接管：假 IP %s → %s 本机解不开，交给上游解析", st.dst, name)
		}
	}
	dialDst := st.displayTarget() // 假 IP 已解析则用真实 IP，否则保持原地址
	// “域名→IP”这一段到此结束：它是本机解析（可能走 DNS），与“连上游”是两件事。
	// 两者分开量，慢的时候才知道该查 DNS 还是查上游（见下方 conn.stage / close 行）。
	resolveEnd := time.Now()

	// 假 IP 阶段只能按“名字”选链，可能把本该按 IP 走的连接选错
	// （宽通配如 main.*.com 抢走 198.51.100.0/24 的连接）。真实 IP 到手后，
	// 用“IP 优先”的匹配再判一次，以其为准 —— 这就是 v0.2.2 / Proxifier 的语义。
	if e.isFakeIP(st.dst) && st.action == rules.ActionChain {
		if real := st.realTarget(); real != nil {
			if chain2, act2, hit := e.ruleSet().MatchName(host, real, st.dport, st.procName); hit && chain2 != st.chain {
				switch act2 {
				case rules.ActionChain:
					e.bus.Detail("route.fixup: target=%s real_ip=%s %s → %s（真实 IP 命中更靠前的规则）",
						host, real, st.chain, chain2)
					st.chain = chain2
					if c2, ok2 := e.cfg.ChainByName(chain2); ok2 {
						ch = c2
					}
				default:
					// 真实 IP 命中直连/阻断：目前仍按原链走（罕见；给出可操作提示）
					e.bus.Warn("route.fixup: target=%s real_ip=%s 命中 %s 规则而非链 —— 仍按原链处理；"+
						"如需直连/阻断，请把该网段的规则排到前面", host, real, act2)
				}
			}
		}
	}
	mode := e.resolveModeFor(host, hasName)
	var up net.Conn
	var err error
	tryName := func() bool {
		if !hasName {
			return false
		}
		up, err = e.dialViaName(ch, host, st.dport)
		if err == nil {
			e.bus.Detail("[%s] 用域名 %s 建隧道（交给上游解析）", st.chain, host)
			return true
		}
		return false
	}
	// 假 IP 且本机解不开：只能交给上游（不能拿假 IP 当目标）。
	// 其余情况保持原有语义：按 DomainResolve 配置走 local / upstream / auto。
	if e.isFakeIP(st.dst) && st.realTarget() == nil {
		e.bus.Detail("[%s] 目标 %s 是假 IP（无真实 IP），只能交给上游解析域名 %s", st.chain, st.dst, host)
		tryName()
	} else {
		switch {
		case mode == "upstream" && hasName:
			if !tryName() {
				up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
			}
		case mode == "upstream":
			up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
		default: // local / auto：先用本机解析出的 IP
			up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
			if err != nil && mode == "auto" && hasName {
				e.bus.Detail("[%s] 按 IP %s 连不上（%v），改用域名 %s 交给上游再试", st.chain, dialDst, err, host)
				tryName()
			}
		}
	}
	if err != nil {
		// 原始报错一字不改地打出来（现场是把日志整段复制给 agent 看的，
		// 任何“翻译成人话”都会把底层信息抹掉）。这里只补几项我们才知道的上下文：
		// 命中哪条链、谁发起的、以及这条链试过哪些上游。
		//
		// 进程定位不到时（系统服务的短连接、受保护进程、连接已消失）：
		// **不进 ERROR**，只打一行 INFO。两个原因：
		//  ① 对用户可操作的信息 = 0（它多半是系统的后台连接，如 Windows 传递优化连局域网邻居）；
		//  ② 以前这里会打 “PID 0” —— PID 0 在 Windows 上是空闲进程、永远不会拥有 TCP 连接，
		//     那只是我们“查不到”的哨兵值，打在日志里纯属误导（用户以为多了个进程）。
		if st.procName == "" {
			e.bus.Info("tunnel.down: chain=%s target=%s:%d proc=unknown src_port=%d err=%s",
				st.chain, dialDst, st.dport, sport, firstLine(err.Error()))
			st.fail(err.Error())
			e.finish(st)
			return
		}
		// 我们自己的探针（DialSelf）**不是业务**：它不进连接列表、不计累计、normal 档不记日志 ——
		// 隧道失败这条也一样。**探针**（DialSelf 开的连接）会周期性去探不存在的地址，
		// 按 ERROR 记就是自己给自己刷日志（实测每 60 秒一条“隧道建立失败 203.0.113.0:65533”，
		// 现场会以为真出了事故）。
		if st.self {
			e.bus.Debug("tunnel.down: chain=%s target=%s:%d proc=nethub(自检探针) src_port=%d err=%s",
				st.chain, dialDst, st.dport, sport, firstLine(err.Error()))
			st.fail(err.Error())
			e.finish(st)
			return
		}
		e.bus.Error("[%s] 隧道建立失败 %s:%d（进程 %s，PID %d，源端口 %d）",
			st.chain, dialDst, st.dport, st.procName, st.pid, sport)
		for _, line := range strings.Split(err.Error(), "\n") {
			e.bus.Error("    %s", line)
		}
		st.fail(err.Error())
		e.finish(st)
		return
	}
	defer up.Close()
	// 拨号花了多少秒都正常：用户可能在这期间点了「结束」。
	// 那就不该再开两条拷贝协程，直接把刚拨通的上游放下走人。
	if st.setUpstream(up) {
		e.finish(st)
		return
	}

	dialEnd := time.Now()
	dialMs := dialEnd.Sub(dialStart).Milliseconds()
	resolveMs := resolveEnd.Sub(dialStart).Milliseconds()
	handshakeMs := dialEnd.Sub(resolveEnd).Milliseconds()

	// 不再单记一行 relay.up：它只是中间态，成功与否看 close（字节数）、
	// 失败看 tunnel.down；每条连接两行（open 开始 / close 结束）就够现场用，
	// 也跟 Proxifier “一条连接 open/close”的粒度对得上，不再把日志刷成三段。

	done := make(chan struct{}, 2)
	// 目标**首个响应字节**的时刻（0 = 到关闭时目标一字未回）。
	// 只记下行：上行那侧的第一个字节是应用刚发的请求，它只能证明“应用很积极”，
	// 证明不了服务端多久才应 —— 那正是排查“连上了但就是慢”要看的东西。
	var firstByte atomic.Int64
	markFirst := func() { firstByte.CompareAndSwap(0, time.Now().UnixNano()) }
	go func() { copyAndClose(up, c, &st.up, e.tunTotal(st, true), nil); done <- struct{}{} }()
	go func() { copyAndClose(c, up, &st.down, e.tunTotal(st, false), markFirst); done <- struct{}{} }()
	<-done

	e.finish(st)
	// 收尾时再补一次进程名：连接刚建那一刻表还没刷新到它（实测的 proc=unknown 根因），
	// 而到收尾时表里通常已经有了（TIME_WAIT 之类的行也在表里）。
	// 每连接一次，不在包路径上。
	if st.procName == "" && e.proc != nil {
		if n, pid, ok := e.proc.ByPort(st.appPort); ok {
			e.mu.Lock()
			st.procName, st.pid = n, pid
			e.mu.Unlock()
		}
	}
	// 与 open 同形（Proxifier 的 open/close 也是同一前缀）：
	//	close: curl.exe (12376) → main.example.com(192.0.2.217):80 via site-a ↑76 B ↓279 B 884ms/997ms
	// 前一个时间是"连上游（含域名解析）"，后一个是"从发起到收尾"。
	e.connInfo(st.self, "close: %s → %s via %s ↑%s ↓%s %dms/%dms",
		connWho(st.procName, st.pid), e.connTargetDial(st.dst, dialDst, st.dport), st.chain,
		humanBytes(st.up.Load()), humanBytes(st.down.Load()),
		dialMs, time.Since(st.start).Milliseconds())
	// verbose：把“慢在哪一步”分开 —— 域名解析 / 连上游握手 / 目标首个响应。
	// normal 的 close 只有一个总数，事后分不清该查 DNS、查上游还是查服务端。
	if !st.self && e.bus.Verbose() {
		first := "未响应"
		if fb := firstByte.Load(); fb > 0 {
			first = fmt.Sprintf("%dms", time.Unix(0, fb).Sub(dialEnd).Milliseconds())
		}
		e.bus.Detail("conn.stage: %s → %s via %s resolve=%dms dial=%dms first_byte=%s total=%dms",
			connWho(st.procName, st.pid), e.connTargetDial(st.dst, dialDst, st.dport), st.chain,
			resolveMs, handshakeMs, first, time.Since(st.start).Milliseconds())
	}
}

// connInfo 连接类日志的分流：真实应用流量走 normal，**我们自己的探针走 verbose**。
//
// 为什么（2026-10-14 用户报“一启动就打印这么多日志”）：自检/共存检测会直接 dial 内网目标
// （DialSelf，见 selfconn.go）—— 它们已经不在连接列表、不计入统计了，但日志还是逐条按 normal 打，
// 于是每次开机都有一串 `proc=nethub.exe` 的“连接”，看日志的人会以为是应用在连。
// 原则与“自己的探针不当应用流量”一致：那是仪器，不是业务（要看它们就切 verbose）。
func (e *Engine) connInfo(self bool, format string, a ...any) {
	if self {
		if e.bus.Verbose() {
			e.bus.Info(format, a...)
		}
		return
	}
	e.bus.Info(format, a...)
}

// KillConn 手动结束一条连接（连接列表里点「结束」）。
//
// 现场诉求：这条连接卡死了（远端重启过、会话粘在一条坏上游上），而应用自己要等到
// 超时才肯重连。关掉两端 → relay 的两条拷贝协程自然返回 → 走正常 finish
// （统计/历史/日志都齐，与“对端断开”同一条路径，不特殊处理）。
//
// **不动判定**：应用下一拍会重新建连，走同一套规则 —— 这才是现场要的“重连”。
func (e *Engine) KillConn(sport uint16) error {
	e.mu.RLock()
	st := e.conns[sport]
	e.mu.RUnlock()
	if st == nil || st.ended.Load() {
		return fmt.Errorf("这条连接已经结束了（列表可能刚刷新）")
	}
	st.killMu.Lock()
	if st.killed {
		st.killMu.Unlock()
		return fmt.Errorf("这条连接已经结束了")
	}
	c, up := st.c, st.upConn
	if c == nil && up == nil {
		st.killMu.Unlock()
		return fmt.Errorf("这条连接不走中转（直连/阻断/还在建链），结束不了它")
	}
	st.killed = true
	st.killMu.Unlock()

	// 记一行（normal 档）：不写的话，现场会把“我手动结束的”当成网络断了，
	// 然后去查上游/驱动 —— 那是 2026-10 实际踩过的排查弯路。
	e.connInfo(st.self, "conn.kill: %s → %s via %s ↑%s ↓%s %dms by=user",
		connWho(st.procName, st.pid), e.connTargetDial(st.dst, st.displayTarget(), st.dport), st.chain,
		humanBytes(st.up.Load()), humanBytes(st.down.Load()), time.Since(st.start).Milliseconds())

	if up != nil {
		up.Close() // 先断上游：让它那侧也收到 FIN，不留下“半死”的会话
	}
	if c != nil {
		c.Close() // 再断应用：应用立刻看到断开，不等超时
	}
	return nil
}

// copyAndClose 单向拷贝并在结束后关闭写端（半关闭，双向都能正常收尾）。
//
// counter = 这条连接的字节数（界面按连接显示）；total = 走链路的字节总数
// （顶栏流量图，见 engine 的 tunUp/tunDown 注释）。两个都要加：前者是“一条多少”，
// 后者是“一共多少”——短连接结束时前者就没人看了，后者才是曲线的基础。
// total 可以是 nil：我们自己的探针不计入总量（见 tunTotal）。
func copyAndClose(dst, src net.Conn, counter, total *atomic.Uint64, onFirst func()) {
	buf := make([]byte, 32*1024)
	add := func(n int) {
		counter.Add(uint64(n))
		if total != nil {
			total.Add(uint64(n))
		}
	}
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if onFirst != nil {
				onFirst() // 首个字节（并发安全由调用方的 CAS 保证；多调几次无妨）
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				add(n)
				break
			}
			add(n)
		}
		if err != nil {
			break
		}
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
	src.Close()
}
