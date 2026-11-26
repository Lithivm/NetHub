package engine

import (
	"fmt"
	"net"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/rules"
)

// ───────────────────────── 包处理 ─────────────────────────

// recoverHandle Recv 出错后的自愈：按退避重建同一只句柄，成则继续收包。
//
// 为什么要它（审计 P0-2）：主句柄一旦不可用，拦截就完全停了，但进程还活着、界面
// 还显示“运行中” —— 内网流量被系统按原路发出去（直连内网 IP，全不通），
// 只有人工重启才能恢复。触发途径实测存在：驱动被卸、安全软件临时拦、句柄失效。
//
// 退避 1s/2s/5s/10s/30s（共 ~48 秒）；期间一旦收到停止信号就立即退出。
// 新句柄先建好、再把旧句柄关掉（防止关完到重建成功这段空窗期里包没人接）。
func (e *Engine) recoverHandle(kind loopKind, stop chan struct{}, shard int) (*divert.Handle, error) {
	backoff := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}
	var lastErr error
	for i, wait := range backoff {
		select {
		case <-e.done:
			return nil, fmt.Errorf("引擎已停止")
		default:
		}
		if i > 0 {
			select {
			case <-e.done:
				return nil, fmt.Errorf("引擎已停止")
			case <-time.After(wait):
			}
		}
		filter, ferr := e.handleFilter(kind, shard)
		if ferr != nil {
			return nil, ferr // 过滤器都不在了（停止过程中）→ 不必再试
		}
		nh, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err != nil {
			lastErr = err
			continue
		}
		// 新句柄已经能收包了，才动旧的
		e.mu.Lock()
		var old *divert.Handle
		if kind == loopDyn {
			// 这期间可能有别的路径重建过：那就不用我们这只
			if e.dynHandle != nil {
				nh.Close()
				e.mu.Unlock()
				return nil, fmt.Errorf("动态句柄已被重建")
			}
			e.dynHandle, e.dynFilter = nh, filter
		} else {
			// 只换坏的那一片：其它分片的句柄不动（它们各自在自己的循环里跑）。
			// 下标越界 = 这中间热重载把分片换过了 → 直接放弃这只（外面会重新读 e.handles）。
			if shard < 0 || shard >= len(e.handles) {
				nh.Close()
				e.mu.Unlock()
				return nil, fmt.Errorf("分片 %d 已不在当前句柄表里（可能刚热重载过）", shard)
			}
			old = e.handles[shard]
			e.handles[shard] = nh
		}
		e.mu.Unlock()
		if old != nil {
			old.Close()
		}
		e.setFatal(nil)
		e.bus.Info("WinDivert: 句柄已重建（第 %d 次尝试）—— 拦截恢复", i+1)
		return nh, nil
	}
	return nil, lastErr
}

// handleFilter 重建句柄时用哪份过滤器：主句柄按当前规则集重算（取第 shard 片），
// 动态句柄用记着的那份。
func (e *Engine) handleFilter(kind loopKind, shard int) (string, error) {
	if kind == loopDyn {
		e.mu.RLock()
		f := e.dynFilter
		e.mu.RUnlock()
		if f == "" {
			return "", fmt.Errorf("动态过滤器没有记录")
		}
		return f, nil
	}
	_, shards, _ := e.buildMainFilters(e.ruleSet(), portOf(e.RelayAddr()), e.shards)
	if len(shards) == 0 {
		return "", fmt.Errorf("主过滤器为空（规则集为空？）")
	}
	if shard < 0 || shard >= len(shards) {
		return "", fmt.Errorf("分片索引 %d 超范围（共 %d 片）", shard, len(shards))
	}
	return shards[shard], nil
}

// loopKind 说明这只句柄是谁的 —— 决定 Recv 出错时怎么处理（这两类差别很大，
// 用 stop 是否为 nil 来区分已经不够了：热重载会让**主**句柄也带着 stop）。
type loopKind int

const (
	loopMain loopKind = iota // 主过滤器：出错＝整个引擎“拦截已中断”
	loopDyn                  // 动态过滤器（通配域名）：出错只是这部分不再接管
)

// shard 本循环负责的分片号（loopDyn 传 -1）：句柄出错重建时要按它只换自己那一片。
func (e *Engine) packetLoop(h *divert.Handle, stop chan struct{}, kind loopKind, shard int) {
	defer e.wg.Done()

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	relayIP := net.ParseIP(hostOf(e.RelayAddr())).To4()
	relayPort := portOf(e.RelayAddr())

	for {
		var pt perfTimes
		if e.perf.on {
			pt.enter = time.Now()
		}
		n, err := h.Recv(buf, addr)
		if e.perf.on {
			pt.recv = time.Now()
		}
		if err != nil {
			select {
			case <-e.done:
				return
			case <-closedCh(stop):
				return // 我们在换句柄（热重载 / 换动态过滤器），不是出错
			default:
			}
			if kind == loopDyn {
				// 动态句柄出错不能把整个引擎置成“已中断”：它只管通配域名那部分流量。
				// 但它也不能就此死掉 —— 先清掉句柄状态（让重建不再被“过滤器没变”挡回去），
				// 再退避重建；不行才放弃。
				e.bus.Warn("域名通配：动态过滤器已中断: %v（正在重建）", err)
				e.mu.Lock()
				e.dynHandle, e.dynStop, e.dynFilter = nil, nil, ""
				e.mu.Unlock()
				if nh, rerr := e.recoverHandle(kind, stop, shard); rerr == nil {
					h = nh
					continue
				}
				return
			}
			// 主句柄：**绝不能就此放弃**。
			//
			// 拦截一停，那些本该走隧道的内网目标就会被系统按原路发出去（直连内网 IP
			// = 全部不通），而进程还活着、界面还是绿的，只有人工重启才能恢复。
			// 实测触发过：驱动被卸、被安全软件拦、句柄失效。
			// 所以按退避重建；连续多次不行才判“已中断”。
			nh, rerr := e.recoverHandle(kind, stop, shard)
			if rerr == nil {
				h = nh
				continue
			}
			e.bus.Error("WinDivert Recv 失败，且重建句柄失败（最后一次: %v）：原错误 %v", rerr, err)
			e.setFatal(err) // 让界面变红「Error」—— 否则状态还说“运行中”，其实一个包都没拦
			if e.Notify != nil {
				e.Notify("拦截已中断", err.Error()+"（请重启服务）", true)
			}
			return
		}
		pkt := buf[:n]

		// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
		// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
		// 只取源端口、不取地址与载荷 —— 每个包都跑这段，udpPayload 会白白分配两块 slice。
		if sport, ok := udpSrcPort(pkt); ok && sport >= dnsProbePortLo && sport <= dnsProbePortHi {
			continue
		}

		src, dst, ihl, proto, ok := parseIPv4(pkt)
		if e.perf.on {
			pt.parsed = time.Now()
		}
		// QUIC（UDP 443）：这条包能到我们手上，说明它的目标落在“该走隧道”的网段里
		// （过滤器只装了那些范围的 UDP 443，直连目标的 QUIC 根本不经过我们）。
		// UDP 走不了隧道 —— 以前是静默直连漏出，现在丢掉并记一行（回 ICMP 是尽力而为）。
		if ok && proto == 17 {
			e.blockQUIC(h, pkt, addr, src, dst, ihl)
			e.perf.record(&pt, n, pkOther, shard)
			continue
		}
		if !ok || proto != 6 || len(pkt) < ihl+20 {
			_, _ = h.Send(pkt, addr)
			e.perf.record(&pt, n, pkOther, shard)
			continue
		}
		t := ihl
		sport := be16(pkt, t+offSrcPort)
		dport := be16(pkt, t+offDstPort)
		flags := pkt[t+offFlags]

		// 入方向：源端口 = relay 端口的包，只可能是本机 relay 回来的
		// （应用不可能正好用着 relay 占着的那个端口）。先判它，
		// 否则“只按进程”的规则会把回来的包也当出站命中。
		if sport == relayPort {
			if e.perf.on {
				pt.decided = time.Now() // 入方向没有判定面，这一段直接进改写+注入
			}
			e.rewriteInbound(h, pkt, addr, t, dport)
			if e.perf.on {
				pt.sent = time.Now()
			}
			e.perf.record(&pt, n, pkIn, shard)
			continue
		}

		// 出方向：这条连接属于哪个进程（只在规则里写了进程条件时才查表，其余情况零开销）。
		// 优先用连接上缓存的结论，避免每个包都查。
		procName, procPID := e.flowProc(sport)

		// 内置直连：Windows 更新传递优化走 TCP 7680，客户内网里不该进隧道。
		// 以前要在规则里写一条 direct 规则来实现；现在内置，规则列表干净。
		if dport == builtinDirectPort && e.cfg.BuiltinDirectEnabled() {
			// 内置直连（Windows 更新传递优化）：一个文件共享的 peer 一对一行，
			// 刷起来全是噪声且对现场结论无影响 → 归到“详细日志”。
			e.passThrough(h, pkt, addr, t, src, dst, sport, dport, flags, rules.ActionDirect, 0, "", procName, procPID, true)
			continue
		}

		// 方向判定不依赖 addr.Flags 的位布局：目标落在规则内 = 应用发出的包。
		// 名字：通配域名只能靠“这个 IP 是哪个域名”匹配。两个来源：
		//  ① DNS 接管发的假 IP（池子反查）② 嗅探/解析学到的真 IP（名字表）
		// 没写通配规则时不做这次查找（每包一次查找，不该白付）。
		name := ""
		if e.ruleSet().HasWildcards() {
			if n, ok := e.nameOf(dst); ok {
				name = n
			}
		}
		chain, act, ruleNo, ruleName, hit := e.ruleSet().MatchNameRule(name, dst, dport, procName)
		if e.perf.on {
			pt.decided = time.Now()
		}
		if hit {
			switch act {
			case rules.ActionDirect, rules.ActionBlock:
				e.passThrough(h, pkt, addr, t, src, dst, sport, dport, flags, act, ruleNo, ruleName, procName, procPID, false)
				e.perf.record(&pt, n, pkOther, shard)
			default:
				e.rewriteOutbound(h, pkt, addr, t, src, dst, sport, dport, flags, chain, relayIP, relayPort, ruleNo, ruleName, procName, procPID)
				if e.perf.on {
					pt.sent = time.Now()
				}
				e.perf.record(&pt, n, pkOut, shard)
			}
			continue
		}
		// 没命中任何规则：要么是“带本机网段条件的规则”**当前不生效**（A16），
		// 要么是“只按进程”的规则拦下的其它程序的包（A20）。
		// 两种都必须原样放回内核，绝不能当入站包改写（会把用户的包改坏）。
		// 直连流量（仅当开了“统计直连流量”才会被拦到这里）：
		// 回来的包也要数上，否则界面上永远只有出方向（A15）。
		if isSyn(flags) {
			// verbose 档：说清“不拦”不是因为包没到我们手上，而是**没有规则命中**
			e.routeMatchLog(sport, dst, dport, procName, procPID, "没有规则命中 → 不拦（按系统路由直连）")
		}
		if st := e.flow(dport); st != nil && st.action == rules.ActionDirect {
			st.touch()
			st.packets.Add(1)
			st.down.Add(uint64(len(pkt)))
			e.dirDown.Add(uint64(len(pkt))) // 顶栏流量图的直连口径（开关关掉时不进表，也就不会到这里）
		}
		e.cap.note(pkt)
		if _, err := h.Send(pkt, addr); err != nil {
			e.bus.Throttle("inject.fail", time.Minute, "注入失败: %v（1 分钟内的重复不再逐条记）", err)
		}
		e.perf.record(&pt, n, pkOther, shard)
	}
}
