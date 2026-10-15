package engine

// ───────────────────── “拦不到包”的检测、自愈与告警 ─────────────────────
//
// 为什么必须有它（2026-10-15 实测）：机器上跑着 Clash Verge（mihomo）时启动的引擎，
// **一个包都拦不到** —— 而界面全绿、日志正常，只有 stats 里一行 `total=0`（没人会盯）。
// 现场最常见的顺序恰恰是**先开着 Clash，再开机自启 NetHub**（"与 Clash 共存"是项目
// 专门写过的场景），踩上就是"内网业务不通，但看起来一切正常"，而且**内网流量会从
// 默认网关漏到公网**。
//
// 判据为什么是**主动探测**而不是"total == 0"：没有业务流量时 total 也是 0，
// 两者在数据上完全不可分。所以要自己造一个"必然会被我们的过滤器捕获"的包：
// 用 DialSelf 朝**规则网段里的一个地址**发一次连接 —— 包进了过滤器，主句柄的
// 收包计数就会涨；不涨就说明**句柄瞎了**（而不在于有没有业务流量）。
//
// 为什么要自愈：实测"句柄瞎了"这件事**重建句柄就能恢复**（重启引擎立刻好）。
// 与其等人工重启，不如连续几次探测失败就自己重建（先开新的、再关旧的，
// 与热重载同一条路径 —— 不断已有连接）。

import (
	"net"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/rules"
)

const (
	// blackholeEvery 探测间隔。60 秒是"几分钟内就能发现"与"不要一直打搅"的折中。
	blackholeEvery = 60 * time.Second
	// blackholeProbeWait 发完探测包之后等多久再看收包计数（本机 loopback/内核往返，够了）。
	blackholeProbeWait = 400 * time.Millisecond
	// blackholeFailsWarn 连续失败几次开始告警（一次失败可能是抖动/包刚好没被计数）。
	blackholeFailsWarn = 2
	// blackholeFailsHeal 连续失败几次触发自愈（重建句柄）。
	blackholeFailsHeal = 4
	// blackholeProbePort 探测用的目标端口：一个几乎不会有人听的端口（连不上无所谓，
	// 我们要的是"这个包经过过滤器"）。
	blackholeProbePort = "65533"
)

// blackholeWarn 纯函数判据：这一轮探测算不算"失败"。
//
// 输入：主句柄收包计数有没有涨（seen）、探测包有没有真的发出去（probed）。
// 抽出纯函数是为了能钉测试（照 runtime.statusWarnings 的做法）。
func blackholeWarn(seen, probed bool) bool {
	if !probed {
		return false // 探测本身没发出去（比如规则集为空）：这次不算数，别误报
	}
	return !seen
}

// blackholeLoop 周期性探测"我的包还能不能被自己的过滤器看见"。
func (e *Engine) blackholeLoop() {
	defer e.wg.Done()
	t := time.NewTicker(blackholeEvery)
	defer t.Stop()
	fails := 0
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			e.mu.RLock()
			running := e.run
			e.mu.RUnlock()
			if !running {
				fails = 0
				e.setBlackhole(0)
				continue
			}
			before := e.pktsIn.Load()
			probed := e.probeSelfPacket()
			time.Sleep(blackholeProbeWait)
			seen := e.pktsIn.Load() > before
			if !blackholeWarn(seen, probed) {
				if fails > 0 {
					e.bus.Info("接管自检：句柄已恢复（探测包重新被看见）")
				}
				fails = 0
				e.setBlackhole(0)
				continue
			}
			fails++
			e.setBlackhole(fails)
			if fails == blackholeFailsWarn {
				e.bus.Error("接管异常：连续 %d 次自检都没看到自己的包经过内核过滤器（重启服务能恢复；正在继续观察）", fails)
				if e.Notify != nil {
					e.Notify("接管可能已失效", "自检发现：引擎在跑，但包没经过过滤器（内网目标会漏到公网）。正在自动尝试重建句柄。", true)
				}
			}
			if fails >= blackholeFailsHeal {
				e.bus.Error("接管异常：连续 %d 次自检失败 —— 自动重建主句柄（先建新的再关旧的）", fails)
				e.healHandles()
			}
		}
	}
}

// probeSelfPacket 朝"规则网段里的一个地址"发一次连接，为的是**让一个包经过我们的过滤器**。
//
// 两个细节：
//   - 用 DialSelf：这是仪器不是业务 —— 不进连接列表、不计累计、normal 档不记日志
//     （见 selfconn.go；用 net.DialTimeout 直连是错的，用户报过"纯误导"）。
//   - 取第一个过滤器区间的首地址（网段的第一个地址，几乎不会是业务主机）+ 一个
//     没人听的端口：连不上没关系，我们要的只是"这个包被捕获"。
//
// 返回 true 表示**探测包确实发出去了**（连不上/被拒都算发出去了）；
// 只有"根本没法发"（比如规则集为空、地址非法）才返回 false —— 那种情况下不参与判据，
// 免得把"没流量"误报成"句柄瞎了"。
func (e *Engine) probeSelfPacket() bool {
	rs := e.ruleSet().FilterRanges(false)
	if len(rs) == 0 {
		return false
	}
	ip := rules.U2IP(rs[0].First)
	if ip == nil {
		return false
	}
	// 连不上是常态（那个地址/端口通常没人听）：错误本身不参与判断。
	_, _ = e.DialSelf("tcp", net.JoinHostPort(ip.String(), blackholeProbePort), blackholeProbeWait)
	return true
}

// healHandles 连续探测失败后的自愈：逐片重建主句柄。
//
// 为什么是重建：实测"句柄瞎了"重建就能恢复（重启引擎立刻好）。重建走的是
// recoverHandle —— 与新句柄"先开新的、再关旧的"同一条路径，不断已有连接。
func (e *Engine) healHandles() {
	e.mu.RLock()
	hs := make([]*divert.Handle, len(e.handles))
	copy(hs, e.handles)
	stops := make([]chan struct{}, len(e.mainStops))
	copy(stops, e.mainStops)
	e.mu.RUnlock()
	for i := range hs {
		if hs[i] == nil {
			continue
		}
		if _, err := e.recoverHandle(loopMain, stops[i], i); err != nil {
			e.bus.Warn("接管自愈：第 %d 片重建失败: %v", i, err)
		} else {
			e.bus.Info("接管自愈：第 %d 片句柄已重建", i)
		}
	}
}

// setBlackhole 记录"连续几次探测失败"（0 = 正常），供界面读取。
func (e *Engine) setBlackhole(fails int) {
	e.blackholeFails.Store(int64(fails))
}

// Blackhole 当前状态：连续失败次数（0 = 正常）。界面据此显示告警。
func (e *Engine) Blackhole() int {
	if e == nil {
		return 0
	}
	return int(e.blackholeFails.Load())
}
