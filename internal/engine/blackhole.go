package engine

// ───────────────── “拦不到包”的检测与告警（**只观察，绝不自动动手**）─────────────────
//
// 为什么必须有它（2026-10-15 实测）：机器上跑着 Clash Verge（mihomo）时启动的引擎，
// **一个包都拦不到** —— 而界面全绿、日志正常，只有 stats 里一行 `total=0`（没人会盯）。
// 那次在这台机器上存在了 **4 小时**没人发现，期间内网目标全部不通、流量从默认网关漏出去。
//
// 判据为什么是**主动探测**而不是 "total == 0"：没有业务流量时 total 也是 0，
// 两者在数据上完全不可分。所以要自己造一个"必然会被我们的过滤器捕获"的包：
// 用 DialSelf 朝**过滤器里的一个地址**发一次连接 —— 包进了过滤器，主句柄的收包计数
// 就会涨；不涨就说明**句柄瞎了**（而不在于有没有业务流量）。
//
// ⚠⚠ **为什么只告警、不自动恢复**（用户 2026-10-15 拍板，这条很重要）：
//   那天想过两档自愈 —— ① 重建句柄 ② 重启引擎（自动重启）。**都去掉了**，因为：
//     · 那次故障**至今无法复现**（两个方向的对照实验都正常），也就**没有根因**；
//       在不知道病因的时候动手，动作本身可能是错的。
//     · 实测证据反而说"重启没用"：故障期间 **三次重启都没救回来**（12:07/12:13/14:16）；
//       真正恢复的那次（14:23）无法与"故障自己结束了"区分。⇒ 自动重启只会变成
//       "重启→还坏→再重启"的循环，把可用性再砍一刀。
//     · 代价不对称：误报一条告警，用户点掉就行；误动作一次，**断的是正在跑的业务**。
//   所以这里只做两件事：**把它看见**（告警条 + 系统通知）和**把它记下来**（日志）。
//   将来真有了可复现的根因，再加对症的处置 —— 而不是先加一个“大概会管用”的动作。

import (
	"net"
	"time"

	"nethub/internal/rules"
)

const (
	// blackholeEvery 探测间隔。60 秒是"几分钟内就能发现"与"不要一直打搅"的折中。
	blackholeEvery = 60 * time.Second
	// blackholeProbeWait 发完探测包之后等多久再看收包计数（本机 loopback/内核往返，够了）。
	blackholeProbeWait = 400 * time.Millisecond
	// blackholeFailsWarn 连续失败几次开始告警。
	//
	// 取 3（约 3 分钟）：探测本身很硬（只看"包有没有到我们手上"，与网络状况无关），
	// 但既然**没有任何自动动作**跟着，多等两次的口子很小，而误报噪声少一点。
	blackholeFailsWarn = 3
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
				// 只告警。**不做任何自动动作** —— 理由见文件头那段（没有根因，
				// 而且实测重启救不回来；误动作断的是正在跑的业务）。
				e.bus.Error("接管异常：连续 %d 次自检都没看到自己的包经过内核过滤器（内网目标现在应该是不通的：包会按系统路由漏出去）—— 只告警不自动处理，请人工确认", fails)
				if e.Notify != nil {
					e.Notify("接管可能已失效", "自检发现：引擎在跑，但包没经过过滤器。内网目标可能不通、流量会漏出去。请人工确认（常见干扰源：机器上跑着 Clash / mihomo 这类会在内核层改向流量的代理）。", true)
				}
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
	// 目标怎么挑（两个约束）：
	//   ① 必须在**内核过滤器**里 —— 否则包根本到不了我们手上，探测就成了假阴性；
	//   ② 尽量**不是客户的内网地址** —— 探测包会一路走到上游（目标不存在，注定 CONNECT
	//      失败），用真实业务网段会让人以为“有东西在扫客户内网”。
	// 所以优先用**假 IP 段**（DNS 接管开着时它也在过滤器里，而且一眼就是假地址），
	// 没有假 IP 段（没开 DNS 接管）才退回规则网段的首地址。
	var ip net.IP
	if e.fake != nil {
		if r := e.fake.Range(); r != nil && r.IP != nil {
			if v4 := r.IP.To4(); v4 != nil {
				ip = net.IPv4(v4[0], v4[1], v4[2], v4[3]+1) // 段内第二个地址，避开网络地址
			}
		}
	}
	if ip == nil {
		rs := e.ruleSet().FilterRanges(false)
		if len(rs) == 0 {
			return false
		}
		ip = rules.U2IP(rs[0].First)
	}
	if ip == nil {
		return false
	}
	// 连不上是常态（那个地址/端口通常没人听）：错误本身不参与判断。
	_, _ = e.DialSelf("tcp", net.JoinHostPort(ip.String(), blackholeProbePort), blackholeProbeWait)
	return true
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
