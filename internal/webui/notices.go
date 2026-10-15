package webui

import (
	"strconv"
	"strings"

	"nethub/internal/alert"
	"nethub/internal/engine"
)

// 顶部常驻告警条的内容 —— **后端出数据，前端只渲染**。
//
// 为什么要机制化：第一条（内网被别的代理接管）是前端自己判的，第二条（内核驱动被安全软件拦）
// 又是另一套，两条各写一份 DOM 与优先级逻辑；再加第三、第四条就得继续动前端布局。
// 现在统一成：**谁发现问题谁在这里登记一条**，前端只管"取优先级最高的那条显示"。
//
// 与"通知"（NotifyView/toast）的分工：通知是一闪而过的；告警条**不自动消失**，
// 条件恢复才隐 —— 人不在电脑前时回来也能看到（这条约定见 frontend 的 renderNotices）。
type Notice struct {
	// ID 稳定标识（前端用它记"这条用户关过"）。改了 ID 等于让用户重新看一次。
	ID string `json:"id"`
	// Kind error | warn。
	Kind string `json:"kind"`
	// Priority 越大越致命。多条同时存在时前端只显示最高的那条 —— 一起喊会互相覆盖。
	Priority int    `json:"priority"`
	Title    string `json:"title"`
	Text     string `json:"text"`
	// Copy 非空 → 前端给一个「复制」按钮（复制它，方便粘到别的软件里）。
	Copy      string `json:"copy"`
	CopyLabel string `json:"copyLabel"`
	// Card 非空 → 「详情」按钮跳到诊断页那张卡的锚点 id（提示与修法放在两个地方会漂移）。
	Card string `json:"card"`
	// Action 非空 → 前端给一个**能直接做事**的按钮（ActionLabel 是它的文案）。
	//
	// 为什么要它：只读态光挂一条"你在只读"没用 —— 用户要的是"那我该怎么办"，
	// 而这个"怎么办"（接管引擎）必须先问一句（会让正在跑引擎的那个进程退出），
	// 所以按钮走前端已有的确认弹窗：动作名在这里登记，前端映射到具体函数。
	Action      string `json:"action"`
	ActionLabel string `json:"actionLabel"`
}

// 优先级（数字之间留空档，方便以后往中间插）。
const (
	prioDriverBlocked = 100 // 驱动装不上 = 整个程序不可用
	prioBlackhole     = 90  // 接管失效（在跑但一个包都没拦到）：业务级故障，而且**看不见**
	prioReadOnly      = 70  // 界面没在管引擎（服务版/另一个实例在跑）：能看不能用
	prioClashTakeover = 50  // 内网**可能**被交给别的代理（有泄漏风险，但程序还在跑）
	prioUpdateAvail   = 30  // 有新版本（不是故障，但也不该只留给用户自己发现）
)

// notifiable 哪些告警值得**发 Windows 系统通知**（用户 2026-10-15 明确：**只有这两类**）。
//
// 为什么要挑：系统通知会进用户的「操作中心」—— 发多了就是骚扰（项目原本因为这一点
// 完全不发系统通知）。而这两个是"**没人在看界面时也必须知道**"的：
//
//	· takeover-blackhole：引擎在跑但包没经过过滤器 —— 业务不通，而且内网流量
//	  会从默认网关漏出去（静默、看不见）
//	· clash-takeover：内网域名可能被别的代理接管（它用自己的 DNS 解析，
//	  有出内网 / 封号风险）
//
// 其余（驱动被拦 / 只读 / 有新版本）留在界面告警条 + 日志里就够。
var notifiable = map[string]bool{
	"takeover-blackhole": true,
	"clash-takeover":     true,
}

// notifyNotices 把**刚从无到有**的可通知告警推成系统通知（另写入 logs/alert.log）。
//
// 为什么在 Notices() 里做翻转检测、而不是各告警点自己调 alert：告警条是"当前该挂什么"
// 的唯一出处（前端也依赖它），在这里判"这条新出现了"最不容易漏 —— 各点各自调的话，
// 总有一天会有某条路径忘了调、或者同一条被反复推。恢复之后从表里移除，下次再出还会通知。
func (b *Backend) notifyNotices(list []Notice) {
	cur := make(map[string]Notice, len(list))
	for _, n := range list {
		if notifiable[n.ID] {
			cur[n.ID] = n
		}
	}
	b.noticeMu.Lock()
	defer b.noticeMu.Unlock()
	if b.notified == nil {
		b.notified = map[string]bool{}
	}
	for id, n := range cur {
		if b.notified[id] {
			continue
		}
		alert.Error(n.Title, n.Text)
		b.notified[id] = true
	}
	for id := range b.notified {
		if _, ok := cur[id]; !ok {
			delete(b.notified, id)
		}
	}
}

// Notices 当前该挂的告警。可能多条，前端按 Priority 取一条显示。
//
// 成本：两个来源都是内存/注册表读（clashCoverage 是纯函数、无网络），
// 所以可以跟着 GetState 每 1.5 秒算一次 —— 不用再单独开一条 60 秒的轮询。
func (b *Backend) Notices() []Notice {
	_, roWhy := b.readOnlyState() // 非空即"界面现在管不着引擎"
	list := noticesFor(b.a.DriverBlocked(), b.clashCoverage(), b.updateInfo(), roWhy, b.a.Engine.Blackhole())
	// 顺手处理"值得发系统通知的那两条"（只在新出现时推一次，见 notifyNotices）。
	b.notifyNotices(list)
	return list
}

// noticesFor 是 Notices 的纯函数形式（可测：不碰注册表、不碰引擎、不碰网络）。
// 前端依赖的契约（有测试盯着）：优先级数字、ID 稳定、Copy/Card 指向真实存在的东西。
func noticesFor(driverBlocked bool, c Coverage, upd UpdateInfo, readOnlyWhy string, blackholeFails int) []Notice {
	out := make([]Notice, 0, 4)

	// ① 内核驱动被安全软件拦（2026-09-28 现场踩过：火绒 6.0 的「漏洞驱动拦截」
	//    按文件把 WinDivert64.sys 判成漏洞驱动在内核层拒加载，报的却是 1450「系统资源不足」，
	//    字面把人往内存上带）。这里把"该去哪点什么"写全，别让人从日志里挖。
	if driverBlocked {
		sys := engine.DriverSysPath()
		out = append(out, Notice{
			ID: "driver-blocked", Kind: "error", Priority: prioDriverBlocked,
			Title: "内核驱动被安全软件拦下了",
			Text: "火绒 6.0：系统防护 → 漏洞驱动拦截 → 例外驱动 → 添加 " + sys +
				"。只信任 nethub.exe 没用（拦的是内核装驱动这一步），加完要重启安全软件。",
			Copy: sys, CopyLabel: "复制驱动路径",
			Card: "cardWhitelist",
		})
	}

	// ② 内网可能被别的系统代理接管（DNS 外泄 / 封号风险）
	if !c.OK && len(c.Missed) > 0 {
		missed := c.Missed
		head := missed
		if len(head) > 4 {
			head = head[:4]
		}
		out = append(out, Notice{
			ID: "clash-takeover", Kind: "error", Priority: prioClashTakeover,
			Title: "内网可能被其他代理接管",
			Text: strings.Join(head, "; ") + " 等 " + strconv.Itoa(len(missed)) +
				" 个目标不在系统代理的绕过列表里 —— 按域名访问内网时可能先交给它" +
				"（它用自己的 DNS 解析，内网域名有出内网的风险）",
			Copy: strings.Join(missed, ";"), CopyLabel: "复制要加的网段",
			Card: "clashDetail",
		})
	}
	// ④ 接管失效：引擎在跑，但包没经过过滤器 —— **静默失效**，本项目最危险的一类故障。
	//
	// 优先级放在"只读"之上：只读是"能看不能动"（一眼能看出来），而这个是
	// "看着一切正常，其实内网一个包都没接管" —— 业务不通 + 内网流量从默认网关漏到公网。
	// 2026-10-15 实测：机器上跑着 Clash Verge（mihomo）时启动的引擎就是这个状态，
	// 而界面上没有任何东西能看出来（日志里也只有一行 stats total=0），整整几小时没人发现。
	if blackholeFails > 0 {
		out = append(out, Notice{
			ID: "takeover-blackhole", Kind: "error", Priority: prioBlackhole,
			Title: "接管失效：引擎在跑，但包没经过过滤器",
			Text: "连续 " + strconv.Itoa(blackholeFails) + " 次自检都没看到自己的包 —— 内网目标" +
				"会按系统路由漏出去（既不通，也有泄漏风险）。" +
				"引擎已在自动重建句柄；若重建无效，请检查机器上有没有其它代理在跑" +
				"（Clash / mihomo 这类会在内核层把流量改向 —— 实测：它在跑时启动的 NetHub 拦不到包，" +
				"而且**先退出它再重启一次服务**才能恢复），关掉它再重启服务。",
			Card: "cardRuntime",
		})
	}
	// ⑤ 有新版本（只在**自动检查**成功且确实有新版时挂）
	//
	// 为什么值得挂常驻条而不是弹个 toast：现场不会天天点「关于」里那个按钮，
	// 而“有新版本”这件事一旦错过就永远错过 —— 而且漏更新正好会漏掉我们修过的那些坑。
	// dev 构建（没有版本号可比）与“查不到”（内网不通）都不挂，不骚扰。
	// ④ 界面处于只读：引擎在别的进程里（Windows 服务版 / 另一个 NetHub 实例）。
	//
	// 为什么必须挂常驻条：这种状态下界面**能看不能动**（启动/停止/重启都不生效），
	// 以前只有顶栏状态胺囊写个"只读"+ 一条一闪而过的 toast —— 现场极容易理解成
	// "软件卡住了/服务没拉起来"（用户 2026-10-13 就是这么反馈的）。常驻条 +
	// 一个带二次确认的按钮，把"为什么、怎么办"一次说完。
	if readOnlyWhy != "" {
		out = append(out, Notice{
			ID: "engine-readonly", Kind: "warn", Priority: prioReadOnly,
			Title: "界面处于只读：引擎在别的进程里",
			Text: readOnlyWhy + " —— 这个界面对流量只读（启动/停止/重启都不会生效）。" +
				"要由这个界面接管引擎，点右边的按钮。",
			Action: "takeover", ActionLabel: "接管引擎",
		})
	}
	if upd.HasNew {
		out = append(out, Notice{
			ID: "update-available", Kind: "info", Priority: prioUpdateAvail,
			Title: "有新版本 " + upd.Latest,
			Text: "当前 " + upd.Current +
				"。到「设置 → 关于」点「下载并更新」会自动升级并重启（出问题可用 nethub.exe -rollback 回退）。",
			Card: "cardAbout",
		})
	}
	return out
}
