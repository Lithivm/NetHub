package webui

import (
	"strconv"
	"strings"

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
}

// 优先级（数字之间留空档，方便以后往中间插）。
const (
	prioDriverBlocked = 100 // 驱动装不上 = 整个程序不可用
	prioClashTakeover = 50  // 内网**可能**被交给别的代理（有泄漏风险，但程序还在跑）
	prioUpdateAvail   = 30  // 有新版本（不是故障，但也不该只留给用户自己发现）
)

// Notices 当前该挂的告警。可能多条，前端按 Priority 取一条显示。
//
// 成本：两个来源都是内存/注册表读（clashCoverage 是纯函数、无网络），
// 所以可以跟着 GetState 每 1.5 秒算一次 —— 不用再单独开一条 60 秒的轮询。
func (b *Backend) Notices() []Notice {
	return noticesFor(b.a.DriverBlocked(), b.clashCoverage(), b.updateInfo())
}

// noticesFor 是 Notices 的纯函数形式（可测：不碰注册表、不碰引擎、不碰网络）。
// 前端依赖的契约（有测试盯着）：优先级数字、ID 稳定、Copy/Card 指向真实存在的东西。
func noticesFor(driverBlocked bool, c Coverage, upd UpdateInfo) []Notice {
	out := make([]Notice, 0, 2)

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
	// ③ 有新版本（只在**自动检查**成功且确实有新版时挂）
	//
	// 为什么值得挂常驻条而不是弹个 toast：现场不会天天点「关于」里那个按钮，
	// 而“有新版本”这件事一旦错过就永远错过 —— 而且漏更新正好会漏掉我们修过的那些坑。
	// dev 构建（没有版本号可比）与“查不到”（内网不通）都不挂，不骚扰。
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
