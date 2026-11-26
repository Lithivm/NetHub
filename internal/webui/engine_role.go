package webui

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"nethub/internal/app"
	"nethub/internal/autostart"
	"nethub/internal/engine"
	"nethub/internal/gostbat"
	"nethub/internal/upstream"
	"nethub/internal/winsvc"
)

// ───────── 引擎互斥：只读降级 / 接管 / 交棒 ─────────

// setReadOnly / clearReadOnly：界面版的只读态（谁在跑、为什么）。
func (b *Backend) setReadOnly(why string) {
	b.roMu.Lock()
	b.readOnly, b.roWhy = true, why
	b.roMu.Unlock()
}

func (b *Backend) clearReadOnly() {
	b.roMu.Lock()
	b.readOnly, b.roWhy = false, ""
	b.roMu.Unlock()
}

func (b *Backend) readOnlyState() (bool, string) {
	b.roMu.RLock()
	defer b.roMu.RUnlock()
	return b.readOnly, b.roWhy
}

// describeEngineHolder 谁拿着引擎。能确定是服务版就说服务版，不确定就不猜。
func describeEngineHolder() string {
	if winsvc.State() == "running" {
		// 两个自启都开着时，用户看到的"只读界面"其实是两者抢引擎的结果 ——
		// 这是进程内部唯一能把这个事实告诉用户的地方（含修法），所以单独说清楚。
		if _, auto, err := winsvc.AutoStart(); err == nil && auto && autostart.Enabled() {
			return "Windows 服务版（headless）正在运行，而且**两个开机自启都开着**：" +
				"服务在开机时先抢到引擎，登录后的界面只能当只读。" +
				"修法：nethub.exe -service-autostart off（或界面「服务模式」里关掉服务自启）"
		}
		return "Windows 服务版（headless）正在运行"
	}
	return "另一个 NetHub 实例正在运行（可能是 -headless 模式）"
}

// TakeoverEngine 界面版接管引擎：停掉正在跑的 Windows 服务，然后本进程把引擎拉起来。
// 供只读态下的「接管」按钮调用。
func (b *Backend) TakeoverEngine() (string, error) {
	if b.a.Running() {
		b.clearReadOnly()
		return "引擎已经在界面版里运行", nil
	}
	stoppedService := false
	if winsvc.State() == "running" {
		b.a.Bus.Info("接管：先停止 Windows 服务版…")
		if err := winsvc.Stop(); err != nil {
			return "", fmt.Errorf("停止服务失败，没有接管: %w", err)
		}
		// 等服务真的停稳：它会放开引擎锁，锁没放开就抢不到
		if err := winsvc.WaitStopped(10 * time.Second); err != nil {
			return "", fmt.Errorf("服务没停稳，没有接管: %w", err)
		}
		stoppedService = true
	}
	if err := b.startEngine(); err != nil {
		// 服务已停但锁仍被占 → 是别的实例拿着，说清楚别让人以为是服务的锅
		if errors.Is(err, app.ErrEngineBusy) {
			return "", fmt.Errorf("%s，接管没成功", describeEngineHolder())
		}
		return "", err
	}
	b.clearReadOnly()
	if stoppedService {
		b.a.Bus.Info("接管完成：服务版已停止，引擎现由界面版运行")
		// “下次开机还会不会自己跑”现在取决于那个开关（装 ≠ 启用），别一句话把钱归包死。
		if _, auto, err := winsvc.AutoStart(); err == nil && auto {
			return "已接管：服务版已停止（注册保留，且**开着开机自启** —— 下次开机还会自己跑；不想就关掉「开机自启用服务形态」开关）", nil
		}
		return "已接管：服务版已停止（注册保留；没开开机自启，下次开机不会自己跑）", nil
	}
	return "已接管引擎", nil
}

// StartServiceHandOver 交棒给服务版：先停本机引擎（释放锁）→ 起服务 →
// 等服务真的 Running 才返回。调用方拿到 nil 错误后再让界面优雅退出。
//
// 顺序必须是“先停自己再起服务”：反过来的话服务抢不到锁，起来也白起。
// 代价是几百毫秒的真空期，TCP 会重传，比两个引擎同时抢流量安全得多。
func (b *Backend) StartServiceHandOver() (string, error) {
	wasRunning := b.a.Running()
	if wasRunning {
		b.a.Bus.Info("交棒：先停止界面版引擎，把互斥让给服务版…")
		b.a.Stop()
	}
	if err := winsvc.Start(); err != nil {
		b.rollbackEngine(wasRunning)
		return "", fmt.Errorf("启动服务失败: %w", err)
	}
	if err := winsvc.WaitRunning(15 * time.Second); err != nil {
		_ = winsvc.Stop()
		b.rollbackEngine(wasRunning)
		return "", fmt.Errorf("服务没起来: %w", err)
	}
	b.a.Bus.Info("交棒完成：服务版已接管（引擎锁现在服务进程里）")
	// 界面自己退出。留 1.5 秒让前端把 toast 画出来（立即退会看起来像崩了）；
	// 走 Quit 而不是 os.Exit —— 它会搞掉托盘图标，避免留下“僵尸图标”。
	go func() {
		time.Sleep(1500 * time.Millisecond)
		b.Quit()
	}()
	return "服务版已接管；界面即将退出（托盘图标会一并移除）", nil
}

// rollbackEngine 交棒失败时把界面版引擎恢复回去 —— 否则会变成
// “原来的停了、新的没起来”，隧道全断还看不到界面。
func (b *Backend) rollbackEngine(wasRunning bool) {
	if !wasRunning {
		return
	}
	b.a.Bus.Warn("交棒失败，正在把界面版引擎恢复回去…")
	if err := b.a.Start(); err != nil {
		b.a.Bus.Error("回滚也失败了，现在没有引擎在跑: %v", err)
		return
	}
	b.a.Bus.Info("已回滚：界面版引擎仍在运行")
}

// refreshAutostart 跑一次 schtasks 并把结果缓存起来（只在启动、切换自启时调）。
func (b *Backend) refreshAutostart() {
	on := autostart.Enabled()
	detail := ""
	if on {
		detail = autostart.Detail()
	}
	b.autoMu.Lock()
	b.autoEnabled, b.autoDetail = on, detail
	b.autoMu.Unlock()
}

func (b *Backend) autostartCached() bool {
	b.autoMu.RLock()
	defer b.autoMu.RUnlock()
	return b.autoEnabled
}

func (b *Backend) autostartDetailCached() string {
	b.autoMu.RLock()
	defer b.autoMu.RUnlock()
	return b.autoDetail
}

func (b *Backend) GetChains() []ChainView {
	chains := b.a.Cfg.ChainsSnapshot()
	out := make([]ChainView, 0, len(chains))
	for _, c := range chains {
		ups := c.Upstreams()
		brief := make([]string, 0, len(ups))
		hasAuth := false
		for _, f := range ups {
			if hasCred(f) {
				hasAuth = true
			}
			brief = append(brief, briefUpstream(f))
		}
		first := ""
		if len(brief) > 0 {
			first = brief[0]
		}
		user := b.a.Cfg.ChainCredUser(c)
		if user == "" {
			user = credUserIn(ups)
		}
		out = append(out, ChainView{
			Name: c.Name, Forward: first, Forwards: brief,
			Strategy: c.StrategyName(), Probe: c.ProbeInterval().String(), Note: c.Note,
			Auth: hasAuth || c.Secret != "", CredUser: user,
		})
	}
	return out
}

// briefUpstream 列表用的简化地址：协议 + 主机:端口。
//
// **不带凭据标记** —— 界面上另有一个单独的“带凭据 / 无凭据”标签，
// 这里再拼一个就重复了（实测被用户当成显示两次的 bug）。
func briefUpstream(raw string) string {
	b := gostbat.Redact(raw)
	if u, err := upstream.Parse(raw); err == nil && u.Addr != "" {
		// 用协议自己的写法（含 ws/wss 这类传输后缀），不要在这里拼 +tls ——
		// 拼接点一多，加了新传输就会漏掉某一处（用户看到的协议名与实际不符）。
		b = u.SchemeTag() + "://" + u.Addr
	}
	return b
}

// hasCred 这个上游地址里到底有没有凭据（userinfo 或 ?auth=）。
func hasCred(raw string) bool {
	if u, err := upstream.Parse(raw); err == nil {
		return u.Creds.User != "" || u.Creds.Pass != ""
	}
	return strings.Contains(raw, "auth=") || strings.Contains(raw, "@")
}

// credUserIn 从一串上游地址里找出账号名（只给界面显示，不泄口令）。
func credUserIn(raws []string) string {
	for _, raw := range raws {
		if u, err := upstream.Parse(raw); err == nil && u.Creds.User != "" {
			return u.Creds.User
		}
	}
	return ""
}

// ChainForwardPlain 取一条链的**真实**上游地址（含凭据），专给编辑页面用。
//
// 为什么不在列表里就明文：列表是拿来一眼扫“哪条链路是什么”的，不需要细节；
// 而编辑页面就是拿来实现/修正凭据的 —— 那里藏起来除了多造麻烦没任何意义。
func (b *Backend) ChainForwardPlain(name string) ([]string, error) {
	ch, ok := b.a.Cfg.ChainByName(name)
	if !ok {
		return nil, fmt.Errorf("没有这条链: %s", name)
	}
	return b.a.Cfg.UpstreamsResolved(ch), nil
}

// GetChainHealth 每条链的上游健康（主动探测 + 真实连接失败都会记进来）。
func (b *Backend) GetChainHealth() []engine.ChainHealthView {
	if b.a.Engine == nil {
		return nil
	}
	return b.a.Engine.ChainHealth()
}

// GetVerdict 一句话结论：现在这套链路到底能不能用（诊断页「链路自检」卡顶部那句）。
//
// 它把两件事合成一句：上游探活（我们到上游那一段）与业务目标实测（经这条链到得了内网吗）。
// 判据在 engine.ChainVerdict —— 纯函数，有表驱动测试钉住。
// 这里只负责把"引擎在不在跑"与两份观测凑齐。
func (b *Backend) GetVerdict() engine.Verdict {
	running, _ := b.a.Status()
	var chains []engine.ChainHealthView
	var targets []engine.TargetHealthView
	if b.a.Engine != nil {
		chains = b.a.Engine.ChainHealth()
		targets = b.a.Engine.TargetHealth()
	}
	return engine.ChainVerdict(running, chains, targets)
}

// ProbeChains 立即把所有上游探一遍（界面上的"立即探测"）。
//
// 为什么在返回前先把整轮标上：探测是异步的，界面点完立刻就回来查 ——
// goroutine 那时可能还没开始跑。不同步标上，“点了没反应”就还会发生
// （用户报的困惑：到底该等还是该点？）。
func (b *Backend) ProbeChains() error {
	if b.a.Engine == nil {
		return fmt.Errorf("引擎未初始化")
	}
	b.a.Engine.StartProbeRound()
	go func() {
		defer b.a.Engine.EndProbeRound()
		b.a.Engine.ProbeAll()
	}()
	return nil
}

func (b *Backend) GetRoutes() []RouteView {
	chains := b.a.Cfg.ChainsSnapshot()
	routes := b.a.Cfg.RoutesSnapshot()
	note := map[string]string{}
	for _, c := range chains {
		note[c.Name] = c.Note
	}
	wildcardStats := b.a.Engine.WildcardStats()
	out := make([]RouteView, 0, len(routes))
	for i, r := range routes {
		note := note[r.Chain]
		switch {
		case r.IsDirect():
			note = "不走代理，直接连（本机网段 / 局域网邻居常用）"
		case r.IsBlock():
			note = "直接丢弃：应用会看到连接被拒"
		}
		resolves := map[string]engine.HostResolveView{}
		for _, hr := range b.a.Engine.HostResolves() {
			resolves[strings.ToLower(hr.Host)] = hr
		}
		var mine []engine.HostResolveView
		for _, t := range r.Targets {
			if hr, ok := resolves[strings.ToLower(strings.TrimSpace(t))]; ok {
				mine = append(mine, hr)
			}
		}
		// 通配域名（*.example.com）没有“解析结果”，但有“已经学到哪些 IP”——
		// 不显示的话，界面上看不到它到底覆盖了什么，跟“静默失效”没区别。
		var wild []engine.WildcardStat
		for _, st := range wildcardStats {
			for _, t := range r.Targets {
				if strings.EqualFold(strings.TrimSpace(t), st.Pattern) {
					wild = append(wild, st)
					break
				}
			}
		}
		out = append(out, RouteView{
			Index: i, Name: r.Name, Targets: r.Targets, Ports: r.Ports,
			Chain: r.Chain, Direct: r.IsDirect(), Block: r.IsBlock(), Note: note,
			Shadowed:     b.a.Cfg.ShadowedTargets(i),
			LocalNets:    r.LocalNets,
			Inactive:     !localNetsMatch(r.LocalNets, localIPv4s()),
			Apps:         r.Apps,
			AllowQUIC:    r.AllowQUIC,
			Enabled:      r.IsEnabled(),
			HostResolves: mine,
			Wildcards:    wild,
		})
	}
	return out
}

// localNetsMatch 规则的本机网段条件在当前网络下是否满足（A16）。
// 空条件 = 总是满足（与以前行为一致）。
func localNetsMatch(conds []string, ips []net.IP) bool {
	if len(conds) == 0 {
		return true
	}
	for _, c := range conds {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			if ip := net.ParseIP(c); ip != nil {
				n = &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
			} else {
				continue
			}
		}
		for _, ip := range ips {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// localIPv4s 本机当前的非回环 IPv4（界面上判断“这条规则现在生不生效”用）。
func localIPv4s() []net.IP {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, it := range ifs {
		if it.Flags&net.FlagUp == 0 || it.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := it.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					out = append(out, v4)
				}
			}
		}
	}
	return out
}

// LocalSubnets 本机直接相连的 IPv4 网段（规则里“本地直连”用）。
//
// 只取 up 且非回环接口上的地址：典型就是 192.168.1.0/24 这种内网段。
// 界面上一键填入，省得每次手敲 —— 忘了配本地直连，局域网里的同事机器 /
// 打印机 / 共享盘会被送进隧道而不可达（异地代理到不了你的局域网）。
func (b *Backend) LocalSubnets() []string {
	out := []string{}
	seen := map[string]bool{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil {
				continue
			}
			s := (&net.IPNet{IP: v4.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}
