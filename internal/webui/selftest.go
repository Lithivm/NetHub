package webui

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"nethub/internal/app"
	"nethub/internal/config"
	"nethub/internal/upstream"
	"nethub/internal/winrun"
)

// SelfTest 对每条链做端到端探测：本地 socks5 通不通 + 经它能不能真连到内网目标。
// 走 gost 的本地监听，不经过 WinDivert，所以它单独验证"链路"这一段。
func (b *Backend) SelfTest() { go b.runSelfTest() }

// runSelfTest 真正跑一轮（同步）。走 selfTestGate 排队：体检与按钮可能同时要结果，
// 排队比重复探测好 —— 探活是对端可见的动作，能少发就少发。
func (b *Backend) runSelfTest() {
	chains := b.a.Cfg.ChainsSnapshot()
	if len(chains) == 0 {
		b.emit("notify", NotifyView{Title: "无法自检", Text: "还没有配置任何链", Kind: "warn"})
		return
	}
	b.selfTestGate.Lock()
	defer b.selfTestGate.Unlock()
	func() {
		b.a.Bus.Info("selftest.start: chains=%d", len(chains))
		report := SelfTestReport{Total: len(chains)}
		// 每条链的结果除了写日志，也攒起来给界面：以前只写日志，界面上一句
		// “详见上方日志”——可现场根本不知道去哪里看，等于没回答。
		add := func(name string, ok bool, detail ...string) {
			report.Chains = append(report.Chains, SelfTestChain{Name: name, OK: ok, Detail: detail})
			if !ok {
				report.Bad++
			}
		}
		defer func() {
			report.At = time.Now().Format("15:04:05")
			b.selfTestMu.Lock()
			b.selfTestLast, b.selfTestAt = report, time.Now()
			b.selfTestMu.Unlock()
			b.emit("selftest-report", report)
		}()
		// 最近真的被访问过的目标：自检优先探它们（端口是真的）
		recent := b.a.Engine.RecentTargets(64)
		bad := 0
		for _, ch := range chains {
			// ⓪ 代理段体检（TCP+TLS+**认证**）—— 先回答“这条链还能用吗”，再谈目标。
			//
			// 这里必须用 UpstreamsResolved（含保险箱里的凭据）：以前用 ch.Upstreams()
			// 拿到的是**不带凭据**的地址，于是“口令错了”自检根本发现不了。
			var live []*upstream.Upstream
			var lastProbe upstream.ProbeAuthResult
			for _, raw := range b.a.Cfg.UpstreamsResolved(ch) {
				u, perr := upstream.Parse(raw)
				if perr != nil {
					b.a.Bus.Error("[%s] 上游无法解析，跳过：%v", ch.Name, perr)
					continue
				}
				r := u.ProbeAuth(6 * time.Second)
				if r.AuthOK {
					live = append(live, u)
					lastProbe = r
				} else if r.Err != nil {
					// 失败也要把**原始错误**留着 —— 否则下面只能报一句
					// “连不上上游”，现场把日志发给 agent 时就没信息了。
					lastProbe = r
				}
			}
			if len(live) == 0 {
				errText := "连不上上游"
				if lastProbe.Err != nil {
					errText = lastProbe.Err.Error()
				}
				b.a.Bus.Error("selftest.fail: chain=%s scope=upstream", ch.Name)
				lines := []string{"代理段不可用"}
				for _, line := range strings.Split(errText, "\n") {
					b.a.Bus.Error("    %s", line)
					lines = append(lines, line)
				}
				bad++
				add(ch.Name, false, lines...)
				b.emit("selftest", ProbeView{Target: ch.Name, OK: false, Err: "代理段不可用：" + errText})
				continue
			}
			if !lastProbe.Public {
				b.a.Bus.Info("[%s] 代理段正常（认证通过）；出口没连到公网 —— 很多客户出口就是这样，对内网无影响", ch.Name)
			}
			dial := func(ip net.IP, port uint16) (net.Conn, error) {
				var lastErr error
				for _, u := range live {
					conn, derr := u.Dial(ip, port, 6*time.Second)
					if derr == nil {
						return conn, nil
					}
					lastErr = derr
				}
				return nil, lastErr
			}
			desc := "上游 " + live[0].String()
			if len(live) > 1 {
				desc = fmt.Sprintf("%d 条上游依次试（%s …）", len(live), live[0].String())
			}

			// ① 先用“最近真的访问过的 目标:端口”：端口是真的，
			// 不会因为“常见端口没猜对”而误报“链路不通”
			hit, hitIP := 0, ""
			for _, ref := range recent {
				if ref.Chain != ch.Name {
					continue
				}
				host, portStr, err := net.SplitHostPort(ref.Target)
				if err != nil {
					continue
				}
				rip := net.ParseIP(host)
				var rport uint16
				if _, err := fmt.Sscanf(portStr, "%d", &rport); err != nil || rip == nil {
					continue
				}
				if conn, derr := dial(rip, rport); derr == nil {
					conn.Close()
					hit, hitIP = int(rport), rip.String()
					b.a.Bus.Detail("selftest.probe: chain=%s target=%s source=recent", ch.Name, ref.Target)
					break
				}
			}

			// ② 没有真实目标（新装机器）才退回：hosts 里的主机 + 常见端口。
			//
			// ⚠ 这条路径上的端口是**猜**的，所以“全没连上”**不能说明链路有问题**：
			// 真实事故：192.0.2.217 上的服务在 9054，而猜测列表里没有这个端口 →
			// 六次全灭 → 界面报“链路有问题，上游挂了？”，但其实链路好好的（同端口
			// 用工具直连 3/3 成功）。所以这里只能报 WARN，不能计入“有问题”的链。
			guessed := false
			ip := net.ParseIP(hitIP)
			if hit == 0 {
				guessed = true
				// 一条链的规则里可能写了多个单 IP，逐个试到底（第一个可能恰好没开）。
				cands := probeIPsForChain(b.a.Cfg, ch.Name)
				if len(cands) == 0 {
					// 不是问题，只是这条链暂时没东西可探 —— 用 INFO，别用 WARN
					// （WARN 在界面日志里是警告色，会让人以为链路有问题）
					b.a.Bus.Info("selftest.skip: chain=%s reason=no-probe-target", ch.Name)
					add(ch.Name, true,
						"跳过：这条链的网段里还没有可探的真实主机",
						"代理段本身正常，只是没东西可探。给它一条 hosts 条目（IP 域名），"+
							"或者先正常访问一次它的内网目标，之后自检就会自动把它纳入探活。")
					continue
				}
				// 猜出来的端口**并行**试（见 probeGuessedParallel 的注释）：串行时每条链
				// 能干吃 20~40 秒，而且整轮自检是串行的，后面所有链都被它拖住。
				if nip, nport, ok := probeGuessedParallel(dial, cands, guessedProbePorts, 8*time.Second); ok {
					ip, hit, hitIP = nip, int(nport), nip.String()
				}
			}
			if hit > 0 {
				if guessed {
					b.a.Bus.Info("selftest.ok: chain=%s upstream=%s reach=%s:%d port_source=guessed", ch.Name, desc, ip, hit)
					add(ch.Name, true, fmt.Sprintf("端到端可达：→ %s:%d（端口是猜的，不代表业务端口）", ip, hit), "上游："+desc)
				} else {
					b.a.Bus.Info("selftest.ok: chain=%s upstream=%s reach=%s:%d port_source=recent", ch.Name, desc, ip, hit)
					add(ch.Name, true, fmt.Sprintf("端到端可达：→ %s:%d（最近真的访问过）", ip, hit), "上游："+desc)
				}
				b.emit("selftest", ProbeView{Target: ip.String(), Port: hit, OK: true})
			} else if guessed {
				// 端口是猜的：不下结论，也不计入“有问题”（以前误报的来源）
				b.a.Bus.Info("[%s] 代理段与认证都正常；%s 的常见端口没通 —— 内网目标要有过访问记录才测得准，现在不下结论",
					ch.Name, ip)
				add(ch.Name, true, "代理段与认证正常；但常见端口都没通", "内网目标要有过访问记录才测得准，现在不下结论")
				b.emit("selftest", ProbeView{Target: ch.Name, OK: true})
			} else {
				b.a.Bus.Error("[%s] ✗ 经该链连不上 %s 的任何端口（上游挂了？上游限制了目标？）", ch.Name, ip)
				bad++
				add(ch.Name, false, fmt.Sprintf("经该链连不上 %s 的任何端口", ip), "上游挂了？还是上游限制了目标？")
				b.emit("selftest", ProbeView{Target: ip.String(), OK: false, Err: "经该链不可达"})
			}
		}
		if bad == 0 {
			b.a.Bus.Info("=== 链路自检通过：%d 条链全部可用 ===", len(chains))
			b.emit("notify", NotifyView{Title: "链路自检通过", Text: fmt.Sprintf("%d 条链全部可用", len(chains)), Kind: "info"})
		} else {
			b.a.Bus.Error("selftest.done: chains_failed=%d", bad)
			b.emit("notify", NotifyView{Title: "链路自检有问题", Text: fmt.Sprintf("%d 条链不可用", bad), Kind: "error"})
		}
	}()
}

func targetIPv4(target string) net.IP {
	if ip, _, err := net.ParseCIDR(target); err == nil {
		return ip.To4()
	}
	if p := net.ParseIP(target); p != nil {
		return p.To4()
	}
	return nil
}

// probeIPForChain 取该链网段内的一个【真实主机 IP】用于探测。
// 不用网段的 .1 —— 那不是真主机，会得到 host unreachable 而误判为“链路不通”。
func probeIPsForChain(cfg *config.Config, chainName string) []net.IP {
	var out []net.IP
	// ① 规则里写死的**单个 IP**（裸 IP 或 /32）就是真实目标，最该拿来探活。
	//
	// 真实例子：xaby-dev 那条规则的网段里全是大网段，但目标里有 10.99.20.172/32、
	// 203.0.113.30/32、203.0.113.40/32 —— 以前只去 hosts 里找，找不到就报“跳过”，
	// 而目标其实就摆在眼前。多个时全部返回（调用方逐个试到底：第一个可能恰好没开）。
	for _, rt := range cfg.RoutesSnapshot() {
		if rt.Chain != chainName {
			continue
		}
		for _, t := range rt.Targets {
			t = strings.TrimSpace(t)
			if ip := net.ParseIP(t); ip != nil && ip.To4() != nil {
				out = append(out, ip.To4())
				continue
			}
			if ip, n, err := net.ParseCIDR(t); err == nil && ip.To4() != nil {
				if ones, _ := n.Mask.Size(); ones == 32 {
					out = append(out, ip.To4())
				}
			}
		}
	}
	if len(out) > 0 {
		return out
	}

	var nets []*net.IPNet
	for _, rt := range cfg.RoutesSnapshot() {
		if rt.Chain != chainName {
			continue
		}
		for _, t := range rt.Targets {
			if _, n, err := net.ParseCIDR(t); err == nil {
				nets = append(nets, n)
			} else if ip := net.ParseIP(t); ip != nil {
				nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			}
		}
	}
	for _, e := range hostsEntriesFrom(cfg) {
		f := strings.Fields(e)
		if len(f) < 2 {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		for _, n := range nets {
			if n.Contains(ip) {
				out = append(out, ip.To4())
				break
			}
		}
	}
	return out
}

// ───────────────────────── 打开文件/目录 ─────────────────────────

func (b *Backend) OpenConfigFile() { openPath(b.a.Cfg.Path()) }
func (b *Backend) OpenProgramDir() { openPath(dirOf(b.a.Cfg.Path())) }
func (b *Backend) OpenLogDir()     { openPath(dirOf(b.a.Bus.FilePath())) }

func openPath(p string) {
	if p == "" {
		return
	}
	_ = winrun.Command("explorer.exe", p).Start()
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return p
}

// save 落盘 + 记日志（编辑类操作的统一收尾）。
func (b *Backend) save(what string) error { return b.saveHint(-1, what) }

// saveHint 保存配置，并对第 hintFor 条规则（-1 = 不管）给出“不拦保存”的提示。
//
// 放宽校验（2026-09-21）后，“目标被前面的规则盖住”这类东西不再拦保存 ——
// 但要说一声，否则用户会以为新规则在干活（它可能永远轮不到）。
// 结论与规则页那一列、「重叠检查」按钮同源（config.RouteHints）。
func (b *Backend) saveHint(hintFor int, what string) error {
	res, err := b.a.SaveConfig()
	if err != nil {
		return err
	}
	b.afterSave(res, what)
	if hintFor >= 0 {
		for _, h := range b.a.Cfg.RouteHints(hintFor) {
			b.a.Bus.Warn("提示（不拦保存）: %s", h)
		}
	}
	return nil
}

// afterSave 保存后的统一收尾：说清楚“热生效了没有、还有哪些改动要重启”。
//
// 界面 toast 另有一份（LastApplyHint），这里只写日志 —— 日志是现场排障的第一手材料。
func (b *Backend) afterSave(res app.ApplyResult, what string) {
	if res.Applied {
		b.a.Bus.Info("%s（已保存到 config.yaml，规则 %d 条已热生效；已在跑的连接不受影响）", what, res.Rules)
	} else {
		b.a.Bus.Info("%s（已保存到 config.yaml）", what)
	}
	if res.Note != "" {
		b.a.Bus.Warn("%s：%s", what, res.Note)
	}
	for _, f := range res.RestartNeeded {
		b.a.Bus.Warn("%s：%s 的改动需要重启才生效", what, f)
	}
}

// LastApplyHint 上一次保存的“附加说明”（需要重启才生效的项 / 异常）；空串＝没什么要说的。
//
// 界面每次保存成功后问一句，把结果接在 toast 里 —— 现场最怕“以为生效了其实没生效”。
func (b *Backend) LastApplyHint() string { return b.a.LastApply().Hint() }

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

var _ = runtime.GOOS

// SetTray 由 main 注入托盘（Backend 不自己建，避免依赖倒置）。
func (b *Backend) SetTray(t *Tray) { b.tray = t }

// ShowMainWindow 从托盘/第二实例唤回窗口。
//
// 返回错误 = 没有界面接着（或叫不动）：调用方（看护者）据此改走「重新拉起一个界面」。
// 不能只“尽力而为”就不看结果 —— 界面不在时那一下就是静默失败，现场看到的是「点了没反应」。
func ShowMainWindow(b *Backend) error {
	b.noteUIHidden(false)
	return b.uiOrNoop().ShowWindow()
}

func (b *Backend) OpenReleases() { openPath(releasesURL) }
