package webui

import (
	"fmt"
	"strings"
	"time"

	"nethub/internal/autostart"
	"nethub/internal/config"
	"nethub/internal/hostsmgr"
)

// ───────────────────────── 设置 ─────────────────────────

func (b *Backend) SaveSettings(s SettingsView) error {
	cfg := b.a.Cfg
	// 记录改之前的自启延迟 —— 下面要靠“变没变”决定要不要重建计划任务。
	oldAutoDelay := int(cfg.AutostartDelayDur() / time.Second)
	// 不动 cfg.Relay：界面上没有这个字段，前端不会传。
	// （之前这里写 cfg.Relay = s.Relay，前端不传时会被清成空串，直接校验失败）
	var entries []string
	if len(s.HostsEntries) > 0 {
		entries = s.HostsEntries
	}
	cfg.SetHosts(s.HostsManage, entries)
	if s.AutostartDelay != nil {
		cfg.SetAutostartDelay(time.Duration(*s.AutostartDelay) * time.Second)
	}
	// 拨号调优：只在界面确实传了值时才改（0 = 没传，保持原样）；
	// 竞速起跑 / 预热会话：nil = 前端没传 → 保持原值；0 = 明确关闭
	cfg.UpdateTuning(func(t *config.Tuning) {
		if s.DialTimeout > 0 {
			t.DialTimeout = fmt.Sprintf("%ds", s.DialTimeout)
		}
		if s.DialBudget > 0 {
			t.DialBudget = fmt.Sprintf("%ds", s.DialBudget)
		}
		if s.RaceAfter != nil {
			if *s.RaceAfter == 0 {
				t.RaceAfter = "off"
			} else {
				t.RaceAfter = fmt.Sprintf("%dms", *s.RaceAfter)
			}
		}
		if s.WarmSessions != nil {
			if *s.WarmSessions == 0 {
				t.WarmSessions = "off"
			} else {
				t.WarmSessions = fmt.Sprintf("%d", *s.WarmSessions)
			}
		}
		// 强制本机解析的域名：nil = 前端没传（不改）；空切片 = 清空（用户确实想清）
		if s.DomainResolveLocal != nil {
			t.DomainResolveLocal = cleanDomainList(s.DomainResolveLocal)
		}
	})
	res, err := b.a.SaveConfig()
	if err != nil {
		return err
	}
	b.afterSave(res, "设置已保存")
	// 计划任务的“登录后延迟”是写死在任务 XML 里的 —— 已经装了就必须重建任务才生效。
	// 放在 SaveConfig **之后**：配置先落盘，重建任务失败也不会丢掉用户刚改的设置。
	//
	// ⚠ 只在**延迟真的变了**的时候才重建（2026-10-14：用户报“保存后提示弹窗要等很久”）。
	// 前端是无条件把 autostartDelay 传上来的，所以这里不比较的话**每次点保存**都要跑：
	//   Enabled()  → schtasks /query   （本机实测 1.42 s）
	//   Enable()   → schtasks /create  （同量级）
	//   refreshAutostart() → 又是 Enabled + Detail 两次查询（实测 ~2.8 s）
	// 合计约 **5.6 秒的外部进程**，而实际需要的只有“延迟变了”这一种情况。
	// （s.AutostartDelay == nil 时配置根本没改，old/new 相等，自动跳过。）
	if newAutoDelay := int(cfg.AutostartDelayDur() / time.Second); newAutoDelay != oldAutoDelay && autostart.Enabled() {
		if err := autostart.Enable(newAutoDelay); err != nil {
			return err
		}
		b.refreshAutostart()
	}
	b.a.Bus.Info("设置已保存（hosts 托管=%v；拨号单次 %s / 总预算 %s / 竞速起跑 %s / 预热 %d 条；自启延迟 %s）",
		b.a.Cfg.HostsCopy().Manage, cfg.DialTimeoutDur(), cfg.DialBudgetDur(), cfg.RaceAfterDur(), cfg.WarmTarget(),
		cfg.AutostartDelayDur())
	return nil
}

// effectiveTheme 把主题**偏好**解析成**生效**的深/浅色。
//
// 为什么要有这一层：偏好可以是 "system"（默认），而生效值只能是 light/dark ——
// 窗口标题栏配色、界面第一帧、看护重启界面都要一个确定的答案，不能把
// “你自己去问系统”留给每个调用方。
func (b *Backend) effectiveTheme() string {
	switch b.a.Cfg.Theme() {
	case "dark":
		return "dark"
	case "light":
		return "light"
	default: // system
		if systemPrefersDark() {
			return "dark"
		}
		return "light"
	}
}

// CurrentTheme 当前**生效**主题（dark/light）—— 看护拉起界面时用它，每次现读
// （所以要拿 systemPrefersDark 的实时值，不能在启动时算一次就存起来）。
func (b *Backend) CurrentTheme() string { return b.effectiveTheme() }

// SetTheme 设置主题偏好并应用（"system"/"light"/"dark"），返回生效的深浅色。
//
// 返回值就是告诉界面“现在到底是什么色”：选了 system 时只有后端知道答案
// （要读系统设置），界面自己去猜会闪一下错色。
func (b *Backend) SetTheme(mode string) (string, error) {
	if mode != "dark" && mode != "light" {
		mode = "system"
	}
	b.a.Cfg.SetTheme(mode)
	eff := b.effectiveTheme()
	b.uiOrNoop().SetTheme(eff == "dark")
	if err := b.a.Cfg.Save(); err != nil {
		return eff, err
	}
	// 这一行是给"设置到底存没存住"用的：以前它静默写盘，现场根本看不出
	// 是没写、还是写了没读回来（见 SaveSettings 那条同源日志）。
	b.a.Bus.Info("主题已切到 %s（偏好 %s，已写入配置）", themeName(eff), themeName(mode))
	return eff, nil
}

// ApplyTheme 只把**生效**主题应用到窗口（不写盘、不改偏好）。
//
// 给“跟随系统”用：用户在 Windows 里改了深/浅色，界面下一秒（轮询）发现生效值变了，
// 调一次这个把窗口标题栏颜色跟上 —— 偏好没变，所以不该动配置。
func (b *Backend) ApplyTheme() string {
	eff := b.effectiveTheme()
	b.uiOrNoop().SetTheme(eff == "dark")
	return eff
}

func themeName(mode string) string {
	switch mode {
	case "dark":
		return "深色"
	case "light":
		return "浅色"
	default:
		return "跟随系统"
	}
}

// SetAutostart 开关开机自启（立即生效，不等"保存"）。
func (b *Backend) SetAutostart(on bool) error {
	delay := int(b.a.Cfg.AutostartDelayDur() / time.Second)
	var err error
	if on {
		err = autostart.Enable(delay)
	} else {
		err = autostart.Disable()
	}
	if err != nil {
		return err
	}
	b.refreshAutostart()
	if on {
		b.a.Bus.Info("已设置开机自启（计划任务 %s，最高权限，登录后延迟 %d 秒静默启动）", autostart.TaskName, delay)
	} else {
		b.a.Bus.Info("已取消开机自启")
	}
	return nil
}

// ───────────────────────── hosts ─────────────────────────

// ApplyHosts 立即把编辑框里的条目写进 hosts（同时打开托管开关）。
func (b *Backend) ApplyHosts(entries []string) error {
	clean := make([]string, 0, len(entries))
	for _, e := range entries {
		if s := strings.TrimSpace(e); s != "" && !strings.HasPrefix(s, "#") {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return fmt.Errorf("条目是空的，没什么可写的")
	}
	res, err := hostsmgr.Apply(clean)
	if err != nil {
		return err
	}
	b.a.Cfg.SetHosts(true, clean)
	if _, err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("hosts 已写入 %d 条内网域名映射（已刷 DNS 缓存）", res.Written)
	for _, t := range res.TakenOver {
		b.a.Bus.Warn("hosts 里原有同名记录，已被 NetHub 接管（否则写进去也不生效）: %s", t)
	}
	if res.FlushError != nil {
		b.a.Bus.Warn("刷 DNS 缓存失败（解析可能要等缓存过期才生效）: %v", res.FlushError)
	}
	return nil
}

// RemoveHosts 从 hosts 移除我们的标记区块。
func (b *Backend) RemoveHosts() error {
	if err := hostsmgr.Remove(); err != nil {
		return err
	}
	b.a.Cfg.SetHosts(false, nil)
	if _, err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("已从 hosts 移除本程序的标记区块")
	return nil
}
