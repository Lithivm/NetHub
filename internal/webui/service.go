package webui

import (
	"os"
	"path/filepath"

	"nethub/internal/autostart"
	"nethub/internal/winsvc"
)

// ServiceInfo 界面要的服务状态。
type ServiceInfo struct {
	State     string `json:"state"` // running / stopped / not installed / unknown
	Installed bool   `json:"installed"`
	Known     bool   `json:"known"` // 只有以管理员跑才查得准；否则不能瞎报“已安装/未安装”
	Elevated  bool   `json:"elevated"`
	// AutoStart = 服务形态随开机自启（界面上的那个开关）。**与"装没装"是两件事**：
	// 装了只是备着；开关打开才是"以后每次开机都跑服务形态"（见 winsvc.Install 的注释）。
	AutoStart      bool `json:"autoStart"`
	AutoStartKnown bool `json:"autoStartKnown"` // 查不准（非管理员）时不能显示成"关"
}

// GetService 查 Windows 服务状态（只读）。
func (b *Backend) GetService() ServiceInfo {
	st := winsvc.State()
	known := st != "unknown"
	installed, auto, autoErr := winsvc.AutoStart()
	_ = installed // 装没装以 State() 为准（它对"没权限"和"没装"分得清）
	info := ServiceInfo{
		State:          st,
		Known:          known,
		Elevated:       isElevated(),
		AutoStart:      auto,
		AutoStartKnown: autoErr == nil,
	}
	switch st {
	case "running", "stopped", "starting", "stopping":
		info.Installed = true
	case "not installed":
		info.Installed = false
	default:
		info.Installed = installed
	}
	return info
}

// InstallService 安装为 Windows 服务（无人登录也能跑；需要管理员）。
//
// 只是**装**（手工启动），不启用：装完不会自己跑、也不随开机跑。要用它请打开界面上的
// 「开机自启用服务形态」开关（SetServiceAutoStart）—— 安装 ≠ 启用，见 winsvc.Install。
func (b *Backend) InstallService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cfg := b.a.Cfg.Path()
	if cfg == "" {
		cfg = filepath.Join(filepath.Dir(exe), "config.yaml")
	}
	if err := winsvc.Install(exe, cfg); err != nil {
		return err
	}
	b.a.Bus.Warn("已安装 Windows 服务 %s（**不会**自己启动，也不随开机启动；要用就打开「开机自启用服务形态」开关）", winsvc.Name)
	return nil
}

// UninstallService 停止并卸载服务。
func (b *Backend) UninstallService() error {
	if err := winsvc.Uninstall(); err != nil {
		return err
	}
	b.a.Bus.Warn("已卸载 Windows 服务 %s（开机自启也一并取消）", winsvc.Name)
	return nil
}

// StartService / StopService 启停服务（界面按钮）。**不改开机自启**：那是一个独立的开关。
func (b *Backend) StartService() error {
	if err := winsvc.Start(); err != nil {
		return err
	}
	return nil
}

func (b *Backend) StopService() error {
	if err := winsvc.Stop(); err != nil {
		return err
	}
	return nil
}

// SetServiceAutoStart 拨「服务形态随开机自启」这个开关。
//
// 语义按用户 2026-10-19 定的来（跟 Clash 开 TUN 一样：开关一拨就生效，不是"下次开机再说"）：
//   - 打开：设成开机自启 → **顺手关掉界面版的计划任务自启**（两个都开必然出现
//     “服务版开机抢到引擎、登录后起来的界面只能当只读失败者”，AGENTS 里记过的坑）→
//     立刻交棒（这一刻起服务形态在跑，界面退出）。
//   - 关闭：取消开机自启（注册保留，随时能手动起）→ 服务正在跑就停掉 → 界面版把引擎接回来
//     （不然隧道就空着没人管了，用户看到的是“关个开关把内网断了”）。
func (b *Backend) SetServiceAutoStart(on bool) (string, error) {
	if err := winsvc.SetAutoStart(on); err != nil {
		return "", err
	}
	if !on {
		b.a.Bus.Info("服务形态不再随开机启动（注册保留：装还装着，随时可以再打开）")
		if winsvc.State() == "running" {
			return b.TakeoverEngine() // 里面会停服务、等锁、由界面版接管引擎
		}
		return "已关闭开机自启：服务仍装着（随时能再打开），这次也没有停它 —— 现在跑的还是原来那个", nil
	}

	b.a.Bus.Info("服务形态已设为随开机启动（无人登录也跑）")
	if b.autostartCached() {
		// 两个自启同时开着 = 开机时两个形态抢同一个引擎，必然有一个变只读失败者。
		// 用户已经明确选了服务形态，这里替他把界面版那条自启关掉并留一行日志。
		if err := autostart.Disable(); err != nil {
			b.a.Bus.Warn("界面版的开机自启没关掉（%v）—— 建议手动关，否则开机时两个形态会抢引擎", err)
		} else {
			b.a.Bus.Warn("已同时关掉界面版的开机自启（计划任务）：两个都开着会在开机时抢引擎，服务版先到、界面版只能当只读")
		}
		b.refreshAutostart()
	}

	if winsvc.State() == "running" {
		return "已开启：服务版本就在跑（无人登录也会跑），这个界面可以关掉了", nil
	}
	return b.StartServiceHandOver()
}
