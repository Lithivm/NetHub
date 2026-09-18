package webui

import (
	"os"
	"path/filepath"

	"nethub/internal/winsvc"
)

// ServiceInfo 界面要的服务状态。
type ServiceInfo struct {
	State     string `json:"state"` // running / stopped / not installed / unknown
	Installed bool   `json:"installed"`
	Known     bool   `json:"known"` // 只有以管理员跑才查得准；否则不能瞎报“已安装/未安装”
	Elevated  bool   `json:"elevated"`
}

// GetService 查 Windows 服务状态（只读）。
func (b *Backend) GetService() ServiceInfo {
	st := winsvc.State()
	known := st != "unknown"
	switch st {
	case "running", "stopped", "starting", "stopping":
		return ServiceInfo{State: st, Installed: true, Known: known, Elevated: isElevated()}
	default:
		return ServiceInfo{State: st, Installed: false, Known: known, Elevated: isElevated()}
	}
}

// InstallService 安装为 Windows 服务（无人登录也能跑；需要管理员）。
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
	b.a.Bus.Warn("已安装 Windows 服务 %s（自动启动、无界面）", winsvc.Name)
	return nil
}

// UninstallService 停止并卸载服务。
func (b *Backend) UninstallService() error {
	if err := winsvc.Uninstall(); err != nil {
		return err
	}
	b.a.Bus.Warn("已卸载 Windows 服务 %s", winsvc.Name)
	return nil
}

// StartService / StopService 启停服务（界面按钮）。
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
