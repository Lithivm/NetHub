// Package winsvc 把 NetHub 跑成 Windows 服务（对齐 Proxifier 的 Service Mode）：
// 无人登录也能跑、只有管理员能停/改配置。
//
// 实现用 golang.org/x/sys/windows/svc（x/sys 本来就在依赖里，不引新库）。
// 服务模式跑的是**无界面**引擎 —— 界面照旧可以由普通用户双击 exe 打开，
// 两者共用同一份 config.yaml；同一时间只应该跑一个（SingleInstanceLock 会挡）。
package winsvc

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Name 服务名（sc 里看到的）。
const Name = "NetHub"

// DisplayName / Description 装在服务管理器里给人看的。
const (
	DisplayName = "NetHub 内网隧道代理"
	Description = "按规则把内网目标的 TCP 流量经上游代理转发（内核层接管，应用零改动）。"
)

// IsService 当前进程是不是被 SCM 拉起来的。
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Run 在服务模式下运行：run 收到 context 取消时应尽快收尾。
// 注意：服务里不能有窗口/托盘，run 里只跑引擎。
func Run(run func(ctx context.Context) error) error {
	return svc.Run(Name, &handler{run: run})
}

type handler struct {
	run func(ctx context.Context) error
}

func (h *handler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
					return true, 2 // 超时不听劝，让 SCM 强杀
				}
				return false, 0
			}
		}
	}
}

// Installed 服务是否已安装。
func Installed() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// Install 安装服务（幂等：已存在就更新可执行路径）。需要管理员权限。
func Install(exePath, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连服务管理器失败（需要管理员权限）: %w", err)
	}
	defer m.Disconnect()

	// 服务模式启动时用 -service 标志（免 GUI），并把配置路径钉死
	args := []string{"-service"}
	if configPath != "" {
		args = append(args, "-config", configPath)
	}

	if s, err := m.OpenService(Name); err == nil {
		defer s.Close()
		if err := s.UpdateConfig(mgr.Config{
			DisplayName: DisplayName, Description: Description,
			StartType: mgr.StartAutomatic, BinaryPathName: quote(exePath) + " " + joinArgs(args),
		}); err != nil {
			return fmt.Errorf("更新已有服务失败: %w", err)
		}
		return nil
	}

	s, err := m.CreateService(Name, exePath, mgr.Config{
		DisplayName: DisplayName,
		Description: Description,
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return fmt.Errorf("创建服务失败: %w", err)
	}
	defer s.Close()
	return nil
}

// Uninstall 停止并删除服务（幂等）。
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连服务管理器失败（需要管理员权限）: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return nil // 本来就没装
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil || st.State == svc.Stopped {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("删除服务失败: %w", err)
	}
	return nil
}

// State 服务的当前状态（没装就是 "not installed"）。只读，不需要管理员。
func State() string {
	m, err := mgr.Connect()
	if err != nil {
		return "unknown"
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return "not installed"
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "unknown"
	}
	switch st.State {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	default:
		return "other"
	}
}

// Start/Stop 供界面按钮用。
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("服务未安装: %w", err)
	}
	defer s.Close()
	return s.Start()
}

func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("服务未安装: %w", err)
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}

func quote(s string) string { return `"` + s + `"` }

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += quote(a)
	}
	return out
}
