// Package winsvc 把 NetHub 跑成 Windows 服务（对齐 Proxifier 的 Service Mode）：
// 无人登录也能跑、只有管理员能停/改配置。
//
// 实现用 golang.org/x/sys/windows/svc（x/sys 本来就在依赖里，不引新库）。
// 服务模式跑的是**无界面**引擎 —— 界面照旧可以由普通用户双击 exe 打开，
// 两者共用同一份 config.yaml。
//
// 同一时间只能有一个引擎在跑：靠 `internal/app` 的命名互斥（Global\NetHubEngineLock）
// 仲裁 —— 界面版抢不到就降级为只读，服务版抢不到会先请界面版优雅退出。
// （不要指望 Wails 的 SingleInstanceLock：它只管界面版之间，服务进程根本不走 Wails。）
package winsvc

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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
	s, err := openSvcForQuery()
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(s)
	return true
}

// Install 安装服务（幂等：已存在就更新可执行路径）。需要管理员权限。
//
// **安装 ≠ 启用**（用户 2026-10-19 拍的）：首次安装把 StartType 设成**手动**，不随开机启动 ——
// 装只是“备好”，真要用它是把界面上的「开机自启用服务形态」拨开（或 `-service-autostart on`）。
// 跟 Clash 装了虚拟网卡却不急着开 TUN 一个道理：装饰式一装就写死自动启动，换来的就是
// “装来备用的服务在每次开机时抢走引擎，登录后起来的界面只能当只读失败者”。
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
		// 已经装着的：**保留它现在的 StartType**，不要顺手改成手动 ——
		// 重新部署（换了路径/参数）不该把用户拨好的“开机自启”开关冲掉。
		startType := uint32(mgr.StartManual)
		if cur, err := s.Config(); err == nil && cur.StartType != 0 {
			startType = cur.StartType
		}
		// 这里的 ServiceType / ErrorControl **必须显式给**：UpdateConfig 不像
		// CreateService 那样把 0 补成默认值，而是原样传给 ChangeServiceConfig，
		// 而 0 不是 SERVICE_NO_CHANGE(0xFFFFFFFF) → 直接 ERROR_INVALID_PARAMETER。
		// 实测报 "The parameter is incorrect"，后果是“更新已装的服务”永远失败、
		// 服务里注册的还是旧路径/旧参数（GUI 与 -service-install 都走这里）。
		// ErrorControl=0 则是 SERVICE_ERROR_IGNORE，会把服务的错误处理静默降级。
		if err := s.UpdateConfig(mgr.Config{
			DisplayName: DisplayName, Description: Description,
			ServiceType:    windows.SERVICE_WIN32_OWN_PROCESS,
			StartType:      startType,
			ErrorControl:   mgr.ErrorNormal,
			BinaryPathName: quote(exePath) + " " + joinArgs(args),
		}); err != nil {
			return fmt.Errorf("更新已有服务失败: %w", err)
		}
		if err := applyRecovery(s); err != nil {
			return fmt.Errorf("设置失败恢复策略失败: %w", err)
		}
		return nil
	}

	s, err := m.CreateService(Name, exePath, mgr.Config{
		DisplayName:  DisplayName,
		Description:  Description,
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartManual, // 装 ≠ 启用，见上
		ErrorControl: mgr.ErrorNormal, // 同样不能留 0（= SERVICE_ERROR_IGNORE）
	}, args...)
	if err != nil {
		return fmt.Errorf("创建服务失败: %w", err)
	}
	defer s.Close()
	if err := applyRecovery(s); err != nil {
		return fmt.Errorf("设置失败恢复策略失败: %w", err)
	}
	return nil
}

// AutoStart 服务现在是不是“随开机自启”（StartType = AUTO_START）。
//
// 安装与启用是两件事（见 Install），界面上的开关问的就是这一个问题。
// 返回 (installed, auto, err)：没装时 auto 无意义；拿不到（非管理员）时 err 非空 ——
// 调用方要按“不知道”处理，**不能报成“未启用”**（那会让人误以为开关是关的）。
func AutoStart() (bool, bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, false, nil
		}
		return false, false, err
	}
	defer s.Close()
	cur, err := s.Config()
	if err != nil {
		return true, false, err
	}
	return true, cur.StartType == mgr.StartAutomatic, nil
}

// SetAutoStart 开/关“随开机自启”（**不动服务现在跑不跑** —— 那是 Start/Stop 的事）。
//
// 关掉时用 DEMAND_START 而不是 DISABLED：注册还在、随时能手动起 —— 正是“装着备用”的样子。
func SetAutoStart(auto bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连服务管理器失败（需要管理员权限）: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("服务未安装: %w", err)
	}
	defer s.Close()
	cur, err := s.Config()
	if err != nil {
		return fmt.Errorf("读服务配置失败: %w", err)
	}
	want := uint32(mgr.StartManual)
	if auto {
		want = mgr.StartAutomatic
	}
	if cur.StartType == want {
		return nil
	}
	cur.StartType = want // 其余字段照抄，别把路径/账户冲掉（UpdateConfig 是全量写）
	if err := s.UpdateConfig(cur); err != nil {
		return fmt.Errorf("修改服务启动方式失败: %w", err)
	}
	return nil
}

// ── 失败恢复（被外部结束 / 崩了之后自动拉起）────────────────────────

// recoveryResetPeriod 失败计数多少秒后清零（SCM 的 RESET_PERIOD）。
const recoveryResetPeriod = 86400 // 1 天

// recoveryActions 服务失败后按顺序执行的动作：5 秒后重启 → 30 秒后重启 → **不再动作**。
//
// 为什么要它（AGENTS 里记的“已知边界”，2026-10-16 补）：无人值守的机器上，
// 有人点名 Kill nethub.exe（现场那台 DF.HIS.Launcher 就是按进程名杀进程的）或进程崩掉之后，
// 服务就静静地没了 —— 表现是“隧道消失、hosts 段留在系统里没人兜付”，而没人会再去点一下。
//
// **熔断是故意的，也是必须的**（用户 2026-10-16 拍板）：配置坏了导致的“启动即崩”
// 绝不能变成无限重启循环（那会把客户网络反复搞断）。这里借 SCM 自己的语义实现：
// 最后一项是 SC_ACTION_NONE，而 Windows 在失败次数超过动作表长度时**重复使用最后一项**
// ⇒ 本窗口内最多自动拉起 2 次，第 3 次起不再动作、服务停在 STOPPED 等人工处理。
// （`sc failure <name>` 能看到这张表；手工 `sc start` 照旧可用。）
func recoveryActions() []windows.SC_ACTION {
	return []windows.SC_ACTION{
		{Type: windows.SC_ACTION_RESTART, Delay: 5 * 1000},
		{Type: windows.SC_ACTION_RESTART, Delay: 30 * 1000},
		{Type: windows.SC_ACTION_NONE}, // 熔断
	}
}

// RecoveryText 恢复策略的一句话（给人看；**真值以 SCM 里那张表为准**：`sc failure <name>`）。
func RecoveryText() string {
	return "被外部结束/崩溃后 5 秒、30 秒各重启一次，之后不再自动拉起（熔断；计数 1 天清零）"
}

// applyRecovery 把恢复策略写进 SCM（需要管理员权限，Install 本来就要）。
//
// 另一个关键点：**我们自己干净地停不会被它拉回来**。SCM 默认只在“进程没报告
// SERVICE_STOPPED 就消失”时才算失败 —— 这正好是我们要的语义：界面上的停止、`-quit`、
// `sc stop` 都照旧停得掉。下面显式把 FailureActionsOnNonCrashFailures 写成 0，
// 不让机器上可能残留的旧设置改变语义（这一条要实测钉住：local/kill-recover.ps1）。
func applyRecovery(s *mgr.Service) error {
	acts := recoveryActions()
	fa := windows.SERVICE_FAILURE_ACTIONS{
		ResetPeriod:  recoveryResetPeriod,
		ActionsCount: uint32(len(acts)),
		Actions:      &acts[0],
	}
	if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_FAILURE_ACTIONS,
		(*byte)(unsafe.Pointer(&fa))); err != nil {
		return err
	}
	flag := windows.SERVICE_FAILURE_ACTIONS_FLAG{FailureActionsOnNonCrashFailures: 0}
	return windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
		(*byte)(unsafe.Pointer(&flag)))
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
	s, err := openSvcForQuery()
	if err != nil {
		// 两种“打不开”必须分开说：没权限（unknown）不等于没装（not installed）。
		// 混成一个值就是老毛病：告诉人“没装”，而服务其实在跑。
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return "not installed"
		}
		return "unknown"
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return "unknown"
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "starting"
	case windows.SERVICE_STOP_PENDING:
		return "stopping"
	default:
		return "other"
	}
}

// openSvcForQuery 只为**查状态/判存在**打开服务，用最小权限。
//
// 为什么不用 svc/mgr：它 Connect/OpenService 请求的是 ALL_ACCESS，普通用户（非提权）
// 一定被拒 —— 于是 -status 在最常见的「服务模式 + 普通用户」组合下一直报
// “没装 / unknown”，而服务跑得好好的（2026-10-15 实测踩到：Get-Service 明明 Running）。
// 服务默认安全描述符允许 Users 查询状态，所以 SC_MANAGER_CONNECT + SERVICE_QUERY_STATUS
// 这一对在非提权下就能用。
func openSvcForQuery() (windows.Handle, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(scm)
	return windows.OpenService(scm, windows.StringToUTF16Ptr(Name), windows.SERVICE_QUERY_STATUS)
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

// WaitRunning / WaitStopped 等服务到达目标状态（最多等 d）。
//
// 为什么要等：SCM 的“启动”只是把请求交给服务进程，进程里还得装配 WinDivert
// 过滤器 —— 不等就以为它好了，会造成“旧的引擎已停、新的还没起来”的空窗。
func WaitRunning(d time.Duration) error { return waitFor("running", d) }

// WaitStopped 等服务停稳（里面会放开引擎互斥）。
func WaitStopped(d time.Duration) error { return waitFor("stopped", d) }

func waitFor(want string, d time.Duration) error {
	deadline := time.Now().Add(d)
	last := State()
	for time.Now().Before(deadline) {
		if last == want {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
		last = State()
	}
	if last == want {
		return nil
	}
	return fmt.Errorf("%s 秒内服务没变成 %s（当前 %s）", d, want, last)
}

// stopControlTimeout 等 SCM 确认“停止”请求的上限。
// 服务端收尾慢（实测优雅退出 40 秒上下）时 `Control` 会一直挂着 —— 那正是
// 2026-10-15 踩到的：一条 `-service-stop` 把实验脚本挂了 11 分钟（现象是“命令没反应”）。
const stopControlTimeout = 20 * time.Second

// Stop 停止服务。
//
// 两条纪律（都是踩出来的）：
//  1. **幂等**：已经 Stopped 就直接成功 —— 否则脚本里“先停再起”会因“已经停了”而报错。
//  2. **有超时**：不确定的等待不能无限 —— 见 stopControlTimeout 的注释。
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

	if st, qerr := s.Query(); qerr == nil && st.State == svc.Stopped {
		return nil // 已经停着：幂等成功
	}
	done := make(chan error, 1)
	go func() {
		_, cerr := s.Control(svc.Stop)
		done <- cerr
	}()
	select {
	case cerr := <-done:
		return cerr
	case <-time.After(stopControlTimeout):
		// 超时也**不算失败到底**：SCM 往往仍在继续停（只是没及时回应）。
		// 所以只报“没等到确认”，让调用方（脚本/界面）自己决定要不要再等。
		// （那个 goroutine 会陪着进程一起结束；这里不为它做额外收尸。）
		return fmt.Errorf("停止请求 %v 内没得到 SCM 确认（服务可能仍在慢收尾）", stopControlTimeout)
	}
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
