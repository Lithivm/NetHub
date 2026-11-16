package autostart

// Form 是开机自启的形态。同一台机器上只能有一种真正生效：
// 服务挂在**开机**（SCM 阶段，登录前）就拿到引擎，计划任务是**登录后**才起，
// 两者并存时后者必然只能当"只读失败者"（2026-10-15、2026-11-16 各踩到一次）。
type Form int

const (
	// FormTask 计划任务：登录后延迟启动 GUI（带托盘图标）。
	FormTask Form = iota
	// FormService Windows 服务：开机即跑，无人登录也跑，无界面（headless）。
	FormService
)

// Step 是一条要执行的自启动作。
type Step int

const (
	// StepEnableTask 创建/更新计划任务（autostart.Enable）。
	StepEnableTask Step = iota
	// StepDisableTask 删除计划任务（autostart.Disable）。
	StepDisableTask
	// StepEnableService 服务改自动（winsvc.SetAutoStart(true)，不动服务进程）。
	StepEnableService
	// StepDisableService 服务改按需（winsvc.SetAutoStart(false)，不动服务进程）。
	StepDisableService
)

// Plan 决定"为了让 target 形态生效，按什么顺序做什么"。
//
// svcAuto/svcErr 来自 winsvc.AutoStart()：err != nil 表示查不准（多半没权限）——
// 这时既不能当"开着"也不能当"关着"，于是只做目标那条，另一条留给人工确认
// （winsvc.AutoStart 的注释专门强调过这个语义，别把"不知道"写成"没开"）。
//
// 顺序恒定：**先设目标，再清对方**。反过来做的话，一旦目标设失败就会留下
// "两边都没自启"——比两个都开着更糟：开机什么也不跑，隧道直接消失、没人兜底。
// 调用方必须按返回顺序执行，并在目标那一步失败时立即停止（不要继续清理）。
func Plan(target Form, svcAuto bool, svcErr error, taskEnabled bool) []Step {
	switch target {
	case FormService:
		steps := []Step{StepEnableService}
		if taskEnabled {
			steps = append(steps, StepDisableTask)
		}
		return steps
	default: // FormTask
		steps := []Step{StepEnableTask}
		if svcErr == nil && svcAuto {
			steps = append(steps, StepDisableService)
		}
		return steps
	}
}
