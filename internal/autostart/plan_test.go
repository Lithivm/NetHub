package autostart

import (
	"errors"
	"reflect"
	"testing"
)

func TestPlan(t *testing.T) {
	cases := []struct {
		name        string
		target      Form
		svcAuto     bool
		svcErr      error
		taskEnabled bool
		want        []Step
	}{
		{
			name:        "服务形态 + 计划任务开着 → 先设服务再删任务",
			target:      FormService,
			taskEnabled: true,
			want:        []Step{StepEnableService, StepDisableTask},
		},
		{
			name:   "服务形态 + 计划任务没开 → 只设服务",
			target: FormService,
			want:   []Step{StepEnableService},
		},
		{
			name:        "服务形态 + 查不准（与本目标无关）→ 仍按任务是否存在决定",
			target:      FormService,
			svcErr:      errors.New("no admin"),
			taskEnabled: true,
			want:        []Step{StepEnableService, StepDisableTask},
		},
		{
			name:    "GUI 形态 + 服务是自动 → 先装任务再关服务",
			target:  FormTask,
			svcAuto: true,
			want:    []Step{StepEnableTask, StepDisableService},
		},
		{
			name:   "GUI 形态 + 服务是按需 → 只装任务",
			target: FormTask,
			want:   []Step{StepEnableTask},
		},
		{
			name:   "GUI 形态 + 查不准 → 不碰服务（只装任务）",
			target: FormTask,
			svcErr: errors.New("access denied"),
			want:   []Step{StepEnableTask},
		},
		{
			name:   "GUI 形态 + 查不准且实际自动 → 也不能擅自关（无证据）",
			target: FormTask,
			// svcAuto 为 true 但 err 非空：err 优先，不做 StepDisableService
			svcAuto: true,
			svcErr:  errors.New("access denied"),
			want:    []Step{StepEnableTask},
		},
	}

	for _, c := range cases {
		got := Plan(c.target, c.svcAuto, c.svcErr, c.taskEnabled)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Plan() = %v, 期望 %v", c.name, got, c.want)
		}
	}
}

// 目标动作永远排在清理动作之前 —— 这是"失败也不会两边都没自启"的前提。
func TestPlanTargetComesFirst(t *testing.T) {
	if s := Plan(FormService, false, nil, true); s[0] != StepEnableService {
		t.Errorf("服务形态的首步应是 EnableService，得到 %v", s)
	}
	if s := Plan(FormTask, true, nil, false); s[0] != StepEnableTask {
		t.Errorf("GUI 形态的首步应是 EnableTask，得到 %v", s)
	}
}
