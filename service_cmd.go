package main

// 服务形态的写类命令：-service-install / -service-uninstall / -service-stop / -service-autostart。
//
// **调用点必须在自动提权之后**（见 main.go 里 runServiceControl 的调用处）：
// 这几条都要写 SCM（CreateService / ChangeServiceConfig / Start），非管理员必然失败；
// 而本程序是 windowsgui 子系统，没有控制台 —— 从快捷方式或计划任务里跑时没有任何人
// 接收 stdout/stderr，失败会表现为"点了没反应"。2026-11-16 排查"服务自启莫名其妙开着"
// 时确认：这几个分支原来在提权检查之前，非管理员运行时连错误提示都看不到。
//
// 与之相对，-service-state 是只读查询（服务的默认安全描述符允许 Users 查状态），
// 留在提权之前，避免查个状态就弹 UAC。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nethub/internal/autostart"
	"nethub/internal/winsvc"
)

// runServiceControl 执行写类服务命令；调用方负责 return（这些命令都不该继续走引擎）。
func runServiceControl(install, uninstall, stop bool, svcAuto, cfgPathArg string) {
	if svcAuto != "" {
		switch strings.ToLower(svcAuto) {
		case "on", "1", "true", "yes":
			enableServiceAutostart()
		case "off", "0", "false", "no":
			// 只关服务自启，不碰计划任务：GUI 那条自启是另一件事，归用户自己管。
			if err := winsvc.SetAutoStart(false); err != nil {
				fatal("%v", err)
			}
			fmt.Printf("服务形态不再随开机自启（注册保留，随时可用 -service-autostart on 再打开）。\n")
		default:
			fatal("-service-autostart 只认 on / off，收到 %q", svcAuto)
		}
		return
	}

	if stop {
		if err := winsvc.Stop(); err != nil {
			fatal("%v", err)
		}
		if err := winsvc.WaitStopped(15 * time.Second); err != nil {
			fatal("%v", err)
		}
		fmt.Println("已停止 Windows 服务 " + winsvc.Name)
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fatal("拿不到自身路径: %v", err)
	}
	cfgPath := cfgPathArg
	if cfgPath == "" {
		cfgPath = filepath.Join(filepath.Dir(exe), "config.yaml")
	}
	if uninstall {
		if err := winsvc.Uninstall(); err != nil {
			fatal("%v", err)
		}
		fmt.Println("已卸载 Windows 服务 " + winsvc.Name)
		return
	}

	_ = install // 进入本函数的条件就是 install||uninstall||stop||auto，走到这里只剩 install
	if err := winsvc.Install(exe, cfgPath); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("已安装 Windows 服务 %s（**不**随开机自启，只是备好）\n", winsvc.Name)
	fmt.Printf("· 要无人值守（开机即跑、不等登录）：nethub.exe -service-autostart on，或界面「服务模式」卡片里拨开开关\n")
	fmt.Printf("· 现在就想用一次：net start %s\n", winsvc.Name)
}

// enableServiceAutostart 把服务改成随开机自启，并按 Plan 清掉另一条自启。
//
// 顺序由 autostart.Plan 保证：**先设服务，成功后再删计划任务**。目标那步失败立刻
// fatal 退出 —— 绝不能"计划任务先删了、服务又没设上"，那会让开机什么都不跑。
func enableServiceAutostart() {
	for _, st := range autostart.Plan(autostart.FormService, false, nil, autostart.Enabled()) {
		switch st {
		case autostart.StepEnableService:
			if err := winsvc.SetAutoStart(true); err != nil {
				fatal("%v", err)
			}
			// 第三份自启来源（HKCU\Run）既不归计划任务也不归服务管，顺手清掉。
			autostart.ClearLegacyRunValue()
		case autostart.StepDisableTask:
			if err := autostart.Disable(); err != nil {
				fmt.Fprintf(os.Stderr,
					"警告：界面版的开机自启（计划任务 %s）没关掉：%v\n"+
						"开机时服务会先抢到引擎，登录后的界面只能当只读。请去界面「开机自启」取消勾选。\n",
					autostart.TaskName, err)
			} else {
				fmt.Printf("· 已同时关掉界面版的开机自启（计划任务 %s）—— 两个都开着会在开机时抢引擎。\n", autostart.TaskName)
			}
		}
	}
	fmt.Printf("服务形态已设为随开机自启（无人登录也跑）。现在想立刻用就 net start %s，或去界面「服务模式」卡片点「启动」。\n", winsvc.Name)
}
