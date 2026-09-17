// Package winrun 起外部进程时强制隐藏控制台窗口。
//
// 为什么必需：本程序是 GUI 子系统（链接时加了 -H=windowsgui），进程**没有自己的控制台**。
// 它却要调 schtasks / sc / explorer 这类控制台程序 —— 不加 CREATE_NO_WINDOW 的话，
// 每次 exec 都会弹出一个新的控制台窗口。
//
// 如果这个调用落在轮询路径上（界面上每秒查一次状态就会），就会表现为
// **窗口一直闪 + 抢焦点，用户连字都打不了**。所以所有外部调用一律走这里。
package winrun

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW：为控制台程序创建但不显示窗口。
const createNoWindow = 0x08000000

// Command 构造一个"不弹窗"的命令。
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	return cmd
}

// Output 跑一条命令并返回合并后的输出（出错也把输出带回来，便于诊断）。
func Output(name string, args ...string) ([]byte, error) {
	return Command(name, args...).CombinedOutput()
}
