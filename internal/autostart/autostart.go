// Package autostart 管理开机自启。
//
// 用「计划任务 + 最高权限」而不是 HKCU\Run：
// WinDivert 需要管理员才能加载，而 Run 键拉起的进程是普通权限，
// 只能靠程序自己再提权一次弹 UAC —— 每次开机都要手点一下，不可接受。
// 计划任务设 RunLevel=HighestAvailable，开机静默拿到管理员令牌。
package autostart

import (
	"fmt"
	"nethub/internal/winrun"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

const (
	// TaskName 计划任务名。
	TaskName = "NetHub"
	// RunKeyPath / RunValueName 早期版本用的注册表自启位置，现在只用来清理。
	RunKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	RunValueName = "NetHub"
)

// Enabled 计划任务是否存在。
func Enabled() bool {
	err := winrun.Command("schtasks", "/query", "/tn", TaskName).Run()
	return err == nil
}

// Detail 返回计划任务的关键设置，用于界面展示。
func Detail() string {
	out, err := winrun.Command("schtasks", "/query", "/tn", TaskName, "/xml").CombinedOutput()
	if err != nil {
		return "（未安装）"
	}
	s := string(out)
	var parts []string
	if strings.Contains(s, "HighestAvailable") {
		parts = append(parts, "最高权限")
	}
	if strings.Contains(s, "<Delay>PT20S</Delay>") {
		parts = append(parts, "登录后延迟 20 秒")
	}
	if strings.Contains(s, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") {
		parts = append(parts, "无运行时长上限")
	}
	if len(parts) == 0 {
		return "（已安装）"
	}
	return "（" + strings.Join(parts, "，") + "）"
}

// Enable 安装计划任务，并清掉历史遗留的 HKCU\Run 值避免双实例。
func Enable() error {
	removeRunValue()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if abs, e := filepath.Abs(exe); e == nil {
		exe = abs
	}

	// schtasks 只吃 UTF-16LE + BOM 的 XML
	tmp, err := os.CreateTemp("", "nethub-task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(utf16BOM(taskXML(exe, filepath.Dir(exe)))); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	out, err := winrun.Command("schtasks", "/create", "/f", "/tn", TaskName, "/xml", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /create: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Disable 删除计划任务（不存在也算成功）。
func Disable() error {
	removeRunValue()
	out, err := winrun.Command("schtasks", "/delete", "/f", "/tn", TaskName).CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "找不到") || strings.Contains(s, "cannot find") ||
			strings.Contains(s, "does not exist") || strings.Contains(s, "错误") {
			return nil
		}
		return fmt.Errorf("schtasks /delete: %v (%s)", err, strings.TrimSpace(s))
	}
	return nil
}

func utf16BOM(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2+len(u)*2)
	b = append(b, 0xFF, 0xFE)
	for _, v := range u {
		b = append(b, byte(v), byte(v>>8))
	}
	return b
}

// taskXML：ExecutionTimeLimit=PT0S 是必须的（默认 PT72H，跑满 3 天会被计划任务掐死）；
// DisallowStartIfOnBatteries=false 是必须的（笔记本用电池时否则根本不启动）。
func taskXML(exe, dir string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>NetHub 内网隧道代理：拦截内网网段并转发到 gost 链路</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT20S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEsc(exe) + `</Command>
      <WorkingDirectory>` + xmlEsc(dir) + `</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`
}

func xmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func removeRunValue() {
	k, err := registry.OpenKey(registry.CURRENT_USER, RunKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(RunValueName)
}
