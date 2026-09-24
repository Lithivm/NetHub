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
	if sec, ok := delaySecondsFromXML(s); ok {
		if sec > 0 {
			parts = append(parts, fmt.Sprintf("登录后延迟 %d 秒", sec))
		} else {
			parts = append(parts, "登录后立即启动")
		}
	}
	if strings.Contains(s, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") {
		parts = append(parts, "无运行时长上限")
	}
	if len(parts) == 0 {
		return "（已安装）"
	}
	return "（" + strings.Join(parts, "，") + "）"
}

// DelaySeconds 从已安装的计划任务里读回实际的登录后延迟（秒）。
// 第二个返回值为 false 表示任务不存在或 XML 读不出来。
func DelaySeconds() (int, bool) {
	out, err := winrun.Command("schtasks", "/query", "/tn", TaskName, "/xml").CombinedOutput()
	if err != nil {
		return 0, false
	}
	return delaySecondsFromXML(string(out))
}

// delaySecondsFromXML 从任务 XML 里抠出 <Delay>PT20S</Delay> 这类 ISO8601 时长。
// 没有 Delay 元素 = 0（不延迟）。
func delaySecondsFromXML(xml string) (int, bool) {
	i := strings.Index(xml, "<Delay>")
	if i < 0 {
		return 0, true
	}
	i += len("<Delay>")
	j := strings.Index(xml[i:], "</Delay>")
	if j < 0 {
		return 0, false
	}
	return parseISO8601(strings.TrimSpace(xml[i : i+j]))
}

// parseISO8601 只解析我们要用到的那几种形态：PT20S / PT1M30S / PT1H2M3S。
func parseISO8601(s string) (int, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "PT") {
		return 0, false
	}
	total, num := 0, 0
	sawDigit, sawUnit := false, false
	for _, r := range s[2:] {
		switch {
		case r >= '0' && r <= '9':
			num = num*10 + int(r-'0')
			sawDigit = true
		case r == 'H' || r == 'M' || r == 'S':
			if !sawDigit {
				return 0, false
			}
			sawUnit = true
			switch r {
			case 'H':
				total += num * 3600
			case 'M':
				total += num * 60
			default:
				total += num
			}
			num, sawDigit = 0, false
		default:
			return 0, false
		}
	}
	// 数字后面没跟单位（"PT20"）= 残缺；一个单位都没有（"PT"）= 空时长。
	// 两者都不是合法的 ISO8601，按解析失败算 —— 否则任务 XML 被截断时会
	// 静默当成“不延迟”处理。
	if sawDigit || !sawUnit {
		return 0, false
	}
	return total, true
}

// iso8601Duration 把秒数写成 ISO8601 时长；0 返回空串（调用方据此**整段省略** Delay 元素）。
func iso8601Duration(sec int) string {
	if sec <= 0 {
		return ""
	}
	h, m, s := sec/3600, (sec%3600)/60, sec%60
	out := "PT"
	if h > 0 {
		out += fmt.Sprintf("%dH", h)
	}
	if m > 0 {
		out += fmt.Sprintf("%dM", m)
	}
	if s > 0 || (h == 0 && m == 0) {
		out += fmt.Sprintf("%dS", s)
	}
	return out
}

// Enable 安装计划任务（delaySec = 登录后延迟秒数，0 = 立即启动），
// 并清掉历史遗留的 HKCU\Run 值避免双实例。
func Enable(delaySec int) error {
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
	if _, err := tmp.Write(utf16BOM(taskXML(exe, filepath.Dir(exe), delaySec))); err != nil {
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
// delaySec = 0 时**整段省略** Delay（写成 <Delay>PT0S</Delay> 虽然也算合法，
// 但省略最不容易被 schtasks 挑刺）。
func taskXML(exe, dir string, delaySec int) string {
	delay := ""
	if d := iso8601Duration(delaySec); d != "" {
		delay = "\n      <Delay>" + d + "</Delay>"
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>NetHub 内网隧道代理：拦截内网网段并转发到 gost 链路</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>` + delay + `
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
