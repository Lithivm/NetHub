package autostart

import (
	"strings"
	"testing"
)

func TestISO8601RoundTrip(t *testing.T) {
	cases := []struct {
		sec  int
		want string
	}{
		{0, ""},
		{5, "PT5S"},
		{20, "PT20S"},
		{60, "PT1M"},
		{90, "PT1M30S"},
		{600, "PT10M"},
		{3600, "PT1H"},
		{3661, "PT1H1M1S"},
	}
	for _, c := range cases {
		got := iso8601Duration(c.sec)
		if got != c.want {
			t.Errorf("iso8601Duration(%d) = %q，期望 %q", c.sec, got, c.want)
			continue
		}
		if got == "" {
			continue
		}
		back, ok := parseISO8601(got)
		if !ok || back != c.sec {
			t.Errorf("parseISO8601(%q) = %d,%v，期望 %d,true", got, back, ok, c.sec)
		}
	}
}

func TestParseISO8601(t *testing.T) {
	// "PT0S" 是合法值（不延迟），不能被当成解析失败
	if v, ok := parseISO8601("PT0S"); !ok || v != 0 {
		t.Errorf(`parseISO8601("PT0S") = %d,%v，期望 0,true`, v, ok)
	}
	// 小写 / 带空格要能容忍（schtasks 回显的写法不保证）
	if v, ok := parseISO8601(" pt20s "); !ok || v != 20 {
		t.Errorf(`parseISO8601(" pt20s ") = %d,%v，期望 20,true`, v, ok)
	}
	for _, bad := range []string{"", "20S", "PT", "PTS", "PT20", "PT1X", "PT-1S"} {
		if _, ok := parseISO8601(bad); ok {
			t.Errorf("parseISO8601(%q) 应当失败", bad)
		}
	}
}

func TestDelaySecondsFromXML(t *testing.T) {
	if v, ok := delaySecondsFromXML("<Triggers><LogonTrigger><Delay>PT20S</Delay></LogonTrigger></Triggers>"); !ok || v != 20 {
		t.Errorf("带 Delay 时应读出 20，得到 %d,%v", v, ok)
	}
	// 没有 Delay 元素 = 不延迟（0），这是合法结果而不是失败
	if v, ok := delaySecondsFromXML("<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"); !ok || v != 0 {
		t.Errorf("无 Delay 时应得到 0,true，得到 %d,%v", v, ok)
	}
	if _, ok := delaySecondsFromXML("<Delay>PT20S"); ok {
		t.Error("Delay 没有闭合标签应当失败")
	}
}

func TestTaskXMLDelay(t *testing.T) {
	withDelay := taskXML(`C:\a\nethub.exe`, `C:\a`, 90)
	if !strings.Contains(withDelay, "<Delay>PT1M30S</Delay>") {
		t.Error("delaySec=90 应写入 <Delay>PT1M30S</Delay>")
	}
	// 延迟必须在 LogonTrigger 里面（放错层级 schtasks 会直接拒掉）
	trig := withDelay[strings.Index(withDelay, "<LogonTrigger>"):strings.Index(withDelay, "</LogonTrigger>")]
	if !strings.Contains(trig, "<Delay>") {
		t.Error("Delay 必须在 LogonTrigger 内")
	}
	// 0 = 不延迟：整段省略（写 <Delay>PT0S</Delay> 也能用，但省略最不容易被挑刺）
	noDelay := taskXML(`C:\a\nethub.exe`, `C:\a`, 0)
	if strings.Contains(noDelay, "<Delay>") {
		t.Error("delaySec=0 时不应出现 Delay 元素")
	}
	// 必须保留的两项：默认 PT72H 会把跑满 3 天的任务掐死；笔记本电池上否则不启动
	if !strings.Contains(noDelay, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") {
		t.Error("ExecutionTimeLimit=PT0S 不能丢")
	}
	if !strings.Contains(noDelay, "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>") {
		t.Error("DisallowStartIfOnBatteries=false 不能丢")
	}
	// 路径要转义，否则含 & 的目录会让整个任务建不起来
	esc := taskXML(`C:\a&b\nethub.exe`, `C:\a&b`, 0)
	if !strings.Contains(esc, `C:\a&amp;b\nethub.exe`) {
		t.Error("exe 路径里的 & 应当被转义")
	}
}
