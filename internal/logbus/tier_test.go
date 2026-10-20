package logbus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 屏幕档与文件档**各自独立**（Proxifier 的 Screen Log / File Log 分开设）。
//
// 为什么必须钉住：这是“界面清爽 + 文件有料”的全部实现。一旦谁把它写回一个档位，
// 现场就只能二选一 —— 要么每台机器上界面一直刷屏，要么出事时把日志发出去却什么都看不出来。
func TestScreenAndFileLevelsAreIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nethub.log")
	b := New(100)
	defer b.Close()
	if err := b.SetFileLimit(path, 1<<20, 2); err != nil {
		t.Fatal(err)
	}

	// 屏幕 normal / 文件 debug：最常见的组合（PROXIFIER 也是这个用法）
	b.SetLevels(LevelNormal, LevelDebug)
	b.Detail("dns.query: name=a.example type=A") // 判定面
	b.Debug("fakeip.recycle: count=3")           // 内部面
	b.Info("open: a.exe (1) → x:80 via c")       // 现场面（两档都该有）

	snap := b.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("屏幕档是 normal，环形缓冲里只该有那一条 INFO，实际 %d 条：%+v", len(snap), snap)
	}
	if !strings.Contains(snap[0].Text, "open:") {
		t.Errorf("屏幕上留下的应当是连接行，实际 %q", snap[0].Text)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	txt := string(data)
	if !strings.Contains(txt, "dns.query:") || !strings.Contains(txt, "fakeip.recycle:") {
		t.Errorf("文件档是 debug，判定面与内部面都该写进文件，实际：\n%s", txt)
	}
	if !strings.Contains(txt, "open:") {
		t.Errorf("现场面那行也该在文件里：\n%s", txt)
	}

	// 反过来也允许（屏幕 debug、文件 normal）：不替用户做主
	path2 := filepath.Join(t.TempDir(), "nethub2.log")
	b2 := New(100)
	defer b2.Close()
	if err := b2.SetFileLimit(path2, 1<<20, 2); err != nil {
		t.Fatal(err)
	}
	b2.SetLevels(LevelDebug, LevelNormal)
	b2.Detail("route.match: x")
	if got := len(b2.Snapshot()); got != 1 {
		t.Errorf("屏幕档是 debug，环形缓冲里该有那条 route.match，实际 %d 条", got)
	}
	d2, err := os.ReadFile(path2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(d2), "route.match:") {
		t.Errorf("文件档是 normal，不该写 route.match：\n%s", string(d2))
	}
}

// 两个 sink 都没到 verbose 时，Detail 一行都不写（也别白做格式化）。
func TestDetailSilentWhenBothNormal(t *testing.T) {
	b := New(50)
	b.SetLevels(LevelNormal, LevelNormal)
	if b.Verbose() || b.IsDebug() {
		t.Fatal("两档都是 normal 时不该自报 verbose/debug")
	}
	b.Detail("dns.query: nope")
	b.Debug("nope")
	if got := len(b.Snapshot()); got != 0 {
		t.Fatalf("不该有输出，实际 %d 条", got)
	}
}

// SetLevel 是“两档一起定”（兼容旧调用点：启动/测试里都是一把定）。
func TestSetLevelSetsBothSinks(t *testing.T) {
	b := New(50)
	b.SetLevel(LevelVerbose)
	if b.Level() != LevelVerbose || b.FileLevel() != LevelVerbose {
		t.Errorf("SetLevel 应当同时定两档，实际 屏幕=%v 文件=%v", b.Level(), b.FileLevel())
	}
}
