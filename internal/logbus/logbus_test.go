package logbus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 日志文件必须**有上限**：客户机上连跑几个月 + 出问题时高频重试，
// 不轮转就会涨到几百 MB（没人会去删）。
func TestFileRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nethub.log")

	b := New(50)
	if err := b.SetFileLimit(path, 400, 2); err != nil { // 上限 400 字节，保留 2 份
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		b.Info("第 %d 条日志，凑点长度占空间 xxxxxxxxxxxxxxxxxx", i)
	}
	b.Close()

	for _, name := range []string{"nethub.log", "nethub.log.1", "nethub.log.2"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s 应该存在: %v", name, err)
		}
		if st.Size() > 400 {
			t.Errorf("%s 超过上限: %d 字节", name, st.Size())
		}
	}
	// 超出 keep 的旧文件不能留下（否则还是无限涨）
	if _, err := os.Stat(filepath.Join(dir, "nethub.log.3")); err == nil {
		t.Error("不该存在 nethub.log.3（只保留 2 份历史）")
	}
	// 当前文件里应该有轮转说明 + 最新的日志
	cur, _ := os.ReadFile(filepath.Join(dir, "nethub.log"))
	if !strings.Contains(string(cur), "第 59 条") {
		t.Errorf("当前文件里应该是最新的日志：\n%s", cur)
	}
	// 历史文件里是更早的日志（证明是轮转、不是丢弃）
	old, _ := os.ReadFile(filepath.Join(dir, "nethub.log.1"))
	if len(old) == 0 {
		t.Error("nethub.log.1 不该是空的")
	}
}

// 打开一个已经超上限的旧文件（旧版本或轮转前被强杀留下的），要先轮转再写。
func TestFileRotationOnOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nethub.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("老日志\n", 200)), 0o644); err != nil {
		t.Fatal(err)
	}
	b := New(10)
	if err := b.SetFileLimit(path, 200, 2); err != nil {
		t.Fatal(err)
	}
	b.Info("新的一条")
	b.Close()

	st, _ := os.Stat(path)
	if st.Size() > 200 {
		t.Errorf("打开时就该轮转，当前文件 %d 字节", st.Size())
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("旧内容应该被滚到 .1: %v", err)
	}
}
