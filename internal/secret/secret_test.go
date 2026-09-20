package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 存取往返 + 落盘后文件里不能出现明文口令。
func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("upstream-a", "user:SuperSecret123"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal("落盘失败:", err)
	}
	if strings.Contains(string(raw), "SuperSecret123") {
		t.Fatal("secrets.dat 里出现了明文口令 —— DPAPI 没生效")
	}

	// 重新载入（模拟重启）
	s2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Get("upstream-a"); got != "user:SuperSecret123" {
		t.Errorf("解出来的口令不对：%q", got)
	}
	if names := s2.Names(); len(names) != 1 || names[0] != "upstream-a" {
		t.Errorf("名字列表不对：%v", names)
	}

	// 删空后不该留一个空文件
	if err := s2.Delete("upstream-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName)); !os.IsNotExist(err) {
		t.Error("删空后应把 secrets.dat 移除")
	}
	if got := s2.Get("upstream-a"); got != "" {
		t.Errorf("删掉后不该还取得到：%q", got)
	}
}

// 保险箱不存在时是空箱子，不是错误（首次运行）。
func TestLoadMissingIsEmpty(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("首次运行不该报错：%v", err)
	}
	if s.Get("nope") != "" || len(s.Names()) != 0 {
		t.Error("空箱子里不该有东西")
	}
}
