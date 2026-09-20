package hostsmgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setup 把 SystemRoot 指到临时目录，Path() 就落在临时 hosts 上（不碰真文件）。
func setup(t *testing.T, initial string) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SystemRoot", root)
	p := filepath.Join(root, "System32", "drivers", "etc", "hosts")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	// 测试里别真去刷系统 DNS 缓存
	old := FlushFunc
	FlushFunc = func() error { return nil }
	t.Cleanup(func() { FlushFunc = old })
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 块外原有的同名记录必须被接管 —— 否则 Windows 取第一条匹配，我们写的永远不生效。
func TestApplyTakesOverOutsideEntries(t *testing.T) {
	initial := "# 原有内容\n192.168.31.85 host.docker.internal\n1.2.3.4 main.his.com\n"
	p := setup(t, initial)

	res, err := Apply([]string{"172.30.4.217 main.his.com"})
	if err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if len(res.TakenOver) != 1 {
		t.Fatalf("应该报告 1 条接管，实际 %+v", res.TakenOver)
	}
	got := readFile(t, p)
	if strings.Contains(got, "1.2.3.4") {
		t.Errorf("块外的旧记录应该被接管掉：\n%s", got)
	}
	// 别的条目一个字都不能动
	if !strings.Contains(got, "host.docker.internal") || !strings.Contains(got, "# 原有内容") {
		t.Errorf("块外其它内容不能被改：\n%s", got)
	}
	if strings.Count(got, "main.his.com") != 1 {
		t.Errorf("同名记录只该剩一条：\n%s", got)
	}
	// 块里是我们写的值
	if ok, why := Verify([]string{"172.30.4.217 main.his.com"}); !ok {
		t.Errorf("写完之后 Verify 应该通过，实际: %s", why)
	}
}

// 幂等：重复 Apply 不能长出重复条目、文件内容要稳定。
func TestApplyIdempotent(t *testing.T) {
	p := setup(t, "# 原文件\n")
	entries := []string{"172.30.4.217 main.his.com", "10.100.100.99 main.wbzxyy.com"}
	if _, err := Apply(entries); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, p)
	if _, err := Apply(entries); err != nil {
		t.Fatal(err)
	}
	if second := readFile(t, p); second != first {
		t.Errorf("两次 Apply 结果应该一样：\n--- 第一次\n%s\n--- 第二次\n%s", first, second)
	}
}

// Verify 要能发现三种“被改坏”：块没了 / 块内容变了 / 块外冒出同名记录。
func TestVerifyDetectsChanges(t *testing.T) {
	p := setup(t, "# 原文件\n")
	entries := []string{"172.30.4.217 main.his.com"}
	if _, err := Apply(entries); err != nil {
		t.Fatal(err)
	}
	if ok, why := Verify(entries); !ok {
		t.Fatalf("刚写完就该一致，实际: %s", why)
	}

	// ① 块内容被人改掉
	got := readFile(t, p)
	_ = os.WriteFile(p, []byte(strings.Replace(got, "172.30.4.217", "1.1.1.1", 1)), 0o644)
	if ok, why := Verify(entries); ok || !strings.Contains(why, "改动") {
		t.Errorf("块内容被改应该被发现，实际 ok=%v why=%s", ok, why)
	}

	// ② 整个块被删掉
	if _, err := Apply(entries); err != nil {
		t.Fatal(err)
	}
	got = readFile(t, p)
	i := strings.Index(got, beginMark)
	_ = os.WriteFile(p, []byte(got[:i]), 0o644)
	if ok, why := Verify(entries); ok || !strings.Contains(why, "不见了") {
		t.Errorf("块被删应该被发现，实际 ok=%v why=%s", ok, why)
	}

	// ③ 别的程序在块外又插了一条同名记录
	if _, err := Apply(entries); err != nil {
		t.Fatal(err)
	}
	got = readFile(t, p)
	_ = os.WriteFile(p, []byte("9.9.9.9 main.his.com\n"+got), 0o644)
	if ok, why := Verify(entries); ok || !strings.Contains(why, "块外") {
		t.Errorf("块外同名应该被发现，实际 ok=%v why=%s", ok, why)
	}
}

// Remove 只摘掉我们的段，别的不动。
func TestRemove(t *testing.T) {
	p := setup(t, "# 原文件\n192.168.31.85 host.docker.internal\n")
	if _, err := Apply([]string{"172.30.4.217 main.his.com"}); err != nil {
		t.Fatal(err)
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, p)
	if strings.Contains(got, "NetHub") || strings.Contains(got, "main.his.com") {
		t.Errorf("我们的段应该被摘干净：\n%s", got)
	}
	if !strings.Contains(got, "host.docker.internal") {
		t.Errorf("别人的条目不能动：\n%s", got)
	}
	if _, exists, _, _ := Read(); exists {
		t.Error("Read 应该报告块不存在")
	}
}
