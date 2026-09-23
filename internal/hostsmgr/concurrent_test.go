package hostsmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// 回归：并发 Apply（后台自愈 + 界面保存会同时发生）不能把 hosts 写坏：
// 只能剩一个标记段、不能残留临时文件、最终内容仍然能通过回读校验。
func TestApplyConcurrentKeepsFileSane(t *testing.T) {
	p := setup(t, "# 原有内容\n127.0.0.1 localhost\n")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = Apply([]string{fmt.Sprintf("10.0.0.%d host%d.example", i%200+1, i)})
		}(i)
	}
	wg.Wait()

	_, exists, full, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("NetHub 标记段不见了")
	}
	if n := strings.Count(full, beginMark); n != 1 {
		t.Fatalf("标记段出现 %d 次（应恰好 1 次）:\n%s", n, full)
	}
	if n := strings.Count(full, endMark); n != 1 {
		t.Fatalf("结束标记出现 %d 次:\n%s", n, full)
	}
	// 唯一临时文件（CreateTemp）不能被留在目录里
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), "nethub-hosts-*.tmp")); len(left) != 0 {
		t.Fatalf("残留临时文件: %v", left)
	}
	// 并发之后仍能正常收敛（回读校验通过）
	if _, err := Apply([]string{"10.0.0.9 final.example"}); err != nil {
		t.Fatalf("收尾 Apply 失败: %v", err)
	}
	if !strings.Contains(readFile(t, p), "10.0.0.9 final.example") {
		t.Fatal("最终内容没写进去")
	}
}

// writeFile 失败时不能原地截断：这里用一个必然 rename 失败的目录名验证它只报错、不毁文件。
func TestWriteFileLeavesOriginalOnRenameFailure(t *testing.T) {
	p := setup(t, "# 原始\n1.2.3.4 keep.example\n")
	before := readFile(t, p)
	// 目标路径是一个**目录**：rename 必定失败
	dir := filepath.Join(filepath.Dir(p), "blocked")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(dir, "new content"); err == nil {
		t.Fatal("对目录写应当失败")
	}
	if after := readFile(t, p); after != before {
		t.Fatalf("原文件被改动了:\n%q\n=>\n%q", before, after)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(dir), "nethub-hosts-*.tmp")); len(left) != 0 {
		t.Fatalf("失败路径残留临时文件: %v", left)
	}
}
