package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

// 回归：只含 nethub.exe 的更新包（exe 已在运行前换过）也必须清掉 pending.json，
// 否则每次启动都重复走一遍收尾流程。
func TestApplyPendingClearsPendingForExeOnlyUpdate(t *testing.T) {
	prog := t.TempDir()
	stage := filepath.Join(prog, StageDirName)
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	// pending：只一个 exe，且已 swap
	if err := writePending(prog, Pending{Version: "v1", Files: []string{"nethub.exe"}, ExeSwapped: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "nethub.exe"), []byte("MZfake"), 0o755); err != nil {
		t.Fatal(err)
	}
	done, err := ApplyPending(prog, nil)
	if err != nil {
		t.Fatalf("收尾失败: %v", err)
	}
	if len(done) != 0 {
		t.Fatalf("exe 已换过，不应再替换任何文件: %v", done)
	}
	if _, ok := HasPending(prog); ok {
		t.Fatal("exe-only 更新的 pending.json 应被清掉")
	}
}

// 回归：e_lfanew 是 4 字节，大 PE（偏移 >64KB）不能被低 16 位截断误判。
func TestLooksLikePEHandlesLargeOffset(t *testing.T) {
	off := 70000
	b := make([]byte, off+64)
	b[0], b[1] = 'M', 'Z'
	b[0x3c] = byte(off)
	b[0x3d] = byte(off >> 8)
	b[0x3e] = byte(off >> 16)
	b[0x3f] = byte(off >> 24)
	b[off], b[off+1], b[off+2], b[off+3] = 'P', 'E', 0, 0
	if !looksLikePE(b) {
		t.Fatal("大 PE 应被判为合法")
	}
	// 截断的 PE 头仍要拒绝
	if looksLikePE(b[:100]) {
		t.Fatal("越界偏移应被拒绝")
	}
}
