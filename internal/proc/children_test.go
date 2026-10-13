package proc

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// ChildrenByName 是界面/引擎两边的存活判据（见 children_windows.go 顶部说明），
// 数错一次就会导致"界面被外部程序杀掉后永远不重启"，所以钉住它。
func TestChildrenByName(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "timeout", "/t", "10", "/nobreak")
	if err := cmd.Start(); err != nil {
		t.Fatalf("起子进程失败: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	me := uint32(os.Getpid())
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := ChildrenByName(me, "cmd.exe")
		t.Logf("ChildrenByName(me=%d, cmd.exe) = %d；子进程 pid=%d", me, n, cmd.Process.Pid)
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			// 再打印一次"换个名字"的结果，区分"没数到"和"整体不可用"
			t.Logf("换个名字试：ChildrenByName(me, timeout.exe) = %d", ChildrenByName(me, "timeout.exe"))
			t.Logf("换个 pid 试（子进程名下）：ChildrenByName(child, timeout.exe) = %d", ChildrenByName(uint32(cmd.Process.Pid), "timeout.exe"))
			t.Fatalf("数不到自己的子进程")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
