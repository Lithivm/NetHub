package proc

import (
	"os"
	"os/exec"
	"testing"
)

// Alive 是界面进程"引擎没了我就退出"的判据：判错了就是界面自杀或孤儿占锁，两头都很难查，
// 所以三条边界都钉住。
func TestAlive(t *testing.T) {
	if !Alive(uint32(os.Getpid())) {
		t.Fatal("自己明明活着，却被判死")
	}

	// 起一个立刻退出的进程，等它退干净 → 必须判死
	cmd := exec.Command("cmd", "/c", "exit", "0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("起子进程失败: %v", err)
	}
	pid := uint32(cmd.Process.Pid)
	if !Alive(pid) {
		t.Fatalf("子进程 %d 还没退出，却被判死（会误杀健康进程）", pid)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("等子进程失败: %v", err)
	}
	if Alive(pid) {
		t.Fatalf("子进程 %d 已经退出，却还判活着（孤儿会一直占着单实例锁）", pid)
	}

	// 0 / 不存在的 pid：不许 panic，判死
	if Alive(0) {
		t.Fatal("pid=0 应判死（那是「没传父进程」，不是活着）")
	}
	if Alive(0xFFFFFFF0) {
		t.Fatal("不存在的 pid 应判死")
	}
}
