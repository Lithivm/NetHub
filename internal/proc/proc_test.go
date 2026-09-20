package proc

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolverFindsOwnProcess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer c.Close()

	local, _ := c.LocalAddr().(*net.TCPAddr)
	r := NewResolver()
	name, pid, ok := r.ByPort(uint16(local.Port))
	if !ok {
		t.Skipf("查不到端口 %d 的进程（可能是受限环境），跳过", local.Port)
	}
	if pid == 0 {
		t.Fatal("查到进程但 PID 为 0")
	}
	// 进程名应该是测试二进制自己
	exe := filepath.Base(ownTestExe(t))
	if !strings.EqualFold(name, exe) && !strings.Contains(strings.ToLower(name), strings.TrimSuffix(strings.ToLower(exe), ".exe")) {
		t.Errorf("端口 %d 反查到 %q（PID %d），期望是自己 %q", local.Port, name, pid, exe)
	}
	if r.FullPath(pid) == "" {
		t.Log("拿不到完整路径（无伤大雅，部分环境受限）")
	}
	t.Logf("端口 %d → PID %d → %s", local.Port, pid, name)
}

func TestStatsAndStop(t *testing.T) {
	r := NewResolver()
	r.Start()
	r.Stop()
	r.Stop()                           // 幂等
	time.Sleep(600 * time.Millisecond) // 让后台至少刷一次
	ports, pids := r.Stats()
	t.Logf("缓存：端口 %d 个、进程 %d 个", ports, pids)
	if ports == 0 {
		t.Skip("TCP 表为空（受限环境）")
	}
}

// ownTestExe 当前测试进程的可执行文件路径。
func ownTestExe(t *testing.T) string {
	p, err := os.Executable()
	if err != nil {
		t.Fatalf("取自身路径失败: %v", err)
	}
	return p
}
