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

// 回归（2026-09-28 现场实测的那个洞）：`intercept:` 那行日志（连接建立那一刻写的）
// **60.7% 是 proc=unknown**，而连接结束的 `relay.done:` 大多已经有名字 —— 名字晚到几百毫秒，
// 可运维要回答"谁连的"读的正是第一行。
//
// 机制：后台刷表是 500ms 一次的**快照**，而 ByPort 里有一条刻意加的限频逻辑
// 「表刚刷过还是没有 → 真查不到」（避免每个连接都全量枚举一次 TCP 表，大表上那是毫秒级）。
// 于是"刚建好、还没进快照"的连接会被直接判成查不到 —— 连表都不再看一眼。
//
// FLOW 层那个事件驱动的补丁（Resolver.Record）就是来解这个的：建立那一刻就把 PID 写进表，
// 于是 hit=true，绕过限频、正常把名字查出来。这条测试把"洞"和"补丁"都钉住。
func TestRecordClosesFreshSnapshotHole(t *testing.T) {
	// ① 先造出"表刚刷过"的状态（fresh=true），此刻快照里还没有我们接下来要建的连接
	r := NewResolver()
	r.refresh()

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
	port := uint16(c.LocalAddr().(*net.TCPAddr).Port)

	// ② 不加 Record：这就是线上那 60.7%（限频生效，直接判"查不到"）
	if _, _, ok := r.ByPort(port); ok {
		t.Logf("端口 %d 意外已在快照里（时序不同）—— 下面的断言仍然有效，只是这条测试这次没复现到洞", port)
	}

	// ③ 补上 FLOW 事件给的那条映射：立刻就能查到进程名
	r.Record(port, uint32(os.Getpid()))
	name, pid, ok := r.ByPort(port)
	if !ok {
		t.Fatalf("Record 之后仍查不到端口 %d —— FLOW 补丁失效了", port)
	}
	if pid != uint32(os.Getpid()) {
		t.Errorf("PID 不对：得到 %d，期望 %d", pid, os.Getpid())
	}
	if name == "" {
		t.Error("Record 之后应当能拿到进程名（否则第一行日志还是空的）")
	}
	t.Logf("端口 %d → PID %d → %s", port, pid, name)
}

// Record 对空值必须无害：FLOW 事件里 ProcessID / LocalPort 为 0 是常见情况。
func TestRecordIgnoresZero(t *testing.T) {
	r := NewResolver()
	r.Record(0, 1234)
	r.Record(4321, 0)
	if ports, _ := r.Stats(); ports != 0 {
		t.Errorf("空值不该写进表，现在有 %d 条", ports)
	}
}

// miss 重读的节流窗口：表刚读过（< missRefillEvery）就不再重读 —— 但**过了窗口必须重读**。
//
// 这条钉的是 2026-09-28 找到的真因：`missRefillEvery` 当时定义了却没用上，
// ByPort 里用的是 1 秒（interval*2），于是同一秒内的一批新连接只有第一个能触发重读，
// 其余全被判"查不到" —— `intercept:` 那行日志 60% proc=unknown 就是这么来的。
func TestMissRefillThrottleWindow(t *testing.T) {
	r := NewResolver()
	r.refresh() // ① 先把快照"定格"在这一刻

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
	c, err := net.Dial("tcp", ln.Addr().String()) // ② 连接建在快照之后 → 快照里没有它
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	port := uint16(c.LocalAddr().(*net.TCPAddr).Port)

	// ③ 立刻查：落在节流窗口内 → 不重读 → 查不到（这就是那个洞）
	if _, _, ok := r.ByPort(port); ok {
		t.Logf("端口 %d 意外已在快照里（时序不同），下面的断言仍然有效", port)
	}

	// ④ 过了窗口再查：必须重读表，把这条连接找出来
	time.Sleep(missRefillEvery + 80*time.Millisecond)
	name, pid, ok := r.ByPort(port)
	if !ok {
		t.Fatalf("过了节流窗口(%v)仍查不到端口 %d —— 节流窗口是不是被写大了？", missRefillEvery, port)
	}
	if pid == 0 || name == "" {
		t.Errorf("查到了但信息不全：pid=%d name=%q", pid, name)
	}
	t.Logf("窗口外命中：端口 %d → PID %d → %s", port, pid, name)
}
