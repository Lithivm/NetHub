package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nethub/internal/config"
	"nethub/internal/engine"
	"nethub/internal/hostsmgr"
	"nethub/internal/logbus"
)

// 外部（编辑器 / agent 工具）是**原地写**配置文件的，2 秒一次的轮询很容易正好读到半截。
// 重试要能自己好掉，不能报一条虚警的 ERROR 让人白查一圈。
func TestReloadRetriesHalfWrittenFile(t *testing.T) {
	a, _, p := seedConfig(t)
	if err := os.WriteFile(p, []byte("relay: 127.0.0.1:0\nroutes: [未闭合"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 150ms 后把文件写完整（早于 400ms 的第一次重试）
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = os.WriteFile(p, []byte("relay: 127.0.0.1:0\nchains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\nroutes: []\n"), 0o600)
	}()

	if _, err := a.applyFromDiskWithRetry(); err != nil {
		t.Fatalf("重试后应当能载入完整文件：%v", err)
	}
	found := false
	for _, l := range a.Bus.Snapshot() {
		if strings.Contains(l.Text, "读到完整文件") {
			found = true
		}
	}
	if !found {
		t.Error("应当记一行“重试后读到完整文件”—— 否则现场不知道刚才那次失败只是写了一半")
	}
}

// 「驱动被安全软件拦」必须能被界面认出来，否则只能让前端去正则匹配那句中文错误消息。
// 完整链：engine 的哨兵错误 → App.driverBlocked → GetState.driverBlocked → 顶部告警条。
// 这里锁住中间一环：标记要跟着“原始错误”走，而不是跟着错误文本。
func TestDriverBlockedFlagFollowsCause(t *testing.T) {
	a, _, _ := seedConfig(t)

	cause := fmt.Errorf("%w（已重试 6 次）: %v", engine.ErrDriverBlocked,
		errors.New("Insufficient system resources exist to complete the requested service."))
	a.setLastError("拦截启动失败："+cause.Error(), cause)
	if !a.DriverBlocked() {
		t.Error("驱动被拦却没打上标记 —— 界面不会弹那条告警条，现场只能从日志里挖")
	}
	if !strings.Contains(a.LastError(), "拦截启动失败") {
		t.Errorf("LastError 不该被改动：%q", a.LastError())
	}

	// 换个原因（配置不合法）：标记必须跟着掉下来，否则驱动修好了横幅还挂着
	a.setLastError("配置不合法：路由为空", errors.New("路由为空"))
	if a.DriverBlocked() {
		t.Error("失败原因已经变了（配置不合法），却还挂着“驱动被拦”的标记")
	}

	// 启动成功会 setLastError("", nil) 清错 —— 标记也要一起清
	a.setLastError("", nil)
	if a.DriverBlocked() || a.LastError() != "" {
		t.Error("启动成功（清空 LastError）后标记没清干净")
	}
}

func seedConfig(t *testing.T) (*App, *config.Config, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	seed := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n" +
		"routes: []\n"
	if err := os.WriteFile(p, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, logbus.New(50)), cfg, p
}

// 回归（#5）：保存必须先编译规则、再落盘。非法规则要“保存失败且一个字节都不写”，
// 不能出现“文件已经改了、界面却说失败”的不一致状态。
func TestSaveConfigDoesNotWriteWhenInvalid(t *testing.T) {
	a, cfg, p := seedConfig(t)
	before, _ := os.ReadFile(p)

	cfg.Routes = append(cfg.Routes, config.Route{
		Name: "坏规则", Targets: []string{"10.0.0.0/24"}, Chain: ""})

	if _, err := a.SaveConfig(); err == nil {
		t.Fatal("非法规则应当保存失败")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("保存失败却把文件写了（磁盘状态与界面提示不一致）")
	}
}

// 正常路径：合法规则要能保存并落盘。
func TestSaveConfigWritesWhenValid(t *testing.T) {
	a, cfg, p := seedConfig(t)
	cfg.Routes = append(cfg.Routes, config.Route{
		Name: "ok", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a"})

	if _, err := a.SaveConfig(); err != nil {
		t.Fatalf("合法规则不该失败: %v", err)
	}
	re, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(re.Routes) != 1 || re.Routes[0].Chain != "proxy-a" {
		t.Fatalf("没落盘或内容不对: %+v", re.Routes)
	}
}

// 收尾（"干净退出"）：引擎一停就该把我们在系统里留的痕迹撤干净。
//   - hosts 段：留着它，那几个名字就指着内网 IP 而没人兑付（应用一直等到超时）
//   - runtime.json：没有实例在跑就不该留自报
//
// 块外的内容（别人的 hosts 记录）一个字节都不能动。
func TestCleanupAfterStopRemovesHostsAndRuntime(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SystemRoot", root) // Path() 就落在临时 hosts 上，不碰真文件
	hostsPath := filepath.Join(root, "System32", "drivers", "etc", "hosts")
	if err := os.MkdirAll(filepath.Dir(hostsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	const outside = "# 原有内容\n1.2.3.4 keep.me keep-alias.me\n"
	if err := os.WriteFile(hostsPath, []byte(outside), 0o644); err != nil {
		t.Fatal(err)
	}
	oldFlush := hostsmgr.FlushFunc
	hostsmgr.FlushFunc = func() error { return nil } // 别真去刷系统 DNS 缓存
	t.Cleanup(func() { hostsmgr.FlushFunc = oldFlush })

	p := filepath.Join(t.TempDir(), "config.yaml")
	seed := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n" +
		"routes: []\n" +
		"hosts:\n  manage: true\n  entries:\n    - 10.0.0.1 a.example.com\n    - 10.0.0.2 b.example.com\n"
	if err := os.WriteFile(p, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostsmgr.Apply(cfg.HostsCopy().Entries); err != nil {
		t.Fatal(err)
	}
	if _, exists, _, _ := hostsmgr.Read(); !exists {
		t.Fatal("前置条件：hosts 段应当已写入")
	}

	// 造一份运行态文件（写在"exe 同目录"，测试里就是测试二进制所在目录）
	rtPath := filepath.Join(exeDir(), RuntimeFile)
	if err := os.WriteFile(rtPath, []byte("{\"running\":true}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := New(cfg, logbus.New(50))
	a.cleanupAfterStop()

	if _, exists, _, _ := hostsmgr.Read(); exists {
		t.Error("收尾后不该还留着 NetHub 的 hosts 段")
	}
	body, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "1.2.3.4 keep.me") {
		t.Errorf("收尾动了块外的内容：\n%s", body)
	}
	if _, err := os.Stat(rtPath); !os.IsNotExist(err) {
		t.Errorf("收尾后应当删掉 %s（err=%v）", RuntimeFile, err)
	}
}

// hosts.manage=false 时收尾不许碰 hosts（用户明确说"hosts 我自己管"）。
func TestCleanupAfterStopLeavesHostsWhenUnmanaged(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SystemRoot", root)
	hostsPath := filepath.Join(root, "System32", "drivers", "etc", "hosts")
	if err := os.MkdirAll(filepath.Dir(hostsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsPath, []byte("# 原有\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldFlush := hostsmgr.FlushFunc
	hostsmgr.FlushFunc = func() error { return nil }
	t.Cleanup(func() { hostsmgr.FlushFunc = oldFlush })
	if _, err := hostsmgr.Apply([]string{"10.0.0.1 a.example.com"}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	seed := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n" +
		"routes: []\n" +
		"hosts:\n  manage: false\n  entries:\n    - 10.0.0.1 a.example.com\n"
	if err := os.WriteFile(p, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	a := New(cfg, logbus.New(50))
	a.cleanupAfterStop()
	if _, exists, _, _ := hostsmgr.Read(); !exists {
		t.Error("hosts.manage=false 时不该动 hosts 文件")
	}
}

// 正常关机/重启时系统直接结束进程（GUI 进程不处理 WM_QUERYENDSESSION，服务形态的
// 关机等待也只有几秒），收尾来不及跑 → runtime.json 必然留下。
// 那不是“被外部结束或崩溃”，判据是**同一次开机**：跨开机就只写一行 Info。
//
// 实测来源：2026-10-30 17:32 正常关机（事件 6006）、11-02 09:09 开机，曾误报一条 WARN。
func TestNoteUncleanExitSkipsShutdownLeftover(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	restore := sysBootTime
	sysBootTime = func() time.Time { return now }
	t.Cleanup(func() { sysBootTime = restore })

	// 上次那次开机是一小时前，进程已经不在 → 中间关过机/重启过
	writeRuntimeDoc(t, RuntimeDoc{
		PID:       999999, // 不存在的 pid：processAlive 为 false
		Running:   true,
		StartedAt: now.Add(-30 * time.Minute).Format(time.RFC3339),
		BootAt:    now.Add(-time.Hour).Format(time.RFC3339),
	})
	bus := logbus.New(50)
	a := New(nil, bus)
	a.noteUncleanExit()
	if msg := warnAbout(bus, "未正常退出"); msg != "" {
		t.Errorf("跨开机周期的残留（正常关机）不该报 WARN，实际：%s", msg)
	}
	if msg := infoAbout(bus, "没撤"); msg == "" {
		t.Error("跨开机周期的残留应当留一行 Info 说明（现场要能解释 runtime.json 为什么还在）")
	}
}

// 同一次开机里进程消失了 = 真被外部结束/崩溃 → 这条 WARN 必须还在
// （否则“隧道为什么重启了”在现场就没人回答）。
func TestNoteUncleanExitWarnsWithinSameBoot(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	restore := sysBootTime
	sysBootTime = func() time.Time { return now }
	t.Cleanup(func() { sysBootTime = restore })

	writeRuntimeDoc(t, RuntimeDoc{
		PID:       999999,
		Running:   true,
		StartedAt: now.Add(-time.Minute).Format(time.RFC3339),
		BootAt:    now.Format(time.RFC3339), // 同一次开机
	})
	bus := logbus.New(50)
	a := New(nil, bus)
	a.noteUncleanExit()
	if msg := warnAbout(bus, "未正常退出"); msg == "" {
		t.Error("同一次开机内进程消失应当报 WARN（这才是这条告警的意义）")
	}
}

// 老版本写的运行态没有 bootAt → 判不出来，不猜也不报。
func TestNoteUncleanExitSilentWhenBootAtMissing(t *testing.T) {
	writeRuntimeDoc(t, RuntimeDoc{PID: 999999, Running: true, StartedAt: time.Now().Format(time.RFC3339)})
	bus := logbus.New(50)
	a := New(nil, bus)
	a.noteUncleanExit()
	if msg := warnAbout(bus, "未正常退出"); msg != "" {
		t.Errorf("缺 bootAt 时不该硬报 WARN，实际：%s", msg)
	}
}

func writeRuntimeDoc(t *testing.T, doc RuntimeDoc) {
	t.Helper()
	dir := exeDir()
	if dir == "" {
		t.Fatal("exeDir 为空，没法造运行态文件")
	}
	path := filepath.Join(dir, RuntimeFile)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}

// warnAbout 环形缓冲里有没有含 substr 的 WARN 行（返回那行，便于报错时看清实际写了什么）。
func warnAbout(bus *logbus.Bus, substr string) string {
	for _, l := range bus.Snapshot() {
		if l.Level == "WARN" && strings.Contains(l.Text, substr) {
			return l.String()
		}
	}
	return ""
}

func infoAbout(bus *logbus.Bus, substr string) string {
	for _, l := range bus.Snapshot() {
		if l.Level == "INFO" && strings.Contains(l.Text, substr) {
			return l.String()
		}
	}
	return ""
}

// bootTime 取不到时（GetTickCount64 的 Call 失败会静默返回 0）算出来的就是“现在”，
// 那样跨开机会被误判成同一次开机 —— 又回到“正常关机也报 WARN”。
// 所以这条要钉住：必须是过去的时刻，而且同一开机内两次算出来一致（容差内）。
func TestBootTimeIsPastAndStable(t *testing.T) {
	b1 := bootTime()
	if d := time.Since(b1); d < 10*time.Second || d > 30*24*time.Hour {
		t.Fatalf("开机时刻算成了 %v 之前，不像真的开机时刻（GetTickCount64 没取到？）", d)
	}
	b2 := bootTime()
	if d := b2.Sub(b1); d > bootSkew || d < -bootSkew {
		t.Fatalf("同一开机内两次算出的开机时刻差 %v（容差 %v）—— 跨开机会判错", d, bootSkew)
	}
}
