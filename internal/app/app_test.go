package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nethub/internal/config"
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
		"hosts:\n  manage: true\n  entries:\n    - 10.0.0.1 a.his.com\n    - 10.0.0.2 b.his.com\n"
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
	if _, err := hostsmgr.Apply([]string{"10.0.0.1 a.his.com"}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	seed := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n" +
		"routes: []\n" +
		"hosts:\n  manage: false\n  entries:\n    - 10.0.0.1 a.his.com\n"
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
