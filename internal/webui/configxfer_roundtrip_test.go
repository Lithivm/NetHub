package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nethub/internal/app"
	"nethub/internal/config"
	"nethub/internal/logbus"
)

// 「导出（含凭据）→ 清空 → 重新导入」的完整回环。
//
// 为什么值得单独测：这里是**唯一**会把整份配置连口令一起搬家的路径
// （换机器靠它）。它一旦有损，现象是"导入成功但某条链悄悄没了口令"——
// 而那种故障在界面上只表现为"某条链认证失败"，极难往回追。
//
// 走的是**真实代码路径**：SaveAs（导出实际用的那个函数）+ importConfigFromRaw（导入实际用的那个）。
func TestConfigExportImportRoundTripWithCreds(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	// 一份"像真的"配置：两种凭据写法都覆盖（?auth= 与 user:pass@）、
	// 直连/阻断/多目标/端口/通配域名/hosts/tuning 全带上。
	src := `relay: 127.0.0.1:0
chains:
    - name: etyy
      forward: socks5+tls://etyy-user:p%40ss%3Aword@10.0.0.1:10080
      strategy: failover
      probe: 30s
    - name: snzyy
      forward: socks5+tls://10.0.0.2:10084?auth=SHQxN3FjVDBydEtRb2JHekVWUUcxV2t3a0xSUHlQQTZZS3FXVUg=
routes:
    - name: 内网 A 段
      targets:
        - 10.1.0.0/24
        - oapi.*.com
      ports:
        - "443"
        - 8000-8010
      chain: etyy
    - name: 更新端口直连
      targets:
        - 10.2.0.0/24
      ports:
        - "7680"
      chain: direct
    - name: 拉黑
      targets:
        - 10.3.0.0/24
      chain: block
patrol:
    interval: "off"
hosts:
    manage: true
    entries:
        - 10.1.0.9 main.his.com
tuning:
    dial_timeout: 7s
    warm_sessions: "3"
`
	if err := os.WriteFile(cfgPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("原始配置就载入失败: %v", err)
	}
	a := app.New(loaded, logbus.New(100))
	b := New(a)

	// ① 导出（含凭据）：走 SaveAs —— 与界面「导出配置（含口令）」同一函数
	exportPath := filepath.Join(dir, "nethub-config.yaml")
	if err := a.Cfg.SaveAs(exportPath); err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	exported, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	// 凭据必须在里面 —— 否则"含凭据导出"是假的
	for _, want := range []string{"p%40ss%3Aword", "SHQxN3FjVDBydEtRb2JHekVWUUcxV2t3a0xSUHlQQTZZS3FXVUg="} {
		if !strings.Contains(string(exported), want) {
			t.Errorf("导出的配置里少了凭据 %q\n%s", want, exported)
		}
	}

	// ② 清空现场：删掉配置文件（模拟新机器/重置），再按程序启动的那条路重新载入
	// （config.Load 发现文件不在会写出一份默认配置 —— 这就是“清空”后的真实状态）
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	empty, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("清空后重新载入失败: %v", err)
	}
	a.Cfg.ReplaceFrom(empty)
	if a.Cfg.ChainCount() != 1 || a.Cfg.ChainsSnapshot()[0].Name != "proxy-a" {
		t.Fatalf("清空后不是默认配置: %+v", a.Cfg.ChainsSnapshot())
	}

	// ③ 导入（走真实导入路径）
	if _, err := b.importConfigFromRaw(exportPath, exported); err != nil {
		t.Fatalf("导入失败: %v", err)
	}

	// ④ 逐字段比对：内存里的 + 磁盘上的，都必须和导出前一致
	got, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("导入后磁盘上的配置载入失败: %v", err)
	}
	assertSameConfig(t, "导入后(磁盘)", loaded, got)
	assertSameConfig(t, "导入后(内存)", loaded, a.Cfg)

	// 凭据再验一次（内存里的上游串）
	if fwd := a.Cfg.Chains[0].Forward; !strings.Contains(fwd, "p%40ss%3Aword") {
		t.Errorf("导入后内存里的口令丢了: %q", fwd)
	}
}

// assertSameConfig 比对两份配置的关键字段（不直接比结构体：里面还有缓存字段/绝对路径）。
func assertSameConfig(t *testing.T, who string, want, got *config.Config) {
	t.Helper()
	if len(want.Chains) != len(got.Chains) {
		t.Fatalf("%s: 链数量 %d ≠ %d", who, len(got.Chains), len(want.Chains))
	}
	for i := range want.Chains {
		if want.Chains[i].Name != got.Chains[i].Name || want.Chains[i].Forward != got.Chains[i].Forward {
			t.Errorf("%s: 第 %d 条链变了\n愿望: %+v\n实际: %+v", who, i, want.Chains[i], got.Chains[i])
		}
	}
	if len(want.Routes) != len(got.Routes) {
		t.Fatalf("%s: 规则数量 %d ≠ %d", who, len(got.Routes), len(want.Routes))
	}
	for i := range want.Routes {
		w, g := want.Routes[i], got.Routes[i]
		if w.Name != g.Name || w.Chain != g.Chain || !sameStrings(w.Targets, g.Targets) ||
			!sameStrings(w.Ports, g.Ports) || w.IsEnabled() != g.IsEnabled() {
			t.Errorf("%s: 第 %d 条规则变了\n愿望: %+v\n实际: %+v", who, i, w, g)
		}
	}
	if want.Hosts.Manage != got.Hosts.Manage || !sameStrings(want.Hosts.Entries, got.Hosts.Entries) {
		t.Errorf("%s: hosts 变了\n愿望: %+v\n实际: %+v", who, want.Hosts, got.Hosts)
	}
	if want.Patrol.Interval != got.Patrol.Interval {
		t.Errorf("%s: 巡检间隔 %q ≠ %q", who, got.Patrol.Interval, want.Patrol.Interval)
	}
	if want.DialTimeoutDur() != got.DialTimeoutDur() || want.WarmTarget() != got.WarmTarget() {
		t.Errorf("%s: tuning 变了: timeout %v/%v warm %q/%q",
			who, got.DialTimeoutDur(), want.DialTimeoutDur(), got.WarmTarget(), want.WarmTarget())
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// 导入一份**坏的**配置：必须原样报错，且**不许碰**现有配置（安全属性）。
func TestImportBadConfigLeavesCurrentUntouched(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	good := `relay: 127.0.0.1:0
chains:
    - name: keep-me
      forward: socks5+tls://10.0.0.1:10080?auth=dTpw
`
	if err := os.WriteFile(cfgPath, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a := app.New(loaded, logbus.New(100))
	b := New(a)

	// 重复键：以前这种配置会让程序**静默起不来**
	bad := []byte("relay: 127.0.0.1:0\nchains:\n    - name: x\n      forward: socks5://1.2.3.4:1080\ntuning:\n    dial_timeout: 5s\n    dial_timeout: 6s\n")
	if _, err := b.importConfigFromRaw("bad.yaml", bad); err == nil {
		t.Fatal("坏配置竟然导入成功了 —— 校验形同虚设")
	}
	// 现场必须没动
	if a.Cfg.Chains[0].Name != "keep-me" {
		t.Errorf("坏配置导入后现有配置被改了: %+v", a.Cfg.Chains)
	}
	onDisk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != good {
		t.Errorf("坏配置导入后磁盘上的文件被改了:\n%s", onDisk)
	}
}

// 无凭据导出必须**仍然可导入**（发给人看 / 存仓库的那种）。
func TestExportRedactedStillImportable(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	src := `relay: 127.0.0.1:0
chains:
    - name: a
      forward: socks5+tls://user:secret@10.0.0.1:10080
routes:
    - name: r
      targets:
        - 10.9.0.0/24
      chain: a
`
	if err := os.WriteFile(cfgPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a := app.New(loaded, logbus.New(100))
	b := New(a)

	// 导出无凭据：走界面按钮用的那个函数 SaveAsRedacted
	redPath := filepath.Join(dir, "redacted.yaml")
	if err := a.Cfg.SaveAsRedacted(redPath); err != nil {
		t.Fatalf("无凭据导出失败: %v", err)
	}
	red, err := os.ReadFile(redPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(red), "secret") {
		t.Errorf("无凭据导出里还有口令:\n%s", red)
	}
	if _, err := b.importConfigFromRaw("redacted.yaml", red); err != nil {
		t.Fatalf("无凭据导出不能导入（这正是它存在的意义）: %v", err)
	}
	if len(a.Cfg.Chains) != 1 || a.Cfg.Chains[0].Name != "a" {
		t.Errorf("无凭据导入后链路不对: %+v", a.Cfg.Chains)
	}
}
