package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nethub/internal/config"
)

// 导入配置：非法文件必须"什么都不改"（先校验后落盘）。
func TestImportConfigRejectsBadFile(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	path := cfg.Path()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 造一个"看起来像配置但链没有上游"的文件 → 校验必须拦住
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("relay: 127.0.0.1:0\nchains:\n  - name: x\nroutes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.importConfigFrom(bad); err == nil {
		t.Fatal("非法配置应该被拒绝")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("校验不过时不该动现有配置文件")
	}
}

// 导入配置：合法文件要真的生效，并且当前配置被自动备份（能回滚）。
func TestImportConfigApplies(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	good := filepath.Join(t.TempDir(), "good.yaml")
	body := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-z\n    forward: socks5://127.0.0.1:1080\n" +
		"routes:\n  - name: 导入的规则\n    targets: [10.9.0.0/16]\n    chain: proxy-z\n"
	if err := os.WriteFile(good, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.importConfigFrom(good); err != nil {
		t.Fatalf("合法配置应导入成功：%v", err)
	}
	if len(cfg.Chains) != 1 || cfg.Chains[0].Name != "proxy-z" {
		t.Errorf("导入后内存里的配置没换：%+v", cfg.Chains)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Name != "导入的规则" {
		t.Errorf("导入后规则没换：%+v", cfg.Routes)
	}
	// 自动备份：backups 目录里应至少有一份
	if bs := cfg.Backups(); len(bs) == 0 {
		t.Error("导入前应自动备份当前配置（可回滚）")
	}
	// 磁盘上的文件也是新的
	raw, _ := os.ReadFile(cfg.Path())
	if !strings.Contains(string(raw), "proxy-z") {
		t.Error("导入的配置没写进磁盘")
	}
}

// 无凭据导出：剔除口令，但仍是可导入的合法配置。
func TestSaveAsRedactedIsImportable(t *testing.T) {
	// 走真实路径：磁盘上写一份带凭据的配置 → 载入 → 无凭据导出
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")
	body := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-a\n    forward: socks5+tls://user:pw@10.0.0.9:10080\n" +
		"routes: []\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "redacted.yaml")
	if err := cfg.SaveAsRedacted(out); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	if strings.Contains(string(raw), "pw@") || strings.Contains(string(raw), "auth=") {
		t.Errorf("无凭据版不该含口令或 auth 参数：\n%s", raw)
	}
	red, err := config.Load(out)
	if err != nil {
		t.Fatalf("无凭据版必须仍能被载入（能导入）：%v", err)
	}
	if err := red.Validate(); err != nil {
		t.Errorf("无凭据版应通过校验：%v", err)
	}
	ups := red.Chains[0].Upstreams()
	if len(ups) != 1 {
		t.Fatalf("无凭据版应保留一条上游：%v", ups)
	}
	if ups[0] != "socks5+tls://10.0.0.9:10080" {
		t.Errorf("剔除凭据后应保留协议与地址，得到 %q", ups[0])
	}
}
