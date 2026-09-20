package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A18：保存后配置文件里不能出现明文口令，但运行时（还原后）口令必须还能用。
func TestSealCredentialsOnSave(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: 主链路\n    forward: socks5+tls://user:SuperSecret@10.0.0.9:10080\n" +
		"routes: []\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "SuperSecret") {
		t.Fatalf("保存后配置里还有明文口令：\n%s", raw)
	}
	if !strings.Contains(string(raw), "secret: chain-主链路") {
		t.Errorf("应写入 secret: 引用：\n%s", raw)
	}
	// secrets.dat 存在且不含明文
	sraw, err := os.ReadFile(filepath.Join(dir, "secrets.dat"))
	if err != nil {
		t.Fatalf("保险箱没落盘：%v", err)
	}
	if strings.Contains(string(sraw), "SuperSecret") {
		t.Error("secrets.dat 里出现了明文口令")
	}

	// 重新载入并还原：口令要能取回来（拨号/探测都靠这个）
	cfg2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	ups := cfg2.UpstreamsResolved(cfg2.Chains[0])
	if len(ups) != 1 {
		t.Fatalf("上游数不对：%v", ups)
	}
	if !strings.Contains(ups[0], "SuperSecret") || !strings.HasPrefix(ups[0], "socks5+tls://") {
		t.Errorf("还原后的上游应带凭据：%q", ups[0])
	}

	// 再存一次不能把口令又写回文件（幂等）
	if err := cfg2.Save(); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(p)
	if strings.Contains(string(raw2), "SuperSecret") {
		t.Error("第二次保存又把明文口令写回去了")
	}
}

// 导出（给人拿去新机器导入）必须带明文口令，否则新机器连不上。
func TestExportPlainRestoresCredentials(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: c\n    forward: socks5://bob:hunter2@10.0.0.9:1080\n" +
		"routes: []\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "export.yaml")
	if err := cfg.ExportPlain(out); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	if !strings.Contains(string(raw), "hunter2") {
		t.Errorf("导出的配置应含明文口令（否则新机器用不了）：\n%s", raw)
	}
	if strings.Contains(string(raw), "secret:") {
		t.Error("导出的配置不该留 secret 引用")
	}
	// 导出的文件必须能直接载入并使用
	red, err := Load(out)
	if err != nil {
		t.Fatalf("导出的配置载入失败：%v", err)
	}
	if ups := red.UpstreamsResolved(red.Chains[0]); len(ups) != 1 || !strings.Contains(ups[0], "hunter2") {
		t.Errorf("导出的配置还原后不带口令：%v", ups)
	}
}

// 关掉加密（secrets_encrypted: false）时应保持老行为：明文留在配置里。
func TestSealDisabledKeepsPlaintext(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := "relay: 127.0.0.1:0\n" +
		"tuning:\n  secrets_encrypted: false\n" +
		"chains:\n  - name: c\n    forward: socks5://user:pw@10.0.0.9:1080\n" +
		"routes: []\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SealEnabled() {
		t.Fatal("显式写了 false 就该是关")
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "pw@") {
		t.Errorf("关掉加密后应保持明文：\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets.dat")); !os.IsNotExist(err) {
		t.Error("关掉加密后不该生成 secrets.dat")
	}
}
