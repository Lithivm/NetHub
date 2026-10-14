package config

import (
	"os"
	"path/filepath"
	"testing"
)

// LoadExisting 对不存在的路径必须**报错**且**什么都不建**。
//
// 这条钉的是一个真实的丢配置事故（2026-10-14）：`-apply -apply-force <file>` 被 Go 的
// flag 解析成 `-apply="-apply-force"`（字符串 flag 吃掉下一个参数），那个路径不存在 →
// Load 静静地造了一份默认配置 → cmdApply 把这份“默认”写进了真正的目标配置：
// 用户的 5 条链 / 7 条规则变成 1 条示例链 proxy-a、0 条规则。
func TestLoadExistingRefusesMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.yaml")
	if _, err := LoadExisting(missing); err == nil {
		t.Fatal("文件不存在时应当报错")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("LoadExisting 不该创建任何文件，但 %s 出现了（stat err=%v）", missing, err)
	}

	// 存在时照常读（并且和 Load 一样会做 Normalize/Validate）
	real := filepath.Join(dir, "real.yaml")
	os.WriteFile(real, []byte("relay: 127.0.0.1:0\nchains:\n    - name: a\n      forward: socks5://127.0.0.1:1080\n"), 0o600)
	cfg, err := LoadExisting(real)
	if err != nil {
		t.Fatalf("已存在的配置应能载入: %v", err)
	}
	if len(cfg.Chains) != 1 || cfg.Chains[0].Name != "a" {
		t.Fatalf("载入的配置不对: %+v", cfg.Chains)
	}
}
