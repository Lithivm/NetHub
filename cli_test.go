package main

import (
	"os"
	"path/filepath"
	"testing"
)

// cmdApply 的源文件不存在时：必须报错退出，且**一个字节都不许写目标配置**。
//
// 回归的是 2026-10-14 那次真实事故：`-apply -apply-force <file>` 在 Go 的 flag 里
// 会被解析成 `-apply="-apply-force"`（字符串 flag 会吃掉下一个参数）——
// 那个路径不存在，config.Load 于是静静地造了一份默认配置并返回，
// cmdApply 把这份“默认”写进了真正的目标配置：5 条链 / 7 条规则被打成
// 1 条示例链 proxy-a、0 条规则（用户的现场配置就这么没了，靠备份救回来）。
func TestCmdApplyRefusesMissingSource(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	good := []byte("relay: 127.0.0.1:0\nchains:\n    - name: keepme\n      forward: socks5://127.0.0.1:1080\n")
	if err := os.WriteFile(target, good, 0o600); err != nil {
		t.Fatal(err)
	}

	if code := cmdApply(filepath.Join(dir, "typo.yaml"), target, true); code != 1 {
		t.Fatalf("源文件不存在应返回 1，得到 %d", code)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(good) {
		t.Fatalf("目标配置被改动了！\n原: %q\n今: %q", good, got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("不该在目录里造出多余文件（只有一个 target.yaml 才对）：%v", entries)
	}
}
