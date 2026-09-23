package app

import (
	"os"
	"path/filepath"
	"testing"

	"nethub/internal/config"
	"nethub/internal/logbus"
)

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

	if err := a.SaveConfig(); err == nil {
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

	if err := a.SaveConfig(); err != nil {
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
