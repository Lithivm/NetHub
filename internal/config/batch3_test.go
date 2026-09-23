package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 回归：无凭据导出必须真的无凭据 —— 连 upstream.Parse 不认的写法也要兜底抹掉
// userinfo 与 ?auth=，不能“解析失败就原样返回”。
func TestStripCredsRedactsUnparseable(t *testing.T) {
	raw := "未知协议://user:secret@1.2.3.4:1080?auth=YWJjZGVm&x=1"
	got := stripCreds(raw)
	if strings.Contains(got, "secret") {
		t.Fatalf("口令泄漏: %q", got)
	}
	if strings.Contains(got, "auth=") || strings.Contains(got, "YWJj") {
		t.Fatalf("auth 凭据泄漏: %q", got)
	}
	if !strings.Contains(got, "x=1") {
		t.Fatalf("非敏感参数不该丢: %q", got)
	}
	// 正常可解析的也照旧
	if got := stripCreds("socks5://u:p@1.2.3.4:1080"); got != "socks5://1.2.3.4:1080" {
		t.Fatalf("stripCreds 正常路径 = %q", got)
	}
}

// 回归：无凭据导出要清掉历史遗留的 secret: 引用（导出文件不带 secrets.dat，
// 留个悬空引用只会在目标机器上报“解不开”）。
func TestSaveAsRedactedDropsSecretRef(t *testing.T) {
	c := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "a", Forward: "socks5://1.2.3.4:1080", Secret: "chain-a"}},
	}
	out := filepath.Join(t.TempDir(), "redacted.yaml")
	if err := c.SaveAsRedacted(out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret:") {
		t.Fatalf("无凭据导出里残留 secret 引用:\n%s", raw)
	}
}

// 回归：SaveAs 在副本上摊平 secret，不能改动程序正在用的配置对象。
func TestSaveAsDoesNotMutateLiveConfig(t *testing.T) {
	c := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "a", Forward: "socks5://1.2.3.4:1080", Secret: "chain-a"}},
	}
	out := filepath.Join(t.TempDir(), "full.yaml")
	if err := c.SaveAs(out); err != nil {
		t.Fatal(err)
	}
	if c.Chains[0].Secret != "chain-a" {
		t.Fatalf("导出改动了正在用的配置：Secret=%q", c.Chains[0].Secret)
	}
}
