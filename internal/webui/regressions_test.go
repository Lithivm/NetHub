package webui

import (
	"testing"

	"nethub/internal/gostbat"
	"nethub/internal/rules"
)

// 回归：模拟功能遇到 IPv6 网段不能 panic（以前 sampleCIDR 对 nil 的 To4() 直接崩）。
func TestSimulateIPv6SegmentDoesNotPanic(t *testing.T) {
	b, _ := newRoutesBackend(t)
	b.a.Rules = rules.New()

	v := b.SimulateTargets("fe80::/10\n::1/128\n2001:db8::/32\n10.0.0.0/24")
	byInput := map[string]SimRow{}
	for _, r := range v.Rows {
		byInput[r.Input] = r
	}
	for _, in := range []string{"fe80::/10", "::1/128", "2001:db8::/32"} {
		r, ok := byInput[in]
		if !ok {
			t.Fatalf("没模拟 %s: %+v", in, v.Rows)
		}
		if r.Err == "" {
			t.Errorf("%s 应报“只支持 IPv4”，得到 OK=%v action=%q", in, r.OK, r.Action)
		}
	}
	if r := byInput["10.0.0.0/24"]; r.Err != "" {
		t.Errorf("IPv4 网段不该报错: %v", r.Err)
	}
}

// 回归：「从 .bat 导入」更新同名链时必须整体替换上游，否则新上游被旧的 Forwards 盖住，
// 界面却报“已更新”。
func TestApplyBatEntriesReplacesExistingUpstreams(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	idx := cfg.FindChain("proxy-a")
	if idx < 0 {
		t.Fatal("测试基座里应有 proxy-a 链")
	}
	// 造出“这条链已经有多上游”的现场
	cfg.Chains[idx].Forwards = []string{"socks5://old1:1080", "socks5://old2:1080"}
	cfg.Chains[idx].Forward = ""

	res, err := b.applyBatEntries([]gostbat.BatEntry{
		{File: "gost-proxy-a.bat", Forward: "socks5://new:1080"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 {
		t.Fatalf("不应有跳过项: %v", res.Skipped)
	}
	got := cfg.Chains[idx].Upstreams()
	if len(got) != 1 || got[0] != "socks5://new:1080" {
		t.Fatalf("上游没被替换：%v（旧值盖住了新值？）", got)
	}
}
