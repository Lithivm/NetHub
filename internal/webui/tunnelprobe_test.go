package webui

import (
	"strings"
	"testing"
	"time"

	"nethub/internal/app"
	"nethub/internal/config"
	"nethub/internal/logbus"
)

// 体检报告里必须有**隧道探测**这一段（用户明确要求：开机自检要带上隧道）。
//
// 这条测试只验“组装与排版”（不真的去探测外网）：直接塞一份自检结果进去，
// 看体检报告有没有把每条链的结论带出来、有没有把“跳过”与“失败”区分开。
func TestPrecheckIncludesTunnelProbe(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/config.yaml"
	cfg := config.Default()
	cfg.Relay = "127.0.0.1:0"
	cfg.Chains = []config.Chain{
		{Name: "ok-chain", Forward: "socks5://127.0.0.1:1080"},
		{Name: "skipped", Forward: "socks5://127.0.0.1:1081"},
		{Name: "bad-chain", Forward: "socks5://127.0.0.1:1082"},
	}
	cfg.Routes = nil
	if err := cfg.SaveAs(cfgPath); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a := app.New(loaded, logbus.New(100))
	b := New(a)

	// 假装刚跑过一轮自检：三种结局各一条
	b.selfTestMu.Lock()
	b.selfTestLast = SelfTestReport{
		At: "12:34:56", Total: 3, Bad: 1,
		Chains: []SelfTestChain{
			{Name: "ok-chain", OK: true, Detail: []string{"端到端可达：→ 10.1.1.5:443（最近真的访问过）"}},
			{Name: "skipped", OK: true, Detail: []string{"跳过：这条链的网段里还没有可探的真实主机", "代理段本身正常，只是没东西可探。"}},
			{Name: "bad-chain", OK: false, Detail: []string{"上游认证失败", "socks 认证被拒（用户名或口令不对）"}},
		},
	}
	b.selfTestAt = time.Now()
	b.selfTestMu.Unlock()

	lines := b.tunnelProbeLines()
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		"隧道探测",
		"✓ 隧道 ok-chain：端到端可达",
		"⚠ 隧道 skipped：跳过",       // 跳过是“不知道”，不是“失败”
		"✗ 隧道 bad-chain：上游认证失败", // 失败要带原始报错
		"socks 认证被拒",
		"1/3 条链的隧道探测没通过",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("体检报告里少了 %q\n---\n%s", want, joined)
		}
	}

	// 新鲜的自检结果不该被重复探测：拿两次结果必须一模一样（且不触发网络）
	again := b.tunnelProbeLines()
	if strings.Join(again, "\n") != joined {
		t.Errorf("重复取体检报告结果不一致:\n%s\n---\n%s", joined, strings.Join(again, "\n"))
	}
}

// 没有自检结果、也没有链时：给一句人话，而不是空着。
func TestTunnelProbeLinesWithoutChains(t *testing.T) {
	cfg := config.Default()
	cfg.Chains = nil // Default 里带着一条空示例链，这里要的是“真的没有链”
	cfg.Routes = nil
	b := New(app.New(cfg, logbus.New(50)))
	lines := b.tunnelProbeLines()
	if len(lines) == 0 || !strings.Contains(lines[0], "没有可探测的链") {
		t.Errorf("没有链时应给出说明: %v", lines)
	}
}
