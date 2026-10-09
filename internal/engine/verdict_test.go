package engine

import (
	"strings"
	"testing"
)

// ⚠ 这条测试定义的是"打开诊断页看到红/黄/绿意味着什么"。
//
// 与 statusWarnings 同一个道理（见 runtime_test.go）：判据不能靠记，也不能靠现场猜 ——
// 改判定必须改这里，否则"绿着但其实不通"这种事故会再次发生。
func TestChainVerdict(t *testing.T) {
	up := func(ok, known, authRejected bool) UpHealthView {
		u := UpHealthView{URL: "socks5+tls://up:1080", Known: known, OK: ok, AuthRejected: authRejected}
		if !ok && known {
			u.Error = "socks 认证被拒（用户名或口令不对）"
			if !authRejected {
				u.Error = "连不上 1.2.3.4:1080"
			}
		}
		return u
	}
	chain := func(name string, ups ...UpHealthView) ChainHealthView {
		return ChainHealthView{Name: name, Strategy: "failover", Probe: "30s", Upstreams: ups}
	}
	tgt := func(target, chainName string, ok bool) TargetHealthView {
		t := TargetHealthView{Target: target, Chain: chainName, OK: ok, Checked: "10:00:00"}
		if !ok {
			t.Error = "i/o timeout"
		}
		return t
	}

	cases := []struct {
		name        string
		running     bool
		chains      []ChainHealthView
		targets     []TargetHealthView
		wantLevel   string
		wantHead    string // 子串
		wantAdvice  string // 建议里要出现的子串（"" = 不查）
		wantDetail  string // 逐条里要出现的子串
		notWantHead string
	}{
		{
			name:      "引擎没在跑：明说这些数字是上一轮的",
			chains:    []ChainHealthView{chain("etyy", up(true, true, false))},
			targets:   []TargetHealthView{tgt("10.1.1.1:443", "etyy", true)},
			wantLevel: "warn", wantHead: "引擎没在跑", wantAdvice: "启动",
		},
		{
			name: "没配链", running: true, wantLevel: "warn", wantHead: "还没有配置链路",
		},
		{
			name: "还没探过", running: true, chains: []ChainHealthView{chain("etyy")},
			wantLevel: "warn", wantHead: "还没探过",
		},
		{
			name:    "全部连不上上游 → 红，且不要让人以为是本机毛病",
			running: true, chains: []ChainHealthView{chain("etyy", up(false, true, false))},
			wantLevel: "error", wantHead: "连不上上游", wantAdvice: "上游服务",
			wantDetail: "✗ 链 etyy",
		},
		{
			name:      "凭据被拒 → 红，且必须与「连不上」分开说",
			running:   true,
			chains:    []ChainHealthView{chain("sjy", up(false, true, true))},
			wantLevel: "error", wantHead: "拒绝", wantAdvice: "口令",
			wantDetail: "凭据被上游拒绝", notWantHead: "连不上上游",
		},
		{
			name:      "部分上游坏 → 黄（不是红：还有能用的）",
			running:   true,
			chains:    []ChainHealthView{chain("etyy", up(true, true, false), up(false, true, false))},
			wantLevel: "warn", wantHead: "1 个不可用",
		},
		{
			name:      "上游通、内网目标不通 → 红，且把责任指到上游那一侧",
			running:   true,
			chains:    []ChainHealthView{chain("etyy", up(true, true, false))},
			targets:   []TargetHealthView{tgt("10.1.1.1:6446", "etyy", false)},
			wantLevel: "error", wantHead: "内网业务目标连不通",
			wantAdvice: "上游管理员", wantDetail: "上游可用，但 1 个内网目标不可达",
		},
		{
			name:      "全都好 → 绿",
			running:   true,
			chains:    []ChainHealthView{chain("etyy", up(true, true, false))},
			targets:   []TargetHealthView{tgt("10.1.1.1:6446", "etyy", true)},
			wantLevel: "ok", wantHead: "实测都通", wantDetail: "✓ 链 etyy",
		},
		{
			name:      "上游都通、但没有可实测的目标 → 黄（别谎报绿）",
			running:   true,
			chains:    []ChainHealthView{chain("etyy", up(true, true, false))},
			wantLevel: "warn", wantHead: "上游实测都可用", wantAdvice: "hosts",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ChainVerdict(c.running, c.chains, c.targets)
			if got.Level != c.wantLevel {
				t.Errorf("level = %q，期望 %q（head=%q）", got.Level, c.wantLevel, got.Head)
			}
			if !strings.Contains(got.Head, c.wantHead) {
				t.Errorf("head = %q，应当包含 %q", got.Head, c.wantHead)
			}
			if c.notWantHead != "" && strings.Contains(got.Head, c.notWantHead) {
				t.Errorf("head = %q，不该包含 %q（凭据被拒与连不上必须分开）", got.Head, c.notWantHead)
			}
			if c.wantAdvice != "" && !containsAny(got.Advice, c.wantAdvice) {
				t.Errorf("建议里应当出现 %q，实际 %v", c.wantAdvice, got.Advice)
			}
			if c.wantDetail != "" && !containsAny(got.Detail, c.wantDetail) {
				t.Errorf("逐条里应当出现 %q，实际 %v", c.wantDetail, got.Detail)
			}
			// 给运维看的文案里不能出现 markdown 标记（界面上是纯文本，会原样显示出来）
			for _, s := range append([]string{got.Head, got.Sub}, append(got.Detail, got.Advice...)...) {
				if strings.Contains(s, "**") || strings.Contains(s, "`") || strings.Contains(s, "【") {
					t.Errorf("文案里不该有 markdown 标记：%q", s)
				}
			}
			// 红了/黄了就必须给一句"该做什么"，否则等于只报告不指路
			if got.Level != "ok" && len(got.Advice) == 0 {
				t.Errorf("level=%s 却没给建议", got.Level)
			}
		})
	}
}

// 逐条列表不静默截断：超过上限要明说"还有 N 条"。
func TestChainVerdictDetailNotSilentlyTruncated(t *testing.T) {
	var chains []ChainHealthView
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		chains = append(chains, ChainHealthView{Name: n,
			Upstreams: []UpHealthView{{URL: "socks5://u:1080", Known: true, OK: true}}})
	}
	v := ChainVerdict(true, chains, nil)
	if len(v.Detail) != verdictDetailMax+1 {
		t.Fatalf("应当列出 %d 条 + 一行说明，实际 %d 条：%v", verdictDetailMax, len(v.Detail), v.Detail)
	}
	last := v.Detail[len(v.Detail)-1]
	if !strings.Contains(last, "另有 2 条") {
		t.Fatalf("截断必须说明丢了几条，实际末行 %q", last)
	}
}

func containsAny(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
