package engine

import (
	"strings"
	"testing"
	"time"

	"nethub/internal/config"
	"nethub/internal/logbus"
)

func eqInts(a, b []int) bool {
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

// 候选顺序：可用的在前、已知坏的垫后，全坏也照样全给（宁可试一次）。
func TestCandidates(t *testing.T) {
	e := newTestEngine()
	ch := config.Chain{Name: "c", Forwards: []string{
		"socks5://127.0.0.1:1", "socks5://127.0.0.1:2", "socks5://127.0.0.1:3"}}

	// 都没探过：按配置顺序，不能因为"没探过"就不敢用
	if got := e.candidates(ch); !eqInts(got, []int{0, 1, 2}) {
		t.Errorf("未探测时应按配置顺序: %v", got)
	}

	// 0 号坏了 → 挪到最后
	hs := e.healthOf(ch)
	hs[0].ok, hs[0].checked = false, time.Now()
	if got := e.candidates(ch); !eqInts(got, []int{1, 2, 0}) {
		t.Errorf("坏上游应垫后: %v", got)
	}

	// 全坏：仍然全部返回（可能已经恢复）
	for _, h := range hs {
		h.ok, h.checked = false, time.Now()
	}
	if got := e.candidates(ch); len(got) != 3 {
		t.Errorf("全坏时也要给全部候选: %v", got)
	}

	// 轮询：起点会轮转，天然均摊
	ch2 := config.Chain{Name: "r", Strategy: config.StrategyRound,
		Forwards: []string{"socks5://127.0.0.1:1", "socks5://127.0.0.1:2"}}
	if a, b := e.candidates(ch2)[0], e.candidates(ch2)[0]; a == b {
		t.Errorf("轮询应换起点: %v %v", a, b)
	}
	if got := e.candidates(ch2); !eqInts(got, []int{0, 1}) && !eqInts(got, []int{1, 0}) {
		t.Errorf("轮询应覆盖全部上游: %v", got)
	}

	// 用户改了上游列表：健康表重建，旧观测作废
	ch3 := config.Chain{Name: "c", Forwards: []string{"socks5://127.0.0.1:9"}}
	hs3 := e.healthOf(ch3)
	if len(hs3) != 1 || !hs3[0].checked.IsZero() {
		t.Error("上游列表变了应重建健康表（旧观测作废）")
	}
}

// 日志/界面里的上游必须遮蔽凭据。
func TestMaskUpstream(t *testing.T) {
	got := maskUpstream("socks5+tls://user:pass@10.0.0.1:10080")
	if strings.Contains(got, "user") || strings.Contains(got, "pass") {
		t.Errorf("凭据没遮蔽: %s", got)
	}
	if !strings.Contains(got, "10.0.0.1:10080") {
		t.Errorf("地址应保留: %s", got)
	}
}

// 探活必须往健康表里写 —— 哪怕界面一次都没调过 ChainHealth。
// （踩过：markUp 依赖懒初始化的表，表没建起来时观测被静默丢弃。）
func TestProbeChainRecords(t *testing.T) {
	e := newTestEngine()
	e.bus = logbus.New(50)
	ch := config.Chain{Name: "c", Forwards: []string{"socks5://127.0.0.1:1"}}
	e.cfg.Chains = []config.Chain{ch}
	e.probeChain(ch)
	hs := e.healthOf(ch)
	if len(hs) != 1 || hs[0].checked.IsZero() {
		t.Fatal("探活结果没记进健康表")
	}
	if hs[0].ok {
		t.Error("127.0.0.1:1 不该被判为可用")
	}

	// 界面看到的那份快照（据此画绿/红点）
	vs := e.ChainHealth()
	if len(vs) != 1 || vs[0].Name != "c" || len(vs[0].Upstreams) != 1 {
		t.Fatalf("ChainHealth 视图不对: %+v", vs)
	}
	u := vs[0].Upstreams[0]
	if !u.Known || u.OK || u.Checked == "" || u.Error == "" {
		t.Errorf("上游快照不对（应 known + 不可用 + 有错误信息）: %+v", u)
	}
	if !strings.Contains(u.URL, "127.0.0.1:1") {
		t.Errorf("URL 应保留地址: %s", u.URL)
	}

	// 同一状态重复上报不算"翻转"（只在变化时告警）；坏→好才算
	if flipped, _ := e.markUp("c", 0, false, 0, "仍然不通"); flipped {
		t.Error("同一状态重复上报不该算翻转")
	}
	if flipped, _ := e.markUp("c", 0, true, time.Millisecond, ""); !flipped {
		t.Error("状态从坏到好应算翻转")
	}
}
