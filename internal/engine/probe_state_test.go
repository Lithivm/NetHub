package engine

import (
	"net"
	"testing"
	"time"

	"nethub/internal/config"
)

// 「探测中」必须是一个界面读得到的状态：它和「待探测」在没有观测时长得一模一样，
// 而用户要回答的问题是"到底该等还是该点一下"（2026-10-09 用户反馈）。
func TestProbingState(t *testing.T) {
	e := newTestEngine()
	e.cfg = &config.Config{Chains: []config.Chain{
		{Name: "etyy", Forward: "socks5://127.0.0.1:1080", Probe: "30s"},
	}}

	if e.ProbingChains() != 0 {
		t.Fatal("刚建好的引擎不该有探测在跑")
	}
	if h := e.ChainHealth(); len(h) != 1 || h[0].Probing {
		t.Fatalf("没在探时不该说在探：%+v", h)
	}

	e.markProbing("etyy", true)
	if h := e.ChainHealth(); !h[0].Probing {
		t.Error("探测在飞时，界面必须能看到")
	}
	if e.ProbingChains() != 1 {
		t.Errorf("在探的链数 = %d，期望 1", e.ProbingChains())
	}

	// 计数可重入：定时探测与手动探测会叠在同一条链上（一轮按链顺序做，可能几十秒）
	e.markProbing("etyy", true)
	e.markProbing("etyy", false)
	if !e.ChainHealth()[0].Probing {
		t.Error("两层叠加时，结束一层不该认为探完了")
	}
	e.markProbing("etyy", false)
	if e.ChainHealth()[0].Probing {
		t.Error("两层都结束后应清掉")
	}

	// 整轮（点「立即探测」）：后端在返回前同步标上 —— 一轮按链顺序做，
	// 还没轮到的那条链也算"探测中/排队中"（界面只需回答"现在是不是在探"）
	e.StartProbeRound()
	if !e.ChainHealth()[0].Probing {
		t.Error("整轮在跑时，每条链都该显示在探")
	}
	if e.ProbingChains() != 1 {
		t.Errorf("整轮在跑时，在探的链数 = %d，期望 1（=链总数）", e.ProbingChains())
	}
	e.EndProbeRound()
	if e.ChainHealth()[0].Probing {
		t.Error("整轮结束后应清掉")
	}
}

// 探测在飞 → 界面看得见；探完（无论成败）→ 必须清掉。
//
// 后半句是这条测试真正的价值：状态一旦漏清，界面就永远停在"探测中"，
// 那比原来的"待探测"更糟（用户会一直等一个不会来的结果）。
func TestProbingVisibleWhileInFlight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// 只接受、不应答：探测会卡在协商上 —— 这就是"在飞"的窗口。
	// 由测试决定什么时候放它走（不然要等 6 秒超时）。
	release := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			<-release
			c.Close()
		}
	}()

	e := newTestEngine()
	ch := config.Chain{Name: "etyy", Forward: "socks5://" + ln.Addr().String(), Probe: "30s"}
	e.cfg = &config.Config{Chains: []config.Chain{ch}}

	done := make(chan struct{})
	go func() { e.probeChain(ch); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for e.ProbingChains() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("探测已经开始了，界面却看不到「探测中」")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h := e.ChainHealth(); !h[0].Probing {
		t.Errorf("探测在飞时，ChainHealth 应标 Probing：%+v", h[0])
	}

	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("探测没结束")
	}
	if e.ProbingChains() != 0 {
		t.Errorf("探完必须清掉「探测中」，否则界面永远等一个不会来的结果（remaining=%d）", e.ProbingChains())
	}
}
