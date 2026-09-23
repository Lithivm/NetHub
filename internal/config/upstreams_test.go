package config

import "testing"

// SetUpstreams 必须把旧的 Forwards 一起清掉：Chain.Upstreams() 优先返回 Forwards，
// 只写 Forward 会被旧值盖住 —— 「从 .bat 导入」曾经因此静默不生效。
func TestSetUpstreamsReplacesOldForwards(t *testing.T) {
	// 单上游：应落到 Forward，且 Forwards 清空
	ch := Chain{Name: "a", Forward: "socks5://old:1080"}
	ch.Forwards = []string{"socks5://old1:1080", "socks5://old2:1080"}
	ch.SetUpstreams([]string{"socks5://new:1080"})
	if got := ch.Upstreams(); len(got) != 1 || got[0] != "socks5://new:1080" {
		t.Fatalf("Upstreams = %v，期望只有新值", got)
	}
	if len(ch.Forwards) != 0 {
		t.Fatalf("Forwards 没清空: %v", ch.Forwards)
	}

	// 多上游：应落到 Forwards
	ch2 := Chain{Name: "b", Forward: "socks5://x:1080"}
	ch2.SetUpstreams([]string{"socks5://a1:1080", "socks5://a2:1080"})
	if got := ch2.Upstreams(); len(got) != 2 || got[0] != "socks5://a1:1080" || got[1] != "socks5://a2:1080" {
		t.Fatalf("Upstreams = %v", got)
	}
	if ch2.Forward != "" {
		t.Fatalf("单值 Forward 没清掉: %q", ch2.Forward)
	}

	// 空列表：两个都清空
	ch3 := Chain{Name: "c", Forward: "socks5://y:1080", Forwards: []string{"z"}}
	ch3.SetUpstreams(nil)
	if got := ch3.Upstreams(); len(got) != 0 {
		t.Fatalf("应当没有任何上游，得到 %v", got)
	}
}
