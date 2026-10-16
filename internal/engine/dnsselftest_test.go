package engine

import (
	"net"
	"strings"
	"testing"
	"time"

	"nethub/internal/logbus"
	"nethub/internal/rules"
)

// DNS 接管自检的判据：什么情况下才该刷那条“我们把别的名字弄坏了”的 ERROR。
//
// 为什么要专门钉住（2026-10-16 现场）：探针走的是**系统解析器**，所以
// “本机 DNS 整体不可用”与“我们把别的名字答坏了”在它眼里长得一模一样。
// 那天早上机器从睡眠唤醒（事件日志：08:58:57 唤醒、08:59:07 物理网卡才有地址），
// 自检在 08:58:58 就跑了，于是每早开机都可能刷一条假警报 —— 判据靠人自觉写不对，
// 必须有用例钉住。

// down 造一条“解不出来”的结果（真实现场就是 Windows 解析器的 no such host）。
func down(name string) dnsCanaryProbe {
	return dnsCanaryProbe{
		Name: name,
		Err:  &net.DNSError{Err: "no such host", Name: name, IsNotFound: true},
	}
}

// resolved 造一条“解出了真实 IP”的结果。
func resolved(name, ip string, answerable bool) dnsCanaryProbe {
	return dnsCanaryProbe{Name: name, IPs: []net.IP{net.ParseIP(ip)}, Answerable: answerable}
}

// fakeAnswered 造一条“被答成了我们的假 IP”的结果（198.19.0.0/16 是我们的假 IP 段）。
func fakeAnswered(name string, answerable bool) dnsCanaryProbe {
	return dnsCanaryProbe{Name: name, IPs: []net.IP{net.ParseIP("198.19.0.7")}, Fake: true, Answerable: answerable}
}

// 机器刚唤醒 / 现场网络不通：本机 DNS 整体解不出，且本轮我们一个应答都没发过
// → **不许报**“DNS 接管弄坏了别的名字”（这是 2026-10-16 早上那次误报的形状）。
func TestJudgeDNSProbe_EnvDownIsNotOurs(t *testing.T) {
	got, bad := judgeDNSProbe([]dnsCanaryProbe{down("www.baidu.com"), down("www.qq.com")}, false)
	if got != dnsProbeEnv {
		t.Fatalf("本机 DNS 整体不可用 + 本轮没注入过应答 ⇒ 该判 dnsProbeEnv，得到 %v", got)
	}
	if len(bad) != 2 {
		t.Fatalf("失败原因要两条都带上，得到 %v", bad)
	}
}

// 同一时刻如果本轮我们确实往网上发过应答 → 不能排除自己，照旧大声报。
func TestJudgeDNSProbe_InjectedCannotBeCleared(t *testing.T) {
	got, bad := judgeDNSProbe([]dnsCanaryProbe{down("www.baidu.com"), down("www.qq.com")}, true)
	if got != dnsProbeOurs {
		t.Fatalf("本轮注入过应答 ⇒ 不能排除自己，得到 %v", got)
	}
	if len(bad) != 2 {
		t.Fatalf("失败原因要两条都带上，得到 %v", bad)
	}
}

// 不相干的名字被答成我们的假 IP = 铁证（它本来不该被我们答）→ 立刻报，与注入计数无关。
func TestJudgeDNSProbe_FakeForUnrelatedNameIsOurs(t *testing.T) {
	got, _ := judgeDNSProbe([]dnsCanaryProbe{
		fakeAnswered("www.baidu.com", false),
		resolved("www.qq.com", "183.3.226.35", false),
	}, false)
	if got != dnsProbeOurs {
		t.Fatalf("不相干名字被答成假 IP ⇒ 该报，得到 %v", got)
	}
}

// canary 自己命中了通配规则（用户把 *.com 写进去了）：被答成假 IP 是**预期行为**，
// 不是故障 —— 这时该名字已经不再是“不相干名字”，自检在它身上没有主张。
func TestJudgeDNSProbe_AnswerableNameIsNotAFailure(t *testing.T) {
	got, bad := judgeDNSProbe([]dnsCanaryProbe{fakeAnswered("www.baidu.com", true)}, false)
	if got != dnsProbeOK || len(bad) != 0 {
		t.Fatalf("命中通配规则的名字被答成假 IP 是预期行为，得到 %v / %v", got, bad)
	}
}

// 解得出真实 IP = 照常（自检通过，normal 档一行都不写）。
func TestJudgeDNSProbe_RealIPIsOK(t *testing.T) {
	got, bad := judgeDNSProbe([]dnsCanaryProbe{
		resolved("www.baidu.com", "39.156.66.10", false),
		resolved("www.qq.com", "183.3.226.35", false),
	}, false)
	if got != dnsProbeOK || len(bad) != 0 {
		t.Fatalf("解出真实 IP 就该通过，得到 %v / %v", got, bad)
	}
}

// 复测（② 防抖）：第一轮全失败、20 秒后复测通过 → 只写 verbose，不报 ERROR。
// 这正是“唤醒那几秒”的形状：先解不出，等它起来就都好了。
func TestDNSProbeRetryRecoversQuietly(t *testing.T) {
	first := []dnsCanaryProbe{down("www.baidu.com"), down("www.qq.com")}
	if dnsProbeAnyOK(first) {
		t.Fatal("前提：第一轮全失败")
	}
	second := []dnsCanaryProbe{
		resolved("www.baidu.com", "39.156.66.10", false),
		resolved("www.qq.com", "183.3.226.35", false),
	}
	if !dnsProbeAnyOK(second) {
		t.Fatal("复测通过 ⇒ 本轮按通过处理")
	}
	if got, _ := judgeDNSProbe(second, false); got != dnsProbeOK {
		t.Fatalf("复测通过就该判 OK，得到 %v", got)
	}
}

// 至少一个照常就算通过（与改动前的口径一致，别顺手把语义改了）。
func TestDNSProbeAnyOK(t *testing.T) {
	if dnsProbeAnyOK([]dnsCanaryProbe{down("www.baidu.com"), resolved("www.qq.com", "1.2.3.4", false)}) != true {
		t.Error("一个通过就该算通过")
	}
	if dnsProbeAnyOK([]dnsCanaryProbe{down("www.baidu.com"), down("www.qq.com")}) {
		t.Error("全失败不能算通过")
	}
}

// 解名路径：把“这条路会被我们答”的标志与假 IP 判据算对（判据纯函数靠这两个字段）。
func TestProbeDNSCanaries(t *testing.T) {
	lookup := func(name string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.19.0.7")}, nil }
	isFake := func(ip net.IP) bool { return ip.Equal(net.ParseIP("198.19.0.7")) }
	// 第二条 canary 当成“命中通配规则”的
	answerable := func(name string) bool { return name == dnsCanaries[1] }

	got := probeDNSCanaries(lookup, isFake, answerable)
	if len(got) != len(dnsCanaries) {
		t.Fatalf("每个 canary 都要有一条结果，得到 %d 条", len(got))
	}
	if !got[0].Fake || got[0].ok() {
		t.Errorf("不相干名字拿到假 IP ⇒ 既不 ok 也要标出 Fake：%+v", got[0])
	}
	if !got[1].Fake || !got[1].ok() {
		t.Errorf("命中通配规则的名字拿到假 IP ⇒ 算照常：%+v", got[1])
	}
}

// C：本机网络刚变化过的静默期判据。
func TestNetChangedWithin(t *testing.T) {
	e := &Engine{}
	if e.netChangedWithin(dnsSelfCheckQuiet) {
		t.Error("没记过任何变化时不该判“刚变过”（引擎启动后的首次采样也不算）")
	}
	e.netChangedAt.Store(time.Now().UnixNano())
	if !e.netChangedWithin(dnsSelfCheckQuiet) {
		t.Error("刚记下变化 ⇒ 静默期内应判真")
	}
	e.netChangedAt.Store(time.Now().Add(-time.Minute).UnixNano())
	if e.netChangedWithin(dnsSelfCheckQuiet) {
		t.Error("一分钟前变的 ⇒ 不该再静默（那时网络早该稳了）")
	}
}

// 接线用例：判据再对，调用点没接上也一样没用 —— 这条**真跑一次自检**，钉两件事：
//
//	normal 档一行都不写（自检通过、或“本机 DNS 此刻不可用”都属此列）
//	verbose 档必须留下说明（否则“早上那一下到底怎么了”事后无从查起）
//
// 本机 DNS 通不通不影响结论：两种情况下都不许在 normal 档写。
func TestDNSSelfCheckLogTier(t *testing.T) {
	e := newTestEngine()
	e.rules.Store(rules.New())
	e.dnsRetry = time.Millisecond // 别真等 20 秒

	n := len(e.bus.Snapshot())
	e.dnsTakeoverSelfCheck()
	if got := newLines(e.bus, n); got != "" {
		t.Fatalf("normal 档不该写 dns.selftest（无论通过还是环境原因）：%q", got)
	}

	e.bus.SetLevel(logbus.LevelVerbose)
	n = len(e.bus.Snapshot())
	e.dnsTakeoverSelfCheck()
	if got := newLines(e.bus, n); !strings.Contains(got, "dns.selftest") {
		t.Errorf("verbose 档必须留下说明（通过 / 复测通过 / 环境原因 / 该报的那两条），得到：%q", got)
	}
}
