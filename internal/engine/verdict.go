package engine

import (
	"fmt"
	"strings"
)

// Verdict 一句话结论：现在这套链路到底能不能用。
//
// 为什么要专门做这一层：逐条链的探活数字（界面上的小圆点）回答的是"哪个上游通"，
// 回答不了现场真正要问的那句 —— **"今天这套业务能不能用"**。而把数字读成人话
// 恰恰是实施人员最容易读错的一步（"上游通"被当成"内网通"，是这里最典型的误判）。
//
// 判据是**纯函数**（ChainVerdict）：它定义的是"打开诊断页看到红/黄/绿意味着什么"，
// 不能靠记 —— 与 engine.statusWarnings 一个道理，改动必须有测试钉住。
type Verdict struct {
	Level  string   `json:"level"`  // ok | warn | error
	Head   string   `json:"head"`   // 一句话结论
	Sub    string   `json:"sub"`    // 补充（可空）
	Detail []string `json:"detail"` // 逐条链一句话（有问题的在前）
	Advice []string `json:"advice"` // 该做什么（给运维，不是给开发者）
}

// verdictDetailMax 结论里逐条列出的链最多几条。
//
// 超过就明说"还有 N 条"（不静默截断）：现场看结论就是为了少读字，
// 但"少读"不能变成"漏读" —— 漏掉的那几条恰恰可能是坏的那些。
const verdictDetailMax = 6

// ChainVerdict 把两件事合成一句结论：
//
//	① 代理段（上游）探活 —— 我们到上游这一段通不通、凭据对不对；
//	② 业务目标实测   —— 经这条链能不能真的到达客户内网的业务。
//
// **这两件事必须分开说**：①通而②不通时，责任在上游那一侧的内网（路由/被访问策略），
// 不在本机 —— 现场最常见的误判就是看到"上游可用"就去查本机，查一天。
//
// running=false 时前面这些数字都是上一轮运行留下的，结论要如实说明。
func ChainVerdict(running bool, chains []ChainHealthView, targets []TargetHealthView) Verdict {
	v := Verdict{Level: "ok"}

	switch {
	case !running:
		v.Level = "warn"
		v.Head = "引擎没在跑，现在没有任何流量被接管"
		v.Sub = "下面列出的观测是上一次运行时的，不能代表现在。"
		v.Advice = []string{
			"要接着查：先点顶栏「启动」，再回来点「开始自检」。",
		}
		return v
	case len(chains) == 0:
		v.Level = "warn"
		v.Head = "还没有配置链路，没有任何流量会走隧道"
		v.Advice = []string{"到「隧道链路」页加一条上游（socks5 / socks5+tls / http(s)）。"}
		return v
	}

	var totalUp, okUp, badUp, authUp int
	for _, ch := range chains {
		for _, u := range ch.Upstreams {
			totalUp++
			if !u.Known {
				continue
			}
			if u.OK {
				okUp++
				continue
			}
			badUp++
			if u.AuthRejected {
				authUp++
			}
		}
	}

	// ① 代理段
	switch {
	case okUp == 0 && badUp == 0:
		v.Level = "warn"
		v.Head = "上游还没探过，现在还不知道通不通"
		v.Sub = fmt.Sprintf("已配置 %d 条链、%d 个上游。", len(chains), totalUp)
		v.Advice = []string{"点上面的「开始自检」（几秒），它会把每条链的代理段与业务目标都实测一遍。"}
		return v
	case okUp == 0 && authUp > 0:
		v.Level = "error"
		v.Head = fmt.Sprintf("上游拒绝了凭据：%d 个上游里 %d 个认证不通过", totalUp, authUp)
		v.Sub = "网络是通的 —— 是账号或口令不对（或被上游停用）。"
		v.Advice = []string{
			"到「隧道链路」页点那条链的「编辑」，核对上游地址里的账号/口令（口令是明文，改完保存即生效）。",
			"另一台机器上同样的口令能用吗？如果那里能用，说明这个账号被限制在这台机器/这个 IP 上。",
		}
		v.Detail = chainDetails(chains, targets)
		return v
	case okUp == 0:
		v.Level = "error"
		v.Head = fmt.Sprintf("连不上上游：%d 个上游全部不可用", totalUp)
		v.Advice = []string{
			"先看本机到上游那一段：地址与端口对不对（有时从公司网通、从客户网不通）。",
			"再确认上游服务本身活着（在别的机器上有没有问题）。",
			"上游挂着的这段时间，本该走隧道的业务会连不上 —— 这是对的，不是本机的毛病。",
		}
		v.Detail = chainDetails(chains, targets)
		return v
	case badUp > 0:
		v.Level = "warn"
		v.Head = fmt.Sprintf("%d 个上游里 %d 个不可用（其余 %d 个可用）", totalUp, badUp, okUp)
		if authUp > 0 {
			v.Sub = fmt.Sprintf("其中 %d 个是凭据被拒（不是网络不通）。", authUp)
			v.Advice = []string{"凭据被拒的那几个：核对账号/口令（口令是明文，改完保存即生效）。"}
		} else {
			v.Sub = "走这些上游的业务会被切到其它上游或失败（按链的策略）。"
			v.Advice = []string{"看看这几个上游为什么掉：上游服务是不是在重启、本机到它的网络是不是不稳。"}
		}
		// 部分坏也要往下看目标（剩下的上游可能还能用）
		v.Detail = chainDetails(chains, targets)
		if t := targetVerdict(targets); t != nil {
			v.Detail = append(v.Detail, t.Detail...)
		}
		return v
	}

	// ② 业务目标（代理段全绿时才轮到它说话）
	if t := targetVerdict(targets); t != nil {
		t.Detail = append(chainDetails(chains, targets), t.Detail...)
		return *t
	}

	// ③ 都好
	v.Level = "ok"
	v.Head = fmt.Sprintf("%d 条链、%d 个上游实测都可用", len(chains), totalUp)
	if n := len(targets); n > 0 {
		v.Head = fmt.Sprintf("%d 条链的上游、%d 个内网业务目标实测都通", len(chains), n)
	} else {
		v.Level = "warn"
		v.Sub = "但还没有可实测的内网业务目标 —— 这只能证明「本机到上游」这一段是好的。"
		v.Advice = []string{
			"在 hosts 里写一条内网主机（或让业务先访问一次），我才能回答「到得了内网吗」。",
		}
	}
	v.Detail = chainDetails(chains, targets)
	return v
}

// targetVerdict 业务目标实测的结论；没有可判的东西（全都没探过）返回 nil。
//
// partial 只用于"有没有探过"的判定：TargetHealthView 里 Checked 为空表示还没探过。
func targetVerdict(targets []TargetHealthView) *Verdict {
	if len(targets) == 0 {
		return nil
	}
	var bad, ok int
	var firstBad *TargetHealthView
	for i := range targets {
		t := targets[i]
		if strings.TrimSpace(t.Checked) == "" {
			continue // 还没探过（不算不通）
		}
		if t.OK {
			ok++
			continue
		}
		bad++
		if firstBad == nil {
			firstBad = &targets[i]
		}
	}
	if bad == 0 {
		return nil // 都通（或还没探过）→ 让调用方去说"全通"那句（它知道链/上游的数量）
	}
	v := Verdict{
		Level: "error",
		Head:  fmt.Sprintf("上游能连上，但 %d 个内网业务目标连不通", bad),
		Sub:   "本机到上游这一段是好的 —— 问题在上游那一侧到客户内网。",
		Advice: []string{
			"把下面的目标（IP:端口）发给上游管理员，核对上游侧的路由与访问策略。",
			"也确认业务本身在跑（数据库/服务没停、端口没变）。",
		},
	}
	if firstBad != nil {
		one := fmt.Sprintf("✗ 目标 %s", firstBad.Target)
		if firstBad.Error != "" {
			one += "：" + firstLine(firstBad.Error)
		}
		if firstBad.Chain != "" {
			one += "（链 " + firstBad.Chain + "）"
		}
		v.Detail = []string{one}
	}
	return &v
}

// chainDetails 逐条链一句话（有问题的在前），最多 verdictDetailMax 条。
func chainDetails(chains []ChainHealthView, targets []TargetHealthView) []string {
	bad := make([]string, 0, len(chains))
	good := make([]string, 0, len(chains))
	targetsBad := map[string]int{}
	targetsOK := map[string]int{}
	for _, t := range targets {
		if strings.TrimSpace(t.Checked) == "" {
			continue
		}
		if t.OK {
			targetsOK[t.Chain]++
		} else {
			targetsBad[t.Chain]++
		}
	}
	for _, ch := range chains {
		var ok, down, auth int
		var lastErr string
		for _, u := range ch.Upstreams {
			if !u.Known {
				continue
			}
			switch {
			case u.OK:
				ok++
			case u.AuthRejected:
				auth++
				lastErr = u.Error
			default:
				down++
				lastErr = u.Error
			}
		}
		switch {
		case auth > 0:
			bad = append(bad, fmt.Sprintf("✗ 链 %s：凭据被上游拒绝 —— %s", ch.Name, firstLine(lastErr)))
		case down > 0:
			bad = append(bad, fmt.Sprintf("✗ 链 %s：%d 个上游不可用", ch.Name, down))
		default:
			line := fmt.Sprintf("✓ 链 %s：上游 %d/%d 可用", ch.Name, ok, len(ch.Upstreams))
			if n := targetsOK[ch.Name]; n > 0 {
				line += fmt.Sprintf("，%d 个内网目标实测可达", n)
			}
			if n := targetsBad[ch.Name]; n > 0 {
				line = fmt.Sprintf("✗ 链 %s：上游可用，但 %d 个内网目标不可达", ch.Name, n)
				bad = append(bad, line)
				continue
			}
			good = append(good, line)
		}
	}
	out := append(bad, good...)
	if len(out) > verdictDetailMax {
		out = append(out[:verdictDetailMax],
			fmt.Sprintf("……另有 %d 条链（见下方逐条结果）", len(out)-verdictDetailMax))
	}
	return out
}
