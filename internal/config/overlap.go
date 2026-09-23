package config

import (
	"fmt"
	"net"
	"strings"
)

// 规则重叠检查（用户点按钮才跑，不在后台自作主张）。
//
// 为什么需要它：规则是"自上而下、命中即停"，所以**重叠一定意味着有人被抢**。
// 但重叠本身不一定是错 —— 常见有两种写法：
//
//	A. 宽的先兜、窄的例外（"内网全走隧道，但本机网段直连"）→ 故意让宽的在前
//	B. 窄的先说、宽的后补                              → 故意让窄的在前
//
// 两种都能表达对的意图，**所以这里只报告事实与后果，不给"你必须怎么改"的结论**：
// 只把"谁实际生效、谁被抢、要不要调顺序"摆出来，让人自己判断。
type Overlap struct {
	Earlier      int      `json:"earlier"`     // 前面的规则（实际生效的那条）
	Later        int      `json:"later"`       // 后面的规则
	EarlierName  string   `json:"earlierName"` // 规则名（可能为空）
	LaterName    string   `json:"laterName"`
	Kind         string   `json:"kind"`        // dead(完全轮不到) | shadowed(部分被抢) | fine(宽窄叠加，符合直觉)
	Targets      []string `json:"targets"`     // 重叠的目标（举例，最多几个）
	Ports        []string `json:"ports"`       // 重叠涉及的端口条件
	Resolution   string   `json:"resolution"`  // 一句话：这块流量实际归谁
	ActionText   string   `json:"actionText"`  // 实际生效的动作
	LaterAction  string   `json:"laterAction"` // 被抢那条的动作
	LaterMoreSpe bool     `json:"laterMoreSpecific"`
}

// CheckOverlaps 全量两两比对，返回所有"会互相影响"的规则对。
// 目标不重叠、或端口不重叠的，都不算（那种重叠没有后果）。
func (c *Config) CheckOverlaps() []Overlap {
	var out []Overlap
	n := len(c.Routes)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			a, b := c.Routes[i], c.Routes[j]
			if !a.IsEnabled() || !b.IsEnabled() {
				continue // 停用的规则不参与“互相影响”的结论
			}
			// 端口：两边都要"有交集"才可能互抢
			if !portsIntersect(a.Ports, b.Ports) {
				continue
			}
			shared, aCoversB, bCoversA := overlapTargets(a.Targets, b.Targets)
			if len(shared) == 0 {
				continue
			}
			o := Overlap{
				Earlier: i, Later: j,
				EarlierName: a.Name, LaterName: b.Name,
				Targets:     shared,
				Ports:       overlapPorts(a.Ports, b.Ports),
				ActionText:  a.ActionText(),
				LaterAction: b.ActionText(),
			}
			aSpec, bSpec := ruleSpecificity(a), ruleSpecificity(b)
			o.LaterMoreSpe = bSpec > aSpec

			switch {
			case aCoversB && PortsCover(a.Ports, b.Ports):
				// 后面这条**整块**都在前面那条里面 → 它永远轮不到
				o.Kind = "dead"
				o.Resolution = fmt.Sprintf("第 %d 条整个被第 %d 条包住，永远不会生效", j+1, i+1)
			case bCoversA && PortsCover(b.Ports, a.Ports):
				// 反过来：前面这条更窄（也在后面那条里面）→ 正常，窄的本来就在前
				o.Kind = "fine"
				o.Resolution = fmt.Sprintf("重叠部分归第 %d 条（更窄的那条在前面，符合直觉）", i+1)
			default:
				o.Kind = "shadowed"
				o.Resolution = fmt.Sprintf("重叠部分归第 %d 条（它在前面，先命中）", i+1)
			}
			out = append(out, o)
		}
	}
	return out
}

// ruleSpecificity 规则的"具体程度"：前缀越长越具体；有端口条件比没端口更具体。
// 与界面上的「按最具体优先」按钮用同一把尺子。
func ruleSpecificity(r Route) int {
	best := 0
	for _, t := range r.Targets {
		if n := targetNet(t); n != nil {
			if ones, _ := n.Mask.Size(); ones > best {
				best = ones
			}
		}
	}
	score := best * 10
	if len(r.Ports) > 0 {
		score += 5 // 有条端口条件的，比"全端口"的具体
	}
	return score
}

// overlapTargets 两条规则的目标里重叠的部分（举例最多 4 个），
// 以及"谁把谁整个包住"。
func overlapTargets(a, b []string) (shared []string, aCoversB, bCoversA bool) {
	aCoversB, bCoversA = true, true
	for _, bt := range b {
		bn := targetNet(bt)
		if bn == nil {
			aCoversB = false
			continue
		}
		covered := false
		for _, at := range a {
			an := targetNet(at)
			if an == nil {
				continue
			}
			if netContains(an, bn) {
				covered = true
				if len(shared) < 4 {
					shared = append(shared, describeNet(bn))
				}
				break
			}
			// 部分相交（一条把另一条的地址段切了一刀）
			if an.Contains(firstIP(bn)) || bn.Contains(firstIP(an)) {
				if len(shared) < 4 {
					shared = append(shared, describeNet(an)+" ∩ "+describeNet(bn))
				}
			}
		}
		if !covered {
			aCoversB = false
		}
	}
	for _, at := range a {
		an := targetNet(at)
		if an == nil {
			bCoversA = false
			continue
		}
		covered := false
		for _, bt := range b {
			bn := targetNet(bt)
			if bn != nil && netContains(bn, an) {
				covered = true
				break
			}
		}
		if !covered {
			bCoversA = false
		}
	}
	return shared, aCoversB, bCoversA
}

func describeNet(n *net.IPNet) string {
	if ones, bits := n.Mask.Size(); ones == bits {
		return n.IP.String() // /32 就写单个地址
	}
	return n.String()
}

func firstIP(n *net.IPNet) net.IP { return n.IP }

// portsIntersect 两组端口条件是否有交集（任一边为空 = 全部端口）。
func portsIntersect(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range portSpans(a) {
		for _, y := range portSpans(b) {
			if x.lo <= y.hi && y.lo <= x.hi {
				return true
			}
		}
	}
	return false
}

// overlapPorts 重叠的端口条件（用于报告展示）。
func overlapPorts(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	var out []string
	for _, x := range portSpans(a) {
		for _, y := range portSpans(b) {
			lo, hi := x.lo, x.hi
			if y.lo > lo {
				lo = y.lo
			}
			if y.hi < hi {
				hi = y.hi
			}
			if lo <= hi {
				if lo == hi {
					out = append(out, fmt.Sprint(lo))
				} else {
					out = append(out, fmt.Sprintf("%d-%d", lo, hi))
				}
			}
		}
	}
	return out
}

// OverlapSummary 一句话汇总（按钮点完先在界面上给人看这行）。
func OverlapSummary(ov []Overlap) string {
	if len(ov) == 0 {
		return "没有互相影响的规则：目标与端口都不重叠。"
	}
	dead, shadowed := 0, 0
	for _, o := range ov {
		switch o.Kind {
		case "dead":
			dead++
		case "shadowed":
			shadowed++
		}
	}
	parts := []string{fmt.Sprintf("发现 %d 处规则重叠", len(ov))}
	if dead > 0 {
		parts = append(parts, fmt.Sprintf("其中 %d 处是「永远不生效」", dead))
	}
	if shadowed > 0 {
		parts = append(parts, fmt.Sprintf("%d 处是「部分被抢」", shadowed))
	}
	parts = append(parts, "重叠本身不一定错（宽兜底+窄例外是常见写法），看下面每条的实际归属再决定要不要调顺序")
	return strings.Join(parts, "；")
}
