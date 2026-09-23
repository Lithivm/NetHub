package webui

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// 「上客户现场之前，把服务器清单糊进来一次验完规则」——
// 单独查一个 IP 在路由规则页已经有了（ExplainTarget，带链/巡检细节）；
// 这里做的是**批量**：一次给几十个 IP/网段，直接告诉每一条走哪条链、哪个是直连、
// 哪个根本没被拦到。现场再一条条试太慢，配错了也看不出来。

// SimRow 一行模拟结果。
type SimRow struct {
	Input  string `json:"input"`
	OK     bool   `json:"ok"`
	Err    string `json:"err,omitempty"`
	Rule   string `json:"rule,omitempty"`   // 命中的规则名
	RuleNo int    `json:"ruleNo"`           // 命中规则序号（1 起；0=没命中）
	Action string `json:"action,omitempty"` // 走隧道 / 直连 / 阻断 / 未命中
	Chain  string `json:"chain,omitempty"`
	Note   string `json:"note,omitempty"` // 抽样、端口限定之类的说明
}

// SimCount 按处理方式分组计数（保序，方便前端直接渲染）。
type SimCount struct {
	Action string `json:"action"`
	N      int    `json:"n"`
}

// SimView 一次模拟的完整结果。
type SimView struct {
	Rows    []SimRow   `json:"rows"`
	Counts  []SimCount `json:"counts"`
	Summary string     `json:"summary"`
}

// 一次最多模拟多少条（防止有人糊进来一整份 IP 表把界面卡住）。
const simMax = 512

// 网段抽样点数：网段不大就全查，大网段按 16 点均匀抽样。
const simSample = 16

// SimulateTargets 解析用户粘进来的清单，逐条给出「会怎么走」。
//
// 支持：单行一个，也支持逗号/空格/分号分隔；支持 # 注释；
// 每条可以是 IP、IP:端口、网段、网段:端口。
// 不填端口时按「只看目标」判断（会注明：带端口条件的规则可能没算进来）。
func (b *Backend) SimulateTargets(text string) SimView {
	tokens := parseSimInput(text)
	truncated := 0
	if len(tokens) > simMax {
		truncated = len(tokens) - simMax
		tokens = tokens[:simMax]
	}

	v := SimView{Rows: make([]SimRow, 0, len(tokens))}
	order := []string{}
	counts := map[string]int{}
	for _, tk := range tokens {
		row := b.simOne(tk)
		v.Rows = append(v.Rows, row)
		key := row.Action
		if !row.OK {
			key = "无法解析"
		}
		if _, seen := counts[key]; !seen {
			order = append(order, key)
		}
		counts[key]++
	}
	for _, k := range order {
		v.Counts = append(v.Counts, SimCount{Action: k, N: counts[k]})
	}

	parts := make([]string, 0, len(v.Counts))
	for _, c := range v.Counts {
		parts = append(parts, fmt.Sprintf("%s %d", c.Action, c.N))
	}
	v.Summary = fmt.Sprintf("共 %d 项：%s", len(tokens), strings.Join(parts, "，"))
	if truncated > 0 {
		v.Summary += fmt.Sprintf("；另有 %d 项超出单次上限（%d）没有模拟", truncated, simMax)
	}
	return v
}

// parseSimInput 把糊进来的文本切成条目：按行、逗号、分号、空白切，支持 # 注释。
func parseSimInput(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		for _, tk := range strings.FieldsFunc(line, func(r rune) bool {
			switch r {
			case ',', '，', ';', '；', '\t', '\r', ' ':
				return true
			}
			return false
		}) {
			tk = strings.TrimSpace(tk)
			if tk == "" || seen[tk] {
				continue
			}
			seen[tk] = true
			out = append(out, tk)
		}
	}
	return out
}

// simOne 模拟一条：IP[:端口] 或 网段[:端口]。
func (b *Backend) simOne(tok string) SimRow {
	row := SimRow{Input: tok}
	host, port, hasPort, err := splitSimTarget(tok)
	if err != nil {
		row.Err = err.Error()
		return row
	}

	// 网段：抽样若干点，全一致算一个结论；不一致就把分界说出来
	if strings.Contains(host, "/") {
		_, ipnet, err := net.ParseCIDR(host)
		if err != nil {
			row.Err = "不是合法的网段（如 10.0.0.0/24）"
			return row
		}
		// 本工具只处理 IPv4：IPv6 网段（fe80::/10）能 ParseCIDR 成功，
		// 但后面按 4 字节解析会直接 panic，所以必须在这里拦下。
		if ipnet.IP.To4() == nil {
			row.Err = "只支持 IPv4 网段（本工具不处理 IPv6）"
			return row
		}
		ips := sampleCIDR(ipnet, simSample)
		if len(ips) == 0 {
			row.Err = "这个网段取不出可用地址"
			return row
		}
		type verdict struct {
			rule   string
			ruleNo int
			action string
			chain  string
		}
		first := b.simEval(ips[0], port, !hasPort)
		row.OK, row.Rule, row.RuleNo, row.Action, row.Chain = true, first.rule, first.ruleNo, first.action, first.chain
		sampleNote := fmt.Sprintf("网段抽样 %d 点", len(ips))
		for _, ip := range ips[1:] {
			got := b.simEval(ip, port, !hasPort)
			if got.action != first.action || got.rule != first.rule || got.chain != first.chain {
				row.Note = fmt.Sprintf("⚠ 网段内不一致：%s → %s%s，%s → %s%s；请拆开写",
					ips[0], first.action, ruleSuffix(first.rule), ip, got.action, ruleSuffix(got.rule))
				sampleNote = ""
				break
			}
		}
		if sampleNote != "" {
			row.Note = sampleNote
		}
		row.Note = joinNote(row.Note, portNote(b, first.ruleNo, hasPort))
		return row
	}

	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		row.Err = "不是合法的 IPv4 地址（本工具只处理 IPv4）"
		return row
	}
	got := b.simEval(ip, port, !hasPort)
	row.OK, row.Rule, row.RuleNo, row.Action, row.Chain = true, got.rule, got.ruleNo, got.action, got.chain
	row.Note = portNote(b, got.ruleNo, hasPort)
	return row
}

type simVerdict struct {
	rule   string
	ruleNo int
	action string
	chain  string
}

// simEval 就是「这个目标会被怎么处理」：命中哪条规则、动作是什么。
func (b *Backend) simEval(ip net.IP, port uint16, ignorePort bool) simVerdict {
	idx, _, ok := b.a.Rules.Explain(ip, port, ignorePort)
	if !ok || idx < 0 || idx >= len(b.a.Cfg.Routes) {
		return simVerdict{action: "未命中（不拦截）"}
	}
	r := b.a.Cfg.Routes[idx]
	return simVerdict{rule: r.Name, ruleNo: idx + 1, action: r.ActionText(), chain: r.Chain}
}

// portNote：没填端口、但命中的规则带端口条件时，把这件事说清楚（别让人误以为结论确定）。
func portNote(b *Backend, ruleNo int, hasPort bool) string {
	if hasPort || ruleNo <= 0 || ruleNo > len(b.a.Cfg.Routes) {
		return ""
	}
	if p := b.a.Cfg.Routes[ruleNo-1].Ports; len(p) > 0 {
		return "该规则限定端口 " + strings.Join(p, ",") + "；未填端口时按「只看目标」判断"
	}
	return ""
}

func ruleSuffix(name string) string {
	if name == "" {
		return ""
	}
	return "「" + name + "」"
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "；" + b
	}
}

// splitSimTarget 拆出 host 与可选端口。网段带端口写成 10.0.0.0/24:443。
func splitSimTarget(tok string) (host string, port uint16, hasPort bool, err error) {
	if i := strings.LastIndex(tok, ":"); i >= 0 {
		host, p := tok[:i], tok[i+1:]
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", 0, false, fmt.Errorf("端口要在 1-65535：%q", p)
		}
		if host == "" {
			return "", 0, false, fmt.Errorf("缺少地址：%q", tok)
		}
		return host, uint16(n), true, nil
	}
	return tok, 0, false, nil
}

// sampleCIDR 在一个网段里取最多 max 个代表性地址（首、尾，中间均匀取样）。
func sampleCIDR(n *net.IPNet, max int) []net.IP {
	if n == nil || n.IP.To4() == nil {
		return nil // 只处理 IPv4（调用方已拦，这里再兜一道）
	}
	if max < 2 {
		max = 2 // 下面有 max-1 做除数
	}
	base := binary.BigEndian.Uint32(n.IP.To4())
	ones, bits := n.Mask.Size()
	if ones < 0 || bits != 32 || ones > bits {
		return nil
	}
	size := uint64(1) << uint(bits-ones)
	if size == 0 {
		return nil
	}
	if size <= uint64(max) {
		out := make([]net.IP, 0, size)
		for i := uint64(0); i < size; i++ {
			out = append(out, u32ip(base+uint32(i)))
		}
		return out
	}
	out := make([]net.IP, 0, max)
	step := (size - 1) / uint64(max-1)
	for i := uint64(0); i < uint64(max); i++ {
		off := i * step
		if off > size-1 {
			off = size - 1
		}
		out = append(out, u32ip(base+uint32(off)))
	}
	return out
}

func u32ip(v uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:])
}
