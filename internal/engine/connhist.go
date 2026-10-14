package engine

import (
	"fmt"
	"time"

	"nethub/internal/rules"
)

// ───────────────────── 连接历史存档 ─────────────────────
//
// 为什么单独存一份（而不是沿用 conns 里那些已经结束的条目）：
// 那些条目是**给"当前连接"列表看的** —— janitor 在连接结束 2 分钟后就把它们物理删了
// （见 janitor 里的 endedCut），界面更是只认最近 15 秒（connEndedViewKeep）。
// 而诊断时最常见的诉求恰恰是"刚才那批连到哪儿去了、为什么失败"，
// 从发现异常到切到这台机器上打开界面，一两分钟早就过去了。
//
// 所以这里是一份**定长环形缓冲区**：连接一结束就留一条紧凑记录（不存 connState 里那堆原子量），
// 界面上以「历史连接」展开区按需拉取（GET 一次，不参与 1.5 秒轮询）。
// ConnHistKeep 连接历史存档的条数上界。导出给界面显示（“只留最近 N 条”），
// 别让人以为丢数据了。
const ConnHistKeep = 300

// ConnHist 一条已结束连接的存档。
//
// 字段刻意与 ConnView 对齐（目标/动作/链/进程/时长/字节/状态），
// 这样界面上两张表可以用同一套列与同一套渲染，不必再造一套。
type ConnHist struct {
	Target   string `json:"target"`
	Action   string `json:"action"`
	Chain    string `json:"chain"`
	RuleNo   int    `json:"ruleNo"`
	RuleName string `json:"ruleName"`
	Proc     string `json:"proc"`
	PID      uint32 `json:"pid"`
	Sport    uint16 `json:"sport"` // 本地端口：一条连接的唯一标识（对着 netstat 核对用）

	Started string `json:"started"` // 开始时刻（本地 HH:MM:SS）
	Ended   string `json:"ended"`   // 结束时刻
	DurSec  int    `json:"durSec"`  // 持续秒数
	// AgoSec 距今多少秒 —— 快照时才算（存下来会随时间变假）
	AgoSec int `json:"agoSec"`

	// endAt 结束时刻的原始值，只用来算 AgoSec（存档里全是字符串，比不了大小）。
	// 不能靠反解 Ended 字符串：ParseInLocation("15:04:05", …) 解出来的是**公元 0 年**，
	// 拿它减 now 得到的是"过了一千多年"（实测踩过）。
	endAt time.Time

	Up      uint64 `json:"up"`
	Down    uint64 `json:"down"`
	Packets uint64 `json:"packets"`

	State string `json:"state"` // 已结束 / 失败 / 已阻断 / 未送达中转
	Err   string `json:"err,omitempty"`
}

// connStateName 连接状态文案。列表与历史**共用同一份判据** ——
// 分成两处写，早晚会出现"列表说失败、历史说已结束"这种自相矛盾。
func connStateName(st *connState) string {
	switch {
	case st.unrelayed.Load():
		return "未送达中转"
	case st.action == rules.ActionBlock:
		return "已阻断"
	case st.err() != "":
		return "失败"
	case st.ended.Load():
		return "已结束"
	}
	return "进行中"
}

// noteHistory 把一条结束的连接记进存档（由 finish 调用，幂等由调用方保证）。
//
// 自己的探针（st.self）不进：那是仪器不是应用流量，跟「当前连接」列表一个口径。
// 用独立的 histMu，不碰引擎的热锁（finish 在转发的收尾路径上被调）。
func (e *Engine) noteHistory(st *connState) {
	if e == nil || st == nil || st.self {
		return
	}
	end := st.endTime()
	if end.IsZero() {
		end = time.Now()
	}
	rec := ConnHist{
		Target:   fmt.Sprintf("%s:%d", st.displayTarget(), st.dport),
		Action:   st.action.String(),
		Chain:    st.chain,
		RuleNo:   st.ruleNo,
		RuleName: st.ruleName,
		Proc:     st.procName,
		PID:      st.pid,
		Sport:    st.appPort,
		Started:  st.start.Format("15:04:05"),
		Ended:    end.Format("15:04:05"),
		endAt:    end,
		DurSec:   int(end.Sub(st.start).Seconds()),
		Up:       st.up.Load(),
		Down:     st.down.Load(),
		Packets:  st.packets.Load(),
		State:    connStateName(st),
		Err:      st.err(),
	}
	e.histMu.Lock()
	e.hist = append(e.hist, rec)
	if n := len(e.hist); n > ConnHistKeep {
		// 裁掉最老的。用 copy 挪进新底层数组（只切片的话底层数组会一直长）
		keep := make([]ConnHist, ConnHistKeep)
		copy(keep, e.hist[n-ConnHistKeep:])
		e.hist = keep
	}
	e.histMu.Unlock()
}

// ConnsHistory 历史连接快照，**新的在前**；limit<=0 表示全部。
func (e *Engine) ConnsHistory(limit int) []ConnHist {
	if e == nil {
		return nil
	}
	e.histMu.Lock()
	n := len(e.hist)
	out := make([]ConnHist, 0, n)
	for i := n - 1; i >= 0; i-- { // 新的在前
		rec := e.hist[i]
		// 距今秒数在快照时算：存档里存死了就永远显示当时那一次的值
		if !rec.endAt.IsZero() {
			rec.AgoSec = int(time.Since(rec.endAt).Seconds())
		}
		out = append(out, rec)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	e.histMu.Unlock()
	return out
}

// ClearConnsHistory 清空存档（界面上「清空」按钮：方便"做一次动作，只看这次新增的"）。
func (e *Engine) ClearConnsHistory() {
	if e == nil {
		return
	}
	e.histMu.Lock()
	e.hist = nil
	e.histMu.Unlock()
}
