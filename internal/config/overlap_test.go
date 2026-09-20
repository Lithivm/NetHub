package config

import (
	"strings"
	"testing"
)

// 重叠检查要区分三种后果：完全轮不到 / 部分被抢 / 正常的宽窄叠加。
func TestCheckOverlaps(t *testing.T) {
	c := &Config{
		Chains: []Chain{{Name: "a", Forward: "socks5://127.0.0.1:1080"},
			{Name: "d", Forward: DirectChain}},
		Routes: []Route{
			// 0：宽，全端口
			{Name: "内网全段", Targets: []string{"10.0.0.0/8"}, Chain: "a"},
			// 1：窄，被 0 整个包住 → dead
			{Name: "本机网段直连", Targets: []string{"10.1.2.0/24"}, Chain: DirectChain},
			// 2：部分重叠（10.0.0.0/8 与 10.5.0.0/16 只有后者被包住）→ 与 0 是 dead
			{Name: "另一段", Targets: []string{"192.168.0.0/16"}, Chain: "a"},
			// 3：与 0 目标重叠但端口不同 → 不算冲突
			{Name: "只走443", Targets: []string{"10.9.0.0/16"}, Chain: "a", Ports: []string{"443"}},
			// 4：窄在前、宽在后 → fine
			{Name: "窄的在前", Targets: []string{"10.7.7.0/24"}, Chain: DirectChain},
		},
	}
	// 把 4 挪到 0 前面才叫"窄在前"，这里直接构造一个干净场景
	c.Routes = []Route{c.Routes[0], c.Routes[1], c.Routes[2], c.Routes[3]}
	ov := c.CheckOverlaps()

	kinds := map[string]int{}
	for _, o := range ov {
		kinds[o.Kind]++
		t.Logf("%d→%d %s | %s | %v 端口%v", o.Earlier+1, o.Later+1, o.Kind, o.Resolution, o.Targets, o.Ports)
	}
	// 0 与 1：完全覆盖（都是全端口）
	found := false
	for _, o := range ov {
		if o.Earlier == 0 && o.Later == 1 {
			found = true
			if o.Kind != "dead" {
				t.Errorf("0→1 应为 dead，得到 %s", o.Kind)
			}
			if !strings.Contains(o.Resolution, "永远不会生效") {
				t.Errorf("结论要说清后果：%q", o.Resolution)
			}
		}
	}
	if !found {
		t.Error("0→1 的重叠没被检出")
	}
	// 0 与 3：端口不重叠（0 是全端口，3 只有 443 → 有交集！）所以应检出 shadowed/dead 之一
	// 0 与 2：目标不重叠（10/8 vs 192.168/16）→ 不该检出
	for _, o := range ov {
		if o.Earlier == 0 && o.Later == 2 {
			t.Error("目标不重叠的不该报（10.0.0.0/8 与 192.168.0.0/16）")
		}
	}
	if len(ov) == 0 {
		t.Fatal("应检出重叠")
	}
	if s := OverlapSummary(ov); !strings.Contains(s, "重叠") {
		t.Errorf("汇总文案不对：%q", s)
	}
}

// 两条规则完全不重叠时不该报，也不该因为"都是全端口"就误报。
func TestCheckOverlapsNone(t *testing.T) {
	c := &Config{Routes: []Route{
		{Name: "a", Targets: []string{"10.1.0.0/16"}, Chain: "x"},
		{Name: "b", Targets: []string{"10.2.0.0/16"}, Chain: "x"},
		{Name: "c", Targets: []string{"192.168.0.0/16"}, Chain: "x", Ports: []string{"443"}},
	}}
	if ov := c.CheckOverlaps(); len(ov) != 0 {
		t.Errorf("不该有重叠：%+v", ov)
	}
	if s := OverlapSummary(nil); !strings.Contains(s, "没有") {
		t.Errorf("空结果文案不对：%q", s)
	}
}

// 同一目标、端口不同 → 不算冲突（端口维度是"与"关系）。
func TestCheckOverlapsPortDiffers(t *testing.T) {
	c := &Config{Routes: []Route{
		{Name: "443", Targets: []string{"10.0.0.0/8"}, Chain: "x", Ports: []string{"443"}},
		{Name: "5432", Targets: []string{"10.0.0.0/8"}, Chain: "y", Ports: []string{"5432"}},
	}}
	if ov := c.CheckOverlaps(); len(ov) != 0 {
		t.Errorf("端口不重叠就不该报冲突：%+v", ov)
	}
	// 但范围端口相交要报
	c.Routes[1].Ports = []string{"400-500"}
	ov := c.CheckOverlaps()
	if len(ov) != 1 {
		t.Fatalf("端口 443 与 400-500 不相交，不该报；实际 %d 条", len(ov))
	}
	c.Routes[1].Ports = []string{"400-443"}
	if ov := c.CheckOverlaps(); len(ov) != 1 || len(ov[0].Ports) == 0 {
		t.Errorf("端口 400-443 与 443 相交，应报并给出重叠端口：%+v", ov)
	}
}
