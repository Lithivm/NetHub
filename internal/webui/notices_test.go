package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 告警条的契约：**后端出数据、前端只渲染**。
//
// 前端依赖三件事，所以这里把它们钉住：
//  1. 多条同时存在时，优先级数字要能分出高下（驱动被拦 > 内网被接管）
//  2. ID 稳定（前端按 ID 记"用户关过"，改 ID 等于让用户重新看一次）
//  3. Copy / Card 要么为空、要么真能用（Copy 有值才出复制按钮；Card 必须是界面上真实存在的锚点）
func TestNoticesFor(t *testing.T) {
	// 什么都没有 → 一条都不挂（不能"没装 Clash 也报风险"）
	if got := noticesFor(false, Coverage{OK: true}, UpdateInfo{}); len(got) != 0 {
		t.Fatalf("没问题时不该有告警，得到 %+v", got)
	}

	// 两条同时存在
	drv := noticesFor(true, Coverage{OK: false, Missed: []string{"10.0.0.1", "app.example.com"}}, UpdateInfo{})
	if len(drv) != 2 {
		t.Fatalf("驱动被拦 + 内网被接管，应当两条都在（取舍是前端按优先级做的，后端不替它选），得到 %d 条", len(drv))
	}

	var d, c *Notice
	for i := range drv {
		switch drv[i].ID {
		case "driver-blocked":
			d = &drv[i]
		case "clash-takeover":
			c = &drv[i]
		}
	}
	if d == nil || c == nil {
		t.Fatalf("ID 不对（前端按 ID 记“关过”，不能随意改）：%+v", drv)
	}
	if d.Priority <= c.Priority {
		t.Errorf("优先级要能分出高下：驱动被拦(%d) 必须 > 内网被接管(%d) —— "+
			"驱动装不上是整个程序不可用", d.Priority, c.Priority)
	}
	// 驱动那条：要带完整驱动路径（现场要把它粘进火绒的例外驱动里）
	if !strings.Contains(d.Copy, "WinDivert64.sys") {
		t.Errorf("驱动那条的 Copy 应当是完整驱动路径，得到 %q", d.Copy)
	}
	if !strings.Contains(d.Text, "漏洞驱动拦截") {
		t.Error("驱动那条必须点名「漏洞驱动拦截」—— 只说“信任”等于没说，现场照做还是起不来")
	}
	// Clash 那条：要带"该加进绕过列表"的网段（一键复制）
	if c.Copy == "" || !strings.Contains(c.Copy, "10.0.0.1") {
		t.Errorf("内网被接管那条的 Copy 应当是待加网段，得到 %q", c.Copy)
	}

	// Card 必须指向界面上真实存在的锚点：拼错一个 id，用户点「详情」就什么都不会发生
	html := readIndexHTML(t)
	for _, n := range drv {
		if n.Card == "" {
			t.Errorf("%s 没给 Card —— 告警条上的「详情」就没地方可跳", n.ID)
			continue
		}
		if !strings.Contains(html, `id="`+n.Card+`"`) {
			t.Errorf("%s 的 Card=%q 在 index.html 里找不到 —— 「详情」会点了没反应", n.ID, n.Card)
		}
	}
	// 每条都要有能显示的标题/正文
	for _, n := range drv {
		if n.Title == "" || n.Text == "" {
			t.Errorf("%s 缺 Title/Text：%+v", n.ID, n)
		}
		if n.Kind != "error" && n.Kind != "warn" && n.Kind != "info" {
			t.Errorf("%s 的 Kind=%q 不是 error/warn/info（前端按它取配色）", n.ID, n.Kind)
		}
	}
}

// 自动检查更新查到新版 → 挂一条**常驻**告警（不是一闪而过的 toast），
// 并且它的优先级要低于前两类（驱动/内网是故障，新版本只是信息）。
func TestNoticeForAvailableUpdate(t *testing.T) {
	upd := UpdateInfo{Current: "v0.4.2", Latest: "v0.5.0", HasNew: true, Published: "2026-09-28"}
	got := noticesFor(false, Coverage{OK: true}, upd)
	if len(got) != 1 {
		t.Fatalf("有新版时应当恰好挂一条，得到 %d 条：%+v", len(got), got)
	}
	n := got[0]
	if n.ID != "update-available" {
		t.Errorf("ID 应为 update-available（前端按 ID 记“关过”），得到 %q", n.ID)
	}
	if n.Kind != "info" {
		t.Errorf("“有新版本”是信息不是故障，Kind 应为 info，得到 %q", n.Kind)
	}
	if n.Priority >= prioClashTakeover {
		t.Errorf("新版本的优先级(%d)应当低于内网被接管(%d) —— 故障优先", n.Priority, prioClashTakeover)
	}
	if !strings.Contains(n.Title, "v0.5.0") || !strings.Contains(n.Text, "v0.4.2") {
		t.Errorf("标题/正文要写清新旧版本号：%+v", n)
	}
	if n.Card != "cardAbout" {
		t.Errorf("“详情”要跳到关于卡（那里有「下载并更新」按钮），得到 %q", n.Card)
	}

	// 三个都不挂的情形（每一种都不该惊动用户）
	for _, c := range []struct {
		name string
		in   UpdateInfo
	}{
		{"dev 构建（没有版本号可比）", UpdateInfo{Current: "dev", Dev: true}},
		{"已是最新", UpdateInfo{Current: "v0.4.2", Latest: "v0.4.2"}},
		{"没查过（零值）", UpdateInfo{}},
	} {
		if got := noticesFor(false, Coverage{OK: true}, c.in); len(got) != 0 {
			t.Errorf("%s 不该挂告警，得到 %+v", c.name, got)
		}
	}
}

// readIndexHTML 读界面的 index.html（测试的工作目录是 internal/webui）。
func readIndexHTML(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "frontend", "index.html"))
	if err != nil {
		t.Fatalf("读不到 frontend/index.html（改动目录结构了？）: %v", err)
	}
	return string(b)
}
