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
	if got := noticesFor(false, Coverage{OK: true}, UpdateInfo{}, "", 0); len(got) != 0 {
		t.Fatalf("没问题时不该有告警，得到 %+v", got)
	}

	// 两条同时存在
	drv := noticesFor(true, Coverage{OK: false, Missed: []string{"10.0.0.1", "app.example.com"}}, UpdateInfo{}, "", 0)
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
	got := noticesFor(false, Coverage{OK: true}, upd, "", 0)
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
		if got := noticesFor(false, Coverage{OK: true}, c.in, "", 0); len(got) != 0 {
			t.Errorf("%s 不该挂告警，得到 %+v", c.name, got)
		}
	}
}

// TestReadOnlyNotice：只读态必须挂一条**带行动按钮**的告警。
//
// 为什么钉它：只读（服务版/另一个实例在跑引擎）时界面能看不能动，以前只有顶栏
// 一个"只读"胺囊 + 一闪而过的 toast，现场很容易理解成"软件卡住了"（用户 2026-10-13 反馈）。
// 这条告警就是那个入口，不许退化成"只通知不给出路"。
func TestReadOnlyNotice(t *testing.T) {
	got := noticesFor(false, Coverage{OK: true}, UpdateInfo{}, "服务版正在运行", 0)
	if len(got) != 1 {
		t.Fatalf("只读态该挂一条告警，实际 %d 条: %+v", len(got), got)
	}
	n := got[0]
	if n.ID != "engine-readonly" || n.Action != "takeover" || n.ActionLabel == "" {
		t.Fatalf("只读告警少了行动按钮（前端靠 action 映射到函数）: %+v", n)
	}
	if !strings.Contains(n.Text, "服务版正在运行") {
		t.Fatalf("原因要写进正文，别让人去猜: %q", n.Text)
	}
	if n.Priority <= prioUpdateAvail {
		t.Fatal("只读比「有新版本」更该被看到，优先级要更高")
	}
	// 恢复正常（why 为空）就不该再挂
	if again := noticesFor(false, Coverage{OK: true}, UpdateInfo{}, "", 0); len(again) != 0 {
		t.Fatalf("不是只读了还在挂告警: %+v", again)
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

// 接管失效告警（2026-10-15）：引擎在跑、但包没经过过滤器时**必须**挂出来 ——
// 这类故障的可怕之处在于"界面上看不出任何异常"（只能靠人盯 stats 里的 total=0）。
func TestNoticeBlackhole(t *testing.T) {
	if got := noticesFor(false, Coverage{OK: true}, UpdateInfo{}, "", 0); len(got) != 0 {
		t.Fatalf("自检正常时不该挂告警，得到 %d 条：%+v", len(got), got)
	}
	got := noticesFor(false, Coverage{OK: true}, UpdateInfo{}, "", 3)
	if len(got) != 1 || got[0].ID != "takeover-blackhole" {
		t.Fatalf("自检失败时该挂 takeover-blackhole，得到 %+v", got)
	}
	if got[0].Priority <= prioReadOnly {
		t.Errorf("优先级 %d 应高于只读告警 %d —— 只读一眼能看出来，这个是看不见的故障",
			got[0].Priority, prioReadOnly)
	}
	if got[0].Card != "cardRuntime" {
		t.Errorf("Card 要指向诊断页真实存在的锚点 cardRuntime，得到 %q", got[0].Card)
	}
}
