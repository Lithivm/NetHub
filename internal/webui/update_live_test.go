package webui

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nethub/internal/selfupdate"
)

// TestUpdateDownloadLive 端到端走一遍"一键更新"的链路：查版本 → 下包 → 校验摘要 → 试解包。
// **不替换任何文件、不重启**（那部分由 selfupdate 的测试与验收门禁管）。
//
// 为什么默认跳过：要出公网、要下几 MB —— 网络不能当测试前提。
// 现场排查"更新按钮点了没反应"时，在本机跑：
//
//	NETHUB_LIVE_UPDATE=1 go test -count=1 ./internal/webui/ -run TestUpdateDownloadLive -v
//
// **`-count=1` 不能省**：go test 会把结果缓存下来、连日志带耗时一起重放，
// 于是"改完代码重跑"看到的是上一次的输出 —— 排查时能把人带进沟里（2026-10-16 踩过）。
//
// 它会把"这次走的是哪条路"（系统代理 / 直连）打在日志第一行 —— 现场多半就差这一句。
func TestUpdateDownloadLive(t *testing.T) {
	if os.Getenv("NETHUB_LIVE_UPDATE") == "" {
		t.Skip("要出公网并下几 MB，默认跳过（NETHUB_LIVE_UPDATE=1 才跑）")
	}
	t.Logf("更新请求走的是：%s", proxyNote())
	// "设置读到了"与"请求真的用上了"是两件事，分别断言
	req, _ := http.NewRequest("GET", releasesLatestURL, nil)
	pf := systemProxyFunc()
	if pf == nil {
		t.Fatal("systemProxyFunc() 返回 nil —— 本机开着系统代理，更新请求却会直连")
	}
	if u, uerr := pf(req); u == nil || uerr != nil {
		t.Fatalf("releases/latest 不会经代理：url=%v err=%v", u, uerr)
	} else {
		t.Logf("releases/latest 实际经：%s", u)
	}

	// 先单独验一下「检查更新」走的那条轻路径（302，不消耗 API 配额）
	tag, err := latestTagViaRedirect()
	if err != nil || tag == "" {
		t.Fatalf("查最新版本（302 那条路）失败：%v", err)
	}
	t.Logf("302 查到最新版本 %s（这条不花 API 配额）", tag)

	rel, err := latestReleaseFull()
	if err != nil {
		t.Fatalf("查最新版本失败：%v", err)
	}
	asset, err := pickAsset(rel)
	if err != nil {
		t.Fatalf("选包失败（%s）：%v", rel.TagName, err)
	}
	// 走零配额那条路（302 + 发布页 HTML）时拿不到文件大小，所以不拿它当判据
	if asset.URL == "" {
		t.Fatalf("包里没有下载地址：%+v", asset)
	}
	// 摘要拿不到时一键更新会 fail-closed 拒掉 —— 那属于"发布流程出问题"，
	// 必须在发版前发现，所以这里判失败而不是跳过。
	if asset.SHA256 == "" {
		t.Fatalf("%s 的 %s 没有 sha256 摘要：一键更新会被 fail-closed 拒绝", rel.TagName, asset.Name)
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "download.zip")
	last := ""
	if err := downloadWithProgress(asset.URL, zipPath, func(stage, text string, pct int) {
		if text != last {
			last = text
			t.Logf("[%s] %s", stage, text)
		}
	}); err != nil {
		t.Fatalf("下载失败：%v", err)
	}

	sum, err := fileSHA256(zipPath)
	if err != nil {
		t.Fatalf("算摘要失败：%v", err)
	}
	if !strings.EqualFold(sum, asset.SHA256) {
		t.Fatalf("摘要不一致：期望 %s…，实际 %s…", asset.SHA256[:12], sum[:12])
	}

	// 解包等同于一键更新里 selfupdate.Stage 那一步（只写 t.TempDir()，不碰程序目录）
	pend, err := selfupdate.Stage(zipPath, dir, rel.TagName, 0)
	if err != nil {
		t.Fatalf("解包失败：%v", err)
	}
	hasExe := false
	for _, f := range pend.Files {
		if f == "nethub.exe" {
			hasExe = true
		}
	}
	if !hasExe {
		t.Fatalf("包里没有 nethub.exe（实际取了 %v）", pend.Files)
	}
	t.Logf("✓ %s 的 %s 下载 / 校验 / 解包全通过（取了 %v）", rel.TagName, asset.Name, pend.Files)
}
