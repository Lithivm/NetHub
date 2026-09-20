package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"nethub/internal/selfupdate"
)

// 「检查更新」。
//
// 为什么只做"检查"、不做"自动下载替换"（评估结论）：
//  1. 客户在医院内网，多半直连不了 github.com —— 自动更新会变成一个"总在失败的按钮"。
//     真要一键更新，得先有**可达的更新源**（内网镜像 / 对象存储上的一个静态文件）。
//  2. 无人值守地替换程序，会让现场排障时"程序什么时候变的"说不清；
//     所以哪怕以后做，也应该是「点一下 → 显示新版本和说明 → 再点确认 → 校验哈希 → 替换重启」。
//  3. 替换正在运行的 exe 在 Windows 上要走"改名自己 → 写新文件 → 重启 → 清理"这套，
//     还要带回滚，属于要做就得做扎实的活（约 1 天），不急在这一步。
//
// 现在这一步：查最新的 Release 标签，和当前版本比一比，只读、不改任何东西。

// UpdateInfo 检查更新的结果。
type UpdateInfo struct {
	Current   string `json:"current"`   // 当前版本
	Latest    string `json:"latest"`    // 最新版本（查不到时为空）
	HasNew    bool   `json:"hasNew"`    // 是否有新版本
	URL       string `json:"url"`       // 下载页
	Note      string `json:"note"`      // 一句话结论（直接显示给用户）
	Published string `json:"published"` // 最新版发布时间
	Dev       bool   `json:"dev"`       // 当前是本地/dev 构建（不做版本比较）
}

// CheckUpdate 查 GitHub 上的最新 Release 并与当前版本比较。
// 查不到（内网不通、限流）时返回 note 说明原因，不当作错误 —— 界面只展示一句话。
func (b *Backend) CheckUpdate() UpdateInfo {
	info := UpdateInfo{Current: Version, URL: releasesURL, Dev: Version == "" || Version == "dev"}
	if info.Dev {
		info.Note = "这是本地/dev 构建，没有版本号可比。正式包在下载页。"
		return info
	}
	latest, published, err := latestRelease()
	if err != nil {
		info.Note = "查不到最新版本（" + err.Error() + "）—— 内网可能连不上 github.com，可直接打开下载页看看。"
		return info
	}
	info.Latest, info.Published = latest, published
	if cmpVersion(latest, Version) > 0 {
		info.HasNew = true
		info.Note = fmt.Sprintf("有新版本 %s（当前 %s），点下面的下载页拿新包。", latest, Version)
	} else {
		info.Note = fmt.Sprintf("已是最新（%s）。", Version)
	}
	return info
}

// latestRelease 调 GitHub API 拿最新 Release 的标签与时间。
// 为什么不用"看 Release 页面 HTML"：HTML 会变，API 稳定且能拿到 tag。
func latestRelease() (tag, published string, err error) {
	const api = "https://api.github.com/repos/Lithivm/NetHub/releases/latest"
	req, err := http.NewRequest(http.MethodGet, api, nil)
	if err != nil {
		return "", "", err
	}
	// GitHub 要求带 User-Agent，否则 403
	req.Header.Set("User-Agent", "NetHub/"+Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("网络不通")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("读取失败")
	}
	var out struct {
		TagName     string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
		Draft       bool   `json:"draft"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("响应看不懂")
	}
	if out.TagName == "" || out.Draft {
		return "", "", fmt.Errorf("没有正式版本")
	}
	if len(out.PublishedAt) >= 10 {
		out.PublishedAt = out.PublishedAt[:10]
	}
	return out.TagName, out.PublishedAt, nil
}

// cmpVersion 比版本号：返回 a>b ? 1 : a<b ? -1 : 0。
// 只认 vX.Y.Z 这种形式；有非数字后缀（-rc1）就只比数字部分。
func cmpVersion(a, b string) int {
	pa, pb := verNums(a), verNums(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] > pb[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}

func verNums(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v = strings.SplitN(v, "-", 2)[0]
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimFunc(part, func(r rune) bool { return r < '0' || r > '9' }))
		out[i] = n
	}
	return out
}

// ───────── 一键更新：下载 → 校验 → 替换 → 自动重启 ─────────

// 更新进度（界面每 0.5 秒轮询一次）。
type UpdateStatus struct {
	Stage       string `json:"stage"`   // idle|check|download|verify|stage|swap|restart|done|error
	Text        string `json:"text"`    // 人话描述（直接显示）
	Percent     int    `json:"percent"` // 0-100，未知时 -1
	Err         string `json:"err"`
	NeedRestart bool   `json:"needRestart"`
}

var (
	updMu     sync.Mutex
	updStatus = UpdateStatus{Stage: "idle", Percent: -1}
)

func setUpd(stage, text string, pct int) {
	updMu.Lock()
	updStatus = UpdateStatus{Stage: stage, Text: text, Percent: pct}
	updMu.Unlock()
}

func setUpdErr(err error) {
	updMu.Lock()
	updStatus = UpdateStatus{Stage: "error", Text: "更新失败", Percent: -1, Err: err.Error()}
	updMu.Unlock()
}

// GetUpdateStatus 当前更新进度。
func (b *Backend) GetUpdateStatus() UpdateStatus {
	updMu.Lock()
	defer updMu.Unlock()
	return updStatus
}

// DownloadAndUpdate 下载最新 Release 包 → 校验 → 暂存 → 换 exe → 自动重启。
//
// 为什么敢在客户机上自动重启：因为这是用户**明确点的一个按钮**，
// 而且替换过程本身是原子的（换 exe 用改名+写入，被占用的 DLL 留到重启后、
// 装载驱动之前再换）。失败时上一版本还在（nethub.exe.old），可一键回滚。
func (b *Backend) DownloadAndUpdate() error {
	updMu.Lock()
	if updStatus.Stage == "download" || updStatus.Stage == "verify" || updStatus.Stage == "stage" {
		updMu.Unlock()
		return fmt.Errorf("已经在更新了")
	}
	updMu.Unlock()

	go func() {
		setUpd("check", "正在查最新版本…", -1)
		rel, err := latestReleaseFull()
		if err != nil {
			setUpdErr(err)
			return
		}
		if cmpVersion(rel.TagName, Version) <= 0 && Version != "dev" {
			setUpd("done", "已经是最新版本（"+Version+"）", 100)
			return
		}
		asset, err := pickAsset(rel)
		if err != nil {
			setUpdErr(err)
			return
		}

		progDir := dirOf(b.a.Cfg.Path())
		if progDir == "" {
			progDir = "."
		}
		// 下载到程序目录下的 update/（同盘写入才能原子替换）
		if err := os.MkdirAll(filepath.Join(progDir, selfupdate.StageDirName), 0o755); err != nil {
			setUpdErr(err)
			return
		}
		zipPath := filepath.Join(progDir, selfupdate.StageDirName, "download.zip")

		setUpd("download", "正在下载 "+asset.Name+"…", 0)
		if err := downloadWithProgress(asset.URL, zipPath); err != nil {
			setUpdErr(err)
			return
		}

		if asset.SHA256 != "" {
			setUpd("verify", "正在校验完整性…", -1)
			sum, err := fileSHA256(zipPath)
			if err != nil {
				setUpdErr(err)
				return
			}
			if !strings.EqualFold(sum, asset.SHA256) {
				setUpdErr(fmt.Errorf("下载包校验不通过（期望 %s…，实际 %s…），已中止，没有动你的程序",
					asset.SHA256[:12], sum[:12]))
				return
			}
		} else {
			b.a.Bus.Warn("更新包没有官方摘要可校验（GitHub 未提供），只做了结构校验")
		}

		setUpd("stage", "正在解包…", -1)
		pend, err := selfupdate.Stage(zipPath, progDir, rel.TagName, os.Getpid())
		if err != nil {
			setUpdErr(err)
			return
		}
		setUpd("swap", "正在替换程序文件…", -1)
		if err := selfupdate.SwapRunningExe(progDir); err != nil {
			setUpdErr(err)
			return
		}

		exe, err := os.Executable()
		if err != nil {
			setUpdErr(err)
			return
		}
		b.a.Bus.Warn("已更新到 %s（替换 %s）；正在自动重启…", pend.Version, selfupdate.Describe(pend.Files))
		setUpd("restart", "已更新到 "+pend.Version+"，正在重启…", 100)

		// 起新进程（带 -after-update：它会先等我们退出，再替换被占用的 DLL）
		cmd := exec.Command(exe, "-after-update")
		cmd.Dir = progDir
		if err := cmd.Start(); err != nil {
			setUpdErr(fmt.Errorf("启动新版本失败（旧版本已保留为 nethub.exe.old，可回滚）: %w", err))
			return
		}
		time.Sleep(700 * time.Millisecond) // 让新进程先把界面起来
		b.Quit()
	}()
	return nil
}

// RestartForUpdate 手动触发"重启并完成更新"（新进程侧用不到，留给界面兜底）。
func (b *Backend) RollbackUpdate() error {
	progDir := dirOf(b.a.Cfg.Path())
	if progDir == "" {
		progDir = "."
	}
	if !selfupdate.HasRollback(progDir) {
		return fmt.Errorf("没有可回滚的上一版本")
	}
	if err := selfupdate.Rollback(progDir); err != nil {
		return err
	}
	b.a.Bus.Warn("已回滚上一版本，正在重启…")
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "-after-update")
	cmd.Dir = progDir
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	b.Quit()
	return nil
}

// ───────── GitHub 细节 ─────────

type ghRelease struct {
	TagName string    `json:"tag_name"`
	HTMLURL string    `json:"html_url"`
	Assets  []ghAsset `json:"assets"`
	Draft   bool      `json:"draft"`
}

type ghAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"` // 形如 sha256:xxxx（GitHub 较新的 API 才有）
	Size   int64  `json:"size"`
	// 校验用（整理后）
	SHA256 string `json:"-"`
}

func latestReleaseFull() (ghRelease, error) {
	const api = "https://api.github.com/repos/Lithivm/NetHub/releases/latest"
	var rel ghRelease
	req, err := http.NewRequest(http.MethodGet, api, nil)
	if err != nil {
		return rel, err
	}
	req.Header.Set("User-Agent", "NetHub/"+Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	cl := &http.Client{Timeout: 15 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return rel, fmt.Errorf("连不上 github.com（客户内网可能不让出网；有 Clash 的话确认它在跑）")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("GitHub 返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return rel, err
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return rel, fmt.Errorf("看不懂 GitHub 的响应")
	}
	if rel.TagName == "" || rel.Draft {
		return rel, fmt.Errorf("还没有正式发布的版本")
	}
	for i := range rel.Assets {
		if d := rel.Assets[i].Digest; strings.HasPrefix(d, "sha256:") {
			rel.Assets[i].SHA256 = strings.TrimPrefix(d, "sha256:")
		}
	}
	return rel, nil
}

// pickAsset 选更新包：优先 NetHub.zip，其次任意 zip。
func pickAsset(rel ghRelease) (ghAsset, error) {
	for _, a := range rel.Assets {
		if strings.EqualFold(a.Name, "NetHub.zip") {
			return a, nil
		}
	}
	for _, a := range rel.Assets {
		if strings.HasSuffix(strings.ToLower(a.Name), ".zip") {
			return a, nil
		}
	}
	return ghAsset{}, fmt.Errorf("这个版本没有提供 zip 包（%s）", rel.TagName)
}

// downloadWithProgress 流式下载并回报进度。
func downloadWithProgress(url, dst string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NetHub/"+Version)
	cl := &http.Client{Timeout: 10 * time.Minute}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败：HTTP %d", resp.StatusCode)
	}
	total := resp.ContentLength
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	var got int64
	last := time.Now()
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			got += int64(n)
			if total > 0 && time.Since(last) > 200*time.Millisecond {
				last = time.Now()
				setUpd("download", fmt.Sprintf("正在下载… %.1f / %.1f MB", float64(got)/1e6, float64(total)/1e6),
					int(got*100/total))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("下载中断：%w", err)
		}
	}
	return nil
}

// fileSHA256 文件摘要（十六进制）。
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
