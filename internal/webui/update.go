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

// 更新：先只读地「检查」，用户点了才走完整的「下载 → 校验 → 替换 → 重启」。
//
// 分两段是因为风险和前提不同：
//
//  1. CheckUpdate 只读、不改任何东西 —— 查 GitHub 最新 Release 标签跟当前版本比一比。
//     查不到（内网不通、限流）**不当作错误**，只回一句 note：界面不该因为网络不通就报红。
//  2. 一键更新（UpdateNow）是用户**明确点按钮**之后才走的：下载 zip → 校验（PE 头 + sha256）
//     → 解到 update/ 并写 pending.json → 换掉正在跑的 exe → 拉起新进程 →
//     新进程在**装载 WinDivert 之前**收尾那些当时被占用的 DLL/驱动。
//     运行中的 exe/DLL 在 Windows 上覆盖不掉，所以这套必须跨进程做，脏活在 internal/selfupdate。
//     失败或想反悔都能一键回滚：旧版本一直留着（nethub.exe.old），`-rollback` 换回来。
//     同一套逻辑拆成了独立函数 `UpdateNow`（不是只写成 Backend 方法），
//     本意是让命令行也能跑一遍、从而能被脚本化验证 ——
//     但**那个命令行入口当时没接上**（`-update-now` 这个 flag 不存在），
//     现在只有界面上的「下载并更新」在调它。要脚本化验证得先把 flag 补上。
//
// **真正的前提是「更新源可达」**：客户在医院内网时多半直连不了 github.com，
// 那时「下载并更新」会失败（「检查更新」也只会回一句查不到）。
// 要让它可用，得先有一个内网可达的静态更新源（内网镜像 / 对象存储），
// 而**不是**改这段代码 —— 当前没有，所以内网现场请走「手工拷 NetHub.zip」那条路。

// 自动检查更新：启动后查一次，之后每 updateCheckEvery 再查一次。
//
// 为什么要自动查：以前只有用户点「关于」卡上那个按钮才查 —— 现场多半不会点，
// 于是“有新版本”永远没人知道，而漏更新正好会漏掉我们修过的那些坑。
// 现在查到会挂**常驻告警条**（不自动消失），人不在电脑前回来也能看到。
//
// 静默条件（都不挂告警条，也不报错）：
//   - dev 构建：没有版本号可比（UpdateInfo.Dev）
//   - 查不到：客户内网直连不了更新源是常态，不该因此报红
const updateCheckEvery = 6 * time.Hour

func (b *Backend) startUpdateCheck() {
	go func() {
		// 先等几秒：刚启动时引擎、hosts、DNS 都在装配，没必要跟它们抢日志与网络
		time.Sleep(8 * time.Second)
		for {
			b.checkUpdateQuiet()
			time.Sleep(updateCheckEvery)
		}
	}()
}

// checkUpdateQuiet 查一次并把结果缓存下来（Notices 会用它决定挂不挂告警条）。
func (b *Backend) checkUpdateQuiet() {
	info := b.CheckUpdate()
	b.updInfoMu.Lock()
	b.updInfoLast = info
	b.updInfoMu.Unlock()

	switch {
	case info.Dev:
		b.a.Bus.Detail("更新检查：本地/dev 构建，跳过版本比较")
	case info.HasNew:
		b.a.Bus.Warn("发现新版本 %s（当前 %s）—— 界面顶部会挂一条告警，到「设置 → 关于」可一键更新",
			info.Latest, info.Current)
	default:
		// 查不到也走这条（Note 里会写清原因），不报错、不打扰
		b.a.Bus.Detail("更新检查：%s（当前 %s）", strings.TrimSpace(info.Note), info.Current)
	}
}

// updateInfo 最近一次自动检查的结果（没查过就返回零值 = 不挂告警条）。
func (b *Backend) updateInfo() UpdateInfo {
	b.updInfoMu.Lock()
	defer b.updInfoMu.Unlock()
	return b.updInfoLast
}

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
// UpdateNow 执行一次完整更新：查 → 下载 → 校验 → 暂存 → 换 exe → 拉起新进程。
//
// 为什么拆成独立函数（而不是只写成 Backend 方法）：本意是让命令行也能跑、
// 以及避免界面和命令行各写一遍只修一处。
// **但命令行入口从没接上**（`-update-now` 这个 flag 在 main.go 里不存在），
// 现在唯一的调用方是界面按钮 `DownloadAndUpdate`。
//
// 返回新版本号；没有新版本时返回 "" 且 err 为 nil。progress 可为 nil。
func UpdateNow(progDir string, progress func(stage, text string, pct int)) (string, error) {
	if progress == nil {
		progress = func(string, string, int) {}
	}
	if progDir == "" {
		progDir = "."
	}
	progress("check", "正在查最新版本…", -1)
	rel, err := latestReleaseFull()
	if err != nil {
		return "", err
	}
	if Version != "dev" && cmpVersion(rel.TagName, Version) <= 0 {
		return "", nil // 已是最新
	}
	asset, err := pickAsset(rel)
	if err != nil {
		return "", err
	}

	// 下载到程序目录下的 update/（同盘写入才能原子替换）
	if err := os.MkdirAll(filepath.Join(progDir, selfupdate.StageDirName), 0o755); err != nil {
		return "", err
	}
	zipPath := filepath.Join(progDir, selfupdate.StageDirName, "download.zip")
	progress("download", "正在下载 "+asset.Name+"…", 0)
	if err := downloadWithProgress(asset.URL, zipPath, progress); err != nil {
		return "", err
	}

	// 摘要必须校验：下载走的是 HTTP + 各种代理/镜像，不能只靠“来源是 GitHub 就信”。
	// 官方 API 从 2025 起会给出 sha256 摘要；拿不到就拒绝自动更新（fail-closed）。
	if asset.SHA256 == "" {
		return "", fmt.Errorf("发布包没有 sha256 摘要，无法校验完整性 —— 已中止，没有动程序文件" +
			"（请到 GitHub Release 手动下载）")
	}
	progress("verify", "正在校验完整性…", -1)
	sum, err := fileSHA256(zipPath)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(sum, asset.SHA256) {
		return "", fmt.Errorf("下载包校验不通过（期望 %s…，实际 %s…），已中止，没有动程序文件",
			asset.SHA256[:12], sum[:12])
	}

	progress("stage", "正在解包…", -1)
	pend, err := selfupdate.Stage(zipPath, progDir, rel.TagName, os.Getpid())
	if err != nil {
		return "", err
	}
	progress("swap", "正在替换程序文件…", -1)
	if err := selfupdate.SwapRunningExe(progDir); err != nil {
		return "", err
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	// 起新进程：它带 -after-update，会先等本进程退出、再替换被占用的 DLL。
	// 原始参数一并带过去（例如 -no-elevate）：重启不该偷偷改变提权行为。
	args := append([]string{"-after-update"}, os.Args[1:]...)
	cmd := exec.Command(exe, args...)
	cmd.Dir = progDir
	if err := cmd.Start(); err != nil {
		return pend.Version, fmt.Errorf("新版本已就位，但启动失败（旧版本保留为 nethub.exe.old，可用 -rollback 回滚）: %w", err)
	}
	return pend.Version, nil
}

// DownloadAndUpdate 界面上的「下载并更新」：跑一遍 UpdateNow，成功后退出界面让新进程接手。
func (b *Backend) DownloadAndUpdate() error {
	updMu.Lock()
	busy := updStatus.Stage == "download" || updStatus.Stage == "verify" || updStatus.Stage == "stage" ||
		updStatus.Stage == "swap" || updStatus.Stage == "check"
	updMu.Unlock()
	if busy {
		return fmt.Errorf("已经在更新了")
	}

	progDir := dirOf(b.a.Cfg.Path())
	go func() {
		v, err := UpdateNow(progDir, func(stage, text string, pct int) {
			updMu.Lock()
			updStatus = UpdateStatus{Stage: stage, Text: text, Percent: pct}
			updMu.Unlock()
		})
		if err != nil {
			setUpdErr(err)
			return
		}
		if v == "" {
			setUpd("done", "已经是最新版本（"+Version+"）", 100)
			return
		}
		b.a.Bus.Warn("已更新到 %s，正在自动重启…", v)
		setUpd("restart", "已更新到 "+v+"，正在重启…", 100)
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
	args := append([]string{"-after-update"}, os.Args[1:]...)
	cmd := exec.Command(exe, args...)
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
func downloadWithProgress(url, dst string, progress func(stage, text string, pct int)) error {
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
				progress("download", fmt.Sprintf("正在下载… %.1f / %.1f MB", float64(got)/1e6, float64(total)/1e6), int(got*100/total))
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
