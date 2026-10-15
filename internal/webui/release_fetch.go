// 查最新版本 / 取发布包信息时，**优先走不消耗 GitHub API 配额的路**。
//
// 为什么（2026-10-16 实测）：GitHub 匿名 API 的额度是 **60 次/小时，按出口 IP 计**。
// 现场机器经 Clash 的「系统代理」出公网，出口是一个共享节点 —— 实测本机那个出口的
// 额度已经用光，`api.github.com` 直接回 `403 rate limit exceeded`。
// 也就是说"把系统代理接上"只是第一步：只要更新流程里还有一步非走 API 不可，
// 在共享出口的机器上就会随机失败（而且报的是一句看不懂的 403）。
//
// 所以三条路按"零配额优先"排：
//
//	查版本   github.com/OWNER/REPO/releases/latest 的 302 Location   ← 不消耗配额
//	包与摘要 github.com/OWNER/REPO/releases/expanded_assets/<tag> 的 HTML ← 不消耗配额
//	API      api.github.com/repos/.../releases/latest               ← 只作保底（顺带给发布时间）
//
// 安全：HTML 里那个 sha256 与 API 的 digest 是同一条（2026-10-16 实测逐位一致）。
// **解析不出来时不猜** —— 回退 API，都拿不到就返回"有版本号但没有摘要"，
// 由上层 fail-closed 拒绝自动更新（绝不"来源是 GitHub 就信"）。
package webui

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const repoOwnerRepo = "Lithivm/NetHub"

// 这两个地址在测试里会被换成本地 httptest 服务，所以用变量。
var (
	releasesLatestURL = "https://github.com/" + repoOwnerRepo + "/releases/latest"
	releasesAssetsURL = "https://github.com/" + repoOwnerRepo + "/releases/expanded_assets/"
)

// fetchLatestRelease 拿"最新版本 + 它的发布包"：零配额的两条路优先，API 保底。
func fetchLatestRelease() (ghRelease, error) {
	var rel ghRelease
	tag, err := latestTagViaRedirect()
	if err != nil {
		// 连 302 都拿不到（多半是出不去的网）：交给 API 那条路报错，错误信息更全
		return latestReleaseByAPI()
	}
	rel.TagName = tag
	if assets, err := assetsViaHTML(tag); err == nil && len(assets) > 0 {
		rel.Assets = assets
		return rel, nil
	}
	// HTML 解析不出来（GitHub 改版？）：回退 API，顺带把发布时间补上
	if apiRel, err := latestReleaseByAPI(); err == nil {
		return apiRel, nil
	}
	// 都不行：包名是我们自己定的（发布流程固定产出 NetHub.zip），地址能直接拼出来；
	// 但**摘要拼不出来** —— 上层会因此 fail-closed 拒绝，这里不猜。
	rel.Assets = []ghAsset{{Name: "NetHub.zip", URL: releaseDownloadURL(tag, "NetHub.zip")}}
	return rel, nil
}

// latestTagViaRedirect 用 releases/latest 的 302 拿最新 tag —— 零配额、不需要解析正文。
func latestTagViaRedirect() (string, error) {
	req, err := http.NewRequest(http.MethodGet, releasesLatestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "NetHub/"+Version)
	cl := updateClient(10 * time.Second)
	// 只看 Location：不把那页 HTML 拖下来
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	loc := strings.TrimSpace(resp.Header.Get("Location"))
	if loc == "" || resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	const marker = "/releases/tag/"
	i := strings.LastIndex(loc, marker)
	if i < 0 {
		return "", fmt.Errorf("重定向地址看不懂：%s", loc)
	}
	tag := strings.Trim(strings.TrimSpace(loc[i+len(marker):]), "/")
	if tag == "" {
		return "", fmt.Errorf("重定向里没有版本号")
	}
	if un, err := url.PathUnescape(tag); err == nil {
		tag = un
	}
	return tag, nil
}

var (
	// 摘要按钮把"名字 ↔ 摘要"绑在一起，这是这一页里最稳的一处（比 href 表单还稳）
	reAssetDigest = regexp.MustCompile(
		`clipboard-button-sha256:([0-9a-fA-F]{64})"[^>]*aria-label="Copy to clipboard digest for ([^"]+)"`)
	// 资产下载地址：/OWNER/REPO/releases/download/TAG/NAME
	reAssetHref = regexp.MustCompile(`href="(/[^"]*?/releases/download/[^"]*?/([^"/]+))"`)
)

// assetsViaHTML 从发布页的资产片段里读出 zip 包的名字、下载地址与 sha256 —— 零配额。
func assetsViaHTML(tag string) ([]ghAsset, error) {
	req, err := http.NewRequest(http.MethodGet, releasesAssetsURL+url.PathEscape(tag), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NetHub/"+Version)
	cl := updateClient(15 * time.Second)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	page := string(body)

	sums := map[string]string{}
	for _, m := range reAssetDigest.FindAllStringSubmatch(page, -1) {
		sums[html.UnescapeString(strings.TrimSpace(m[2]))] = strings.ToLower(m[1])
	}

	var out []ghAsset
	for _, m := range reAssetHref.FindAllStringSubmatch(page, -1) {
		name := html.UnescapeString(strings.TrimSpace(m[2]))
		if !strings.HasSuffix(strings.ToLower(name), ".zip") {
			continue // 只要更新包（.sha256 / 源码包之类与一键更新无关）
		}
		out = append(out, ghAsset{
			Name:   name,
			URL:    "https://github.com" + html.UnescapeString(m[1]),
			SHA256: sums[name],
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没解析出 zip 资产")
	}
	return out, nil
}

// releaseDownloadURL 拼发布包地址（包名是我们自己定的，必要时可以直接拼）。
func releaseDownloadURL(tag, name string) string {
	return "https://github.com/" + repoOwnerRepo + "/releases/download/" +
		url.PathEscape(tag) + "/" + url.PathEscape(name)
}

// latestReleaseByAPI 走 GitHub API（保底路径）：能一次拿到 tag、Asset URL 与摘要，
// 但**要花配额**，共享出口 IP 上很容易 403。
func latestReleaseByAPI() (ghRelease, error) {
	var rel ghRelease
	req, err := http.NewRequest(http.MethodGet,
		"https://api.github.com/repos/"+repoOwnerRepo+"/releases/latest", nil)
	if err != nil {
		return rel, err
	}
	req.Header.Set("User-Agent", "NetHub/"+Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	cl := updateClient(15 * time.Second)
	resp, err := cl.Do(req)
	if err != nil {
		// 不带"走的是哪条路"：这句会被夹进界面的 toast 里，
		// 那件事由外层（CheckUpdate 的结论 / 更新失败的提示）统一说一次。
		return rel, fmt.Errorf("连不上 github.com —— 客户内网可能不让出网；" +
			"靠 Clash 出外网的话，请在它里面打开「系统代理」（TUN 与本程序互斥，别开）")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 403 大多是配额的锅（出口 IP 共享），把话说明白，别让人以为是自己的网络坏了
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return rel, fmt.Errorf("GitHub 接口被限流（HTTP %d，匿名额度按出口 IP 计，共享代理节点容易用光）", resp.StatusCode)
		}
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
	if len(rel.PublishedAt) >= 10 {
		rel.PublishedAt = rel.PublishedAt[:10]
	}
	return rel, nil
}
