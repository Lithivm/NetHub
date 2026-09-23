package webui

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"nethub/internal/config"
)

// 配置的导出与导入（「设置 → 配置：导出与导入」这张卡）。
//
// 设计取向：**一个文件就够**。
//   - 导出（含凭据）= 完整 config.yaml，新机器装好程序后「导入配置」选它即可开箱即用；
//   - 导出（无凭据）= 同样能导入的 config.yaml，只是把上游 URL 里的用户名/口令剔除
//     （适合发给人看、或存进仓库做版本记录）；
//   - 导入 = 选文件 → 先校验 → 自动备份当前 → 生效并重启；校验不过什么都不动。
//
// 刻意**不做**"装机包"（程序 + 驱动 + 配置 + 脚本打成一个 zip）：
// 程序怎么分发是发布流程的事（Release 附件），配置怎么给才是这个页面的职责，
// 混在一起只会让两件事都变复杂。

// ExportConfigRedacted 导出"能导入、但没凭据"的配置：上游 URL 里的用户名/口令被剔除。
func (b *Backend) ExportConfigRedacted() (string, error) {
	name := "nethub-config-无凭据.yaml"
	if p := b.a.Cfg.Path(); p != "" {
		name = filepath.Join(dirOf(p), name)
	}
	path, err := wruntime.SaveFileDialog(b.ctx, wruntime.SaveDialogOptions{
		Title:           "导出配置（无凭据，仍可导入）",
		DefaultFilename: name,
		Filters: []wruntime.FileFilter{
			{DisplayName: "配置文件 (*.yaml)", Pattern: "*.yaml"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	if !strings.HasSuffix(strings.ToLower(path), ".yaml") && !strings.HasSuffix(strings.ToLower(path), ".yml") {
		path += ".yaml"
	}
	if err := b.a.Cfg.SaveAsRedacted(path); err != nil {
		return "", err
	}
	b.a.Bus.Info("已导出无凭据配置：%s（可直接导入，需补上游口令）", filepath.Base(path))
	return path, nil
}

// ImportConfig 导入一个配置文件（.yaml/.yml，或含 config.yaml 的 .zip）。
//
// 顺序很讲究：**先校验 → 再备份 → 才落盘**。校验不过就什么都不动，
// 免得把一台正在干活的机器改成起不来。
func (b *Backend) ImportConfig() (string, error) {
	dir := dirOf(b.a.Cfg.Path())
	path, err := wruntime.OpenFileDialog(b.ctx, wruntime.OpenDialogOptions{
		Title:            "导入配置（.yaml 或含 config.yaml 的 .zip）",
		DefaultDirectory: dir,
		Filters: []wruntime.FileFilter{
			{DisplayName: "配置/压缩包 (*.yaml;*.yml;*.zip)", Pattern: "*.yaml;*.yml;*.zip"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil // 用户取消
	}

	raw, err := readConfigFile(path)
	if err != nil {
		return "", err
	}
	if _, err := b.importConfigFromRaw(path, raw); err != nil {
		return "", err
	}
	// 生效：重启服务（这一步在测试里会失败——引擎要驱动；配置本身已经落盘并生效）
	if err := b.a.Restart(); err != nil {
		return path, fmt.Errorf("配置已导入，但重启服务失败：%w", err)
	}
	return path, nil
}

// importConfigFrom 从文件导入（不含重启，便于测试）。
func (b *Backend) importConfigFrom(path string) (string, error) {
	raw, err := readConfigFile(path)
	if err != nil {
		return "", err
	}
	return b.importConfigFromRaw(path, raw)
}

// importConfigFromRaw 校验 → 备份 → 落盘 → 重新载入（内存里生效）。
func (b *Backend) importConfigFromRaw(srcPath string, raw []byte) (string, error) {
	// ① 先落成临时文件做校验（走真正的 Load/Validate 路径，不做"简化版校验"）
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("nethub-import-%d.yaml", time.Now().UnixNano()))
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return "", err
	}
	loaded, err := config.Load(tmp)
	if err != nil {
		return "", fmt.Errorf("这个配置不能用：%w", err)
	}
	if err := loaded.Validate(); err != nil {
		return "", fmt.Errorf("这个配置校验不过：%w", err)
	}

	// ② 备份当前（含时间戳，出问题能回滚）
	if err := b.a.Cfg.BackupNow(); err != nil {
		return "", err
	}
	// ③ 落盘并生效：保持 *b.a.Cfg 这个指针不变（引擎/规则都指着它）
	raw = ensurePathInFile(raw, b.a.Cfg.Path())
	if err := os.WriteFile(b.a.Cfg.Path(), raw, 0o600); err != nil {
		return "", err
	}
	cur, err := config.Load(b.a.Cfg.Path())
	if err != nil {
		return "", fmt.Errorf("导入后重新载入失败（已备份，可从 backups 目录回滚）：%w", err)
	}
	b.a.Cfg.ReplaceFrom(cur)
	b.a.Bus.Info("已导入配置：%s（%d 条链，%d 条规则）", filepath.Base(srcPath), len(cur.Chains), len(cur.Routes))
	return srcPath, nil
}

// readConfigFile 读配置：直接 .yaml，或从 .zip 里取第一份 yaml（优先 config.yaml）。
func readConfigFile(path string) ([]byte, error) {
	if !strings.EqualFold(filepath.Ext(path), ".zip") {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return raw, nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("打开压缩包失败: %w", err)
	}
	defer zr.Close()
	var fallback []byte
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.ToLower(filepath.Base(f.Name))
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(rc, 4<<20)) // 4MB 够放任何配置了
		rc.Close()
		if name == "config.yaml" || name == "config.yml" {
			return raw, nil
		}
		if fallback == nil {
			fallback = raw
		}
	}
	if fallback == nil {
		return nil, fmt.Errorf("压缩包里没有 .yaml/.yml 配置文件")
	}
	return fallback, nil
}

// ensurePathInFile 导入时不改对方的 relay 等字段，只做一件事：
// 把 exportedConfig 里可能残留的注释头补上，保持文件可读。
func ensurePathInFile(raw []byte, _ string) []byte {
	s := string(raw)
	if strings.HasPrefix(s, "#") {
		return raw
	}
	return []byte("# NetHub 配置 —— 由「导入配置」写入\n" + s)
}

// ImportConfigFromURL 从 URL 拉一份配置导入（集中更新配置的最小形态）。
//
// 刻意只做"手动触发"：自动轮询会引入"谁在什么时候把什么推到我机器上"的问题，
// 现场排障时最怕这种说不清的变化。要集中管理就先发个链接，让人点一下。
func (b *Backend) ImportConfigFromURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("请填配置地址（http/https）")
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "", fmt.Errorf("只支持 http/https 地址")
	}
	body, err := httpGet(rawURL)
	if err != nil {
		return "", err
	}
	if _, err := b.importConfigFromRaw(rawURL, body); err != nil {
		return "", err
	}
	if err := b.a.Restart(); err != nil {
		return rawURL, fmt.Errorf("配置已导入，但重启服务失败：%w", err)
	}
	return rawURL, nil
}

// httpGet 简单拉取（限时 20s、限 4MB）。
func httpGet(u string) ([]byte, error) {
	cl := &http.Client{Timeout: 20 * time.Second}
	resp, err := cl.Get(u)
	if err != nil {
		return nil, fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载失败：HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("读取失败：%w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("下载到的是空文件")
	}
	return body, nil
}
