// Package gostbat 读旧的 gost 批处理脚本（.bat），把 -L/-F 解析成我们的链配置。
//
// 注意：本包**不启动 gost**。上游能力（socks5+tls + 认证 + CONNECT）已在
// internal/upstream 原生实现，用户机器不需要装 gost。这里存在的唯一理由是
// 兼容从旧脚本导入 —— 脚本里的 -F 就是我们的上游 URL。
package gostbat

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"nethub/internal/config"
)

// BatEntry 一个 .bat 解析出来的结果。
type BatEntry struct {
	File    string // 文件名（不含目录）
	Listen  string // 已归一化（回环）的监听地址
	Forward string // 上游转发 URL（可能含凭据）
}

// ParseBatText 从 bat 文本里抓出第一组 -L / -F 的值。
// 只支持 -L "..." / -F "..." 这种带引号的写法（两个旧 bat 都是这格式）。
func ParseBatText(s string) (listen, forward string) {
	get := func(flagName string) string {
		i := strings.Index(s, flagName)
		if i < 0 {
			return ""
		}
		rest := s[i+len(flagName):]
		q := strings.Index(rest, `"`)
		if q < 0 || q > 8 {
			return ""
		}
		rest = rest[q+1:]
		e := strings.Index(rest, `"`)
		if e < 0 {
			return ""
		}
		return rest[:e]
	}
	l, f := get("-L"), get("-F")
	l = strings.TrimPrefix(l, "socks5://")
	f = strings.TrimPrefix(f, "socks5://")
	if i := strings.Index(l, "?"); i >= 0 {
		l = l[:i]
	}
	return l, f
}

// ParseBatFile 读一个 .bat 并解析。第二个返回值 ok=false 表示这文件里没有可用的 -L/-F。
func ParseBatFile(path string) (BatEntry, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return BatEntry{}, false
	}
	l, f := ParseBatText(string(b))
	if l == "" || f == "" {
		return BatEntry{}, false
	}
	return BatEntry{File: filepath.Base(path), Listen: config.NormalizeListenLoose(l), Forward: f}, true
}

// Name 从 bat 文件名推链名：gost-lan-a.bat → lan-a。
func (e BatEntry) Name() string {
	n := e.File
	if i := strings.LastIndex(n, "."); i > 0 {
		n = n[:i]
	}
	n = strings.TrimPrefix(n, "gost-")
	n = strings.TrimPrefix(n, "gost_")
	return strings.TrimSpace(n)
}

// ScanBatDir 扫描目录下所有 *.bat，返回解析成功的条目（按文件名排序，保证顺序稳定）。
func ScanBatDir(dir string) []BatEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []BatEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".bat") {
			continue
		}
		if be, ok := ParseBatFile(filepath.Join(dir, e.Name())); ok {
			out = append(out, be)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

// Redact 遮蔽上游 URL 里的凭据，用于界面/日志显示。
func Redact(s string) string {
	if s == "" {
		return "(未配置)"
	}
	if i := strings.Index(s, "auth="); i >= 0 {
		tail := ""
		if j := strings.IndexAny(s[i:], "&"); j >= 0 {
			// 保留 auth 之后可能存在的其它参数
			tail = s[i+j:]
			if tail == "&" {
				tail = ""
			}
		}
		return s[:i] + "auth=***" + tail
	}
	if at := strings.Index(s, "@"); at >= 0 {
		if sl := strings.Index(s, "://"); sl >= 0 && sl+3 < at {
			return s[:sl+3] + "***@" + s[at+1:]
		}
	}
	return s
}

// SplitListen 拆 "host:port"，供界面校验用。
func SplitListen(s string) (host, port string, err error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("缺少端口号")
	}
	host, port = s[:i], s[i+1:]
	if port == "" {
		return "", "", fmt.Errorf("缺少端口号")
	}
	return host, port, nil
}
