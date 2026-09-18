// Package hostsmgr 管理系统 hosts 文件里"我们自己那一段"。
//
// 只动标记块之间的内容，块外一个字都不碰（Docker 的条目、微信的 pin 都在块外）。
// 写之前会留一次备份，写入用"临时文件 + 替换"，避免半截文件。
package hostsmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	beginMark = "# >>> NetHub 自动维护开始（勿手改本段内的内容）"
	endMark   = "# <<< NetHub 自动维护结束"
)

// isBegin 判定是否是"我们的区块开始"。
func isBegin(line string) bool {
	return strings.HasPrefix(line, beginMark)
}

// isEnd 判定是否是"我们的区块结束"。
func isEnd(line string) bool {
	return strings.HasPrefix(line, endMark)
}

// Path 返回系统 hosts 路径。
func Path() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

// Read 返回 (块内的行, 块是否存在, 整个文件内容, 错误)。
func Read() (block []string, exists bool, full string, err error) {
	b, err := os.ReadFile(Path())
	if err != nil {
		return nil, false, "", err
	}
	full = string(b)
	lines := strings.Split(full, "\n")
	in := false
	for _, l := range lines {
		t := strings.TrimRight(l, "\r")
		switch {
		case isBegin(t):
			in, exists = true, true
		case isEnd(t):
			in = false
		case in:
			if s := strings.TrimSpace(t); s != "" && !strings.HasPrefix(s, "#") {
				block = append(block, s)
			}
		}
	}
	return block, exists, full, nil
}

// Apply 把 entries 写进标记块（替换旧的块；没有块就追加到文件末尾）。
// 会先备份一次到 hosts.nethub.bak（只在备份不存在时创建，避免覆盖最初的原件）。
func Apply(entries []string) error {
	p := Path()
	_, _, full, err := Read()
	if err != nil {
		return err
	}

	// 备份（仅首次）
	bak := p + ".nethub.bak"
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		if err := os.WriteFile(bak, []byte(full), 0o644); err != nil {
			return fmt.Errorf("备份 hosts 失败: %w", err)
		}
	}

	// 保留原有的 BOM 状态
	bom := strings.HasPrefix(full, "\ufeff")
	body := strings.TrimPrefix(full, "\ufeff")

	// 去掉旧块
	var kept []string
	lines := strings.Split(body, "\n")
	skip := false
	for _, l := range lines {
		t := strings.TrimRight(l, "\r")
		switch {
		case isBegin(t):
			skip = true
			continue
		case isEnd(t):
			skip = false
			continue
		}
		if !skip {
			kept = append(kept, t)
		}
	}
	// 去掉尾部空行，稍后统一补一个换行
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}

	var out strings.Builder
	if bom {
		out.WriteString("\ufeff")
	}
	out.WriteString(strings.Join(kept, "\n"))
	out.WriteString("\n\n")
	out.WriteString(beginMark + "\n")
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		out.WriteString(e + "\n")
	}
	out.WriteString(endMark + "\n")

	tmp := p + ".nethub.tmp"
	if err := os.WriteFile(tmp, []byte(out.String()), 0o644); err != nil {
		return fmt.Errorf("写临时文件失败: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("替换 hosts 失败: %w", err)
	}
	return nil
}

// Remove 删掉我们的标记块（卸载/停用时调用）。
func Remove() error {
	p := Path()
	_, exists, full, err := Read()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	bom := strings.HasPrefix(full, "\ufeff")
	body := strings.TrimPrefix(full, "\ufeff")
	var kept []string
	skip := false
	for _, l := range strings.Split(body, "\n") {
		t := strings.TrimRight(l, "\r")
		switch {
		case isBegin(t):
			skip = true
			continue
		case isEnd(t):
			skip = false
			continue
		}
		if !skip {
			kept = append(kept, t)
		}
	}
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}
	s := strings.Join(kept, "\n") + "\n"
	if bom {
		s = "\ufeff" + s
	}
	return os.WriteFile(p, []byte(s), 0o644)
}
