package hostsmgr

import (
	"strings"
	"testing"
)

// 回归：块外一条**别名行**（1.2.3.4 a b）里只要有我们要管的名字，整行都要被接管。
// 旧实现只看每行的第一个主机名，于是 `1.2.3.4 other ours` 会被留下 ——
// 而 Windows 取第一条匹配，我们写的那条等于没用。
func TestApplyTakesOverAliasLine(t *testing.T) {
	p := setup(t, "# 原始内容\n1.2.3.4 other.example ours.example\n")
	if _, err := Apply([]string{"10.0.0.5 ours.example"}); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	full := readFile(t, p)
	if strings.Contains(full, "1.2.3.4 other.example") {
		t.Fatalf("块外别名行没被接管，Windows 仍会先用它:\n%s", full)
	}
	if !strings.Contains(full, "10.0.0.5 ours.example") {
		t.Fatalf("我们的条目没写进去:\n%s", full)
	}
}
