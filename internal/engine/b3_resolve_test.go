package engine

import (
	"testing"

	"nethub/internal/config"
)

// B3：domain_resolve_local 命中时强制本机解析（压过全局策略）。
//
// 为什么这条要钉住：它是“公网域名交上游、内网域名必须本机”这种混合场景的唯一开关。
// 配错的后果很直接 —— 内网域名被交给公网上游解析，结果是连不上（且日志里只说超时）。
func TestResolveModeForHonorsLocalWhitelist(t *testing.T) {
	cfg := &config.Config{Tuning: config.Tuning{
		DomainResolve:      "upstream",
		DomainResolveLocal: []string{"main.his.com", "*.hospital.cn"},
	}}
	e := newTestEngine()
	e.cfg = cfg

	cases := []struct {
		host    string
		hasName bool
		want    string
		why     string
	}{
		{"main.his.com", true, "local", "精确命中白名单"},
		{"db.hospital.cn", true, "local", "通配命中白名单"},
		{"hospital.cn", true, "upstream", "通配不含裸域名（与规则里的通配语义一致）"},
		{"api.github.com", true, "upstream", "没命中白名单 → 按全局 upstream"},
		{"", false, "upstream", "没有域名时白名单不参与"},
	}
	for _, c := range cases {
		if got := e.resolveModeFor(c.host, c.hasName); got != c.want {
			t.Errorf("%s: resolveModeFor(%q, %v) = %q，想要 %q", c.why, c.host, c.hasName, got, c.want)
		}
	}

	// 全局是 local 时白名单不该改变什么（也不该刷日志）
	cfg2 := &config.Config{Tuning: config.Tuning{DomainResolve: "local", DomainResolveLocal: []string{"a.com"}}}
	e.cfg = cfg2
	if got := e.resolveModeFor("a.com", true); got != "local" {
		t.Errorf("全局 local + 白名单命中应当仍是 local，得到 %q", got)
	}
}
