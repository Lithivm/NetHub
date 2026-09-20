// Package netx 放与网络地址有关的小工具（规则目标、配置归一化都要用）。
package netx

import (
	"fmt"
	"strings"
)

// IsWildcardIP 判断是否是 Proxifier 风格的 IP 通配，形如 10.100.100.*
// （只允许 * 出现在最后一段；10.*.100.5 这种猜不出范围的不算）。
func IsWildcardIP(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 4 && parts[3] == "*"
}

// WildcardToCIDR 把 10.100.100.* 展开成 10.100.100.0/24。
//
// 语义就是"整段"（和 Proxifier 一致）；展开成 CIDR 之后，配置、规则、
// 内核过滤器都只需要认识 CIDR 一种东西。
func WildcardToCIDR(s string) (string, error) {
	parts := strings.Split(s, ".")
	if !IsWildcardIP(s) {
		return "", fmt.Errorf("这种写法猜不出范围 —— 末尾一段才能用 *（如 10.100.100.*）；" +
			"其他情况请写 CIDR（如 10.100.0.0/16）")
	}
	for _, p := range parts[:3] {
		if p == "" || len(p) > 3 {
			return "", fmt.Errorf("%q 不是合法的 IP 段", s)
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return "", fmt.Errorf("%q 不是合法的 IP 段（* 只能出现在最后一段）", s)
			}
		}
	}
	return strings.Join(parts[:3], ".") + ".0/24", nil
}
