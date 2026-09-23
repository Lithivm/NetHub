package netx

import "testing"

// 回归：IP 通配的前三段必须校验 0-255，不能只数位数。
// "999.1.1.*" 以前会生成 "999.1.1.0/24"（非法 CIDR），要到更下游才报错、方向还指错。
func TestWildcardToCIDRValidatesOctets(t *testing.T) {
	if _, err := WildcardToCIDR("999.1.1.*"); err == nil {
		t.Fatal("999 超出 0-255，应当报错")
	}
	if _, err := WildcardToCIDR("256.0.0.*"); err == nil {
		t.Fatal("256 超出 0-255，应当报错")
	}
	got, err := WildcardToCIDR("10.100.100.*")
	if err != nil || got != "10.100.100.0/24" {
		t.Fatalf("正常写法应得到 10.100.100.0/24，得到 %q, %v", got, err)
	}
	got, err = WildcardToCIDR("0.0.0.*")
	if err != nil || got != "0.0.0.0/24" {
		t.Fatalf("0 段应合法，得到 %q, %v", got, err)
	}
}
