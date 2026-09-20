package netx

import "testing"

// IP 通配：只认“末尾一段是 *”，其余写法要给出能照着改的提示。
func TestWildcardToCIDR(t *testing.T) {
	ok := map[string]string{
		"10.100.100.*": "10.100.100.0/24",
		"172.30.4.*":   "172.30.4.0/24",
		"1.2.3.*":      "1.2.3.0/24",
	}
	for in, want := range ok {
		got, err := WildcardToCIDR(in)
		if err != nil {
			t.Errorf("%s 应该能展开，却报错 %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s → %s，期望 %s", in, got, want)
		}
		if !IsWildcardIP(in) {
			t.Errorf("%s 应被识别为通配", in)
		}
	}
	for _, bad := range []string{"10.*.100.5", "*", "10.100.*.5", "10.100.100.1", "10.100.100.0/24"} {
		if IsWildcardIP(bad) {
			t.Errorf("%s 不该被看成通配", bad)
			continue
		}
		if _, err := WildcardToCIDR(bad); err == nil {
			t.Errorf("%s 应该报错（猜不出范围）", bad)
		}
	}
}

// 形状像通配、但前三段不是数字：识别得出来，展开时要报错。
func TestWildcardNonNumeric(t *testing.T) {
	if !IsWildcardIP("abc.def.ghi.*") {
		t.Error("形状上是通配，应该识别出来（由展开那步报错）")
	}
	if _, err := WildcardToCIDR("abc.def.ghi.*"); err == nil {
		t.Error("前三段不是数字，必须报错")
	}
}
