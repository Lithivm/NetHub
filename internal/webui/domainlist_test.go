package webui

import (
	"reflect"
	"testing"
)

// 「强制本机解析的域名」这一栏是给人手填的：允许贴多行、允许空行与 # 注释、允许重复。
// 清洗必须在后端做 —— 前端只按行拆，脏数据进了匹配器就是“永远不命中的垃圾项”。
func TestCleanDomainList(t *testing.T) {
	got := cleanDomainList([]string{
		"  main.his.com  ",
		"",
		"# 影像库",
		"*.hospital.cn",
		"main.his.com",                // 重复
		"db.hospital.cn\nopm.his.com", // 一次贴两行
	})
	want := []string{"main.his.com", "*.hospital.cn", "db.hospital.cn", "opm.his.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cleanDomainList = %#v，想要 %#v", got, want)
	}
	if got := cleanDomainList(nil); got == nil || len(got) != 0 {
		t.Errorf("nil 入参应当给空切片（前端要能安全 join）")
	}
}
