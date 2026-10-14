package hostsmgr

import (
	"os"
	"testing"
)

// 缓存必须能看见**外部**改动（手工编辑 hosts、别的程序写的）—— 判据是 mtime+size。
func TestReadCacheSeesExternalChange(t *testing.T) {
	p := setup(t, "# 头\n")
	if _, exists, _, err := Read(); err != nil || exists {
		t.Fatalf("初始不该有块: exists=%v err=%v", exists, err)
	}
	// 不经过我们的写入路径，直接改文件（模拟手工编辑）
	if err := os.WriteFile(p, []byte(beginMark+"\n10.0.0.1 opm.his.com\n"+endMark+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	block, exists, _, err := Read()
	if err != nil || !exists || len(block) != 1 || block[0] != "10.0.0.1 opm.his.com" {
		t.Fatalf("外部改动没被看见（缓存没失效）: block=%v exists=%v err=%v", block, exists, err)
	}
}

// 写入路径必须**显式**失效缓存，不能只靠 mtime。
//
// 为什么这个测试要伸手改 cacheMTime/cacheSize：光靠「写完之后再 Read」是钉不住这件事的 ——
// 写新内容通常连 mtime 也变了，只靠 mtime 的实现照样能过。要复现真正的危险场景
// （同一个时钟刻度内连写两次、且新旧内容长度恰好相同），就得把缓存记的元数据
// 伪装成与当前文件一致：这时**只有显式失效能救**。同包测试，动内部变量是可接受的代价。
func TestWriteInvalidatesReadCache(t *testing.T) {
	setup(t, "# 头\n")
	if _, _, _, err := Read(); err != nil { // 先把缓存喂上（这是复现的前提）
		t.Fatal(err)
	}
	if _, err := Apply([]string{"172.30.4.217 main.his.com"}); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	cacheMu.Lock()
	if fi, e := os.Stat(Path()); e == nil {
		cacheMTime, cacheSize = fi.ModTime(), fi.Size()
	}
	cacheMu.Unlock()

	block, exists, _, err := Read()
	if err != nil || !exists || len(block) != 1 || block[0] != "172.30.4.217 main.his.com" {
		t.Fatalf("刚写进去却读到旧的（写入路径没有显式失效缓存）: block=%v exists=%v err=%v", block, exists, err)
	}

	if err := Remove(); err != nil {
		t.Fatalf("Remove 失败: %v", err)
	}
	cacheMu.Lock()
	if fi, e := os.Stat(Path()); e == nil {
		cacheMTime, cacheSize = fi.ModTime(), fi.Size()
	}
	cacheMu.Unlock()
	if _, exists, _, err := Read(); err != nil || exists {
		t.Fatalf("Remove 之后还看到块: exists=%v err=%v", exists, err)
	}
}

// 缓存返回的必须是拷贝：调用方改了不该把缓存本身改脏。
func TestReadCacheReturnsCopy(t *testing.T) {
	setup(t, beginMark+"\n1.2.3.4 a.test\n"+endMark+"\n")
	b1, _, _, err := Read()
	if err != nil || len(b1) != 1 {
		t.Fatalf("读失败: %v %v", b1, err)
	}
	b1[0] = "被调用方改坏了"
	b2, _, _, err := Read()
	if err != nil || len(b2) != 1 || b2[0] != "1.2.3.4 a.test" {
		t.Fatalf("缓存被调用方改脏了: %v", b2)
	}
}
