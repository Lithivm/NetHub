package engine

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// A19 抓包：产出的必须是 Wireshark 能直接打开的标准 pcap（magic/版本/链路类型/包记录长度）。
func TestCaptureWritesValidPcap(t *testing.T) {
	dir := t.TempDir()
	c := newCapturer()
	t.Cleanup(func() { c.stop() }) // Windows 上文件开着就删不掉临时目录
	path, err := c.start(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	pkt := mkPkt(60)
	for i := 0; i < 5; i++ {
		c.note(pkt)
	}
	on, gotPath, written, packets, _ := c.status()
	if !on || packets != 5 {
		t.Fatalf("状态不对：on=%v packets=%d", on, packets)
	}
	if gotPath != path {
		t.Errorf("路径不一致：%s vs %s", gotPath, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 头部 24 字节：magic d4 c3 b2 a1（小端 .pcap）+ ver 2.4 + snaplen + LINKTYPE_RAW(101)
	if len(raw) < 24 {
		t.Fatalf("文件太小：%d", len(raw))
	}
	if raw[0] != 0xd4 || raw[1] != 0xc3 || raw[2] != 0xb2 || raw[3] != 0xa1 {
		t.Errorf("pcap magic 不对：%x", raw[:4])
	}
	if v := binary.LittleEndian.Uint32(raw[20:24]); v != 101 {
		t.Errorf("链路类型应为 101(RAW)，得到 %d", v)
	}
	// 包记录：16 字节头 + 数据，incl==orig
	off := 24
	for i := 0; i < 5; i++ {
		if off+16 > len(raw) {
			t.Fatalf("第 %d 个包记录不完整", i+1)
		}
		incl := binary.LittleEndian.Uint32(raw[off+8:])
		orig := binary.LittleEndian.Uint32(raw[off+12:])
		if incl != orig || int(incl) != len(pkt) {
			t.Fatalf("第 %d 个包长度字段不对：incl=%d orig=%d", i+1, incl, orig)
		}
		off += 16 + int(incl)
	}
	if off != len(raw) {
		t.Errorf("文件尾部有多余/缺失字节：off=%d len=%d", off, len(raw))
	}
	if written != int64(len(raw)) {
		t.Errorf("统计的字节数与文件不符：%d vs %d", written, len(raw))
	}
}

// 到上限必须“停”，不能无限涨，也不能静默丢弃（文件末尾要有说明）。
func TestCaptureStopsAtLimit(t *testing.T) {
	dir := t.TempDir()
	c := newCapturer()
	t.Cleanup(func() { c.stop() })
	c.max = 1024 // 手动压小上限（start 会用 MB 换算）
	if _, err := c.start(filepath.Join(dir, "x"), 1); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.max = 1024
	c.mu.Unlock()
	pkt := mkPkt(200)
	for i := 0; i < 100; i++ {
		c.note(pkt)
	}
	on, _, _, _, reason := c.status()
	if on {
		t.Error("到上限后应停止抓包")
	}
	if reason == "" {
		t.Error("停止时要给出原因（供界面显示）")
	}
	fi, err := os.Stat(c.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 2048 {
		t.Errorf("到上限还在涨：%d 字节", fi.Size())
	}
}
