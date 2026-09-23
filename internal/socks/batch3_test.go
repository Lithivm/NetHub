package socks

import (
	"strings"
	"testing"
	"time"
)

// 回归：ATYP=域名 是 1 字节长度，超长域名必须被拒（否则 byte(256)==0 → 空域名 + 字节错位，
// 可能连到完全不同的目标）。
func TestDialTLSHostRejectsBadLength(t *testing.T) {
	_, err := DialTLSHost("127.0.0.1:1", Creds{}, nil, strings.Repeat("a", 256), 80, time.Second)
	if err == nil {
		t.Fatal("256 字节域名应当被拒绝")
	}
	_, err = DialTLSHost("127.0.0.1:1", Creds{}, nil, "", 80, time.Second)
	if err == nil {
		t.Fatal("空域名应当被拒绝")
	}
}
