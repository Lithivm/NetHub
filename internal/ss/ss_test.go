package ss

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

// EVP_BytesToKey 是 shadowsocks 唯一"照抄 OpenSSL"的地方，写错了表现是
// "连不上但什么都看不出来" —— 所以这里用 crypto/md5 **自己再算一遍**（不是调用被测函数）。
func TestEVPBytesToKey(t *testing.T) {
	pass := "sesame"
	for _, keyLen := range []int{16, 24, 32} {
		want := manualEVP(pass, keyLen)
		got := EVPBytesToKey(pass, keyLen)
		if !bytes.Equal(got, want) {
			t.Errorf("keyLen=%d: 派生结果不对\n得到 %x\n期望 %x", keyLen, got, want)
		}
	}
}

func manualEVP(pass string, n int) []byte {
	var out, prev []byte
	for len(out) < n {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(pass))
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// 套件名的提示要"能照着改"：老流密码与 2022 的诉求不同，不能混成一句"不支持"。
func TestLookupHints(t *testing.T) {
	if _, err := Lookup("aes-256-cfb"); err == nil {
		t.Error("老式流密码应该被拒")
	} else if !bytes.Contains([]byte(err.Error()), []byte("aes-256-gcm")) {
		t.Errorf("报错里应该给出可用的替代: %v", err)
	}
	if _, err := Lookup("2022-blake3-aes-256-gcm"); err == nil {
		t.Error("2022 还没实现，应该报错而不是当成传统 AEAD")
	}
	if _, err := Lookup("AES-256-GCM"); err != nil {
		t.Errorf("套件名大小写不敏感: %v", err)
	}
}

// 读路径的**独立**验证：测试里手写一个服务端（按规范自己加解密，不复用被测代码），
// 于是"nonce 是小端计数器""chunk = 长度段+载荷段"这些细节错了就会被抓到 ——
// gost 互操作能抓，但要起进程；这个用例随时能跑。
func TestReadPathAgainstManualServer(t *testing.T) {
	cli, srv := tcpPair(t)
	defer cli.Close()
	defer srv.Close()

	cip, err := Lookup("aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	const password = "sesame"
	// 地址编码由调用方（upstream 侧）给：ss 包只管"把这段字节写进首块"。
	target := []byte{0x01, 10, 0, 0, 9, 0x15, 0x38}

	conn, err := ClientConn(cli, cip, password, target)
	if err != nil {
		t.Fatal(err)
	}

	gotAddr := make(chan []byte, 1)
	go func() {
		// ① 读客户端 salt 并派生 subkey（按 SIP004 手写）
		salt := make([]byte, cip.KeySize)
		if _, err := io.ReadFull(srv, salt); err != nil {
			t.Errorf("读 salt: %v", err)
			return
		}
		rk := make([]byte, cip.KeySize)
		if _, err := io.ReadFull(hkdf.New(sha1.New, manualEVP(password, cip.KeySize), salt, []byte("ss-subkey")), rk); err != nil {
			t.Errorf("派生 subkey: %v", err)
			return
		}
		blk, _ := aes.NewCipher(rk)
		aead, _ := cipher.NewGCM(blk)
		nonce := make([]byte, 12)
		openChunk := func() []byte {
			h := make([]byte, 2+aead.Overhead())
			if _, err := io.ReadFull(srv, h); err != nil {
				return nil
			}
			lb, err := aead.Open(nil, nonce, h, nil)
			if err != nil {
				t.Errorf("解长度失败: %v", err)
				return nil
			}
			incNonce(nonce)
			n := int(binary.BigEndian.Uint16(lb))
			b := make([]byte, n+aead.Overhead())
			if _, err := io.ReadFull(srv, b); err != nil {
				return nil
			}
			p, err := aead.Open(nil, nonce, b, nil)
			if err != nil {
				t.Errorf("解载荷失败: %v", err)
				return nil
			}
			incNonce(nonce)
			return p
		}
		gotAddr <- openChunk() // 首块 = 地址
		openChunk()            // 第二块 = 业务数据（ping）：先读掉再回，避免两端同时写

		// ② 回应方向：服务端自己的 salt + 自己的 nonce 计数器（从 0 开始）
		wsalt := make([]byte, cip.KeySize)
		_, _ = rand.Read(wsalt)
		wk := make([]byte, cip.KeySize)
		if _, err := io.ReadFull(hkdf.New(sha1.New, manualEVP(password, cip.KeySize), wsalt, []byte("ss-subkey")), wk); err != nil {
			t.Errorf("派生响应 subkey: %v", err)
			return
		}
		wblk, _ := aes.NewCipher(wk)
		waead, _ := cipher.NewGCM(wblk)
		wnonce := make([]byte, 12)
		wchunk := func(p []byte) {
			var l [2]byte
			binary.BigEndian.PutUint16(l[:], uint16(len(p)))
			e1 := waead.Seal(nil, wnonce, l[:], nil)
			incNonce(wnonce)
			e2 := waead.Seal(nil, wnonce, p, nil)
			incNonce(wnonce)
			_, _ = srv.Write(append(append(wsalt, e1...), e2...))
		}
		wchunk([]byte("pong"))
	}()

	_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	addr := <-gotAddr
	if !bytes.Equal(addr, target) {
		t.Fatalf("服务端读到的目标地址 %x，期望 %x", addr, target)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读响应失败: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("响应内容不对: %q", got)
	}
}

// 首段是 salt（明文）+ 地址（密文）：salt 长度按套件走（16/32），
// 写错了服务端就是"解不开"，本地也不该静默通过。
func TestFirstWriteWritesSaltThenAddr(t *testing.T) {
	cli, srv := tcpPair(t)
	defer cli.Close()
	defer srv.Close()

	for _, method := range []string{"aes-128-gcm", "chacha20-ietf-poly1305"} {
		cip, _ := Lookup(method)
		target := []byte{0x01, 1, 2, 3, 4, 0x00, 0x50}
		conn, err := ClientConn(cli, cip, "pw", target)
		if err != nil {
			t.Fatal(err)
		}
		// 不能只读一次就断言字节数：TCP 不保证"一次 Write 一次 Read"（实测只读到 salt 那一段）。
		// 所以读到"暂时没有更多数据"为止（短期限），再比总数。
		done := make(chan int, 1)
		go func() {
			total := 0
			buf := make([]byte, 4096)
			for {
				_ = srv.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				n, err := srv.Read(buf)
				total += n
				if err != nil {
					done <- total
					return
				}
			}
		}()
		_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		n := <-done
		// salt(keySize) + 长度段(2+16) + 地址块(7+16) + 长度段 + 载荷块(1+16)
		want := cip.KeySize + 2 + 16 + 7 + 16 + 2 + 16 + 1 + 16
		if n != want {
			t.Errorf("%s: 首段字节数 %d，期望 %d", method, n, want)
		}
	}
}

// tcpPair 一对**真 TCP** 环回连接（不用 net.Pipe：它是无缓冲的，
// 两边同时写就死锁，测试会以"i/o timeout"的样子失败，看着像被测代码的问题）。
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := l.Accept()
		ch <- res{c, err}
	}()
	cli, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return cli, r.c
}
