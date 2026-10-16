package ss

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// chunkStream AEAD chunk 流的读写 —— SIP004（传统）与 SIP022（2022）的数据块是同一个形状：
//
//	chunk = [E(长度 2B BE)][tag] [E(载荷)][tag]
//
// 差别只在**上限**（传统 0x3FFF，2022 是 0xFFFF）与"头两块没有长度域"（只有 2022 有头，
// 用 seal/openRaw 直接加解密，见 ss2022.go）。
//
// nonce 是 12 字节**小端计数器**，从 0 起，**每个 AEAD 操作 +1**（所以一个数据块用掉两次、
// 一个 2022 头块用掉一次）。这条规则写反了本地自测照样过，只有真服务端会失败。
type chunkStream struct {
	raw      net.Conn
	aead     cipher.AEAD
	nonce    []byte
	maxChunk int
	rbuf     []byte // 已解出的明文（等上层来取）
}

func newChunkStream(raw net.Conn, aead cipher.AEAD, maxChunk int) *chunkStream {
	return &chunkStream{
		raw:      raw,
		aead:     aead,
		nonce:    make([]byte, aead.NonceSize()),
		maxChunk: maxChunk,
	}
}

// seal 加解密一个"没有长度域"的块（2022 的头块用），nonce 用后自增。
func (s *chunkStream) seal(plain []byte) []byte {
	out := s.aead.Seal(nil, s.nonce, plain, nil)
	incNonce(s.nonce)
	return out
}

// openRaw 读 n 字节密文并解密（n 是**明文**长度；密文长度 = n + tag）。
func (s *chunkStream) openRaw(n int, what string) ([]byte, error) {
	if n < 0 || n > s.maxChunk {
		return nil, fmt.Errorf("ss %s长度异常: %d", what, n)
	}
	body := make([]byte, n+s.aead.Overhead())
	if _, err := io.ReadFull(s.raw, body); err != nil {
		return nil, err
	}
	plain, err := s.aead.Open(nil, s.nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("ss 解密%s失败（口令/加密方式不对？）: %w", what, err)
	}
	incNonce(s.nonce)
	return plain, nil
}

// writeChunk 写一个数据块：E(长度) + tag ‖ E(载荷) + tag（**一次** write，省一次系统调用）。
func (s *chunkStream) writeChunk(payload []byte) error {
	if len(payload) > s.maxChunk {
		return fmt.Errorf("ss chunk 过大: %d（上限 %d）", len(payload), s.maxChunk)
	}
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(payload)))
	buf := make([]byte, 0, 2+s.aead.Overhead()*2+len(payload))
	buf = append(buf, s.seal(lb[:])...)
	buf = append(buf, s.seal(payload)...)
	_, err := s.raw.Write(buf)
	return err
}

// readChunk 解一个数据块，明文进 rbuf（空块是合法的：继续读下一块）。
func (s *chunkStream) readChunk() error {
	plain, err := s.openRaw(2, "长度域")
	if err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(plain))
	if n == 0 {
		return nil
	}
	body, err := s.openRaw(n, "数据")
	if err != nil {
		return err
	}
	s.rbuf = append(s.rbuf, body...)
	return nil
}

// take 取走已解出的明文（不足则给多少算多少）。
func (s *chunkStream) take(p []byte) int {
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n
}

// incNonce 小端计数器 +1（SIP004 明确是 LE；写成 BE 通不了，但本地自测也看不出来 ——
// 只有跟真服务端对测才暴露）。
func incNonce(n []byte) {
	for i := 0; i < len(n); i++ {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}
