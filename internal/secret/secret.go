// Package secret 用 Windows DPAPI 保管上游凭据。
//
// 动机：config.yaml 是纯文本，拷走就能看到上游口令（客户机器上的运维、备份、同事顺手
// 复制一份，都是泄漏面）。DPAPI 是 Windows 自带的"跟机器/用户绑定"的加密：
// 把密文拷到别的机器上解不开 —— 所以配置文件被拷走也不等于口令泄漏。
//
// 取舍（为什么不是整文件加密）：config.yaml 必须继续能被手工编辑、能被 diff，
// 所以我们**只加密口令那一小段**：配置文件里留 `secret: <名字>`，
// 真正的口令放在同目录 secrets.dat（DPAPI 加密）。
// 导出配置时再还原成明文 —— 于是"一个文件导入即开箱即用"这条体验不受影响。
package secret

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Store 一个目录下的凭据保险箱（文件名固定 secrets.dat）。
type Store struct {
	path string
	m    map[string]string // 名字 → 明文（在内存里）
}

const fileName = "secrets.dat"

// Load 读保险箱；文件不存在时返回一个空箱子（不是错误）。
func Load(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, fileName), m: map[string]string{}}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	// 文件里存的是 DPAPI 密文的 base64（保证是纯文本、能被 diff/传输）
	enc, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("secrets.dat 不是合法的 base64：%w", err)
	}
	plain, err := unprotect(enc)
	if err != nil {
		return nil, fmt.Errorf("secrets.dat 解不开（换了机器/用户？）：%w", err)
	}
	if err := json.Unmarshal(plain, &s.m); err != nil {
		return nil, fmt.Errorf("secrets.dat 内容损坏：%w", err)
	}
	return s, nil
}

// Get 取一个口令（不存在返回空）。
func (s *Store) Get(name string) string {
	if s == nil {
		return ""
	}
	return s.m[name]
}

// Put 存入一个口令并立刻落盘（DPAPI 加密）。
func (s *Store) Put(name, value string) error {
	if s == nil {
		return fmt.Errorf("保险箱未初始化")
	}
	s.m[name] = value
	return s.Save()
}

// Delete 删掉一个口令（如果存在）。
func (s *Store) Delete(name string) error {
	if s == nil {
		return nil
	}
	delete(s.m, name)
	return s.Save()
}

// Names 当前存了哪些名字（不含口令本身）。
func (s *Store) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	return out
}

// Save 落盘（DPAPI + base64）。
func (s *Store) Save() error {
	if s == nil {
		return nil
	}
	if len(s.m) == 0 {
		// 空箱子就别留文件了，免得让人以为丢了什么
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	plain, err := json.Marshal(s.m)
	if err != nil {
		return err
	}
	enc, err := protect(plain)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(base64.StdEncoding.EncodeToString(enc)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Path 保险箱文件路径（给界面显示）。
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// ───────── DPAPI ─────────

// protect 加密（用户+机器绑定：同一台机器同一个用户才能解开）。
func protect(plain []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(plain))}
	if len(plain) > 0 {
		in.Data = &plain[0]
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafePointer(out.Data)))
	return blobBytes(out), nil
}

// unprotect 解密。
func unprotect(enc []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(enc))}
	if len(enc) > 0 {
		in.Data = &enc[0]
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafePointer(out.Data)))
	return blobBytes(out), nil
}

// blobBytes 把 DPAPI 返回的 blob 拷成 Go 切片（原内存由调用方 LocalFree 释放）。
func blobBytes(b windows.DataBlob) []byte {
	if b.Size == 0 || b.Data == nil {
		return nil
	}
	out := make([]byte, b.Size)
	copy(out, unsafeSlice(b.Data, b.Size))
	return out
}

func unsafeSlice(p *byte, n uint32) []byte {
	return unsafe.Slice(p, n)
}

func unsafePointer(p *byte) uintptr {
	if p == nil {
		return 0
	}
	return uintptr(unsafe.Pointer(p))
}
