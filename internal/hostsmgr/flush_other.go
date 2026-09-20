//go:build !windows

package hostsmgr

// flushDNS 非 Windows 上没有这个概念（本项目只跑 Windows，留桩好编译）。
func flushDNS() error { return nil }
