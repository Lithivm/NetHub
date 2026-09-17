//go:build windows

// Job Object 包装：把 gost 子进程放进一个 job，
// 并设置 KILL_ON_JOB_CLOSE —— 这样即使我们的进程被强杀（任务管理器结束进程），
// 子进程也会被内核连带杀掉，不会留下孤儿 gost。
package gostproc

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type job struct {
	h windows.Handle
}

func newJob() (*job, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return &job{h: h}, nil
}

// assign 把 pid 对应的进程加入 job。
func (j *job) assign(pid int) error {
	if j == nil {
		return nil
	}
	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(j.h, h)
}

func (j *job) close() {
	if j != nil && j.h != 0 {
		windows.CloseHandle(j.h)
		j.h = 0
	}
}
