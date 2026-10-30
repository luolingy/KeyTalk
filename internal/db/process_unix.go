//go:build !windows

package db

import (
	"errors"
	"syscall"
)

// processAlive 报告 pid 是否是一个仍存在的进程。
//
// 在 POSIX 上用 signal 0 探测：进程存在返回 nil 或 EPERM
// （存在但无权限），不存在返回 ESRCH。
func processAlive(pid int) bool {
	p, err := findProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}
