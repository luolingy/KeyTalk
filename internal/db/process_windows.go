//go:build windows

package db

import (
	"golang.org/x/sys/windows"
)

// processAlive 报告 pid 是否是一个仍存在的进程。
//
// 用 OpenProcess 要一个最小的查询权限；拿不到句柄通常意味着
// 进程不存在（或无权查询，此时保守按"活着"处理会误报被锁，
// 而按"死了"会抢锁——两害相权，无权查询更像进程存在，
// 因此 ERROR_ACCESS_DENIED 归为活着）。
func processAlive(pid int) bool {
	const processQueryLimitedInformation = 0x1000
	h, err := windows.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		if err == windows.ERROR_ACCESS_DENIED {
			return true
		}
		return false
	}
	defer windows.CloseHandle(h)

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return true
	}
	// STILL_ACTIVE (259) 表示进程还在跑。
	const stillActive = 259
	return code == stillActive
}
