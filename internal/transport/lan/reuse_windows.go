//go:build windows

package lan

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// reusePortControl 在 socket 创建后、绑定前设置端口复用选项。
//
// Windows 的语义与 Unix 不同（这是一处容易踩坑的差异）：
//
//   - Unix 需要 SO_REUSEADDR + SO_REUSEPORT 两者；
//   - Windows **没有** SO_REUSEPORT，但 SO_REUSEADDR 的语义
//     恰好等价于 Unix 的 SO_REUSEPORT——它允许多个 socket
//     绑定同一地址端口，并都能收到组播/广播。
//
// 因此 Windows 上只设 SO_REUSEADDR 即可，且**必须**在 bind 之前设置。
func reusePortControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		// SO_REUSEADDR = 0x0004 on Windows
		opErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return opErr
}
