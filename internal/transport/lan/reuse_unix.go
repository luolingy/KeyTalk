//go:build !windows

package lan

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortControl 在 socket 创建后、绑定前设置端口复用选项。
//
// Unix 上需要**两个**选项，缺一不可：
//
//   - SO_REUSEADDR：允许绑定到处于 TIME_WAIT 的地址；
//   - SO_REUSEPORT：允许多个 socket 同时绑定同一端口并各自收到数据报。
//
// 只设前者不足以让第二个 mDNS 进程收到组播包。
//
// 注：SO_REUSEPORT 在 Linux 3.9+ 与 BSD/macOS 可用。
// 若某平台不支持，SetSockoptInt 会返回错误，我们忽略它
// 并继续——降级为"只有一个实例能做发现"，而不是完全失败。
func reusePortControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
			opErr = e
			return
		}
		// 单独处理：不支持该选项时不应让整个发现功能失效。
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return opErr
}
