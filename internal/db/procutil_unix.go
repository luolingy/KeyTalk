//go:build !windows

package db

import (
	"fmt"
	"os"
)

// findProcess 找到 pid 对应的进程，用于发 signal 0 探活。
func findProcess(pid int) (*os.Process, error) {
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("db: find process %d: %w", pid, err)
	}
	return p, nil
}
