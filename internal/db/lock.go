package db

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// fileLock 是一个跨进程的独占锁。
//
// # 为什么不用 flock/LockFileEx
//
// 那些需要 golang.org/x/sys 的平台分派，而本项目的依赖集是刻意
// 收紧的。这里用一个足够简单的做法：以 O_EXCL 创建一个 .lock
// 文件，里面写持有者 PID。O_EXCL 保证同一时刻只有一个进程能建成
// 它——这在本地文件系统上是原子的。
//
// # 陈锁
//
// 进程崩溃会留下 .lock。若不去处理，用户重启程序就再也打不开库。
// 所以记录 PID，并在发现锁文件时检查该 PID 是否还活着；进程已死
// 就视为陈锁并接管。PID 复用的极端情况会导致误判，但那需要
// 两件事同时发生（原进程崩溃 + PID 恰好被另一个进程复用），
// 而且后果是"多进程写库"，不是数据泄漏——权衡后接受。
type fileLock struct {
	path string
	held bool
}

// lockFile 获取 path 上的独占锁。
func lockFile(path string) (*fileLock, error) {
	lk := &fileLock{path: path}

	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			// 抢到了。写入自己的 PID 以支持陈锁检测。
			_, werr := fmt.Fprintf(f, "%d\n", os.Getpid())
			cerr := f.Close()
			if werr != nil || cerr != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("db: initialising lock file: %v", werr)
			}
			lk.held = true
			return lk, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("db: creating lock file %s: %w", path, err)
		}

		// 锁已存在：判断是不是陈锁。
		stale, holder := isStaleLock(path)
		if !stale {
			return nil, fmt.Errorf("db: the database is locked by process %s "+
				"(%s). Close the other instance of KeyTalk, or delete the file "+
				"if that process is gone", holder, path)
		}
		// 陈锁：删掉再抢一次。第二次仍失败就放弃。
		_ = os.Remove(path)
	}

	return nil, fmt.Errorf("db: could not acquire lock on %s", path)
}

// isStaleLock 判断锁文件是否属于一个已经死掉的进程。
//
// 无法判断时返回 false（保守：宁可报"被锁"也不要误删活锁）。
func isStaleLock(path string) (stale bool, holder string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// 读不到（可能刚被删除）：按陈锁处理，重试一次即可。
		return true, "unknown"
	}
	s := strings.TrimSpace(string(raw))
	if s == "" {
		// 空锁文件：创建者写完 PID 前就崩了，视为陈锁。
		return true, "unknown"
	}
	pid, err := strconv.Atoi(s)
	if err != nil {
		return false, s
	}
	if pid == os.Getpid() {
		// 自己的 PID：几乎不可能是本进程建的（本进程还没建），
		// 说明前一个同 PID 的实例死了。
		return true, s
	}
	// 持有者进程还活着 → 锁不是陈锁。
	return !processAlive(pid), s
}

// release 释放锁。幂等。
func (l *fileLock) release() error {
	if l == nil || !l.held {
		return nil
	}
	l.held = false
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("db: releasing lock %s: %w", l.path, err)
	}
	return nil
}
