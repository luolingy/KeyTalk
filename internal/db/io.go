package db

import (
	"errors"
	"fmt"
	"os"

	"github.com/exeliang/keytalk/internal/crypto"
)

// readPageRecord 从磁盘读第 no 页的原始记录（不解密）。
func (d *DB) readPageRecord(no uint32) ([]byte, error) {
	rec := make([]byte, PageRecordSize)
	n, err := d.f.ReadAt(rec, pageOffset(no))
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, fmt.Errorf("db: reading page %d: %w", no, err)
		}
		// 文件比预期短：通常是崩溃在写入中途，或文件被截断。
		if n == 0 || n < PageRecordSize {
			return nil, fmt.Errorf("%w: page %d is truncated (%d of %d bytes)",
				ErrCorrupt, no, n, PageRecordSize)
		}
		return nil, fmt.Errorf("db: reading page %d: %w", no, err)
	}
	return rec, nil
}

// writePageNow 立即把一页写回磁盘（不 fsync）。
func (d *DB) writePageNow(no uint32, plain []byte) error {
	rec, err := encodePage(d.mk, d.hdr.salt[:], no, plain)
	if err != nil {
		return err
	}
	if _, err := d.f.WriteAt(rec, pageOffset(no)); err != nil {
		return fmt.Errorf("db: writing page %d: %w", no, err)
	}
	return nil
}

// syncFile 把文件落盘。
func (d *DB) syncFile() error {
	if err := d.f.Sync(); err != nil {
		return fmt.Errorf("db: syncing %s: %w", d.path, err)
	}
	return nil
}

// zeroBytes 覆写一段内存。
//
// 委托给 crypto.Zero，让擦密钥的实现只有一处。
func zeroBytes(b []byte) { crypto.Zero(b) }
