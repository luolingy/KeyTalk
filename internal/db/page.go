// Package db 是本项目的嵌入式加密数据库。
//
// # 为什么自研
//
// 需要的纯 Go SQLite 驱动（modernc.org/sqlite）在本项目的构建环境中
// 取不到：模块缓存里没有、网络代理也不可达（见
// docs/architecture.md §3.6）。而"聊天记录存在一个数据库里、按会话
// 检索"是产品的核心需求，不该被一个依赖卡住。于是自研一个只解决
// 本场景问题的迷你引擎。
//
// # 它是什么 / 不是什么
//
// 是：单文件、页式、每个字节（除固定文件头外）都是密文、支持多张表、
// 支持有序索引、支持事务、崩溃后能识别并丢弃半写页。
//
// 不是：通用 SQL 数据库。没有查询语言、没有多表连接、没有并发
// 多进程写（靠文件锁互斥）、没有 B+树的页分裂与平衡。表数据是
// 页链，检索靠索引页链 + 页内线性找。聊天数据量下这足够，
// 但必须说清楚：**这是有意的取舍，不是完成度不足**。
//
// # 加密设计
//
// 文件头 64 字节**明文**，只含 magic、版本、页大小、每库随机盐、
// 以及一个密钥校验值（KCV）。KCV 让"口令错"在打开的第一毫秒就
// 变成 ErrWrongKey，而不是解出一堆垃圾再报一个莫名其妙的解析错误。
//
// 每个数据页独立加密：
//
//	page_plaintext -> EncryptLocalBound(MK, PurposePage,
//	                                    binding = salt || pageNo, plaintext)
//
// binding 里带 salt 与页号，于是：
//   - 页被搬到另一个偏移 → 页号不匹配 → 解密失败（防页交换）；
//   - 页被搬到另一个库文件 → salt 不匹配 → 解密失败；
//   - 页被截断/篡改 → AEAD 校验失败。
//
// 这些都是"篡改可被察觉"，而不是"篡改不会发生"。区别在于：
// 后者做不到（攻击者能写磁盘），前者做得到。
package db

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/exeliang/keytalk/internal/crypto"
)

// 文件格式常量。
const (
	// Magic 是文件开头的 8 字节魔数。
	Magic = "KTALDB01"
	// FormatVersion 是当前写出的格式版本。
	FormatVersion = 1

	// HeaderSize 是明文文件头的固定长度。
	HeaderSize = 64
	// PageSize 是每个明文页的字节数。
	//
	// 4 KiB 是页式存储的常规选择：足够装下几十条消息，
	// 又小到单页重写的代价可以忽略。
	PageSize = 4096

	// 页在磁盘上的记录头：4 字节密文长度（不含 nonce）。
	pageRecHeader = 4
	// 单页密文上限 = 明文页 + AEAD 标签(16)。
	pageCipherMax = PageSize + 16
	// PageRecordSize 是**每个页记录固定的磁盘长度**。
	//
	// 记录固定长度是随机访问的前提：第 no 页永远在
	// HeaderSize + no*PageRecordSize。为此明文在加密前被填充
	// 到恰好 PageSize（见 encodePage），密文因此恒为
	// PageSize+16（AEAD 标签固定），记录恒为本值。
	//
	// 代价是每页浪费一些填充字节；换来的是 O(1) 随机读写，
	// 而不是扫描整条页链——这个交换完全值得。
	PageRecordSize = pageRecHeader + crypto.NonceLen + pageCipherMax

	// SaltLen 是每库随机盐的长度。
	SaltLen = 16
	// KCVLen 是密钥校验值的长度。
	KCVLen = 8
)

// 错误。
var (
	// ErrWrongKey 表示口令/MK 与这个库不匹配。
	ErrWrongKey = errors.New("db: wrong passphrase or key (key check failed)")
	// ErrNotADB 表示文件不是本包的数据库格式。
	ErrNotADB = errors.New("db: not a KeyTalk database file")
	// ErrCorrupt 表示文件结构被破坏。
	ErrCorrupt = errors.New("db: file is corrupt")
	// ErrClosed 表示库已关闭。
	ErrClosed = errors.New("db: closed")
)

// header 是解析后的文件头。
type header struct {
	version  uint16
	pageSize uint32
	salt     [SaltLen]byte
	kcv      [KCVLen]byte
}

// kcv 计算密钥校验值。
//
// 用 HMAC-SHA256(MK, salt || magic) 取前 8 字节。用 HMAC 而不是
// 直接哈希 MK：即使将来 KCV 泄漏，也不能反推或暴力出 MK。
// 它只是"这把钥匙对不对"的快速判据，不解密任何东西。
func computeKCV(mk []byte, salt []byte) [KCVLen]byte {
	m := hmac.New(sha256.New, mk)
	m.Write([]byte(Magic))
	m.Write(salt)
	var out [KCVLen]byte
	copy(out[:], m.Sum(nil))
	return out
}

// encode 把文件头序列化为 64 字节。
func (h header) encode() []byte {
	b := make([]byte, HeaderSize)
	copy(b[0:8], Magic)
	binary.BigEndian.PutUint16(b[8:10], h.version)
	binary.BigEndian.PutUint32(b[10:14], h.pageSize)
	// 14..16 保留
	copy(b[16:32], h.salt[:])
	copy(b[32:40], h.kcv[:])
	// 40..64 保留（将来可放创建时间、库 ID 等）
	return b
}

// parseHeader 解析并校验文件头的前 40 字节。
func parseHeader(b []byte) (header, error) {
	var h header
	if len(b) < HeaderSize {
		return h, fmt.Errorf("%w: shorter than a header", ErrNotADB)
	}
	if string(b[0:8]) != Magic {
		return h, ErrNotADB
	}
	h.version = binary.BigEndian.Uint16(b[8:10])
	if h.version != FormatVersion {
		return h, fmt.Errorf("%w: format version %d, this build reads %d",
			ErrNotADB, h.version, FormatVersion)
	}
	h.pageSize = binary.BigEndian.Uint32(b[10:14])
	if h.pageSize != PageSize {
		return h, fmt.Errorf("%w: page size %d, this build expects %d",
			ErrNotADB, h.pageSize, PageSize)
	}
	copy(h.salt[:], b[16:32])
	copy(h.kcv[:], b[32:40])
	return h, nil
}

// pageBinding 构造第 no 页的 AAD 绑定串。
//
// salt 让页与它所属的库绑定；no 让页与它的偏移绑定。
// 8 字节大端避免十进制拼接的歧义（如 "1"+"2" 与 "12"）。
func pageBinding(salt []byte, no uint32) []byte {
	out := make([]byte, 0, len(salt)+4)
	out = append(out, salt...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], no)
	return append(out, n[:]...)
}

// errShortWrite 表示写入的字节数不足。
var errShortWrite = io.ErrShortWrite

// newFile 创建一个新的库文件并写入文件头。
func newFile(path string, mk []byte) (header, error) {
	var h header
	h.version = FormatVersion
	h.pageSize = PageSize
	if _, err := rand.Read(h.salt[:]); err != nil {
		return h, fmt.Errorf("db: generating file salt: %w", err)
	}
	h.kcv = computeKCV(mk, h.salt[:])

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return h, fmt.Errorf("db: creating %s: %w", path, err)
	}
	defer f.Close()

	if err := writeFull(f, h.encode()); err != nil {
		return h, fmt.Errorf("db: writing header: %w", err)
	}
	if err := f.Sync(); err != nil {
		return h, fmt.Errorf("db: syncing new file: %w", err)
	}
	return h, nil
}

// writeFull 写满 b，返回短写错误。
func writeFull(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return errShortWrite
	}
	return nil
}

// encodePage 把一个明文页加密成**固定长度**的磁盘记录。
//
// 明文先被填充到恰好 PageSize 再加密，于是密文恒为
// PageSize+16，整条记录恒为 PageRecordSize。填充用 0x00，
// 解密后由各页类型自己按槽表长度解析，填充字节不会被读到。
func encodePage(mk []byte, salt []byte, no uint32, plain []byte) ([]byte, error) {
	if len(plain) > PageSize {
		return nil, fmt.Errorf("db: page %d plaintext is %d bytes, limit %d",
			no, len(plain), PageSize)
	}
	padded := make([]byte, PageSize)
	copy(padded, plain)

	nonce, ct, err := crypto.EncryptLocalBound(mk, crypto.PurposePage,
		pageBinding(salt, no), padded)
	if err != nil {
		return nil, err
	}
	if len(ct) != pageCipherMax {
		return nil, fmt.Errorf("db: page %d ciphertext is %d bytes, expected %d",
			no, len(ct), pageCipherMax)
	}

	rec := make([]byte, PageRecordSize)
	binary.BigEndian.PutUint32(rec[0:4], uint32(len(ct)))
	copy(rec[pageRecHeader:], nonce)
	copy(rec[pageRecHeader+len(nonce):], ct)
	return rec, nil
}

// decodePage 解密一条固定长度的页记录。
func decodePage(mk []byte, salt []byte, no uint32, rec []byte) ([]byte, error) {
	if len(rec) != PageRecordSize {
		return nil, fmt.Errorf("%w: page %d record is %d bytes, expected %d",
			ErrCorrupt, no, len(rec), PageRecordSize)
	}
	ctLen := int(binary.BigEndian.Uint32(rec[0:4]))
	if ctLen != pageCipherMax {
		return nil, fmt.Errorf("%w: page %d claims %d ciphertext bytes, expected %d",
			ErrCorrupt, no, ctLen, pageCipherMax)
	}
	nonce := rec[pageRecHeader : pageRecHeader+crypto.NonceLen]
	ct := rec[pageRecHeader+crypto.NonceLen : pageRecHeader+crypto.NonceLen+ctLen]
	plain, err := crypto.DecryptLocalBound(mk, crypto.PurposePage,
		pageBinding(salt, no), nonce, ct)
	if err != nil {
		// AEAD 校验失败：页被改过、或被从别处搬来、或密钥不对。
		return nil, fmt.Errorf("%w: page %d: %v", ErrCorrupt, no, err)
	}
	if len(plain) != PageSize {
		return nil, fmt.Errorf("%w: page %d decrypted to %d bytes, expected %d",
			ErrCorrupt, no, len(plain), PageSize)
	}
	return plain, nil
}

// pageOffset 返回第 no 页在文件中的字节偏移。
//
// 因为所有页记录等长，这是纯算术，不需要任何页表。
func pageOffset(no uint32) int64 {
	return int64(HeaderSize) + int64(no)*int64(PageRecordSize)
}
