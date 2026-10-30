// Package files 负责附件正文的分块加密存储。
//
// # 为什么要分块
//
// 附件可能很大（几十 MB 的图片、PDF）。整块读进内存再加密，
// 会让一个 200 MB 的附件瞬间吃掉 200 MB 内存，在手机上直接
// 被系统杀掉。分块之后，内存占用只有一个块（默认 64 KiB），
// 与附件大小无关。
//
// # 为什么每块单独加密而不是"加密整条流"
//
// 每块用 binding = blobID || 块号 作为 AAD：
//   - 块与块之间不能互换（块号不同，解密失败）；
//   - 一个附件的块不能搬到另一个附件下面（blobID 不同）；
//   - 文件被截断时，最后一块不完整，读取时会失败而不是
//     悄悄返回半张图片。
//
// 链式认证（每块 AAD 里带上上一块的密文哈希）能进一步防止
// "整块删除"，但会让读取必须严格顺序且不能随机访问。这里
// 选择支持随机访问 + 明确记录"整块删除检测不到"这个局限。
package files

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/exeliang/keytalk/internal/crypto"
)

const (
	// ChunkSize 是每个明文档的字节数（默认 64 KiB）。
	ChunkSize = 64 * 1024

	// blobMagic 是附件文件头的魔数。
	blobMagic = "KTALB001"
	// blobHeaderSize 是附件文件头长度。
	//
	// 头是**明文**，只含魔数、块大小、明文总长度与明文的 SHA-256。
	// 这些都是元数据，不含内容；把它们放明文是为了让读取方
	// 在解密前就能知道总共多少块、以及事后能否校验完整性。
	blobHeaderSize = 8 + 4 + 8 + 32

	// 块记录头：4 字节密文长度。
	chunkRecHeader = 4
)

// 错误。
var (
	// ErrNotABlob 表示文件不是本包的附件格式。
	ErrNotABlob = errors.New("files: not a KeyTalk blob file")
	// ErrIntegrity 表示明文哈希校验失败。
	ErrIntegrity = errors.New("files: content integrity check failed")
	// ErrTooLarge 表示附件超过允许的大小。
	ErrTooLarge = errors.New("files: attachment is too large")
)

// MaxSize 是允许的最大明文附件大小（256 MiB）。
//
// 设上限是为了让"附件"和"把整个数据库塞进一个附件"区分开，
// 也避免手机上一个误操作写满磁盘。
const MaxSize = 256 << 20

// Info 是一个已写入附件的元数据。
type Info struct {
	// BlobID 是文件名主干。
	BlobID string
	// Size 是明文字节数。
	Size int64
	// SHA256 是明文的哈希（hex），用于读回后校验。
	SHA256 string
}

// blobBinding 构造第 i 块的 AAD。
func blobBinding(blobID string, chunk uint32) []byte {
	out := make([]byte, 0, len(blobID)+4)
	out = append(out, blobID...)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], chunk)
	return append(out, n[:]...)
}

// Write 把 r 的内容加密写入 dir/blobs/<blobID>.bin。
//
// 边读边加密边写，内存占用与附件大小无关。
// 返回的 Info 应当存进数据库的 attachments 表。
//
// 失败时删除半个文件：宁可没有附件，也不要留一个读不出来的残件
// 让用户以为它完整。
func Write(dir string, mk []byte, blobID string, r io.Reader) (Info, error) {
	var info Info
	if len(mk) == 0 {
		return info, errors.New("files: empty master key")
	}
	if blobID == "" {
		return info, errors.New("files: empty blob ID")
	}

	blobDir := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return info, fmt.Errorf("files: creating %s: %w", blobDir, err)
	}
	path := blobPath(dir, blobID)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return info, fmt.Errorf("files: creating %s: %w", path, err)
	}
	// 任何一步失败都要清理残件。
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()

	// 先占位写一个空头，等读完知道总长度与哈希后再回填。
	if _, err := f.Write(make([]byte, blobHeaderSize)); err != nil {
		return info, fmt.Errorf("files: reserving header: %w", err)
	}

	hasher := sha256.New()
	var total int64
	var chunkNo uint32
	buf := make([]byte, ChunkSize)

	for {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			total += int64(n)
			if total > MaxSize {
				return info, ErrTooLarge
			}
			hasher.Write(buf[:n])

			nonce, ct, err := crypto.EncryptLocalBound(mk, crypto.PurposeAttachmentBlob,
				blobBinding(blobID, chunkNo), buf[:n])
			if err != nil {
				return info, fmt.Errorf("files: encrypting chunk %d: %w", chunkNo, err)
			}
			rec := make([]byte, chunkRecHeader+len(nonce)+len(ct))
			binary.BigEndian.PutUint32(rec[0:4], uint32(len(ct)))
			copy(rec[chunkRecHeader:], nonce)
			copy(rec[chunkRecHeader+len(nonce):], ct)
			if _, err := f.Write(rec); err != nil {
				return info, fmt.Errorf("files: writing chunk %d: %w", chunkNo, err)
			}
			chunkNo++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return info, fmt.Errorf("files: reading source: %w", rerr)
		}
	}

	// 回填文件头。
	sum := hasher.Sum(nil)
	hdr := make([]byte, blobHeaderSize)
	copy(hdr[0:8], blobMagic)
	binary.BigEndian.PutUint32(hdr[8:12], ChunkSize)
	binary.BigEndian.PutUint64(hdr[12:20], uint64(total))
	copy(hdr[20:52], sum)
	if _, err := f.WriteAt(hdr, 0); err != nil {
		return info, fmt.Errorf("files: writing header: %w", err)
	}
	if err := f.Sync(); err != nil {
		return info, fmt.Errorf("files: syncing: %w", err)
	}
	if err := f.Close(); err != nil {
		return info, fmt.Errorf("files: closing: %w", err)
	}
	committed = true

	return Info{BlobID: blobID, Size: total, SHA256: hex.EncodeToString(sum)}, nil
}

// Read 解密 dir/blobs/<blobID>.bin 到 w。
//
// 读完会校验明文 SHA-256；不匹配返回 ErrIntegrity。
// 调用方不要在被篡改的数据上重试或忽略，那正是校验的意义。
func Read(dir string, mk []byte, blobID string, w io.Writer) error {
	if len(mk) == 0 {
		return errors.New("files: empty master key")
	}
	path := blobPath(dir, blobID)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("files: opening %s: %w", path, err)
	}
	defer f.Close()

	hdr := make([]byte, blobHeaderSize)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return fmt.Errorf("%w: short header", ErrNotABlob)
	}
	if string(hdr[0:8]) != blobMagic {
		return ErrNotABlob
	}
	chunkSize := binary.BigEndian.Uint32(hdr[8:12])
	total := int64(binary.BigEndian.Uint64(hdr[12:20]))
	wantSum := hdr[20:52]

	if chunkSize == 0 || chunkSize > ChunkSize {
		return fmt.Errorf("%w: chunk size %d is out of range", ErrNotABlob, chunkSize)
	}
	if total < 0 || total > MaxSize {
		return fmt.Errorf("%w: declared size %d out of range", ErrNotABlob, total)
	}

	hasher := sha256.New()
	var written int64
	var chunkNo uint32

	for written < total {
		remaining := total - written
		thisChunk := int64(chunkSize)
		if remaining < thisChunk {
			thisChunk = remaining
		}

		recHdr := make([]byte, chunkRecHeader)
		if _, err := io.ReadFull(f, recHdr); err != nil {
			return fmt.Errorf("%w: chunk %d header missing (file truncated?)", ErrNotABlob, chunkNo)
		}
		ctLen := int64(binary.BigEndian.Uint32(recHdr))
		if ctLen <= 0 || ctLen > int64(ChunkSize)+16 {
			return fmt.Errorf("%w: chunk %d claims %d ciphertext bytes", ErrNotABlob, chunkNo, ctLen)
		}
		rec := make([]byte, crypto.NonceLen+int(ctLen))
		if _, err := io.ReadFull(f, rec); err != nil {
			return fmt.Errorf("%w: chunk %d body missing (file truncated?)", ErrNotABlob, chunkNo)
		}
		nonce := rec[:crypto.NonceLen]
		ct := rec[crypto.NonceLen:]

		plain, err := crypto.DecryptLocalBound(mk, crypto.PurposeAttachmentBlob,
			blobBinding(blobID, chunkNo), nonce, ct)
		if err != nil {
			return fmt.Errorf("files: chunk %d failed to decrypt (tampered or wrong key): %w", chunkNo, err)
		}
		if int64(len(plain)) != thisChunk {
			return fmt.Errorf("%w: chunk %d decrypted to %d bytes, expected %d",
				ErrNotABlob, chunkNo, len(plain), thisChunk)
		}

		hasher.Write(plain)
		if _, err := w.Write(plain); err != nil {
			return fmt.Errorf("files: writing output: %w", err)
		}
		written += int64(len(plain))
		chunkNo++
	}

	if !equalBytes(hasher.Sum(nil), wantSum) {
		return ErrIntegrity
	}
	return nil
}

// Remove 删除一个附件。元数据由调用方从数据库里删。
func Remove(dir, blobID string) error {
	if err := os.Remove(blobPath(dir, blobID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("files: removing %s: %w", blobID, err)
	}
	return nil
}

// blobPath 返回附件正文路径。
//
// ⚠️ blobID 来自数据库（也就是说来源于网络数据）。必须校验
// 只含安全字符，否则 "../../../x" 就是一个合法的 blobID，
// 一次 Write 就能往任意路径写文件。
func blobPath(dir, blobID string) string {
	if !safeID(blobID) {
		// 调用方应当先校验；这里兜底成一个必然失败的路径，
		// 而不是把用户输入的路径拼进去。
		blobID = "__invalid__"
	}
	return filepath.Join(dir, "blobs", blobID+".bin")
}

// safeID 报告 s 是否只含 [A-Za-z0-9_-]，且长度合理。
func safeID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
