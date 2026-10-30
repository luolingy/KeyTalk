package files

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mk() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// TestRoundTrip 是最基本的断言：写进去、读出来，字节相同。
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := mk()

	// 用显式 ASCII ID：blobID 是文件名的一部分，中文名经过
	// sanitize 会全部塌成同一个 "blob"，互相覆盖。
	cases := []struct {
		id  string
		src []byte
	}{
		{"empty", nil},
		{"onebyte", []byte{0x42}},
		{"small", bytes.Repeat([]byte("A"), 1000)},
		{"exact", bytes.Repeat([]byte("B"), ChunkSize)},
		{"plusone", bytes.Repeat([]byte("C"), ChunkSize+1)},
		{"multiblock", bytes.Repeat([]byte("D"), ChunkSize*3+777)},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			src := tc.src
			if src == nil {
				src = []byte{}
			}
			info, err := Write(dir, key, tc.id, bytes.NewReader(src))
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			if info.Size != int64(len(src)) {
				t.Errorf("Size = %d, want %d", info.Size, len(src))
			}
			if info.SHA256 == "" {
				t.Error("SHA256 is empty")
			}

			var out bytes.Buffer
			if err := Read(dir, key, tc.id, &out); err != nil {
				t.Fatalf("Read: %v", err)
			}
			if !bytes.Equal(out.Bytes(), src) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", out.Len(), len(src))
			}
		})
	}
}

// TestNoPlaintextOnDisk 验证附件正文不以明文出现。
func TestNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("这是一份机密文件的正文内容，绝不应当以明文出现在磁盘上")
	info, err := Write(dir, mk(), "secret-blob", bytes.NewReader(secret))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "blobs", info.BlobID+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("attachment plaintext appears verbatim on disk")
	}
	if bytes.Contains(raw, []byte("机密文件")) {
		t.Fatal("part of the attachment plaintext appears on disk")
	}
}

// TestWrongKeyFails 验证拿错密钥解不出来。
func TestWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	src := bytes.Repeat([]byte("X"), 5000)
	if _, err := Write(dir, mk(), "b1", bytes.NewReader(src)); err != nil {
		t.Fatal(err)
	}

	wrong := mk()
	wrong[0] ^= 0xFF
	var out bytes.Buffer
	err := Read(dir, wrong, "b1", &out)
	if err == nil {
		t.Fatal("Read with the wrong key succeeded")
	}
}

// TestTamperedChunkDetected 验证改一个字节会被发现。
func TestTamperedChunkDetected(t *testing.T) {
	dir := t.TempDir()
	src := bytes.Repeat([]byte("Y"), 3000)
	info, err := Write(dir, mk(), "b2", bytes.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "blobs", info.BlobID+".bin")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 改文件末尾一个字节（在最后一块的密文里）。
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Read(dir, mk(), "b2", &out); err == nil {
		t.Fatal("a tampered chunk was accepted")
	}
}

// TestChunkSwapDetected 验证把块挪位置会被发现。
//
// 两个长度相同的块互换，内容就错了；块号绑进 AAD 使这被察觉。
func TestChunkSwapDetected(t *testing.T) {
	dir := t.TempDir()
	// 三块等长明文，块边界清晰。
	src := append(bytes.Repeat([]byte("1"), ChunkSize), bytes.Repeat([]byte("2"), ChunkSize)...)
	src = append(src, bytes.Repeat([]byte("3"), ChunkSize)...)
	info, err := Write(dir, mk(), "b3", bytes.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "blobs", info.BlobID+".bin")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 解析两条块记录的长度，交换第 0 块与第 1 块的正文。
	// 记录 = [4 字节密文长度][nonce][密文]。
	recLen := func(off int) int {
		ctLen := int(uint32(raw[off])<<24 | uint32(raw[off+1])<<16 |
			uint32(raw[off+2])<<8 | uint32(raw[off+3]))
		return 4 + 12 + ctLen // 头 + nonce + 密文
	}
	if len(raw) < blobHeaderSize+8 {
		t.Fatal("test setup: file too small")
	}
	first := blobHeaderSize
	l0 := recLen(first)
	second := first + l0
	l1 := recLen(second)
	if l0 != l1 {
		t.Fatalf("test setup: chunk record sizes differ (%d vs %d)", l0, l1)
	}

	// 交换两块的密文部分（保留各自长度头与 nonce 位置不变更简单：
	// 直接交换整条记录）。
	tmp := make([]byte, l0)
	copy(tmp, raw[first:first+l0])
	copy(raw[first:first+l0], raw[second:second+l1])
	copy(raw[second:second+l1], tmp)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Read(dir, mk(), "b3", &out); err == nil {
		t.Fatal("swapped chunks were accepted; the chunk number is not bound into the AAD")
	}
}

// TestTruncatedBlobDetected 验证被截断的附件读不出来。
func TestTruncatedBlobDetected(t *testing.T) {
	dir := t.TempDir()
	src := bytes.Repeat([]byte("Z"), ChunkSize*2)
	info, err := Write(dir, mk(), "b4", bytes.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "blobs", info.BlobID+".bin")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:len(raw)-100], 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Read(dir, mk(), "b4", &out); err == nil {
		t.Fatal("a truncated attachment was read successfully")
	}
}

// TestPathTraversalRejected 验证 blobID 不能被拼成路径。
func TestPathTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{
		"../../../etc/passwd",
		"..\\..\\windows\\evil",
		"a/b",
		"a.b",
		"",
	} {
		if _, err := Write(dir, mk(), bad, bytes.NewReader([]byte("x"))); err != nil {
			// 报错是可接受的；关键是不要写到目标路径。
			continue
		}
		// 若没报错，必须没有在预期之外的地方落文件。
		if _, err := os.Stat(filepath.Join(dir, "blobs", bad+".bin")); err == nil {
			t.Errorf("Write created a file for unsafe blobID %q", bad)
		}
	}
}

// TestMaxSizeEnforced 验证超大附件被拒绝。
func TestMaxSizeEnforced(t *testing.T) {
	dir := t.TempDir()
	// 超过上限 1 字节。用 LimitReader 造一个"声称很大"的流。
	src := io.LimitReader(bigReader{}, MaxSize+1)
	if _, err := Write(dir, mk(), "huge", src); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Write of an oversized attachment returned %v, want ErrTooLarge", err)
	}
	// 失败后不该留下残件。
	if _, err := os.Stat(filepath.Join(dir, "blobs", "huge.bin")); !os.IsNotExist(err) {
		t.Error("a failed oversized write left a partial file behind")
	}
}

// TestRandomBlobIDs 验证随机 ID 也能用（真实调用会是这样）。
func TestRandomBlobIDs(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		id := "b" + hexish(b[:])
		src := []byte("content " + id)
		if _, err := Write(dir, mk(), id, bytes.NewReader(src)); err != nil {
			t.Fatalf("Write %q: %v", id, err)
		}
		var out bytes.Buffer
		if err := Read(dir, mk(), id, &out); err != nil {
			t.Fatalf("Read %q: %v", id, err)
		}
		if !bytes.Equal(out.Bytes(), src) {
			t.Fatalf("mismatch for %q", id)
		}
	}
}

// --- 辅助 ---

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return "blob"
	}
	return out
}

func hexish(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0xF])
	}
	return string(out)
}

// bigReader 返回一个无限长的读取器，配合 io.LimitReader 造出
// 任意大小、又不必真的分配那么多内存的输入。
type bigReader struct{}

func (bigReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
