package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// --- 重放窗口测试（docs/crypto-protocol.md §13.1 的对应用例）---

func TestReplayWindowBasic(t *testing.T) {
	var w ReplayWindow
	if got := w.Accept(1); got != AcceptOK {
		t.Fatalf("first Accept(1) = %v, want OK", got)
	}
	if got := w.Accept(2); got != AcceptOK {
		t.Fatalf("Accept(2) = %v, want OK", got)
	}
	if got := w.Accept(1); got != AcceptReplay {
		t.Fatalf("replayed Accept(1) = %v, want Replay", got)
	}
	if w.Highest() != 2 {
		t.Errorf("Highest = %d, want 2", w.Highest())
	}
}

func TestReplayWindowOutOfOrderWithinWindow(t *testing.T) {
	var w ReplayWindow
	w.Accept(100)
	// 窗口内的乱序都应被接受。
	for _, seq := range []uint64{99, 95, 50, 98, 97} {
		if got := w.Accept(seq); got != AcceptOK {
			t.Errorf("Accept(%d) = %v, want OK", seq, got)
		}
	}
	// 二次投递同一个都要被拒。
	for _, seq := range []uint64{99, 95, 50, 98, 97, 100} {
		if got := w.Accept(seq); got != AcceptReplay {
			t.Errorf("re-Accept(%d) = %v, want Replay", seq, got)
		}
	}
}

func TestReplayWindowTooOld(t *testing.T) {
	var w ReplayWindow
	w.Accept(ReplayWindowSize * 2)
	// 早于窗口下界的 seq 应返回 TooOld，而不是 Replay。
	// 这不是攻击证据——可能是严重乱序或对端异常。
	if got := w.Accept(1); got != AcceptTooOld {
		t.Fatalf("Accept(1) = %v, want TooOld", got)
	}
}

func TestReplayWindowBoundary(t *testing.T) {
	var w ReplayWindow
	const top uint64 = 10_000
	w.Accept(top)

	// 恰好位于窗口下界内的应被接受。
	edge := top - (ReplayWindowSize - 1)
	if got := w.Accept(edge); got != AcceptOK {
		t.Errorf("Accept(%d) = %v, want OK (inside window)", edge, got)
	}
	// 再早一个就出界了。
	if got := w.Accept(edge - 1); got != AcceptTooOld {
		t.Errorf("Accept(%d) = %v, want TooOld (outside window)", edge-1, got)
	}
}

func TestReplayWindowBigJump(t *testing.T) {
	var w ReplayWindow
	w.Accept(5)
	// 跨越整个窗口的跳跃应清空位图，旧 seq 全部作废。
	w.Accept(ReplayWindowSize * 10)
	if got := w.Accept(5); got != AcceptTooOld {
		t.Errorf("Accept(5) after big jump = %v, want TooOld", got)
	}
	if got := w.Accept(ReplayWindowSize * 10); got != AcceptReplay {
		t.Errorf("re-Accept(highest) = %v, want Replay", got)
	}
}

// Revoke 的存在理由：先检查重放、后解密的流程中，
// 攻击者若抢先投递一个 (epoch,seq) 相同但内容伪造的帧，
// 解密失败后必须能撤销标记，否则真正的合法帧会被永久拒绝。
func TestReplayWindowRevoke(t *testing.T) {
	var w ReplayWindow
	w.Accept(1)
	w.Accept(2)
	w.Accept(3)

	if got := w.Accept(3); got != AcceptReplay {
		t.Fatalf("Accept(3) = %v, want Replay", got)
	}
	w.Revoke(3)
	if got := w.Accept(3); got != AcceptOK {
		t.Fatalf("Accept(3) after Revoke = %v, want OK", got)
	}
}

func TestReplayWindowReset(t *testing.T) {
	var w ReplayWindow
	w.Accept(42)
	if !w.Init() {
		t.Fatal("Init() = false after Accept")
	}
	w.Reset()
	if w.Init() {
		t.Fatal("Init() = true after Reset")
	}
	if got := w.Accept(1); got != AcceptOK {
		t.Fatalf("Accept(1) after Reset = %v, want OK", got)
	}
}

func TestReplayWindowZeroSeq(t *testing.T) {
	// seq 从 0 开始是合法的（每代新密钥的第一帧）。
	var w ReplayWindow
	if got := w.Accept(0); got != AcceptOK {
		t.Fatalf("Accept(0) = %v, want OK", got)
	}
	if got := w.Accept(0); got != AcceptReplay {
		t.Fatalf("re-Accept(0) = %v, want Replay", got)
	}
}

// --- nonce / AAD 构造的固定向量测试 ---
// 这些是线上格式的一部分，重构时不得悄然改变。

func TestBuildNonceLayout(t *testing.T) {
	n := BuildNonce(0x0102030405060708)
	want := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(n, want) {
		t.Fatalf("BuildNonce =\n%x\nwant\n%x", n, want)
	}
	if len(n) != NonceLen {
		t.Fatalf("nonce len = %d, want %d", len(n), NonceLen)
	}
}

func TestChunkNonceLayout(t *testing.T) {
	// nonce = index(11B 大端) ‖ isFinal(1B)
	// index 占字节 0..10（高 3 字节补零），字节 11 是 isFinal 标志。
	//
	// 实测输出（用于固定线上格式，重构时不得悄然改变）：
	//   ChunkNonce(0x0102, false) = 00 00 00 00 00 00 00 00 00 01 02 00
	//   ChunkNonce(0x0102, true ) = 00 00 00 00 00 00 00 00 00 01 02 01
	n := ChunkNonce(0x0102, false)
	want := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0}
	if !bytes.Equal(n, want) {
		t.Fatalf("ChunkNonce =\n% x\nwant\n% x", n, want)
	}
	n2 := ChunkNonce(0x0102, true)
	wantFinal := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 1}
	if !bytes.Equal(n2, wantFinal) {
		t.Fatalf("ChunkNonce(final) =\n% x\nwant\n% x", n2, wantFinal)
	}
	// 末块标志必须参与 nonce，否则无法区分末块与普通块。
	if bytes.Equal(n, n2) {
		t.Fatal("final and non-final nonces must differ")
	}

	// 大 index 的边界：index 必须完整占据 11 字节。
	big := ChunkNonce(0xFFFFFFFFFFFFFFFF, false)
	if big[10] != 0xFF || big[3] != 0xFF {
		t.Fatalf("large index not encoded big-endian across 11 bytes: % x", big)
	}
	if big[0] != 0 || big[1] != 0 || big[2] != 0 {
		t.Fatalf("high 3 bytes of 11-byte index must be zero: % x", big)
	}
}

func TestChunkAADBindsPosition(t *testing.T) {
	fid := []byte("file-id-16-bytes")
	a0 := ChunkAAD(Version, fid, 0, 10, 1000)
	a1 := ChunkAAD(Version, fid, 1, 10, 1000)
	if bytes.Equal(a0, a1) {
		t.Fatal("AAD for different indices must differ (anti-reorder)")
	}

	b := ChunkAAD(Version, fid, 0, 11, 1000)
	if bytes.Equal(a0, b) {
		t.Fatal("AAD for different totalChunks must differ (anti-truncation)")
	}

	c := ChunkAAD(Version, fid, 0, 10, 1001)
	if bytes.Equal(a0, c) {
		t.Fatal("AAD for different fileSize must differ")
	}
}

// --- 分块 AEAD 测试（docs/attachments.md §15.1）---

func TestChunkRoundTrip(t *testing.T) {
	key := randomBytes(KeyLen)
	fid := randomBytes(16)
	plaintext := bytes.Repeat([]byte("A"), ChunkSize)

	ct, err := SealChunk(key, fid, 0, 5, uint64(len(plaintext)*5), plaintext, false)
	if err != nil {
		t.Fatalf("SealChunk: %v", err)
	}
	got, err := OpenChunk(key, fid, 0, 5, uint64(len(plaintext)*5), ct, false)
	if err != nil {
		t.Fatalf("OpenChunk: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip mismatch")
	}
	if len(ct) != SealedSize(len(plaintext)) {
		t.Errorf("ciphertext len = %d, want %d", len(ct), SealedSize(len(plaintext)))
	}
}

// 关键安全用例：重排两块必须失败。
func TestChunkReorderingDetected(t *testing.T) {
	key := randomBytes(KeyLen)
	fid := randomBytes(16)
	size := uint64(ChunkSize * 3)

	ct0, err := SealChunk(key, fid, 0, 3, size, bytes.Repeat([]byte{0x00}, ChunkSize), false)
	if err != nil {
		t.Fatal(err)
	}
	ct1, err := SealChunk(key, fid, 1, 3, size, bytes.Repeat([]byte{0x11}, ChunkSize), false)
	if err != nil {
		t.Fatal(err)
	}

	// 攻击者交换两块的位置：接收方在 index=0 处拿到 ct1。
	if _, err := OpenChunk(key, fid, 0, 3, size, ct1, false); err == nil {
		t.Fatal("reordered chunk must fail authentication")
	}
	if _, err := OpenChunk(key, fid, 1, 3, size, ct0, false); err == nil {
		t.Fatal("reordered chunk must fail authentication (reverse)")
	}
}

// 关键安全用例：把非末块伪装成末块（或反之）必须失败。
func TestChunkFinalFlagBound(t *testing.T) {
	key := randomBytes(KeyLen)
	fid := randomBytes(16)
	size := uint64(ChunkSize * 2)
	body := bytes.Repeat([]byte{0xAB}, ChunkSize/2)

	ct, err := SealChunk(key, fid, 0, 2, size, body, false)
	if err != nil {
		t.Fatal(err)
	}
	// 用 isFinal=true 去解，nonce 不同 → 必须失败。
	if _, err := OpenChunk(key, fid, 0, 2, size, ct, true); err == nil {
		t.Fatal("flipping final flag must fail authentication")
	}
}

func TestChunkTamperDetected(t *testing.T) {
	key := randomBytes(KeyLen)
	fid := randomBytes(16)
	body := []byte("sensitive file contents")
	size := uint64(len(body))

	ct, err := SealChunk(key, fid, 0, 1, size, body, true)
	if err != nil {
		t.Fatal(err)
	}

	// 逐字节翻转都必须导致失败（AEAD 完整性）。
	for i := 0; i < len(ct); i++ {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if _, err := OpenChunk(key, fid, 0, 1, size, bad, true); err == nil {
			t.Fatalf("bit flip at %d was not detected", i)
		}
	}
}

func TestChunkWrongKeyOrFile(t *testing.T) {
	key := randomBytes(KeyLen)
	fid := randomBytes(16)
	body := []byte("data")

	ct, err := SealChunk(key, fid, 0, 1, uint64(len(body)), body, true)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenChunk(randomBytes(KeyLen), fid, 0, 1, uint64(len(body)), ct, true); err == nil {
		t.Fatal("wrong key must fail")
	}
	if _, err := OpenChunk(key, randomBytes(16), 0, 1, uint64(len(body)), ct, true); err == nil {
		t.Fatal("wrong file id must fail")
	}
}

func TestChunkSizeLimits(t *testing.T) {
	key := randomBytes(KeyLen)
	fid := randomBytes(16)
	oversized := bytes.Repeat([]byte{1}, ChunkSize+1)
	if _, err := SealChunk(key, fid, 0, 1, uint64(len(oversized)), oversized, false); !errors.Is(err, ErrChunkSize) {
		t.Fatalf("err = %v, want ErrChunkSize", err)
	}
	// 空块若不是末块应被拒绝。
	if _, err := SealChunk(key, fid, 0, 2, 100, nil, false); !errors.Is(err, ErrChunkSize) {
		t.Fatalf("err = %v, want ErrChunkSize for empty non-final chunk", err)
	}
}

func TestChunkCount(t *testing.T) {
	cases := []struct {
		size, want uint64
	}{
		{0, 1}, // 空文件定义为 1 个空块
		{1, 1},
		{ChunkSize, 1},
		{ChunkSize + 1, 2},
		{ChunkSize * 3, 3},
		{ChunkSize*3 + 1, 4},
	}
	for _, c := range cases {
		if got := ChunkCount(c.size); got != c.want {
			t.Errorf("ChunkCount(%d) = %d, want %d", c.size, got, c.want)
		}
	}
}

func TestChunkPlaintextLen(t *testing.T) {
	size := uint64(ChunkSize + 100)
	if got := ChunkPlaintextLen(size, 0); got != ChunkSize {
		t.Errorf("chunk 0 len = %d, want %d", got, ChunkSize)
	}
	if got := ChunkPlaintextLen(size, 1); got != 100 {
		t.Errorf("chunk 1 len = %d, want 100", got)
	}
	if got := ChunkPlaintextLen(size, 2); got != 0 {
		t.Errorf("chunk 2 len = %d, want 0", got)
	}
}

// --- HKDF 派生测试 ---

func TestDeriveSessionKeysAreDistinct(t *testing.T) {
	shared := randomBytes(32)
	salt := randomBytes(SaltLen)
	ctx := randomBytes(32)

	i2r, r2i := DeriveSessionKeys(shared, salt, ctx)

	if bytes.Equal(i2r, r2i) {
		t.Fatal("directional keys must differ — identical keys would cause nonce reuse")
	}
	if len(i2r) != KeyLen || len(r2i) != KeyLen {
		t.Fatalf("key lens = %d/%d, want %d", len(i2r), len(r2i), KeyLen)
	}

	// 相同输入必须可复现（双方独立派生出相同密钥）。
	i2r2, r2i2 := DeriveSessionKeys(shared, salt, ctx)
	if !bytes.Equal(i2r, i2r2) || !bytes.Equal(r2i, r2i2) {
		t.Fatal("derivation must be deterministic")
	}

	// 不同 context 必须产生不同密钥（UKS 防护）。
	i2r3, _ := DeriveSessionKeys(shared, salt, randomBytes(32))
	if bytes.Equal(i2r, i2r3) {
		t.Fatal("different context must yield different keys")
	}
}

func TestSessionContextBindsIdentities(t *testing.T) {
	sid := randomBytes(SessionIDLen)
	a := SessionContext(sid, "AAAA", "BBBB", randomBytes(32), randomBytes(32))
	b := SessionContext(sid, "AAAA", "CCCC", randomBytes(32), randomBytes(32))
	if bytes.Equal(a, b) {
		t.Fatal("context must bind peer identities")
	}
}

func TestHandshakeHashLengthPrefixed(t *testing.T) {
	// 长度前缀是必须的：否则 ("ab","c") 与 ("a","bc") 会得到相同哈希。
	h1 := HandshakeHash([]byte("ab"), []byte("c"))
	h2 := HandshakeHash([]byte("a"), []byte("bc"))
	if bytes.Equal(h1, h2) {
		t.Fatal("handshake hash must be unambiguous (length-prefixed)")
	}
	if len(h1) != HashLen {
		t.Fatalf("hash len = %d, want %d", len(h1), HashLen)
	}
}

// --- AEAD 基础测试 ---

func TestSealOpenRoundTrip(t *testing.T) {
	key := randomBytes(KeyLen)
	nonce := BuildNonce(7)
	pt := []byte("hello 世界")
	aad := []byte("header")

	ct, err := Seal(key, nonce, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("round trip mismatch")
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	key := randomBytes(KeyLen)
	nonce := BuildNonce(1)
	ct, err := Seal(key, nonce, []byte("x"), []byte("aad-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, nonce, ct, []byte("aad-b")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
	if _, err := Open(key, nonce, ct, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt for missing AAD", err)
	}
}

func TestOpenRejectsWrongNonce(t *testing.T) {
	key := randomBytes(KeyLen)
	ct, err := Seal(key, BuildNonce(1), []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, BuildNonce(2), ct, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

// --- 指纹测试 ---

func TestFingerprintGrouping(t *testing.T) {
	fp := Fingerprint("ABCD1234EF567890")
	got := fp.Display()
	want := "ABCD 1234 EF56 7890"
	if got != want {
		t.Fatalf("Display = %q, want %q", got, want)
	}
	if fp.String() != "ABCD1234EF567890" {
		t.Fatalf("String = %q", fp.String())
	}
}

func TestFingerprintLess(t *testing.T) {
	a := Fingerprint("AAAA")
	b := Fingerprint("BBBB")
	if !a.Less(b) {
		t.Error("AAAA should be less than BBBB")
	}
	if b.Less(a) {
		t.Error("BBBB should not be less than AAAA")
	}
	// 全序性：双方必得出互斥结论。
	if a.Less(b) == b.Less(a) {
		t.Error("ordering must be a total order (exactly one direction true)")
	}
}
