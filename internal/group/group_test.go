package group

import (
	"bytes"
	"testing"

	"github.com/exeliang/keytalk/internal/crypto"
)

func newRingWith(t *testing.T, epoch uint64) (*Keyring, []byte) {
	t.Helper()
	gk := NewGroupKey()
	if len(gk) != 32 {
		t.Fatalf("group key is %d bytes, want 32", len(gk))
	}
	r := NewKeyring()
	r.Put(epoch, gk)
	return r, gk
}

// TestSealClassifyRoundTrip 验证正常收发：加密后能解回原文。
func TestSealClassifyRoundTrip(t *testing.T) {
	ring, _ := newRingWith(t, 1)
	plaintext := []byte("群消息正文，必须能原样解回")

	sealed, err := SealGroupMessage(ring, "group-A", 1, "m1", "SENDERFP", plaintext)
	if err != nil {
		t.Fatalf("SealGroupMessage: %v", err)
	}
	got := Classify(ring, sealed)
	if got.Visibility != VisibleReadable {
		t.Fatalf("visibility = %v, want readable (reason: %s)", got.Visibility, got.Reason)
	}
	if !bytes.Equal(got.Plaintext, plaintext) {
		t.Errorf("plaintext = %q, want %q", got.Plaintext, plaintext)
	}
}

// TestUnreadableWithoutKey 是用户需求的核心：没有 GK 时是"等待密钥"，
// 不是错误、不是乱码、更不是丢弃。
func TestUnreadableWithoutKey(t *testing.T) {
	sender, _ := newRingWith(t, 2)
	sealed, err := SealGroupMessage(sender, "group-A", 2, "m1", "SENDERFP",
		[]byte("这条我现在读不了"))
	if err != nil {
		t.Fatal(err)
	}

	// 接收方完全没有这个 epoch 的 GK。
	empty := NewKeyring()
	got := Classify(empty, sealed)
	if got.Visibility != Unreadable {
		t.Fatalf("visibility = %v, want unreadable", got.Visibility)
	}
	if got.Plaintext != nil {
		t.Error("an unreadable message leaked plaintext")
	}
	if got.Reason == "" {
		t.Error("unreadable should carry a human-readable reason for the UI")
	}

	// 密文本身完好——拿到 GK 之后应当能解开。
	empty.Put(2, sender.Get(2))
	again := Classify(empty, sealed)
	if again.Visibility != VisibleReadable {
		t.Fatalf("after receiving the key, visibility = %v, want readable", again.Visibility)
	}
	if !bytes.Equal(again.Plaintext, []byte("这条我现在读不了")) {
		t.Errorf("plaintext = %q after key arrived", again.Plaintext)
	}
}

// TestWrongEpochKeyIsTampered 验证用错 epoch 的 GK 解不出来，且被判为
// Tampered 而不是解出垃圾或误报"缺钥匙"。
//
// AAD 绑定 epoch，所以拿 epoch 3 的钥匙解 epoch 4 的密文必然 AEAD 失败。
func TestWrongEpochKeyIsTampered(t *testing.T) {
	sender, _ := newRingWith(t, 4)
	sealed, err := SealGroupMessage(sender, "group-A", 4, "m1", "FP", []byte("epoch 4 的消息"))
	if err != nil {
		t.Fatal(err)
	}

	// 接收方手上只有 epoch 3 的 GK。
	recv := NewKeyring()
	recv.Put(3, NewGroupKey()) // 一把无关的钥匙，但 epoch 3

	got := Classify(recv, sealed)
	if got.Visibility == VisibleReadable {
		t.Fatal("decrypted an epoch-4 message with an epoch-3 key — AAD is not binding epoch")
	}
	// 有 epoch 4 的钥匙槽位却没有 -> 应当是 Unreadable（4 不在钥匙环）。
	// 这里 4 确实不在，所以是 Unreadable。
	if got.Visibility != Unreadable {
		t.Errorf("visibility = %v, want unreadable (epoch 4 key absent)", got.Visibility)
	}

	// 再把一把**错误的** epoch 4 密钥放进去：此时有钥匙却解不开 -> Tampered。
	recv.Put(4, NewGroupKey())
	got2 := Classify(recv, sealed)
	if got2.Visibility != Tampered {
		t.Fatalf("with a wrong epoch-4 key, visibility = %v, want tampered", got2.Visibility)
	}
}

// TestTamperedCiphertext 验证密文被改一个字节后判为 Tampered。
func TestTamperedCiphertext(t *testing.T) {
	ring, _ := newRingWith(t, 1)
	sealed, err := SealGroupMessage(ring, "g", 1, "m1", "FP", []byte("原始内容"))
	if err != nil {
		t.Fatal(err)
	}
	sealed.Ciphertext[0] ^= 0xFF

	got := Classify(ring, sealed)
	if got.Visibility != Tampered {
		t.Fatalf("visibility = %v, want tampered", got.Visibility)
	}
	if got.Plaintext != nil {
		t.Error("a tampered message returned plaintext")
	}
}

// TestTamperedNonce 验证 nonce 被改也被发现。
func TestTamperedNonce(t *testing.T) {
	ring, _ := newRingWith(t, 1)
	sealed, _ := SealGroupMessage(ring, "g", 1, "m1", "FP", []byte("内容"))
	sealed.Nonce[0] ^= 0xFF
	if got := Classify(ring, sealed); got.Visibility != Tampered {
		t.Errorf("visibility = %v, want tampered", got.Visibility)
	}
}

// TestCrossGroupCannotDecrypt 验证 AAD 绑定了 group_id：
// 把 group-A 的密文拿去当 group-B 的解，必须失败。
func TestCrossGroupCannotDecrypt(t *testing.T) {
	ring, gk := newRingWith(t, 1)
	sealed, _ := SealGroupMessage(ring, "group-A", 1, "m1", "FP", []byte("A 的内容"))

	// 同一把 GK、同一 epoch，但冒充成 group-B。
	forged := sealed
	forged.GroupID = "group-B"

	got := Classify(ring, forged)
	if got.Visibility == VisibleReadable {
		t.Fatal("a group-A message was accepted as group-B — group_id is not bound in AAD")
	}
	_ = gk
}

// TestSealWithUnknownEpochFails 验证不能用一个不持有的 epoch 加密。
func TestSealWithUnknownEpochFails(t *testing.T) {
	ring, _ := newRingWith(t, 1)
	if _, err := SealGroupMessage(ring, "g", 99, "m", "FP", []byte("x")); err == nil {
		t.Fatal("sealing with an unknown epoch succeeded")
	}
}

// TestKeyringPutCopies 验证存入后会复制，外部改原切片不影响钥匙环。
func TestKeyringPutCopies(t *testing.T) {
	r := NewKeyring()
	gk := NewGroupKey()
	r.Put(1, gk)
	original := append([]byte(nil), r.Get(1)...)

	gk[0] ^= 0xFF // 篡改调用方手里的切片
	if !bytes.Equal(r.Get(1), original) {
		t.Error("Keyring.Put did not copy the key; external mutation changed it")
	}
}

// TestKeyringWipe 验证 wipe 后所有 epoch 都没了。
func TestKeyringWipe(t *testing.T) {
	r, _ := newRingWith(t, 1)
	r.Put(2, NewGroupKey())
	r.Wipe()
	if r.Has(1) || r.Has(2) {
		t.Error("Wipe left keys behind")
	}
}

// TestKeyringConcurrent 验证钥匙环并发读写不 panic（配合 -race）。
func TestKeyringConcurrent(t *testing.T) {
	r := NewKeyring()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			r.Put(uint64(i), NewGroupKey())
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		_ = r.Has(uint64(i))
		_ = r.Get(uint64(i))
	}
	<-done
}

// TestGroupAADDistinct 验证不同 (group, epoch) 的 AAD 两两不同。
func TestGroupAADDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range []string{"a", "b"} {
		for _, e := range []uint64{0, 1, 1 << 40} {
			aad := groupAAD(g, e)
			k := string(aad)
			if seen[k] {
				t.Errorf("duplicate AAD for group=%q epoch=%d", g, e)
			}
			seen[k] = true
		}
	}
	_ = crypto.NonceLen
}
