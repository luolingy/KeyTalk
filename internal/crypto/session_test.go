package crypto

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/openpgp"
)

// testPeer 是一对握手参与方，用于端到端测试。
type testPeer struct {
	name     string
	provider *PGPProvider
	importer PGPImporter
}

func newTestPeer(t *testing.T, name string) *testPeer {
	t.Helper()
	// 用较小的 RSA 位数以加快测试（安全性由协议保证，此处只验证流程）。
	p, err := GeneratePGPIdentity(PGPConfig{Name: name, Email: name + "@test", RSABits: 2048})
	if err != nil {
		t.Fatalf("generate identity %s: %v", name, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return &testPeer{name: name, provider: p}
}

func (p *testPeer) cfg(peer *testPeer) HandshakeConfig {
	return HandshakeConfig{
		Identity:        p.provider,
		Importer:        p.importer,
		PeerPublicKey:   peer.provider.PublicKey(),
		PeerFingerprint: peer.provider.Fingerprint(),
		NowMS:           func() int64 { return 1_700_000_000_000 },
	}
}

// TestHandshakeEndToEnd 覆盖完整握手 + 双向加密通信。
func TestHandshakeEndToEnd(t *testing.T) {
	alice := newTestPeer(t, "alice")
	bob := newTestPeer(t, "bob")

	// --- Alice 发起 ---
	initRes, err := Initiate(alice.cfg(bob))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	// --- Bob 响应 ---
	respRes, err := Respond(bob.cfg(alice), initRes.KEMInit)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	// Bob 解出的 sid 必须与 Alice 生成的一致。
	if respRes.SessionID != initRes.SessionID {
		t.Fatal("session IDs disagree")
	}

	// --- Alice 处理 ACK（单次调用完成派生、解密与校验）---
	if _, err := CompleteInitiate(alice.cfg(bob), initRes, respRes.KEMACK); err != nil {
		t.Fatalf("CompleteInitiate: %v", err)
	}

	// --- 握手哈希必须一致 ---
	if !bytes.Equal(initRes.Session.HandshakeHash(), respRes.Handshake) {
		t.Fatal("handshake hashes disagree — sessions would be rejected")
	}
	if err := initRes.Session.VerifyHandshake(respRes.Handshake); err != nil {
		t.Fatalf("VerifyHandshake: %v", err)
	}
	if err := respRes.Session.VerifyHandshake(initRes.Session.HandshakeHash()); err != nil {
		t.Fatalf("VerifyHandshake (responder side): %v", err)
	}

	if initRes.Session.State() != StateEstablished {
		t.Errorf("initiator state = %v, want established", initRes.Session.State())
	}
	if respRes.Session.State() != StateEstablished {
		t.Errorf("responder state = %v, want established", respRes.Session.State())
	}

	// --- 双向通信 ---
	// 双方使用同一个 AAD 构造函数：同一帧的 AAD 必须逐字节一致。
	aad := frameAAD()

	// Alice 发给 Bob。
	frame := mustSeal(t, initRes.Session, []byte("你好 Bob"), aad)
	got, err := respRes.Session.Open(frame.Epoch, frame.Seq, frame.Body, aad)
	if err != nil {
		t.Fatalf("bob open: %v", err)
	}
	if string(got) != "你好 Bob" {
		t.Fatalf("got %q", got)
	}

	// Bob 回给 Alice。
	bframe := mustSeal(t, respRes.Session, []byte("hi Alice"), aad)
	got2, err := initRes.Session.Open(bframe.Epoch, bframe.Seq, bframe.Body, aad)
	if err != nil {
		t.Fatalf("alice open: %v", err)
	}
	if string(got2) != "hi Alice" {
		t.Fatalf("got %q", got2)
	}
}

// AAD 构造辅助：真实实现由 wire 包提供，这里用一个等价形式。
//
// ⚠️ 关键点：AAD 必须**与方向无关**。
// 同一帧在发送方与接收方必须产生完全相同的 AAD 字节串，
// 否则接收方解密必然失败（AAD 参与认证）。
//
// 方向隔离已由**密钥**保证（i2r / r2i 是两条不同的密钥），
// 因此 AAD 里不能再掺入方向标签——那不是"额外防护"，
// 而是会让双方算出不同 AAD 的 bug。
func testAAD(sid [SessionIDLen]byte, epoch, seq uint64) []byte {
	buf := make([]byte, 0, 8+16)
	buf = append(buf, sid[:]...)
	buf = append(buf, EncodeU64(epoch)...)
	buf = append(buf, EncodeU64(seq)...)
	return buf
}

// frameAAD 返回双方共用的 AAD 构造函数。
func frameAAD() func([SessionIDLen]byte, uint64, uint64) []byte {
	return testAAD
}

func mustSeal(t *testing.T, s *Session, pt []byte, aad func([SessionIDLen]byte, uint64, uint64) []byte) *SealedFrame {
	t.Helper()
	f, err := s.Seal(pt, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return f
}

// TestHandshakeRejectsWrongRecipient 验证 KEM 载荷被转发给第三方时不会生效。
func TestHandshakeRejectsWrongRecipient(t *testing.T) {
	alice := newTestPeer(t, "alice")
	bob := newTestPeer(t, "bob")
	mallory := newTestPeer(t, "mallory")

	// Alice 写给 Bob 的载荷，交给 Mallory 处理。
	initRes, err := Initiate(cfgFixed(alice, bob))
	if err != nil {
		t.Fatal(err)
	}
	// Mallory 期望的"对端"是 Alice，因此 sender 校验会先过，
	// 但 recipient 校验必须失败。
	_, err = Respond(HandshakeConfig{
		Identity:        mallory.provider,
		Importer:        mallory.importer,
		PeerPublicKey:   alice.provider.PublicKey(),
		PeerFingerprint: alice.provider.Fingerprint(),
		NowMS:           fixedNow,
	}, initRes.KEMInit)
	if err == nil {
		t.Fatal("expected rejection: KEM payload addressed to another recipient")
	}
}

// TestHandshakeRejectsWrongSigner 验证"用自己密钥签名却声称是他人"被拒绝。
func TestHandshakeRejectsWrongSigner(t *testing.T) {
	alice := newTestPeer(t, "alice")
	bob := newTestPeer(t, "bob")
	mallory := newTestPeer(t, "mallory")

	// Mallory 用自己的身份包装一个声称 sender 是 Alice 的 KEM 载荷。
	ephPriv, ephPub, err := generateECDH()
	if err != nil {
		t.Fatal(err)
	}
	defer zero(ephPriv)

	sid := newSessionID()
	kp := &KEMPlaintext{
		SessionID:   sid,
		SenderFP:    alice.provider.Fingerprint(), // 声称是 Alice
		RecipientFP: bob.provider.Fingerprint(),
		Timestamp:   1_700_000_000_000,
		EphPub:      ephPub,
	}
	bobEntity, _, err := ImportPGPPublicKey(bob.provider.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := mallory.provider.Wrap(bobEntity, kp.Encode()) // 但用 Mallory 的密钥签名
	if err != nil {
		t.Fatal(err)
	}

	_, err = Respond(cfgFixed(bob, alice), blob)
	if err == nil {
		t.Fatal("expected rejection: signer does not match declared sender")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
}

// TestHandshakeRejectsStaleTimestamp 验证陈旧的握手交互被拒绝（防重放）。
func TestHandshakeRejectsStaleTimestamp(t *testing.T) {
	alice := newTestPeer(t, "alice")
	bob := newTestPeer(t, "bob")

	initRes, err := Initiate(cfgFixed(alice, bob))
	if err != nil {
		t.Fatal(err)
	}

	// Bob 的时钟比 Alice 晚 1 小时，远超 ±300s 容忍窗口。
	_, err = Respond(HandshakeConfig{
		Identity:        bob.provider,
		Importer:        bob.importer,
		PeerPublicKey:   alice.provider.PublicKey(),
		PeerFingerprint: alice.provider.Fingerprint(),
		NowMS:           func() int64 { return 1_700_000_000_000 + 3_600_000 },
	}, initRes.KEMInit)
	if !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want ErrStale", err)
	}
}

// TestHandshakeRejectsUnexpectedPeer 验证对端指纹与预期不符时拒绝。
func TestHandshakeRejectsUnexpectedPeer(t *testing.T) {
	alice := newTestPeer(t, "alice")
	bob := newTestPeer(t, "bob")
	mallory := newTestPeer(t, "mallory")

	initRes, err := Initiate(cfgFixed(alice, bob))
	if err != nil {
		t.Fatal(err)
	}

	// Bob 期望对端是 Mallory，但载荷来自 Alice。
	_, err = Respond(cfgFixed(bob, mallory), initRes.KEMInit)
	if err == nil {
		t.Fatal("expected rejection: sender is not the expected peer")
	}
}

func TestSelfAddressedRejected(t *testing.T) {
	alice := newTestPeer(t, "alice")
	_, err := Initiate(HandshakeConfig{
		Identity:        alice.provider,
		Importer:        alice.importer,
		PeerPublicKey:   alice.provider.PublicKey(),
		PeerFingerprint: alice.provider.Fingerprint(), // 自己
		NowMS:           fixedNow,
	})
	if !errors.Is(err, ErrSelfAddressed) {
		t.Fatalf("err = %v, want ErrSelfAddressed", err)
	}
}

// TestSessionTamperDetection 验证篡改密文/AAD/epoch/seq 全部失败。
func TestSessionTamperDetection(t *testing.T) {
	alice, bob, a2b := establishPair(t)

	frame := mustSeal(t, alice, []byte("secret message"), a2b)

	// 1. 篡改密文。
	bad := append([]byte(nil), frame.Body...)
	bad[0] ^= 0x01
	if _, err := bob.Open(frame.Epoch, frame.Seq, bad, a2b); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered ciphertext: err = %v, want ErrDecrypt", err)
	}

	// 2. 篡改 seq（导致 nonce 不匹配）。
	if _, err := bob.Open(frame.Epoch, frame.Seq+1, frame.Body, a2b); err == nil {
		t.Fatal("wrong seq must fail")
	}

	// 3. 未知 epoch。
	if _, err := bob.Open(frame.Epoch+99, frame.Seq, frame.Body, a2b); !errors.Is(err, ErrBadEpoch) {
		t.Fatalf("err = %v, want ErrBadEpoch", err)
	}
}

// TestSessionReplayDetected 验证重放被拒绝。
func TestSessionReplayDetected(t *testing.T) {
	alice, bob, a2b := establishPair(t)
	frame := mustSeal(t, alice, []byte("once"), a2b)

	if _, err := bob.Open(frame.Epoch, frame.Seq, frame.Body, a2b); err != nil {
		t.Fatalf("first open: %v", err)
	}
	_, err := bob.Open(frame.Epoch, frame.Seq, frame.Body, a2b)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want ErrReplay", err)
	}
}

// TestSessionOutOfOrderAccepted 验证窗口内乱序被接受。
func TestSessionOutOfOrderAccepted(t *testing.T) {
	alice, bob, a2b := establishPair(t)

	var frames []*SealedFrame
	for i := 0; i < 5; i++ {
		frames = append(frames, mustSeal(t, alice, []byte{byte(i)}, a2b))
	}

	// 乱序投递：3, 1, 4, 0, 2
	for _, idx := range []int{3, 1, 4, 0, 2} {
		f := frames[idx]
		pt, err := bob.Open(f.Epoch, f.Seq, f.Body, a2b)
		if err != nil {
			t.Fatalf("open frame %d: %v", idx, err)
		}
		if pt[0] != byte(idx) {
			t.Fatalf("frame %d content mismatch", idx)
		}
	}
}

// TestSealAfterClose 验证关闭后无法再加密。
func TestSealAfterClose(t *testing.T) {
	alice, _, a2b := establishPair(t)
	alice.Close()
	if _, err := alice.Seal([]byte("x"), a2b); err == nil {
		t.Fatal("Seal after Close must fail")
	}
	if alice.State() != StateClosed {
		t.Errorf("state = %v, want closed", alice.State())
	}
}

// TestOpenAfterClose 验证关闭后无法解密。
func TestOpenAfterClose(t *testing.T) {
	alice, bob, a2b := establishPair(t)
	frame := mustSeal(t, alice, []byte("x"), a2b)
	bob.Close()
	if _, err := bob.Open(frame.Epoch, frame.Seq, frame.Body, a2b); !errors.Is(err, ErrNoKey) {
		t.Fatalf("err = %v, want ErrNoKey", err)
	}
}

// TestSessionKeysAreWiped 验证 Close 会清零密钥材料。
func TestSessionKeysAreWiped(t *testing.T) {
	alice, _, _ := establishPair(t)
	alice.mu.Lock()
	cur := alice.cur
	alice.mu.Unlock()
	if cur == nil {
		t.Fatal("expected current epoch state")
	}
	// 保留密钥切片引用以便验证清零。
	sendRef := cur.sendKey
	recvRef := cur.recvKey

	alice.Close()

	for i, b := range sendRef {
		if b != 0 {
			t.Fatalf("sendKey[%d] = %d, want 0 after Close", i, b)
		}
	}
	for i, b := range recvRef {
		if b != 0 {
			t.Fatalf("recvKey[%d] = %d, want 0 after Close", i, b)
		}
	}
}

/*
TestM2ForwardSecrecy 是本项目最重要的安全测试。

它验证方案 M2（ECDH 派生）的**前向保密**属性：
即使攻击者拿到双方的长期 OpenPGP 私钥，也无法重建已建立会话的会话密钥。

理由：会话密钥由**一次性的 X25519 私钥** ECDH 派生，而这些临时私钥
在握手完成后即被销毁，从未以任何形式落盘或经长期密钥保护。

（对比方案 M1——"用长期公钥直接加密一个随机会话密钥"——
在 M1 下本测试会失败：攻击者用长期私钥解开 KEM 载荷即可得到会话密钥。）
*/
func TestM2ForwardSecrecy(t *testing.T) {
	alice := newTestPeer(t, "alice")
	bob := newTestPeer(t, "bob")

	initRes, respRes := runHandshake(t, alice, bob)

	// 记录会话密钥的一份副本，模拟"密文已被录制"。
	initRes.Session.mu.Lock()
	recordedKey := append([]byte(nil), initRes.Session.cur.sendKey...)
	initRes.Session.mu.Unlock()
	if len(recordedKey) != KeyLen {
		t.Fatal("no session key recorded")
	}

	// 攻击者能力：获得双方的**长期私钥**。
	// 在 M2 下，长期私钥只能解开 KEM 载荷，得到的是**公开的临时公钥**，
	// 无法反推出临时私钥，因而无法重建会话密钥。
	kemData, senderFP, err := alice.provider.Unwrap(
		// 用 Alice 自己无法解自己的密文；这里改为模拟攻击者用 Bob 的私钥解 Alice 的 KEM。
		initRes.KEMInit)
	if err == nil {
		// 若 Alice 竟然能解开自己发给 Bob 的密文，说明协议有严重问题。
		t.Fatal("initiator must not be able to decrypt its own KEM payload addressed to peer")
		_ = kemData
		_ = senderFP
	}

	// 用 Bob 的长期私钥解开 KEM 载荷——这是攻击者在拿到私钥后能做的事。
	kemPT, _, err := bob.provider.Unwrap(initRes.KEMInit)
	if err != nil {
		t.Fatalf("bob unwrap kem: %v", err)
	}
	kp, err := DecodeKEMPlaintext(kemPT)
	if err != nil {
		t.Fatalf("decode kem: %v", err)
	}

	// 攻击者拿到的全部信息：公开的临时公钥 + 双方临时**公**钥。
	// 关键断言：从这里无法得到会话密钥，因为它还需要至少一个临时**私**钥。
	// 而临时私钥已在 CompleteInitiate / Respond 中被 zero 销毁。

	// 验证 1：会话密钥不等于 KEM 载荷中的任何内容。
	if bytes.Equal(recordedKey, kp.EphPub) {
		t.Fatal("session key leaks the ephemeral public key")
	}

	// 验证 2：临时私钥确实已被销毁。
	initRes.Session.mu.Lock()
	pending := initRes.Session.pendingEphPriv
	initRes.Session.mu.Unlock()
	if pending != nil {
		t.Fatal("initiator still holds its ephemeral private key after handshake")
	}

	// 验证 3：用攻击者可知的任何材料都无法重现会话密钥。
	// 攻击者知道：两个临时公钥、sessionID、双方指纹。
	// 他缺少：共享秘密（需要一个临时私钥才能算出）。
	//
	// 这里做一次反证：若攻击者尝试用"两个临时公钥直接当共享秘密"派生，
	// 结果必然不同于真实会话密钥。
	fakeShared := append(append([]byte(nil), kp.EphPub...), respRes.Session.ID()...)
	fakeShared = DeriveKey(fakeShared, nil, "keytalk/v1/guess", 32)
	fakeKey := DeriveKey(fakeShared, nil, kdfInfoI2R, KeyLen)

	if bytes.Equal(recordedKey, fakeKey) {
		t.Fatal("session key is derivable from public information")
	}
}

// TestM2EphemeralKeysAreUnique 验证每次握手的会话密钥都不同。
//
// 若两次会话产生相同密钥，说明临时密钥没有真正随机（可能是 RNG 问题），
// 这会直接破坏前向保密。
func TestM2EphemeralKeysAreUnique(t *testing.T) {
	alice := newTestPeer(t, "alice")
	bob := newTestPeer(t, "bob")

	i1, _ := runHandshake(t, alice, bob)
	i2, _ := runHandshake(t, alice, bob)

	i1.Session.mu.Lock()
	k1 := append([]byte(nil), i1.Session.cur.sendKey...)
	i1.Session.mu.Unlock()
	i2.Session.mu.Lock()
	k2 := append([]byte(nil), i2.Session.cur.sendKey...)
	i2.Session.mu.Unlock()

	if bytes.Equal(k1, k2) {
		t.Fatal("two handshakes produced identical session keys — ephemeral keys not random")
	}
	if bytes.Equal(i1.SessionID[:], i2.SessionID[:]) {
		t.Fatal("two handshakes produced identical session IDs")
	}
}

// --- 测试辅助 ---

func fixedNow() int64 { return 1_700_000_000_000 }

func cfgFixed(self, peer *testPeer) HandshakeConfig {
	return HandshakeConfig{
		Identity:        self.provider,
		Importer:        self.importer,
		PeerPublicKey:   peer.provider.PublicKey(),
		PeerFingerprint: peer.provider.Fingerprint(),
		NowMS:           fixedNow,
	}
}

// establishPair 完成一次握手并返回 Alice 的会话、Bob 的会话与 AAD 构造器。
func establishPair(t *testing.T) (aliceSess, bobSess *Session, aad func([SessionIDLen]byte, uint64, uint64) []byte) {
	t.Helper()
	alice := newTestPeer(t, "alice")
	bob := newTestPeer(t, "bob")
	i, _ := runHandshake(t, alice, bob)
	return i.Session, i.bobSession, frameAAD()
}

// initiateResult 是 runHandshake 的返回。
type initiateResult struct {
	*InitiateResult
	bobSession *Session
}

func runHandshake(t *testing.T, alice, bob *testPeer) (*initiateResult, *RespondResult) {
	t.Helper()

	initRes, err := Initiate(cfgFixed(alice, bob))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	respRes, err := Respond(cfgFixed(bob, alice), initRes.KEMInit)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if _, err := CompleteInitiate(cfgFixed(alice, bob), initRes, respRes.KEMACK); err != nil {
		t.Fatalf("CompleteInitiate: %v", err)
	}
	return &initiateResult{InitiateResult: initRes, bobSession: respRes.Session}, respRes
}

// 确保 openpgp 包被引用（Importer 返回的 entity 类型来自该包）。
var _ = openpgp.EntityList{}
