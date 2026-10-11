package session

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/transport"
	"github.com/exeliang/keytalk/internal/transport/lan"
	"github.com/exeliang/keytalk/internal/wire"
)

// testIdentity 是一对用于测试的 OpenPGP 身份。
type testIdentity struct {
	provider crypto.IdentityProvider
	fp       crypto.Fingerprint
	pub      []byte
}

func newTestIdentity(t *testing.T, name string) testIdentity {
	t.Helper()
	entity, err := crypto.GeneratePGPIdentity(crypto.PGPConfig{
		Name:    name,
		Email:   name + "@example.test",
		RSABits: 1024, // 测试用短密钥，加快生成
	})
	if err != nil {
		t.Fatalf("generate identity %s: %v", name, err)
	}
	pub := entity.PublicKey()
	return testIdentity{provider: entity, fp: entity.Fingerprint(), pub: pub}
}

// peerPair 是两个通过真实 TCP 连接互通的会话管理器。
type peerPair struct {
	aliceMgr *Manager
	bobMgr   *Manager
	alice    PeerID
	bob      PeerID
	aliceID  testIdentity
	bobID    testIdentity
	cleanup  func()
}

// setupPair 建立一对通过真实 loopback TCP 连接的会话管理器。
//
// 不依赖 mDNS：直接注入地址，让测试确定且快速。
// mDNS 本身已由 transport/lan 的测试覆盖。
func setupPair(t *testing.T) *peerPair {
	t.Helper()

	aliceID := newTestIdentity(t, "alice")
	bobID := newTestIdentity(t, "bob")

	aliceTr := lan.New(lan.Config{
		Fingerprint: aliceID.fp.String(),
		ListenPort:  0,
	})
	bobTr := lan.New(lan.Config{
		Fingerprint: bobID.fp.String(),
		ListenPort:  0,
	})

	if err := aliceTr.Start(t.Context()); err != nil {
		t.Fatalf("alice transport: %v", err)
	}
	if err := bobTr.Start(t.Context()); err != nil {
		t.Fatalf("bob transport: %v", err)
	}

	aliceAddr := aliceTr.LocalAddr().(*net.TCPAddr)
	bobAddr := bobTr.LocalAddr().(*net.TCPAddr)

	alicePeer := PeerID(aliceID.fp.String())
	bobPeer := PeerID(bobID.fp.String())

	// 互相告知对方地址（模拟 mDNS 发现的结果）。
	injectPeer(t, aliceTr, transport.PeerID(bobPeer), bobAddr, bobID.fp.String())
	injectPeer(t, bobTr, transport.PeerID(alicePeer), aliceAddr, aliceID.fp.String())

	aliceMgr := New(Config{
		Identity:  aliceID.provider,
		Importer:  &crypto.PGPImporter{},
		Transport: aliceTr,
	})
	bobMgr := New(Config{
		Identity:  bobID.provider,
		Importer:  &crypto.PGPImporter{},
		Transport: bobTr,
	})

	// Alice 知道 Bob 的公钥与指纹（来自联系人表）。
	aliceMgr.AddPeer(bobPeer, PeerConfig{Fingerprint: bobID.fp, PublicKey: bobID.pub})
	aliceMgr.SetTransportPeer(bobPeer, transport.PeerID(bobPeer))

	// Bob 也知道 Alice 的（responder 侧需要用来校验签名者）。
	bobMgr.AddPeer(alicePeer, PeerConfig{Fingerprint: aliceID.fp, PublicKey: aliceID.pub})
	bobMgr.SetTransportPeer(alicePeer, transport.PeerID(alicePeer))

	aliceMgr.Start(t.Context())
	bobMgr.Start(t.Context())

	cleanup := func() {
		aliceMgr.Close()
		bobMgr.Close()
		_ = aliceTr.Close()
		_ = bobTr.Close()
	}

	return &peerPair{
		aliceMgr: aliceMgr,
		bobMgr:   bobMgr,
		alice:    alicePeer,
		bob:      bobPeer,
		aliceID:  aliceID,
		bobID:    bobID,
		cleanup:  cleanup,
	}
}

// injectPeer 把地址注入传输层，代替 mDNS。
func injectPeer(t *testing.T, tr *lan.Transport, id transport.PeerID, addr net.Addr, fp string) {
	t.Helper()
	// lan.Transport 的 peers 是未导出的；这里通过公开的 Peers() 无法写入，
	// 因此用一个小的测试辅助：通过发送一次握手让 connFor 自动建连。
	// 但 connFor 需要 peers 里有地址……
	//
	// 解决方式：lan.Transport 提供 SetPeerForTest（见 transport/lan 中的实现）。
	tr.SetPeerForTest(id, addr, fp)
}

// waitForEvent 等待满足条件的会话层事件。
func waitForEvent[T Event](t *testing.T, ch <-chan Event, timeout time.Duration, what string) T {
	t.Helper()
	var zero T
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ch:
			if v, ok := ev.(T); ok {
				return v
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %s", what)
			return zero
		}
	}
}

// --- 端到端：握手 ---

func TestHandshakeOverRealTCP(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceMgr.StartHandshake(p.bob); err != nil {
		t.Fatalf("alice start handshake: %v", err)
	}

	// 双方都应报告握手完成且已验证。
	done := waitForEvent[HandshakeDone](t, p.aliceMgr.Events(), 30*time.Second, "alice HandshakeDone")
	if !done.Verified {
		t.Error("alice handshake not verified")
	}
	bobDone := waitForEvent[HandshakeDone](t, p.bobMgr.Events(), 30*time.Second, "bob HandshakeDone")
	if !bobDone.Verified {
		t.Error("bob handshake not verified")
	}

	if !p.aliceMgr.HasSession(p.bob) {
		t.Error("alice has no session")
	}
	if !p.bobMgr.HasSession(p.alice) {
		t.Error("bob has no session")
	}
}

// --- 端到端：双向加密消息 ---

func TestEncryptedMessagesBothDirections(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceMgr.StartHandshake(p.bob); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitForEvent[HandshakeDone](t, p.aliceMgr.Events(), 30*time.Second, "alice done")
	waitForEvent[HandshakeDone](t, p.bobMgr.Events(), 30*time.Second, "bob done")

	// Alice -> Bob
	if err := p.aliceMgr.SendText(p.bob, "你好，Bob！这是一条加密消息。"); err != nil {
		t.Fatalf("alice send: %v", err)
	}
	msg := waitForEvent[Message](t, p.bobMgr.Events(), 20*time.Second, "bob receives message")
	if msg.Plaintext.Text != "你好，Bob！这是一条加密消息。" {
		t.Errorf("bob got %q", msg.Plaintext.Text)
	}
	if msg.Plaintext.Kind != wire.KindText {
		t.Errorf("kind = %v, want KindText", msg.Plaintext.Kind)
	}
	if msg.Peer != p.alice {
		t.Errorf("peer = %q, want %q", msg.Peer, p.alice)
	}

	// Bob -> Alice
	if err := p.bobMgr.SendText(p.alice, "收到！你好 Alice。"); err != nil {
		t.Fatalf("bob send: %v", err)
	}
	msg2 := waitForEvent[Message](t, p.aliceMgr.Events(), 20*time.Second, "alice receives message")
	if msg2.Plaintext.Text != "收到！你好 Alice。" {
		t.Errorf("alice got %q", msg2.Plaintext.Text)
	}
}

// 多条消息的顺序与完整性。
func TestManyMessagesOrdered(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceMgr.StartHandshake(p.bob); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitForEvent[HandshakeDone](t, p.aliceMgr.Events(), 30*time.Second, "alice done")
	waitForEvent[HandshakeDone](t, p.bobMgr.Events(), 30*time.Second, "bob done")

	const n = 20
	for i := 0; i < n; i++ {
		if err := p.aliceMgr.SendText(p.bob, fmt.Sprintf("msg-%02d", i)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	for i := 0; i < n; i++ {
		msg := waitForEvent[Message](t, p.bobMgr.Events(), 20*time.Second, fmt.Sprintf("msg %d", i))
		want := fmt.Sprintf("msg-%02d", i)
		if msg.Plaintext.Text != want {
			t.Fatalf("message %d = %q, want %q (order or integrity broken)", i, msg.Plaintext.Text, want)
		}
	}
}

// --- 安全属性 ---

// 会话建立前发送加密消息必须失败，而不是静默丢弃。
func TestSendBeforeHandshakeFails(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	err := p.aliceMgr.SendText(p.bob, "too early")
	if err == nil {
		t.Fatal("SendText before handshake must fail")
	}
}

// 身份不匹配时必须拒绝握手（模拟冒充攻击）。
func TestHandshakeRejectsWrongIdentity(t *testing.T) {
	aliceID := newTestIdentity(t, "alice2")
	bobID := newTestIdentity(t, "bob2")
	malloryID := newTestIdentity(t, "mallory")

	aliceTr := lan.New(lan.Config{Fingerprint: aliceID.fp.String(), ListenPort: 0})
	bobTr := lan.New(lan.Config{Fingerprint: bobID.fp.String(), ListenPort: 0})
	if err := aliceTr.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := bobTr.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = aliceTr.Close(); _ = bobTr.Close() }()

	alicePeer := PeerID(aliceID.fp.String())
	bobPeer := PeerID(bobID.fp.String())

	aliceTr.SetPeerForTest(transport.PeerID(bobPeer), bobTr.LocalAddr(), bobID.fp.String())
	bobTr.SetPeerForTest(transport.PeerID(alicePeer), aliceTr.LocalAddr(), aliceID.fp.String())

	aliceMgr := New(Config{Identity: aliceID.provider, Importer: &crypto.PGPImporter{}, Transport: aliceTr})
	bobMgr := New(Config{Identity: bobID.provider, Importer: &crypto.PGPImporter{}, Transport: bobTr})
	defer aliceMgr.Close()
	defer bobMgr.Close()

	// ⚠️ 关键：Alice 的联系人表里，Bob 的条目被填上了 **Mallory 的公钥**。
	// 这模拟"联系人表被污染"或"用户在错误渠道交换了公钥"。
	aliceMgr.AddPeer(bobPeer, PeerConfig{Fingerprint: malloryID.fp, PublicKey: malloryID.pub})
	aliceMgr.SetTransportPeer(bobPeer, transport.PeerID(bobPeer))

	// Bob 正常配置。
	bobMgr.AddPeer(alicePeer, PeerConfig{Fingerprint: aliceID.fp, PublicKey: aliceID.pub})
	bobMgr.SetTransportPeer(alicePeer, transport.PeerID(alicePeer))

	aliceMgr.Start(t.Context())
	bobMgr.Start(t.Context())

	// Alice 尝试握手：她期望的对端指纹是 Mallory，而实际连的是 Bob。
	if err := aliceMgr.StartHandshake(bobPeer); err != nil {
		// 本地就能发现配置矛盾（对端指纹与公钥不符），也算正确拒绝。
		t.Logf("handshake rejected locally: %v", err)
		return
	}

	// 否则必须在握手阶段失败，且**绝不能**出现 HandshakeDone。
	//
	// 两条可能的失败路径，都属于正确行为：
	//   a) Bob 无法解密（载荷加密给了 Mallory），静默丢弃 → Alice 超时
	//   b) 某一方在更早的校验中发现指纹不符
	//
	// 关键断言是"绝不成功"——这才是安全属性。
	deadline := time.After(60 * time.Second) // 需覆盖 handshakeTimeout(20s)
	for {
		select {
		case ev := <-aliceMgr.Events():
			switch e := ev.(type) {
			case HandshakeDone:
				t.Fatalf("handshake must NOT complete with mismatched identity (peer=%s)", e.Peer)
			case HandshakeFailed:
				t.Logf("correctly rejected: %v", e.Err)
				return
			}
		case ev := <-bobMgr.Events():
			if e, ok := ev.(HandshakeDone); ok {
				t.Fatalf("bob must not accept a handshake addressed to another key (peer=%s)", e.Peer)
			}
		case <-deadline:
			t.Fatal("timeout: mismatch neither succeeded nor failed explicitly")
		}
	}
}

// 会话关闭后密钥被销毁，继续发送必须失败。
func TestSessionDestroyedOnTransportClose(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceMgr.StartHandshake(p.bob); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitForEvent[HandshakeDone](t, p.aliceMgr.Events(), 30*time.Second, "alice done")
	waitForEvent[HandshakeDone](t, p.bobMgr.Events(), 30*time.Second, "bob done")

	// 关闭 Bob 一侧管理器：Bob 的传输层随之关闭（TCP 断开）。
	p.bobMgr.Close()
	_ = p.bobMgr.cfg.Transport.Close()

	// 等 Alice 感知到连接断开。
	ev := waitForEvent[StateChanged](t, p.aliceMgr.Events(), 25*time.Second, "alice state change")
	if ev.State != crypto.StateClosed {
		t.Errorf("alice state = %v, want closed", ev.State)
	}

	// 关闭后不应再有可用会话。
	if p.aliceMgr.HasSession(p.bob) {
		t.Error("session should be destroyed after connection closed")
	}
	if err := p.aliceMgr.SendText(p.bob, "should fail"); err == nil {
		t.Error("send after session destroyed must fail")
	}
}

// 畸形帧不应导致 panic。
//
// ⚠️ 重要语义：传输层遇到**非法长度声明**（如声称 4 GiB）会**主动断开连接**。
// 这是有意的防御——声明超大长度的对端只能是恶意或有严重故障，
// 继续读下去会让我们陷入内存分配或无限等待。
//
// 因此本用例验证的是：
//  1. 畸形帧不会 panic；
//  2. 会话层不会因畸形帧而永久挂死（连接被干净地关闭并上报）；
//  3. 帧内容层面的畸形（而非长度层面）被丢弃后连接仍可用。
func TestMalformedFramesDoNotCrash(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceMgr.StartHandshake(p.bob); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitForEvent[HandshakeDone](t, p.aliceMgr.Events(), 30*time.Second, "alice done")
	waitForEvent[HandshakeDone](t, p.bobMgr.Events(), 30*time.Second, "bob done")

	tr := p.aliceMgr.cfg.Transport

	// 第一组：**帧内容**畸形，但长度声明合法。
	// 这些应被会话层丢弃，连接保持可用。
	contentGarbage := [][]byte{
		// 合法长度、非法类型
		{0x00, 0x00, 0x00, 0x02, 0x99, 0x01},
		// Secure 帧但 header 不完整
		{0x00, 0x00, 0x00, 0x06, 0x03, 0x00},
		// Secure 帧 header 完整但 AEAD 密文是垃圾
		{0x00, 0x00, 0x00, 0x1A, 0x03,
			1, 2, 3, 4, 5, 6, 7, 8, // session id
			0, 0, 0, 0, 0, 0, 0, 0, // epoch
			0, 0, 0, 0, 0, 0, 0, 1, // seq
			0xDE, 0xAD},
	}
	for i, g := range contentGarbage {
		if err := tr.Send(transport.PeerID(p.bob), g); err != nil {
			t.Logf("content garbage %d not deliverable: %v", i, err)
		}
	}

	// 连接必须仍然可用：正常消息仍能收发。
	if err := p.aliceMgr.SendText(p.bob, "still alive after content garbage"); err != nil {
		t.Fatalf("manager unusable after content garbage: %v", err)
	}
	msg := waitForEvent[Message](t, p.bobMgr.Events(), 20*time.Second, "bob receives after garbage")
	if msg.Plaintext.Text != "still alive after content garbage" {
		t.Errorf("got %q", msg.Plaintext.Text)
	}
}

// 传输层长度声明非法的帧必须导致连接被主动关闭，而不是挂死或 OOM。
//
// 这是防御性设计的关键验证：对端声称要发 4 GiB，
// 我们不能去分配那块内存，也不能无限等待永远不会到达的字节。
//
// ⚠️ 注意区分两个"长度"：
//   - **传输层**长度前缀（4B）——由 readFrame 校验
//   - **wire** 层长度前缀（帧内容的头 4B）——由 wire.DecodeFrame 校验
//
// 本用例测试前者：直接发送一个传输层就声明超长的载荷。
// 后者由 TestMalformedFramesDoNotCrash 覆盖（属于内容畸形，连接不受影响）。
func TestBogusLengthDeclarationClosesConnection(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceMgr.StartHandshake(p.bob); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitForEvent[HandshakeDone](t, p.aliceMgr.Events(), 30*time.Second, "alice done")
	waitForEvent[HandshakeDone](t, p.bobMgr.Events(), 30*time.Second, "bob done")

	// ⚠️ 不能用 p.bobMgr 的传输层来观察这个事件。
	//
	// 原因：session.Manager 会**独占消费** transport.Events() 通道
	// （见 consumeTransportEvents）。测试再去读同一个通道，
	// 两者会竞争，谁先拿到事件是随机的——表现为间歇性失败。
	//
	// 因此这里另起一个**独立的**传输层，只用来验证
	// "读取侧能挡住非法长度声明"这个传输层自身的性质。
	probe := lan.New(lan.Config{Fingerprint: "PROBE0000000000000000000000000000000000", ListenPort: 0})
	if err := probe.Start(t.Context()); err != nil {
		t.Fatalf("probe transport: %v", err)
	}
	defer func() { _ = probe.Close() }()

	nc, err := net.DialTimeout("tcp", probe.LocalAddr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial probe: %v", err)
	}
	defer func() { _ = nc.Close() }()

	// 传输层长度前缀声明 0xFFFFFFFF，然后什么都不给。
	if _, err := nc.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatalf("write bogus prefix: %v", err)
	}

	// probe 必须干净地关闭该连接，而不是挂起等待 4 GiB。
	deadline := time.After(25 * time.Second)
	for {
		select {
		case ev := <-probe.Events():
			cc, ok := ev.(transport.ConnClosed)
			if !ok {
				continue
			}
			if cc.Err == nil || !errors.Is(cc.Err, transport.ErrFrameTooLarge) {
				t.Logf("ignoring unrelated close: %s (err=%v)", cc.ID, cc.Err)
				continue
			}
			t.Logf("correctly closed connection from hostile peer: %s (err=%v)", cc.ID, cc.Err)
			return
		case <-deadline:
			t.Fatal("timeout: transport did not close connection after bogus length declaration")
		}
	}
}

// 并发发送不应破坏会话状态。
func TestConcurrentSendsAreSerialized(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceMgr.StartHandshake(p.bob); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	waitForEvent[HandshakeDone](t, p.aliceMgr.Events(), 30*time.Second, "alice done")
	waitForEvent[HandshakeDone](t, p.bobMgr.Events(), 30*time.Second, "bob done")

	const n = 15
	var wg sync.WaitGroup
	var mu sync.Mutex
	var succeeded []string
	for i := 0; i < n; i++ {
		body := fmt.Sprintf("concurrent-%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.aliceMgr.SendText(p.bob, body); err == nil {
				mu.Lock()
				succeeded = append(succeeded, body)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// 收到的消息必须与成功发送的一致（不重不漏）。
	got := map[string]bool{}
	for i := 0; i < len(succeeded); i++ {
		msg := waitForEvent[Message](t, p.bobMgr.Events(), 20*time.Second, "concurrent recv")
		if got[msg.Plaintext.Text] {
			t.Fatalf("duplicate message %q (replay or seq corruption)", msg.Plaintext.Text)
		}
		got[msg.Plaintext.Text] = true
	}
	for _, s := range succeeded {
		if !got[s] {
			t.Errorf("message %q succeeded locally but never arrived", s)
		}
	}
}
