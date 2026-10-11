package core

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/session"
	"github.com/exeliang/keytalk/internal/transport"
	"github.com/exeliang/keytalk/internal/transport/lan"
)

// testIdentity 生成一个临时身份。
func testIdentity(t *testing.T, name string) *crypto.PGPProvider {
	t.Helper()
	p, err := crypto.GeneratePGPIdentity(crypto.PGPConfig{
		Name: name, Email: name + "@test.local", RSABits: 1024,
	})
	if err != nil {
		t.Fatalf("generate identity %s: %v", name, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// pair 是两名通过真实 loopback TCP 连通的用户。
type pair struct {
	aliceApp *App
	bobApp   *App
	aliceFP  crypto.Fingerprint
	bobFP    crypto.Fingerprint
	aliceID  *crypto.PGPProvider
	bobID    *crypto.PGPProvider
	cleanup  func()
}

// setupPair 建立一对已能互相通信的 core.App。
func setupPair(t *testing.T) *pair {
	t.Helper()

	aliceID := testIdentity(t, "alice")
	bobID := testIdentity(t, "bob")
	aliceFP := aliceID.Fingerprint()
	bobFP := bobID.Fingerprint()

	aliceTr := lan.New(lan.Config{Fingerprint: aliceFP.String(), DisplayName: "alice", ListenPort: 0})
	bobTr := lan.New(lan.Config{Fingerprint: bobFP.String(), DisplayName: "bob", ListenPort: 0})

	if err := aliceTr.Start(context.Background()); err != nil {
		t.Fatalf("alice transport: %v", err)
	}
	if err := bobTr.Start(context.Background()); err != nil {
		t.Fatalf("bob transport: %v", err)
	}

	// 直接注入地址，避免测试依赖 mDNS（CI/容器里不可靠）。
	//
	// 用 127.0.0.1 显式构造地址：LocalAddr() 返回的是 [::]:port，
	// 直接拿它去 Dial 在部分环境会失败或不稳定。
	_, bobPort, _ := net.SplitHostPort(bobTr.LocalAddr().String())
	_, alicePort, _ := net.SplitHostPort(aliceTr.LocalAddr().String())
	bobAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("127.0.0.1", bobPort))
	if err != nil {
		t.Fatalf("resolve bob addr: %v", err)
	}
	aliceAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("127.0.0.1", alicePort))
	if err != nil {
		t.Fatalf("resolve alice addr: %v", err)
	}
	t.Logf("bob listening %s (dial as %s); alice listening %s (dial as %s)",
		bobTr.LocalAddr(), bobAddr, aliceTr.LocalAddr(), aliceAddr)
	aliceTr.SetPeerForTest(transport.PeerID(bobFP.String()), bobAddr, bobFP.String())
	bobTr.SetPeerForTest(transport.PeerID(aliceFP.String()), aliceAddr, aliceFP.String())

	aliceApp, err := New(Config{
		Identity:  aliceID,
		Importer:  &crypto.PGPImporter{},
		Transport: aliceTr,
		Contacts: []ContactConfig{{
			Name:        "bob",
			Fingerprint: bobFP.String(),
			PublicKey:   bobID.PublicKey(),
		}},
		TrustedFingerprints: []string{bobFP.String()},
		Logf:                func(f string, a ...any) { t.Logf("[alice] "+f, a...) },
	})
	if err != nil {
		t.Fatalf("alice core: %v", err)
	}

	bobApp, err := New(Config{
		Identity:  bobID,
		Importer:  &crypto.PGPImporter{},
		Transport: bobTr,
		Contacts: []ContactConfig{{
			Name:        "alice",
			Fingerprint: aliceFP.String(),
			PublicKey:   aliceID.PublicKey(),
		}},
		TrustedFingerprints: []string{aliceFP.String()},
		Logf:                func(f string, a ...any) { t.Logf("[bob] "+f, a...) },
	})
	if err != nil {
		aliceApp.Shutdown()
		t.Fatalf("bob core: %v", err)
	}

	// 关联传输层 ID，使 Send 能找到对端。
	aliceApp.mgr.SetTransportPeer(session.PeerID(bobFP.String()), transport.PeerID(bobFP.String()))
	bobApp.mgr.SetTransportPeer(session.PeerID(aliceFP.String()), transport.PeerID(aliceFP.String()))

	p := &pair{
		aliceApp: aliceApp, bobApp: bobApp,
		aliceFP: aliceFP, bobFP: bobFP,
		aliceID: aliceID, bobID: bobID,
	}
	p.cleanup = func() {
		aliceApp.Shutdown()
		bobApp.Shutdown()
		_ = aliceTr.Close()
		_ = bobTr.Close()
	}
	return p
}

// waitEvent 等待一个满足条件的 core 事件。
func waitEvent[T Event](t *testing.T, ch <-chan Event, timeout time.Duration, what string) T {
	t.Helper()
	var zero T
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("event channel closed while waiting for %s", what)
			}
			if e, ok := ev.(T); ok {
				return e
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %s", what)
			return zero
		}
	}
}

// TestContactsLoadedFromConfig 验证配置里的联系人被正确装载。
func TestContactsLoadedFromConfig(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	contacts := p.aliceApp.Snapshot()
	if len(contacts) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(contacts))
	}
	c := contacts[0]
	if c.Name != "bob" {
		t.Errorf("name = %q, want bob", c.Name)
	}
	if c.Fingerprint.String() != p.bobFP.String() {
		t.Errorf("fingerprint = %s, want %s", c.Fingerprint, p.bobFP)
	}
	if c.Status != StatusOffline {
		t.Errorf("initial status = %v, want offline", c.Status)
	}
}

// TestRefusesUnverifiedContacts 验证核心安全决策：
// 未带外核对的联系人不得被静默信任。
func TestRefusesUnverifiedContacts(t *testing.T) {
	aliceID := testIdentity(t, "alice")
	bobID := testIdentity(t, "bob")
	tr := lan.New(lan.Config{Fingerprint: aliceID.Fingerprint().String(), ListenPort: 0})
	if err := tr.Start(context.Background()); err != nil {
		t.Fatalf("transport: %v", err)
	}
	defer func() { _ = tr.Close() }()

	// 有联系人但没有 TrustedFingerprints —— 必须拒绝启动。
	_, err := New(Config{
		Identity:  aliceID,
		Importer:  &crypto.PGPImporter{},
		Transport: tr,
		Contacts: []ContactConfig{{
			Name:        "bob",
			Fingerprint: bobID.Fingerprint().String(),
			PublicKey:   bobID.PublicKey(),
		}},
		// TrustedFingerprints 故意留空
	})
	if err == nil {
		t.Fatal("New() accepted contacts without TrustedFingerprints; " +
			"this would silently treat unverified contacts as trusted")
	}
	if !strings.Contains(err.Error(), "TrustedFingerprints") {
		t.Errorf("error should mention TrustedFingerprints, got: %v", err)
	}
}

// TestAddContactRequiresConfirmation 验证导入公钥必须显式确认指纹。
func TestAddContactRequiresConfirmation(t *testing.T) {
	aliceID := testIdentity(t, "alice")
	bobID := testIdentity(t, "bob")

	tr := lan.New(lan.Config{Fingerprint: aliceID.Fingerprint().String(), ListenPort: 0})
	if err := tr.Start(context.Background()); err != nil {
		t.Fatalf("transport: %v", err)
	}
	defer func() { _ = tr.Close() }()

	app, err := New(Config{
		Identity:  aliceID,
		Importer:  &crypto.PGPImporter{},
		Transport: tr,
	})
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	defer app.Shutdown()

	// 未确认指纹：必须拒绝。
	if _, err := app.AddContact("bob", bobID.PublicKey(), false); err == nil {
		t.Fatal("AddContact accepted a contact without fingerprint confirmation; " +
			"this is the TOFU failure mode the design explicitly avoids")
	}

	// 已确认：应当成功。
	c, err := app.AddContact("bob", bobID.PublicKey(), true)
	if err != nil {
		t.Fatalf("AddContact with confirmation: %v", err)
	}
	if c.Name != "bob" || c.Fingerprint.String() != bobID.Fingerprint().String() {
		t.Errorf("unexpected contact: %+v", c)
	}

	// 重复添加是幂等的。
	c2, err := app.AddContact("bob", bobID.PublicKey(), true)
	if err != nil {
		t.Fatalf("idempotent AddContact: %v", err)
	}
	if c2.ID != c.ID {
		t.Errorf("re-add changed ID: %s -> %s", c.ID, c2.ID)
	}
}

// TestSendTextBeforeSessionFails 验证无会话时发送被明确拒绝。
//
// 必须**明确报错**而不是静默丢弃：用户需要知道消息没发出去。
func TestSendTextBeforeSessionFails(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	err := p.aliceApp.SendText(p.bobFP.String(), "hello")
	if err == nil {
		t.Fatal("SendText succeeded without an established session")
	}
	if !errors.Is(err, ErrNoSession) {
		t.Errorf("error = %v, want ErrNoSession", err)
	}
}

// TestSendTextValidation 验证输入校验。
func TestSendTextValidation(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceApp.SendText(p.bobFP.String(), ""); !errors.Is(err, ErrEmptyMessage) {
		t.Errorf("empty message error = %v, want ErrEmptyMessage", err)
	}
	if err := p.aliceApp.SendText("nobody", "hi"); !errors.Is(err, ErrUnknownContact) {
		t.Errorf("unknown contact error = %v, want ErrUnknownContact", err)
	}
	// 非法 UTF-8：对端会解析成乱码，必须在本地拦下。
	if err := p.aliceApp.SendText(p.bobFP.String(), string([]byte{0xff, 0xfe})); err == nil {
		t.Error("invalid UTF-8 was accepted")
	}
	// 超长消息必须在本地拦下，而不是让对端因帧过大断开。
	huge := strings.Repeat("a", MaxMessageBytes+1)
	if err := p.aliceApp.SendText(p.bobFP.String(), huge); !errors.Is(err, ErrMessageTooLong) {
		t.Errorf("oversized message error = %v, want ErrMessageTooLong", err)
	}
}

// TestEndToEndThroughCore 是核心验收测试：
// 两个 core.App 完成握手并双向收发消息，UI 只通过事件与快照观察。
func TestEndToEndThroughCore(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	// --- 握手 ---
	// 不指定谁发起：完全依赖 core 的角色规则（指纹较大方主动）
	// 与局域网发现驱动，与生产路径一致。
	// 若测试里强行让某一方发起，会掩盖角色竞态——那正是
	// 本项目出现过两次的真实故障（双方同时拨号导致握手互相顶掉）。

	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 30*time.Second)
	waitForStatus(t, p.bobApp, p.aliceFP.String(), StatusSecure, 30*time.Second)
	t.Log("both sides report StatusSecure")

	// --- alice -> bob ---
	msgs := []string{
		"hello bob",
		"第二条消息（含中文与 emoji 🙂）",
		"third message",
	}
	for _, m := range msgs {
		if err := p.aliceApp.SendText(p.bobFP.String(), m); err != nil {
			t.Fatalf("SendText(%q): %v", m, err)
		}
	}

	for i, want := range msgs {
		ev := waitEvent[MessageReceived](t, p.bobApp.Events(), 20*time.Second,
			"bob receives message "+want)
		if ev.Message.Text != want {
			t.Fatalf("bob message %d = %q, want %q", i, ev.Message.Text, want)
		}
		if ev.Message.Outgoing {
			t.Errorf("message %d marked as outgoing on the receiving side", i)
		}
	}

	// --- bob -> alice ---
	replies := []string{"reply one", "reply two"}
	for _, m := range replies {
		if err := p.bobApp.SendText(p.aliceFP.String(), m); err != nil {
			t.Fatalf("bob SendText(%q): %v", m, err)
		}
	}
	for i, want := range replies {
		ev := waitEvent[MessageReceived](t, p.aliceApp.Events(), 20*time.Second, "alice receives reply")
		if ev.Message.Text != want {
			t.Fatalf("alice reply %d = %q, want %q", i, ev.Message.Text, want)
		}
	}

	// --- 消息历史可被 UI 按会话读取 ---
	//
	// Bob 的历史 = 收到的 3 条 + 他回复的 2 条，共 5 条，
	// 且必须严格按发生顺序排列。这里同时验证"入站/出站"标记正确，
	// 因为 UI 靠它决定气泡往左还是往右画。
	bobHistory := p.bobApp.Messages(p.aliceFP.String())
	wantBob := len(msgs) + len(replies)
	if len(bobHistory) != wantBob {
		t.Fatalf("bob history has %d messages, want %d", len(bobHistory), wantBob)
	}
	// 前 3 条是收到的，之后 2 条是发出的。
	for i := 0; i < len(msgs); i++ {
		m := bobHistory[i]
		if m.Text != msgs[i] {
			t.Errorf("bob history[%d] = %q, want %q", i, m.Text, msgs[i])
		}
		if m.Outgoing {
			t.Errorf("bob history[%d] should be incoming", i)
		}
	}
	for i, want := range replies {
		m := bobHistory[len(msgs)+i]
		if m.Text != want {
			t.Errorf("bob history[%d] = %q, want %q", len(msgs)+i, m.Text, want)
		}
		if !m.Outgoing {
			t.Errorf("bob history[%d] should be outgoing", len(msgs)+i)
		}
	}

	// 出站消息也应出现在本机历史里，且已不在 Pending 状态。
	aliceHistory := p.aliceApp.Messages(p.bobFP.String())
	wantAlice := len(msgs) + len(replies)
	if len(aliceHistory) != wantAlice {
		t.Fatalf("alice history has %d messages, want %d", len(aliceHistory), wantAlice)
	}
	if !aliceHistory[0].Outgoing {
		t.Error("alice's first message should be outgoing")
	}
	if aliceHistory[0].Pending {
		t.Error("alice's first message is still marked Pending after a successful send")
	}

	t.Logf("core end-to-end: %d messages out, %d replies back, history consistent",
		len(msgs), len(replies))
}

// TestMessageTooLongIsNotSilentlyTruncated 验证超长消息被拒绝而非截断。
func TestMessageTooLongIsNotSilentlyTruncated(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceApp.StartChat(p.bobFP.String()); err != nil {
		t.Fatalf("StartChat: %v", err)
	}
	// ⚠️ 必须等**双方**都进入 secure。
	//
	// 只等 Alice 是不够的：握手是双向的，Alice 可能已经能加密发送，
	// 而 Bob 那一侧的会话尚未就绪（或仍在等 ACK）。
	// 此时 Alice 发出的帧会被 Bob 丢弃（"secure frame before handshake"），
	// 表现为"消息偶尔收不到"——看起来像丢包，实际是测试条件不足。
	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 30*time.Second)
	waitForStatus(t, p.bobApp, p.aliceFP.String(), StatusSecure, 30*time.Second)

	huge := strings.Repeat("x", MaxMessageBytes+10)
	err := p.aliceApp.SendText(p.bobFP.String(), huge)
	if !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("error = %v, want ErrMessageTooLong", err)
	}

	// 拒绝之后会话必须仍然可用——校验失败不能破坏已有会话。
	if err := p.aliceApp.SendText(p.bobFP.String(), "still works"); err != nil {
		t.Fatalf("session broken after a rejected oversized message: %v", err)
	}
	ev := waitEvent[MessageReceived](t, p.bobApp.Events(), 20*time.Second, "bob receives follow-up")
	if ev.Message.Text != "still works" {
		t.Errorf("got %q", ev.Message.Text)
	}
}

// TestSnapshotIsSafeConcurrently 验证快照可被 UI 线程并发读取。
//
// Gio 每帧都会读状态，因此这条路径必须无锁竞争。
// 用 -race 运行时才有实际意义。
func TestSnapshotIsSafeConcurrently(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = p.aliceApp.Snapshot()
			_ = p.aliceApp.Messages(p.bobFP.String())
			_, _ = p.aliceApp.Contact(p.bobFP.String())
		}
	}()

	if err := p.aliceApp.StartChat(p.bobFP.String()); err != nil {
		t.Fatalf("StartChat: %v", err)
	}
	<-done
	t.Log("concurrent snapshot reads completed without incident")
}

// TestShutdownIsIdempotent 验证重复关闭是安全的。
func TestShutdownIsIdempotent(t *testing.T) {
	p := setupPair(t)
	p.aliceApp.Shutdown()
	p.aliceApp.Shutdown()
	p.bobApp.Shutdown()
	p.cleanup()

	// 关闭后命令应返回 ErrClosed 而不是 panic 或挂起。
	if err := p.aliceApp.SendText(p.bobFP.String(), "after shutdown"); !errors.Is(err, ErrClosed) {
		t.Errorf("SendText after Shutdown = %v, want ErrClosed", err)
	}
}

// waitForStatus 轮询等待某个联系人达到指定状态。
func waitForStatus(t *testing.T, app *App, peerID string, want ContactStatus, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last ContactStatus
	var lastErr string
	for time.Now().Before(deadline) {
		if c, ok := app.Contact(peerID); ok {
			last = c.Status
			lastErr = c.LastError
			if c.Status == want {
				return
			}
			if c.Status == StatusFailed {
				t.Fatalf("contact entered StatusFailed: %s", c.LastError)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for status %v (last status %v, lastErr %q)", want, last, lastErr)
}
