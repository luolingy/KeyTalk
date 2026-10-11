package core

import (
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/sas"
)

// waitForEmoji 等到某联系人拿到 emoji 核对值。
func waitForEmoji(t *testing.T, app *App, peerID string, timeout time.Duration) Contact {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c, ok := app.Contact(peerID); ok && len(c.Emoji) > 0 {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	c, _ := app.Contact(peerID)
	t.Fatalf("timed out waiting for emoji for %s (status=%v, emoji=%d)",
		peerID, c.Status, len(c.Emoji))
	return Contact{}
}

// TestBothSidesDeriveIdenticalEmoji 是本功能的核心断言。
//
// 双方各自从自己的握手哈希派生 emoji，必须得到**完全相同**的结果——
// 否则用户永远无法核对成功，功能等于不存在。
//
// 同时也验证了"两端算出的握手哈希确实一致"，这在密码学上是
// SAS 能成立的前提：如果记录哈希不同，说明其中一方被篡改了。
func TestBothSidesDeriveIdenticalEmoji(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 45*time.Second)
	waitForStatus(t, p.bobApp, p.aliceFP.String(), StatusSecure, 45*time.Second)

	ac := waitForEmoji(t, p.aliceApp, p.bobFP.String(), 10*time.Second)
	bc := waitForEmoji(t, p.bobApp, p.aliceFP.String(), 10*time.Second)

	if len(ac.Emoji) != sas.EmojiCount {
		t.Errorf("alice has %d emoji, want %d", len(ac.Emoji), sas.EmojiCount)
	}
	if len(bc.Emoji) != sas.EmojiCount {
		t.Errorf("bob has %d emoji, want %d", len(bc.Emoji), sas.EmojiCount)
	}

	if !sas.Matches(ac.Emoji, bc.Emoji) {
		t.Fatalf("SAS mismatch between the two sides — users could never "+
			"verify successfully\n  alice: %s\n  bob:   %s\n"+
			"This means the handshake transcript hashes differ, which is "+
			"itself a security-relevant defect.",
			sas.Format(ac.Emoji), sas.Format(bc.Emoji))
	}
	t.Logf("both sides derived: %s", sas.Format(ac.Emoji))
}

// TestHandshakeDoesNotAutoVerify 是本功能最重要的**安全**断言。
//
// 握手完成绝不能自动把联系人标成"已核对"。
// 若这条测试失败，整个 SAS 机制就退化成 TOFU
// （首次使用即信任）——那正是本项目想避免的攻击面：
// 攻击者只要抢先连接一次，就能长期冒名而用户看到"已验证"。
func TestHandshakeDoesNotAutoVerify(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 45*time.Second)
	waitForStatus(t, p.bobApp, p.aliceFP.String(), StatusSecure, 45*time.Second)

	for _, side := range []struct {
		name string
		app  *App
		peer string
	}{
		{"alice", p.aliceApp, p.bobFP.String()},
		{"bob", p.bobApp, p.aliceFP.String()},
	} {
		c, ok := side.app.Contact(side.peer)
		if !ok {
			t.Fatalf("%s: contact missing", side.name)
		}
		if c.Status != StatusSecure {
			t.Fatalf("%s: status = %v, want StatusSecure", side.name, c.Status)
		}
		if c.Verified {
			t.Errorf("%s: contact is marked Verified after the handshake alone. "+
				"This defeats the entire point of the emoji check: the user "+
				"never confirmed anything, yet the UI would claim the identity "+
				"was verified.", side.name)
		}
	}
}

// TestVerifyEmojiRequiresUserAction 验证只有显式调用才会置为已验证。
func TestVerifyEmojiRequiresUserAction(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 45*time.Second)

	waitForEmoji(t, p.aliceApp, p.bobFP.String(), 10*time.Second)

	if err := p.aliceApp.VerifyEmoji(p.bobFP.String()); err != nil {
		t.Fatalf("VerifyEmoji: %v", err)
	}

	c, _ := p.aliceApp.Contact(p.bobFP.String())
	if !c.Verified {
		t.Fatal("VerifyEmoji returned nil but the contact is still not Verified")
	}

	// 只影响被确认的那一方，不能连带把其他联系人标成已验证。
	if len(p.aliceApp.Snapshot()) != 1 {
		t.Fatalf("expected exactly 1 contact in this fixture")
	}
}

// TestVerifyEmojiRejectsUnknownContact 验证未知联系人被拒绝。
func TestVerifyEmojiRejectsUnknownContact(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	if err := p.aliceApp.VerifyEmoji("0000000000000000000000000000000000000000"); err == nil {
		t.Error("VerifyEmoji accepted an unknown contact; a typo in the peer " +
			"ID must not silently succeed")
	}
}

// TestVerifyEmojiRejectsWhenNoSession 验证没有会话时无法确认。
//
// 若允许，界面就能在"根本还没建立会话"时显示"已验证"——
// 那是纯粹的谎报。
func TestVerifyEmojiRejectsWhenNoSession(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	// 不做任何握手，直接尝试确认。
	if err := p.aliceApp.VerifyEmoji(p.bobFP.String()); err == nil {
		t.Error("VerifyEmoji succeeded with no established session; " +
			"there is nothing to have verified yet")
	}

	c, _ := p.aliceApp.Contact(p.bobFP.String())
	if c.Verified {
		t.Error("contact is marked Verified despite having no session")
	}
}

// TestVerificationResetsOnSessionLoss 验证会话断开后核对状态被清除。
//
// 这是安全关键：新会话 = 新密钥 = 新 emoji。
// 若沿用旧确认，用户核对过的"那个人"会被自动套用到全新链路上，
// 攻击者只要等一次重连就能继承信任。
func TestVerificationResetsOnSessionLoss(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 45*time.Second)
	waitForEmoji(t, p.aliceApp, p.bobFP.String(), 10*time.Second)

	if err := p.aliceApp.VerifyEmoji(p.bobFP.String()); err != nil {
		t.Fatalf("VerifyEmoji: %v", err)
	}
	if c, _ := p.aliceApp.Contact(p.bobFP.String()); !c.Verified {
		t.Fatal("precondition failed: not verified")
	}

	// 让 bob 侧断开，alice 应观察到会话回落。
	p.bobApp.Shutdown()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, _ := p.aliceApp.Contact(p.bobFP.String())
		if !c.Verified {
			t.Logf("verification cleared after session loss (status=%v, emoji=%d)",
				c.Status, len(c.Emoji))
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	c, _ := p.aliceApp.Contact(p.bobFP.String())
	t.Fatalf("contact is STILL marked Verified after the peer disconnected "+
		"(status=%v). A stale confirmation must never outlive its session: "+
		"the next session has different keys and different emoji.", c.Status)
}

// TestEmojiAreStableWithinASession 验证同一会话内 emoji 不变化。
//
// 若 emoji 会抖动，用户核对到一半就变了，核对无法完成。
func TestEmojiAreStableWithinASession(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 45*time.Second)
	first := waitForEmoji(t, p.aliceApp, p.bobFP.String(), 10*time.Second)

	for i := 0; i < 25; i++ {
		c, _ := p.aliceApp.Contact(p.bobFP.String())
		if !sas.Matches(first.Emoji, c.Emoji) {
			t.Fatalf("emoji changed within a single session at poll %d:\n"+
				"  before: %s\n  after:  %s",
				i, sas.Format(first.Emoji), sas.Format(c.Emoji))
		}
		time.Sleep(40 * time.Millisecond)
	}
}

// TestSnapshotDoesNotAliasInternalEmoji 验证快照返回的 emoji 是副本。
//
// 若返回内部切片，调用方（UI）改写它会污染 core 的状态，
// 产生难以复现的串数据。
func TestSnapshotDoesNotAliasInternalEmoji(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 45*time.Second)
	waitForEmoji(t, p.aliceApp, p.bobFP.String(), 10*time.Second)

	snap := p.aliceApp.Snapshot()
	if len(snap) == 0 || len(snap[0].Emoji) == 0 {
		t.Fatal("no emoji in snapshot")
	}

	// 破坏快照里的第一项。
	original := snap[0].Emoji[0].Char
	snap[0].Emoji[0] = sas.Emoji{Char: "XXX", Name: "corrupted"}

	fresh := p.aliceApp.Snapshot()
	if fresh[0].Emoji[0].Char != original {
		t.Fatal("mutating a returned snapshot changed core's internal state; " +
			"Snapshot must return copies")
	}
}
