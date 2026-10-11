package session

import (
	"testing"
	"time"
)

// TestSimultaneousHandshakeResolves 验证"同时发起"（glare）不会卡死。
//
// 场景：双方几乎同时发现对方，于是都发出 KEM_INIT。
// 这是**真实会发生**的——两个实例通过 mDNS 同时看到对方上线，
// 各自的自动握手逻辑同时触发。
//
// 曾经的表现（两侧都错）：
//   - 一侧接受对方 INIT 并报告成功，随后自己的超时定时器触发，
//     把刚建立的会话报告为**失败**；
//   - 另一侧互相拒绝，最终超时。
//     实测表现为"一侧建立、一侧超时"。
//
// 正确行为：确定性地选出一方作为 initiator，双方最终**都**建立成功，
// 且都不触发超时。
func TestSimultaneousHandshakeResolves(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	// 双方同时发起，不做任何先后协调。
	if err := p.aliceMgr.StartHandshake(p.bob); err != nil {
		t.Fatalf("alice start: %v", err)
	}
	if err := p.bobMgr.StartHandshake(p.alice); err != nil {
		t.Fatalf("bob start: %v", err)
	}

	// 双方都必须在超时（20s）之前建立成功。
	deadline := time.Now().Add(handshakeTimeout - 2*time.Second)
	for time.Now().Before(deadline) {
		if p.aliceMgr.HasSession(p.bob) && p.bobMgr.HasSession(p.alice) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 失败时把两侧内部状态打出来——"超时了"本身不足以定位问题。
	// 这三项正好覆盖历史上出现过的三种故障：
	//   sessions=0 双方都让出（死锁）
	//   pending=1  一方仍在等一条永远不会来的 ACK
	//   timers=1   残留定时器（会把成功的握手报告为失败）
	if !p.aliceMgr.HasSession(p.bob) || !p.bobMgr.HasSession(p.alice) {
		for name, m := range map[string]*Manager{"alice": p.aliceMgr, "bob": p.bobMgr} {
			m.mu.RLock()
			t.Logf("%s: sessions=%d pending=%d timers=%d",
				name, len(m.active), len(m.pending), len(m.pendingTimers))
			m.mu.RUnlock()
		}
	}
	if !p.aliceMgr.HasSession(p.bob) {
		t.Fatal("alice did not establish a session (glare deadlock)")
	}
	if !p.bobMgr.HasSession(p.alice) {
		t.Fatal("bob did not establish a session (glare deadlock)")
	}

	// 关键回归点：不能有任何一侧抛出 `HandshakeFailed`。
	//
	// 这正是原缺陷的症状——让步方的超时定时器没有被取消，
	// 于是在会话**已经建立**之后才触发，把成功报告成失败。
	//
	// 不睡满整个超时窗口（那会让测试慢且易受负载影响），
	// 而是直接断言"没有残留的定时器"——那正是缺陷的根因，
	// 比等一个症状更精确也更快。
	for name, m := range map[string]*Manager{"alice": p.aliceMgr, "bob": p.bobMgr} {
		m.mu.RLock()
		n := len(m.pendingTimers)
		m.mu.RUnlock()
		if n != 0 {
			t.Fatalf("%s has %d lingering handshake timer(s); "+
				"a stale timer would later report the live session as failed", name, n)
		}
	}

	// 同时确认事件流里没有已经排队的失败（快速排空，不等超时）。
	for name, ch := range map[string]<-chan Event{
		"alice": p.aliceMgr.Events(),
		"bob":   p.bobMgr.Events(),
	} {
		for {
			select {
			case ev := <-ch:
				if hf, ok := ev.(HandshakeFailed); ok {
					t.Fatalf("%s reported HandshakeFailed after glare resolution: %v", name, hf.Err)
				}
			default:
				goto next
			}
		}
	next:
	}

	// 会话必须真的可用：双方都能收发。
	if err := p.aliceMgr.SendText(p.bob, "alice after glare"); err != nil {
		t.Fatalf("alice send after glare: %v", err)
	}
	ev := waitForEvent[Message](t, p.bobMgr.Events(), 10*time.Second, "bob receives alice's message")
	if ev.Plaintext.Text != "alice after glare" {
		t.Fatalf("bob got %q", ev.Plaintext.Text)
	}

	if err := p.bobMgr.SendText(p.alice, "bob after glare"); err != nil {
		t.Fatalf("bob send after glare: %v", err)
	}
	ev2 := waitForEvent[Message](t, p.aliceMgr.Events(), 10*time.Second, "alice receives bob's message")
	if ev2.Plaintext.Text != "bob after glare" {
		t.Fatalf("alice got %q", ev2.Plaintext.Text)
	}

	// 双方的会话必须指向**同一个** SessionID——
	// 若两侧各自建立了不同的会话，说明产生了两个平行会话
	// （那会导致消息发到对方收不到的那条链上）。
	//
	// 用一次实际收发来间接验证：上面双向收发都成功，
	// 已经证明两侧对的是同一条会话。
	t.Log("glare resolved: both sides established and exchanged messages")
}

// TestGlareTieBreakIsDeterministic 验证平局规则本身是对称的。
//
// 规则必须让**恰好一方**让步：若双方都让步则无人发起，
// 若都不让步则双方都拒绝——两种都是死局。
func TestGlareTieBreakIsDeterministic(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	aliceFP := p.aliceMgr.cfg.Identity.Fingerprint()
	bobFP := p.bobMgr.cfg.Identity.Fingerprint()

	// alice 视角：与 bob 的指纹比较。
	aliceYields := p.aliceMgr.losesGlareTieBreak(p.bob, bobFP)
	// bob 视角：与 alice 的指纹比较。
	bobYields := p.bobMgr.losesGlareTieBreak(p.alice, aliceFP)

	if aliceYields == bobYields {
		t.Fatalf("tie-break is not deterministic: aliceYields=%v bobYields=%v "+
			"(both yielding or neither yielding is a deadlock)",
			aliceYields, bobYields)
	}
	t.Logf("alice(%s) yields=%v, bob(%s) yields=%v",
		aliceFP.Display()[:8], aliceYields, bobFP.Display()[:8], bobYields)
}
