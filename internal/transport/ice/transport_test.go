package ice

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/transport"
)

// TestLoopbackConnectivity 是本包最重要的一条：两个 ICE agent 在同一台
// 机器上通过**手动交换信令**（offer/answer）建立连接，然后互发帧。
//
// 这是"零服务器、人工搬运信令"路径的端到端验证。它跑在 loopback 上，
// 因此不依赖外部网络或公共 STUN（host 候选即可连通）。
func TestLoopbackConnectivity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 两个 agent 都只启用 loopback 网络，避免依赖真实网卡/STUN。
	mk := func(fp string) *Transport {
		tr := New(Config{Fingerprint: fp})
		tr.testLoopback = true
		return tr
	}
	alice := mk("ALICE0000")
	bob := mk("BOB00000")

	if err := alice.Start(ctx); err != nil {
		t.Fatalf("alice.Start: %v", err)
	}
	defer alice.Close()
	if err := bob.Start(ctx); err != nil {
		t.Fatalf("bob.Start: %v", err)
	}
	defer bob.Close()

	// 收集候选并生成"offer/answer"式信令。
	aliceSig, err := alice.LocalSignal(20 * time.Second)
	if err != nil {
		t.Fatalf("alice.LocalSignal: %v", err)
	}
	bobSig, err := bob.LocalSignal(20 * time.Second)
	if err != nil {
		t.Fatalf("bob.LocalSignal: %v", err)
	}

	// 发起方是 alice（controlling=true），应答方 bob。
	var wg sync.WaitGroup
	wg.Add(2)
	var aliceErr, bobErr error
	go func() { defer wg.Done(); aliceErr = alice.Connect(ctx, bobSig, true) }()
	go func() { defer wg.Done(); bobErr = bob.Connect(ctx, aliceSig, false) }()
	wg.Wait()
	if aliceErr != nil {
		t.Fatalf("alice.Connect: %v", aliceErr)
	}
	if bobErr != nil {
		t.Fatalf("bob.Connect: %v", bobErr)
	}

	// alice 发一帧，bob 应当收到（内容完全一致）。
	payload := []byte("hello over ice, 中文也要能过")
	if err := alice.Send("BOB00000", payload); err != nil {
		t.Fatalf("alice.Send: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-bob.Events():
			if fr, ok := ev.(transport.FrameReceived); ok {
				if string(fr.Frame) != string(payload) {
					t.Fatalf("bob got %q, want %q", fr.Frame, payload)
				}
				return // 成功
			}
		case <-deadline:
			t.Fatal("bob did not receive the frame within 10s")
		}
	}
}

// TestSendWithoutConnection 验证未连接时 Send 返回 ErrNotConnected（可重试语义）。
func TestSendWithoutConnection(t *testing.T) {
	tr := New(Config{Fingerprint: "NOPE000"})
	if err := tr.Send("someone", []byte("x")); err != transport.ErrNotConnected {
		t.Errorf("Send without connection = %v, want ErrNotConnected", err)
	}
}

// TestSendOversizeFrame 验证超大帧被拒绝。
func TestSendOversizeFrame(t *testing.T) {
	tr := New(Config{Fingerprint: "NOPE000"})
	huge := make([]byte, maxFrame+1)
	if err := tr.Send("x", huge); err != transport.ErrFrameTooLarge {
		t.Errorf("oversize Send = %v, want ErrFrameTooLarge", err)
	}
}

// TestConnectBadSignal 验证坏信令不会 panic，返回错误。
func TestConnectBadSignal(t *testing.T) {
	tr := New(Config{Fingerprint: "X"})
	// Start 一个 agent，否则 SetRemoteCredentials 会 panic。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tr.Close()
	if err := tr.Connect(ctx, "garbage", true); err == nil {
		t.Fatal("Connect accepted garbage signaling")
	}
}
