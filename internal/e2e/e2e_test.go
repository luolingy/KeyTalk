// Package e2e 是跨模块的端到端测试。
//
// 与各模块自己的单元测试不同，这里把 **crypto + wire + transport + session**
// 四层串起来跑真实 TCP，验证它们**协作**时的行为。
//
// 存在理由：每个模块单独测试都通过，不代表组合起来能工作。
// 本项目实际就踩到过这个坑——各层单测全绿，但整条链路
// 因为入站连接的身份归属问题而静默失败。
package e2e

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/session"
	"github.com/exeliang/keytalk/internal/transport"
	"github.com/exeliang/keytalk/internal/transport/lan"
	"github.com/exeliang/keytalk/internal/wire"
)

func TestFullStackEncryptedChat(t *testing.T) {
	ctx := t.Context()

	aliceID := mustID(t, "alice")
	bobID := mustID(t, "bob")
	malloryID := mustID(t, "mallory")

	aliceTr := lan.New(lan.Config{Fingerprint: aliceID.fp.String(), ListenPort: 0})
	bobTr := lan.New(lan.Config{Fingerprint: bobID.fp.String(), ListenPort: 0})
	if err := aliceTr.Start(ctx); err != nil {
		t.Fatalf("alice transport: %v", err)
	}
	if err := bobTr.Start(ctx); err != nil {
		t.Fatalf("bob transport: %v", err)
	}
	defer func() { _ = aliceTr.Close(); _ = bobTr.Close() }()

	ap := session.PeerID(aliceID.fp.String())
	bp := session.PeerID(bobID.fp.String())

	aliceTr.SetPeerForTest(transport.PeerID(bp), bobTr.LocalAddr(), bobID.fp.String())
	bobTr.SetPeerForTest(transport.PeerID(ap), aliceTr.LocalAddr(), aliceID.fp.String())

	alice := session.New(session.Config{Identity: aliceID.prov, Importer: &crypto.PGPImporter{}, Transport: aliceTr})
	bob := session.New(session.Config{Identity: bobID.prov, Importer: &crypto.PGPImporter{}, Transport: bobTr})
	defer alice.Close()
	defer bob.Close()

	alice.AddPeer(bp, session.PeerConfig{Fingerprint: bobID.fp, PublicKey: bobID.pub})
	alice.SetTransportPeer(bp, transport.PeerID(bp))
	bob.AddPeer(ap, session.PeerConfig{Fingerprint: aliceID.fp, PublicKey: aliceID.pub})
	bob.SetTransportPeer(ap, transport.PeerID(ap))

	alice.Start(ctx)
	bob.Start(ctx)

	aliceMsgs := make(chan string, 100)
	bobMsgs := make(chan string, 100)
	go collect(alice, aliceMsgs)
	go collect(bob, bobMsgs)

	step("handshake")
	if err := alice.StartHandshake(bp); err != nil {
		t.Fatalf("start handshake: %v", err)
	}
	if !waitState(alice, bp, 30*time.Second) {
		t.Fatalf("alice handshake never completed")
	}
	if !waitState(bob, ap, 30*time.Second) {
		t.Fatalf("bob handshake never completed")
	}
	pass("both sides report an established session")

	step("send alice -> bob")
	fromAlice := []string{
		"hello bob",
		"this is the second message",
		"a third one, with unicode: message",
	}
	for _, m := range fromAlice {
		if err := alice.SendText(bp, m); err != nil {
			t.Fatalf("alice send %q: %v", m, err)
		}
	}
	for i, want := range fromAlice {
		got, ok := recv(bobMsgs, 20*time.Second)
		if !ok {
			t.Fatalf("bob never received message %d (%q)", i, want)
		}
		if got != want {
			t.Fatalf("bob message %d = %q, want %q", i, got, want)
		}
	}
	pass("%d messages delivered in order, byte-identical", len(fromAlice))

	step("send bob -> alice")
	fromBob := []string{"reply one", "reply two"}
	for _, m := range fromBob {
		if err := bob.SendText(ap, m); err != nil {
			t.Fatalf("bob send %q: %v", m, err)
		}
	}
	for i, want := range fromBob {
		got, ok := recv(aliceMsgs, 20*time.Second)
		if !ok {
			t.Fatalf("alice never received reply %d", i)
		}
		if got != want {
			t.Fatalf("alice reply %d = %q, want %q", i, got, want)
		}
	}
	pass("reverse direction works")

	step("many messages (ordering + no loss)")
	const n = 30
	sent := 0
	for i := 0; i < n; i++ {
		m := fmt.Sprintf("bulk-%03d", i)
		if err := alice.SendText(bp, m); err != nil {
			break
		}
		sent++
	}
	received := 0
	deadline := time.After(30 * time.Second)
loop:
	for received < sent {
		select {
		case m := <-bobMsgs:
			want := fmt.Sprintf("bulk-%03d", received)
			if m != want {
				t.Fatalf("out of order at %d: got %q want %q", received, m, want)
			}
			received++
		case <-deadline:
			break loop
		}
	}
	if received != sent {
		t.Fatalf("lost messages: sent %d, received %d", sent, received)
	}
	pass("%d bulk messages delivered in exact order", sent)

	step("attacker cannot inject")
	// Mallory dials Bob directly and sends a garbage KEM_INIT.
	nc, err := net.DialTimeout("tcp", bobTr.LocalAddr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = nc.Close() }()
	// A syntactically valid frame carrying a bogus OpenPGP blob.
	bogus := &wire.Frame{Type: wire.TypeKEMInit, Body: []byte("not-a-real-pgp-blob-at-all-padding")}
	raw, _ := bogus.Encode(nil)
	lenPfx := []byte{byte(len(raw) >> 24), byte(len(raw) >> 16), byte(len(raw) >> 8), byte(len(raw))}
	_, _ = nc.Write(append(lenPfx, raw...))
	time.Sleep(1 * time.Second)

	if bob.HasSession("mallory" + session.PeerID(malloryID.fp.String())) {
		t.Fatalf("bob accepted a session from an unknown identity")
	}
	pass("unknown sender rejected (no session created)")

	step("session still healthy after attack")
	if err := alice.SendText(bp, "after the attack"); err != nil {
		t.Fatalf("send after attack: %v", err)
	}
	got, ok := recv(bobMsgs, 20*time.Second)
	if !ok || got != "after the attack" {
		t.Fatalf("legitimate traffic broken after attack attempt (got %q, ok=%v)", got, ok)
	}
	pass("legitimate traffic unaffected")

	fmt.Println()
	fmt.Println("*** ALL END-TO-END CHECKS PASSED ***")
}

func collect(m *session.Manager, out chan<- string) {
	for ev := range m.Events() {
		switch e := ev.(type) {
		case session.Message:
			out <- e.Plaintext.Text
		case session.HandshakeFailed:
			fmt.Printf("  [handshake failed] %v\n", e.Err)
		}
	}
}

func waitState(m *session.Manager, peer session.PeerID, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if m.HasSession(peer) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func recv(ch <-chan string, d time.Duration) (string, bool) {
	select {
	case m := <-ch:
		return m, true
	case <-time.After(d):
		return "", false
	}
}

type id struct {
	prov *crypto.PGPProvider
	fp   crypto.Fingerprint
	pub  []byte
}

func mustID(t *testing.T, name string) id {
	t.Helper()
	p, err := crypto.GeneratePGPIdentity(crypto.PGPConfig{
		Name: name, Email: name + "@x.test", RSABits: 1024,
	})
	if err != nil {
		t.Fatalf("generate %s: %v", name, err)
	}
	return id{prov: p, fp: p.Fingerprint(), pub: p.PublicKey()}
}

func step(s string)           { fmt.Printf("\n=== %s ===\n", s) }
func pass(f string, a ...any) { fmt.Printf("  [OK] "+f+"\n", a...) }
