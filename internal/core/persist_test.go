package core

import (
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/storage"
)

// TestSetupRestoresHistoryFromDisk 验证"重启后消息还在"这条完整路径：
// 存储层里有记录 -> 组装 App -> Messages() 能读出来。
func TestSetupRestoresHistoryFromDisk(t *testing.T) {
	dir := t.TempDir()
	s := newTestSetup(t, dir)
	if err := s.CreateIdentity("alice", setupPass); err != nil {
		t.Fatal(err)
	}

	peer := testIdentity(t, "bob")
	peerFP := peer.Fingerprint().String()
	if _, err := s.AddContact("bob", string(peer.PublicKey())); err != nil {
		t.Fatal(err)
	}

	// 加密身份必须带出主密钥，否则消息无法加密落盘。
	if !s.HasMessageStore() {
		t.Fatal("an encrypted identity produced no message store; " +
			"history would silently never persist")
	}

	// 直接往存储层写一条，模拟上一次运行留下的记录。
	// 用的是 Setup 自己打开的那一份，因此密钥一定对得上。
	if err := s.msgStore.Append(storage.MessageRecord{
		ID:       "m-from-last-run",
		PeerFP:   peerFP,
		Outgoing: false,
		Text:     "上一次运行时说的话",
		SentAt:   time.Now().Add(-time.Hour),
		State:    storage.StateSent,
	}); err != nil {
		t.Fatal(err)
	}

	app, err := s.App()
	if err != nil {
		t.Fatal(err)
	}

	got := app.Messages(peerFP)
	if len(got) != 1 {
		t.Fatalf("Messages() returned %d entries, want the 1 from disk", len(got))
	}
	if got[0].Text != "上一次运行时说的话" {
		t.Errorf("restored text = %q", got[0].Text)
	}
	if got[0].Outgoing {
		t.Error("direction was lost: an inbound message came back as outbound")
	}
	if got[0].State != MessageStateReceived {
		t.Errorf("state = %d, want MessageStateReceived", got[0].State)
	}
}

// TestSetupPlaintextIdentityHasNoStore 验证明文身份不持久化。
//
// 这是有意的：没有主密钥就无法加密，而 storage 层拒绝明文降级。
// 于是结果是"没有历史"，而不是"明文历史"。
func TestSetupPlaintextIdentityHasNoStore(t *testing.T) {
	dir := t.TempDir()

	// 造一份 v1 明文身份（等价于命令行 -setup 的产物）。
	if _, err := newTestSetup(t, dir).store.CreateUnencrypted("legacy"); err != nil {
		t.Fatal(err)
	}

	s := newTestSetup(t, dir)
	if s.Stage() != StageReady {
		t.Fatalf("plaintext identity did not reach StageReady")
	}
	if s.HasMessageStore() {
		t.Fatal("a plaintext identity got a message store; " +
			"there is no master key, so any write would be plaintext")
	}
}

// TestRestorePendingBecomesFailed 验证崩溃遗留的"待发送"按失败恢复。
//
// 显示成已发送会让用户以为对方看到了这条消息。
func TestRestorePendingBecomesFailed(t *testing.T) {
	a := &App{
		contacts: map[string]*contactState{peerAConst: {}},
		messages: map[string][]Message{},
	}
	a.restoreHistory([]storage.MessageRecord{
		{ID: "m1", PeerFP: peerAConst, Outgoing: true, Text: "没发出去的", State: storage.StatePending},
		{ID: "m2", PeerFP: peerAConst, Outgoing: true, Text: "发失败的", State: storage.StateFailed},
		{ID: "m3", PeerFP: peerAConst, Outgoing: true, Text: "发出去的", State: storage.StateSent},
	})

	byID := map[string]Message{}
	for _, m := range a.messages[peerAConst] {
		byID[m.ID] = m
	}
	if len(byID) != 3 {
		t.Fatalf("restored %d records, want 3", len(byID))
	}

	if got := byID["m1"].State; got != MessageStateFailed {
		t.Errorf("a pending record came back as state %d; "+
			"it must not look sent after a crash", got)
	}
	if got := byID["m2"].State; got != MessageStateFailed {
		t.Errorf("a failed record came back as state %d, want failed", got)
	}
	if got := byID["m3"].State; got != MessageStateSent {
		t.Errorf("a sent record came back as state %d, want sent", got)
	}
	// 恢复出来的都不能是 pending：本版本没有重发机制。
	for id, m := range byID {
		if m.Pending {
			t.Errorf("%s came back as pending; nothing will ever send it", id)
		}
	}
}

// TestRestoreDropsUnknownPeers 验证被删掉的联系人不恢复历史。
//
// 否则"删除联系人"只删掉了列表项，聊天记录还在，
// 那个联系人以另一种方式继续存在。
func TestRestoreDropsUnknownPeers(t *testing.T) {
	a := &App{
		contacts: map[string]*contactState{},
		messages: map[string][]Message{},
	}
	a.restoreHistory([]storage.MessageRecord{
		{ID: "m1", PeerFP: peerAConst, Outgoing: true, Text: "不该出现", State: storage.StateSent},
	})
	if n := len(a.messages[peerAConst]); n != 0 {
		t.Fatalf("restored %d messages for a peer that is not a contact", n)
	}
}

// TestStoreStateMapping 验证 core 状态到存储状态的映射。
func TestStoreStateMapping(t *testing.T) {
	cases := []struct {
		in   MessageState
		want int
	}{
		{MessageStatePending, storage.StatePending},
		{MessageStateSent, storage.StateSent},
		{MessageStateFailed, storage.StateFailed},
		// 入站消息折叠为"已送达"，方向由 Outgoing 单独记录。
		{MessageStateReceived, storage.StateSent},
	}
	for _, c := range cases {
		if got := storeStateOf(c.in); got != c.want {
			t.Errorf("storeStateOf(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestMessageIDsAreUnique 验证消息 ID 全局唯一。
//
// 早期实现是进程内自增的 "m1"、"m2"……，落盘后重启再发一条
// 又会得到 "m1"，与历史撞号——而日志按"同 ID 取最后一次"折叠，
// 新消息会把旧消息顶掉。
func TestMessageIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id := newMessageID()
		if seen[id] {
			t.Fatalf("duplicate message ID %q", id)
		}
		seen[id] = true
	}
}

// peerAConst 是一个合法的 40 位十六进制指纹，供不依赖真实密钥的用例使用。
const peerAConst = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
