package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/db"
	"github.com/exeliang/keytalk/internal/storage"
)

// TestMigrateLegacyLog 验证旧版 jsonl 日志能一次导入新库，
// 且原目录被改名保留（可回退）。
func TestMigrateLegacyLog(t *testing.T) {
	dir := t.TempDir()
	mk := make([]byte, 32)
	for i := range mk {
		mk[i] = byte(i*7 + 3)
	}

	const peerFP = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"

	// 用旧存储层造两条消息，模拟上一个版本留下的数据。
	oldStore, err := storage.Open(dir, mk)
	if err != nil {
		t.Fatalf("seeding legacy store: %v", err)
	}
	for _, r := range []storage.MessageRecord{
		{ID: "old-1", PeerFP: peerFP, Outgoing: false, Text: "旧消息一",
			SentAt: time.UnixMilli(1000), State: storage.StateSent},
		{ID: "old-2", PeerFP: peerFP, Outgoing: true, Text: "旧消息二",
			SentAt: time.UnixMilli(2000), State: storage.StateFailed},
	} {
		if err := oldStore.Append(r); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}
	if err := oldStore.Close(); err != nil {
		t.Fatal(err)
	}

	// 确认旧目录存在。
	if _, err := os.Stat(filepath.Join(dir, "messages")); err != nil {
		t.Fatalf("legacy dir missing before migration: %v", err)
	}

	// 打开新库并迁移。
	store, err := OpenDBStore(dir, mk)
	if err != nil {
		t.Fatalf("OpenDBStore: %v", err)
	}
	defer store.Close()

	var logs []string
	if err := migrateLegacyLog(dir, mk, store, func(f string, a ...any) {
		logs = append(logs, f)
	}); err != nil {
		t.Fatalf("migrateLegacyLog: %v", err)
	}

	// 1. 消息进了新库。
	msgs, err := store.LoadMessages()
	if err != nil {
		t.Fatalf("LoadMessages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("migrated %d messages, want 2 (logs: %v)", len(msgs), logs)
	}
	byID := map[string]db.Message{}
	for _, m := range msgs {
		byID[m.ID] = m
	}
	if m, ok := byID["old-1"]; !ok || m.Text != "旧消息一" || m.Outgoing {
		t.Errorf("old-1 migrated wrong: %+v (present=%v)", m, ok)
	}
	if m, ok := byID["old-2"]; !ok || m.Text != "旧消息二" || !m.Outgoing || m.State != db.StateFailed {
		t.Errorf("old-2 migrated wrong: %+v (present=%v)", m, ok)
	}

	// 2. 旧目录被改名保留。
	if _, err := os.Stat(filepath.Join(dir, "messages")); !os.IsNotExist(err) {
		t.Error("the legacy messages/ directory is still in place after migration")
	}
	if _, err := os.Stat(filepath.Join(dir, "messages.migrated")); err != nil {
		t.Errorf("no messages.migrated/ backup was kept: %v", err)
	}

	// 3. 再跑一次迁移：旧目录已不在，应当安静地什么都不做。
	if err := migrateLegacyLog(dir, mk, store, nil); err != nil {
		t.Errorf("a second migration run failed: %v", err)
	}
	if got, _ := store.LoadMessages(); len(got) != 2 {
		t.Errorf("a second migration run duplicated messages: %d", len(got))
	}
}

// TestMigrateNoLegacyData 验证全新安装时迁移是空操作。
func TestMigrateNoLegacyData(t *testing.T) {
	dir := t.TempDir()
	mk := make([]byte, 32)
	store, err := OpenDBStore(dir, mk)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := migrateLegacyLog(dir, mk, store, nil); err != nil {
		t.Fatalf("migration on a fresh install returned %v", err)
	}
	if got, _ := store.LoadMessages(); len(got) != 0 {
		t.Errorf("fresh install got %d messages", len(got))
	}
}

// TestOpenDBStoreNoKey 验证没有主密钥时不建库。
func TestOpenDBStoreNoKey(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenDBStore(dir, nil)
	if err != nil {
		t.Fatalf("OpenDBStore(nil) returned %v", err)
	}
	if st != nil {
		t.Fatal("OpenDBStore(nil) returned a store; plaintext identities must not persist")
	}
	if _, err := os.Stat(filepath.Join(dir, "chat.db")); !os.IsNotExist(err) {
		t.Error("a database file was created without a key")
	}
}
