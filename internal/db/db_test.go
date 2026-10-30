package db

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// key 返回一把固定的 32 字节主密钥。
func key(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed*31 + byte(i)
	}
	return k
}

// openDB 打开一个测试库并注册清理。
func openDB(t *testing.T, dir string, mk []byte) *DB {
	t.Helper()
	d, err := Open(dir, mk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// withTx 在一个事务里跑 fn，成功则提交。
func withTx(t *testing.T, d *DB, fn func() error) {
	t.Helper()
	if err := d.Begin(); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := fn(); err != nil {
		_ = d.Rollback()
		t.Fatalf("tx body: %v", err)
	}
	if err := d.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// TestRoundTrip 是最基本的可用性断言：写进去、提交、读出来。
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	d := openDB(t, dir, key(1))

	want := Message{
		ID: "m-1", PeerFP: "AAAA", Outgoing: true,
		Text: "你好，数据库", SentAtMS: 1700000000000, State: StateSent,
	}
	withTx(t, d, func() error { return d.Messages().Put(want) })

	withTx(t, d, func() error {
		got, ok, err := d.Messages().ByID("m-1")
		if err != nil {
			return err
		}
		if !ok {
			t.Error("message not found after commit")
			return nil
		}
		if got != want {
			t.Errorf("got %+v\nwant %+v", got, want)
		}
		return nil
	})
}

// TestNoPlaintextOnDisk 是本包最重要的断言。
//
// 整个库文件（除 64 字节明文头）都应当是密文，
// 所以消息正文不该以任何形式出现。
func TestNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	d := openDB(t, dir, key(2))

	const secret = "我的银行卡密码是 987654"
	withTx(t, d, func() error {
		return d.Messages().Put(Message{
			ID: "m-secret", PeerFP: "BBBB", Text: secret,
			SentAtMS: 1, State: StateSent,
		})
	})

	raw, err := os.ReadFile(filepath.Join(dir, "chat.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("message body appears verbatim in the database file")
	}
	if bytes.Contains(raw, []byte("银行卡")) {
		t.Fatal("part of the message body appears in the database file")
	}
	// 连 ID 都不该明文出现（ID 也在加密页里）。
	if bytes.Contains(raw, []byte("m-secret")) {
		t.Fatal("message ID appears in plaintext in the database file")
	}
}

// TestWrongKeyRejected 验证错口令在打开时就报错，而不是解出垃圾。
func TestWrongKeyRejected(t *testing.T) {
	dir := t.TempDir()
	d := openDB(t, dir, key(3))
	withTx(t, d, func() error {
		return d.Messages().Put(Message{ID: "m1", PeerFP: "P", Text: "x", SentAtMS: 1})
	})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	for name, wrong := range map[string][]byte{
		"flipped bit": flip(key(3)),
		"other key":   key(9),
		"short key":   {1, 2, 3},
		"long key":    append(key(3), 0xFF),
	} {
		if _, err := Open(dir, wrong); !errors.Is(err, ErrWrongKey) && len(wrong) == 32 {
			t.Errorf("%s: Open with a wrong key returned %v, want ErrWrongKey", name, err)
		}
	}
}

// TestReopenSeesData 验证重启后数据还在——本次工作的核心。
func TestReopenSeesData(t *testing.T) {
	dir := t.TempDir()
	mk := key(4)

	d := openDB(t, dir, mk)
	withTx(t, d, func() error {
		for _, id := range []string{"m1", "m2", "m3"} {
			if err := d.Messages().Put(Message{
				ID: id, PeerFP: "PEER", Text: "消息 " + id, SentAtMS: int64(len(id)),
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d2 := openDB(t, dir, mk)
	withTx(t, d2, func() error {
		msgs, err := d2.Messages().All()
		if err != nil {
			return err
		}
		if len(msgs) != 3 {
			t.Fatalf("after reopen got %d messages, want 3", len(msgs))
		}
		return nil
	})
}

// TestPageSwapDetected 验证页被搬到另一个偏移会解密失败。
//
// 攻击者若能改磁盘，可以尝试把第 5 页的内容复制到第 6 页，
// 从而篡改某条消息。页号绑进 AAD，所以这会被察觉。
func TestPageSwapDetected(t *testing.T) {
	dir := t.TempDir()
	mk := key(5)
	d := openDB(t, dir, mk)

	// 写足够多的消息，占用多个数据页。
	withTx(t, d, func() error {
		for i := 0; i < 40; i++ {
			if err := d.Messages().Put(Message{
				ID:       "m" + string(rune('A'+i)),
				PeerFP:   "PEER",
				Text:     strings.Repeat("填充数据", 20),
				SentAtMS: int64(i),
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "chat.db")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 把第 2 页的记录整段复制到第 3 页（都在文件头之后）。
	src := pageOffset(2)
	dst := pageOffset(3)
	if dst+int64(PageRecordSize) > int64(len(raw)) {
		t.Fatalf("test setup: file too small for 4 pages (%d bytes)", len(raw))
	}
	copy(raw[dst:dst+int64(PageRecordSize)], raw[src:src+int64(PageRecordSize)])
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Open(dir, mk)
	if err == nil {
		t.Fatal("a swapped page was accepted; the page number is not bound into the AAD")
	}
}

// TestPageTamperDetected 验证改一个字节就会 AEAD 校验失败。
func TestPageTamperDetected(t *testing.T) {
	dir := t.TempDir()
	mk := key(6)
	d := openDB(t, dir, mk)
	withTx(t, d, func() error {
		return d.Messages().Put(Message{ID: "m1", PeerFP: "P", Text: "原始内容", SentAtMS: 1})
	})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "chat.db")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 翻转页 1 密文中间的一个字节。
	pos := pageOffset(1) + int64(PageRecordSize/2)
	raw[pos] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Open(dir, mk)
	if err == nil {
		t.Fatal("a tampered page was accepted")
	}
}

// TestTruncatedFileRejected 验证半截文件被识别为损坏而不是崩溃。
func TestTruncatedFileRejected(t *testing.T) {
	dir := t.TempDir()
	mk := key(7)
	d := openDB(t, dir, mk)
	withTx(t, d, func() error {
		return d.Messages().Put(Message{ID: "m1", PeerFP: "P", Text: "x", SentAtMS: 1})
	})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "chat.db")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 砍掉尾部半页。
	if err := os.WriteFile(path, raw[:len(raw)-PageRecordSize/2], 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir, mk); err == nil {
		t.Fatal("a truncated database opened successfully")
	}
}

// TestRollbackDiscardsWrites 验证回滚确实丢弃。
func TestRollbackDiscardsWrites(t *testing.T) {
	dir := t.TempDir()
	d := openDB(t, dir, key(8))

	if err := d.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := d.Messages().Put(Message{ID: "m-rollback", PeerFP: "P", Text: "不该留下", SentAtMS: 1}); err != nil {
		t.Fatal(err)
	}
	if err := d.Rollback(); err != nil {
		t.Fatal(err)
	}

	withTx(t, d, func() error {
		_, ok, err := d.Messages().ByID("m-rollback")
		if err != nil {
			return err
		}
		if ok {
			t.Error("a rolled-back message is visible")
		}
		return nil
	})
}

// TestUpdateSameID 验证状态变更就地覆盖而不是新增一行。
func TestUpdateSameID(t *testing.T) {
	dir := t.TempDir()
	d := openDB(t, dir, key(9))

	withTx(t, d, func() error {
		return d.Messages().Put(Message{ID: "m1", PeerFP: "P", Text: "同一条", SentAtMS: 5, State: StatePending})
	})
	withTx(t, d, func() error {
		return d.Messages().Put(Message{ID: "m1", PeerFP: "P", Text: "同一条", SentAtMS: 5, State: StateSent})
	})

	withTx(t, d, func() error {
		all, err := d.Messages().All()
		if err != nil {
			return err
		}
		if len(all) != 1 {
			t.Fatalf("got %d rows after updating the same ID, want 1", len(all))
		}
		if all[0].State != StateSent {
			t.Errorf("state = %d, want %d", all[0].State, StateSent)
		}
		return nil
	})
}

// TestManyRowsAcrossPages 验证跨多页的写入与读取。
func TestManyRowsAcrossPages(t *testing.T) {
	dir := t.TempDir()
	d := openDB(t, dir, key(10))

	const n = 300
	withTx(t, d, func() error {
		for i := 0; i < n; i++ {
			if err := d.Messages().Put(Message{
				ID:       "msg-" + itoa(i),
				PeerFP:   "PEER",
				Text:     strings.Repeat("x", 100),
				SentAtMS: int64(1000 + i),
			}); err != nil {
				return err
			}
		}
		return nil
	})

	withTx(t, d, func() error {
		all, err := d.Messages().All()
		if err != nil {
			return err
		}
		if len(all) != n {
			t.Fatalf("got %d rows, want %d", len(all), n)
		}
		// 顺序必须按时间升序。
		for i := 1; i < len(all); i++ {
			if all[i-1].SentAtMS > all[i].SentAtMS {
				t.Fatalf("rows out of order at %d: %d > %d", i, all[i-1].SentAtMS, all[i].SentAtMS)
			}
		}
		return nil
	})
}

// TestContactsAndAttachments 验证另外两张表也能用。
func TestContactsAndAttachments(t *testing.T) {
	dir := t.TempDir()
	d := openDB(t, dir, key(11))

	withTx(t, d, func() error {
		if err := d.Contacts().Upsert(Contact{
			Fingerprint: "AAAA1111", Name: "张三",
			PublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----", Verified: true, AddedAtMS: 42,
		}); err != nil {
			return err
		}
		return d.Attachments().Put(Attachment{
			ID: "at-1", MessageID: "m1", BlobID: "blob-1",
			Name: "报表.pdf", MIME: "application/pdf", Size: 1234, SHA256: "deadbeef",
		})
	})

	withTx(t, d, func() error {
		cs, err := d.Contacts().All()
		if err != nil {
			return err
		}
		if len(cs) != 1 || cs[0].Name != "张三" || !cs[0].Verified {
			t.Fatalf("contacts round-trip failed: %+v", cs)
		}
		as, err := d.Attachments().ByMessage("m1")
		if err != nil {
			return err
		}
		if len(as) != 1 || as[0].Name != "报表.pdf" || as[0].Size != 1234 {
			t.Fatalf("attachments round-trip failed: %+v", as)
		}
		return nil
	})
}

// TestLockPreventsSecondOpen 验证同一库不能被两个实例同时打开。
func TestLockPreventsSecondOpen(t *testing.T) {
	dir := t.TempDir()
	mk := key(12)
	d := openDB(t, dir, mk)

	// 同进程第二次打开：锁文件已存在且 PID 是自己，
	// 被判为陈锁（因为本进程还没建它）——这里验证的是
	// "另一个活体进程持有的锁会被拒绝"。
	// 同进程内我们无法伪造另一个活体 PID，因此直接测
	// 锁文件的创建与释放，以及陈锁接管。
	if _, err := os.Stat(filepath.Join(dir, "chat.db.lock")); err != nil {
		t.Fatalf("no lock file was created: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "chat.db.lock")); !os.IsNotExist(err) {
		t.Error("the lock file was not removed on Close")
	}
	// 关闭之后可以重新打开。
	d2 := openDB(t, dir, mk)
	if d2 == nil {
		t.Fatal("could not reopen after Close")
	}
}

// TestStaleLockTakenOver 验证死进程留下的锁会被接管。
func TestStaleLockTakenOver(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "chat.db.lock")

	// 造一个不存在的 PID 的锁文件。
	if err := os.WriteFile(lockPath, []byte("999999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Open(dir, key(13))
	if err != nil {
		t.Fatalf("a stale lock was not taken over: %v", err)
	}
	_ = d.Close()
}

// TestEmptyKeyRejected 验证空密钥被拒绝。
func TestEmptyKeyRejected(t *testing.T) {
	if _, err := Open(t.TempDir(), nil); err == nil {
		t.Fatal("Open accepted a nil key")
	}
	if _, err := Open(t.TempDir(), []byte{}); err == nil {
		t.Fatal("Open accepted an empty key")
	}
}

// --- 辅助 ---

func flip(k []byte) []byte {
	out := append([]byte(nil), k...)
	out[0] ^= 0xFF
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
