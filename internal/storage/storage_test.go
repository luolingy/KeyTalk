package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
)

const (
	peerA = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
	peerB = "FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000"
)

// testMK 返回一把固定的 32 字节主密钥。
func testMK() []byte {
	mk := make([]byte, 32)
	for i := range mk {
		mk[i] = byte(i*7 + 1)
	}
	return mk
}

func openTest(t *testing.T, dir string, mk []byte) *LogStore {
	t.Helper()
	st, err := Open(dir, mk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func rec(id, peer, text string, out bool, state int) MessageRecord {
	return MessageRecord{
		ID:       id,
		PeerFP:   peer,
		Outgoing: out,
		Text:     text,
		SentAt:   time.Now(),
		State:    state,
	}
}

// TestRoundTrip 是最基本的可用性断言。
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())

	want := "你好，这是一条测试消息"
	if err := st.Append(rec("m1", peerA, want, true, StateSent)); err != nil {
		t.Fatal(err)
	}

	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].Text != want {
		t.Errorf("text = %q, want %q", got[0].Text, want)
	}
	if got[0].PeerFP != peerA {
		t.Errorf("peer = %q, want %q", got[0].PeerFP, peerA)
	}
	if !got[0].Outgoing {
		t.Error("direction was not preserved")
	}
	if got[0].State != StateSent {
		t.Errorf("state = %d, want %d", got[0].State, StateSent)
	}
}

// TestNoPlaintextOnDisk 是本文件最重要的断言。
//
// 它存在的理由就是存储加密存在的理由。
func TestNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())

	const secret = "我的银行卡密码是 123456"
	if err := st.Append(rec("m1", peerA, secret, true, StateSent)); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "messages", peerA+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("the message body appears verbatim in the log file")
	}
	// 中文按 UTF-8 存，逐个子串也检查一遍，
	// 防止"只匹配整串"漏掉部分泄漏。
	if strings.Contains(string(raw), "银行卡") {
		t.Fatal("part of the message body appears in the log file")
	}
}

// TestWrongKeyYieldsNothing 验证拿错密钥解不出东西。
func TestWrongKeyYieldsNothing(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())
	if err := st.Append(rec("m1", peerA, "secret text", true, StateSent)); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	wrong := testMK()
	wrong[0] ^= 0xFF
	st2 := openTest(t, dir, wrong)

	got, err := st2.Load()
	if err != nil {
		t.Fatalf("Load with the wrong key: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("decrypted %d records with the wrong key", len(got))
	}
	if st2.BadLines() == 0 {
		t.Error("a failed decryption was not reported as a bad line")
	}
}

// TestCrossPeerRelocationDetected 验证把密文搬到另一个会话会被发现。
//
// 场景：攻击者能改磁盘上的文件，把 A 会话的消息复制进 B 会话，
// 让 B 看起来说过那些话。AAD 绑定了对端指纹，因此解密会失败。
func TestCrossPeerRelocationDetected(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())

	if err := st.Append(rec("m1", peerA, "这是 A 说的话", true, StateSent)); err != nil {
		t.Fatal(err)
	}

	msgDir := filepath.Join(dir, "messages")
	data, err := os.ReadFile(filepath.Join(msgDir, peerA+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(msgDir, peerB+".jsonl"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	// 只能读出 A 的那条；B 名下那条必须解密失败。
	for _, r := range got {
		if r.PeerFP == peerB {
			t.Fatalf("a record relocated to another peer still decrypted: %+v", r)
		}
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (the relocated copy must be rejected)", len(got))
	}
}

// TestStateTamperingDetected 验证改状态位会被发现。
//
// 场景：把 StateFailed 改成 StateSent，让一条根本没发出去的消息
// 在重启后显示成"已发送"。state 绑进了 AAD，因此改不动。
func TestStateTamperingDetected(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())

	if err := st.Append(rec("m1", peerA, "这条没发出去", true, StateFailed)); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "messages", peerA+".jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"st":2`, `"st":1`, 1)
	if tampered == string(raw) {
		t.Fatalf("test setup: could not find st:2 in %s", raw)
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a record with a tampered state still loaded: %+v", got)
	}
}

// TestSameIDTwiceLastWins 验证状态变更是追加而不是原地改写。
func TestSameIDTwiceLastWins(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())

	if err := st.Append(rec("m1", peerA, "hello", true, StatePending)); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(rec("m1", peerA, "hello", true, StateSent)); err != nil {
		t.Fatal(err)
	}

	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (same ID must fold)", len(got))
	}
	if got[0].State != StateSent {
		t.Errorf("state = %d, want %d (the last write must win)", got[0].State, StateSent)
	}
}

// TestCorruptLineSkipped 验证坏行不影响其余记录。
//
// 崩溃留下的半行不应该让整个会话的历史消失。
func TestCorruptLineSkipped(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())

	if err := st.Append(rec("m1", peerA, "第一条", true, StateSent)); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(rec("m2", peerA, "第二条", true, StateSent)); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "messages", peerA+".jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟崩溃：写到一半截断，没有换行。
	if _, err := f.WriteString(`{"v":1,"id":"m3","out":tr`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want the 2 intact ones", len(got))
	}
	if st.BadLines() == 0 {
		t.Error("the truncated line was not counted as bad")
	}
}

// TestPathTraversalRejected 验证对端指纹被当作文件名之前有校验。
//
// ⚠️ 对端指纹来自网络。不校验就是一个任意文件写入漏洞。
func TestPathTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())

	for _, bad := range []string{
		"../../../.ssh/authorized_keys",
		"..\\windows\\system32\\evil",
		"a/b",
		"a.b",
		"",
		strings.Repeat("A", 200),
	} {
		if err := st.Append(rec("m1", bad, "x", true, StateSent)); err == nil {
			t.Errorf("Append accepted peer fingerprint %q; that is a path traversal hole", bad)
		}
	}
}

// TestOpenWithoutKeyRefuses 验证没有 MK 时拒绝持久化而不是明文降级。
func TestOpenWithoutKeyRefuses(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Open with a nil key returned %v, want ErrNoKey", err)
	}
	if _, err := Open(dir, []byte{}); !errors.Is(err, ErrNoKey) {
		t.Fatal("Open accepted an empty key")
	}
	// 而且不应该留下任何目录。
	if _, err := os.Stat(filepath.Join(dir, "messages")); !os.IsNotExist(err) {
		t.Error("a refused Open still created the messages directory")
	}
}

// TestLoadSortsByTime 验证跨会话读取后的顺序。
func TestLoadSortsByTime(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())

	base := time.Now()
	r1 := rec("m1", peerA, "first", true, StateSent)
	r1.SentAt = base
	r2 := rec("m2", peerB, "second", false, StateSent)
	r2.SentAt = base.Add(time.Second)
	r3 := rec("m3", peerA, "third", true, StateSent)
	r3.SentAt = base.Add(2 * time.Second)

	for _, r := range []MessageRecord{r2, r3, r1} {
		if err := st.Append(r); err != nil {
			t.Fatal(err)
		}
	}

	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
	for i, want := range []string{"m1", "m2", "m3"} {
		if got[i].ID != want {
			t.Errorf("position %d = %s, want %s", i, got[i].ID, want)
		}
	}
	// 时间也要保下来。磁盘精度是**毫秒**（UnixMilli）：纳秒部分
	// 会被截断，这是有意的——毫秒足够给聊天排序，而 JSON 行更紧凑。
	// 同一毫秒内的两条消息由排序里的 ID 兜底。
	if gotMS, wantMS := got[0].SentAt.UnixMilli(), base.UnixMilli(); gotMS != wantMS {
		t.Errorf("timestamp = %d ms, want %d ms", gotMS, wantMS)
	}
}

// TestRepopenSeesHistory 验证"重启后消息还在"——本次工作的全部意义。
func TestRepopenSeesHistory(t *testing.T) {
	dir := t.TempDir()
	mk := testMK()

	st := openTest(t, dir, mk)
	if err := st.Append(rec("m1", peerA, "重启之后我还应该在", true, StateSent)); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// 新进程、新对象、同一份密钥。
	st2 := openTest(t, dir, mk)
	got, err := st2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Text != "重启之后我还应该在" {
		t.Fatalf("history did not survive the restart: %+v", got)
	}
}

// TestCloseZeroesKey 验证关闭后密钥被擦除、且不可再用。
func TestCloseZeroesKey(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, testMK())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if st.mk != nil {
		t.Error("the master key was not released on Close")
	}
	if err := st.Append(rec("m1", peerA, "x", true, StateSent)); err == nil {
		t.Error("Append succeeded after Close")
	}
	if _, err := st.Load(); err == nil {
		t.Error("Load succeeded after Close")
	}
	// 幂等。
	if err := st.Close(); err != nil {
		t.Errorf("second Close returned %v", err)
	}
}

// TestAnotherIdentityCannotReadHistory 验证换身份读不到旧历史。
func TestAnotherIdentityCannotReadHistory(t *testing.T) {
	dir := t.TempDir()
	st := openTest(t, dir, testMK())
	if err := st.Append(rec("m1", peerA, "只有我能看", true, StateSent)); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	other := crypto.NewIdentityStore(filepath.Join(dir, "elsewhere"))
	_ = other // 仅表明另一份身份会带来另一把 MK

	st2 := openTest(t, dir, []byte("a completely different 32-byte key"))
	got, err := st2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("history was readable without the correct master key")
	}
}
