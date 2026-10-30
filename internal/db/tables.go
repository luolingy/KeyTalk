package db

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// 记录编码：每个字段用"长度前缀 + 字节"。
//
// 不用 JSON 而是手写二进制，原因有二：
//   1. 记录要能塞进 4096 字节的页，JSON 的键名和转义浪费空间；
//   2. 索引需要在不解码整条记录的情况下取出键，
//      所以键必须放在固定位置（见 indexKeyOf）。
//
// 统一的记录前缀：
//
//	[0]      recordKind
//	[1:5]    keyLen (uint32)
//	[5:...]  key
//	其余按各表定义。

// 字段写出辅助。
func putBytes(buf []byte, b []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	buf = append(buf, n[:]...)
	return append(buf, b...)
}

func putString(buf []byte, s string) []byte { return putBytes(buf, []byte(s)) }

func putU64(buf []byte, v uint64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	return append(buf, n[:]...)
}

func putI64(buf []byte, v int64) []byte { return putU64(buf, uint64(v)) }

func putBool(buf []byte, v bool) []byte {
	if v {
		return append(buf, 1)
	}
	return append(buf, 0)
}

// reader 顺序读取记录字段。
type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) bytes() []byte {
	if r.err != nil {
		return nil
	}
	if r.off+4 > len(r.b) {
		r.err = fmt.Errorf("%w: truncated field", ErrCorrupt)
		return nil
	}
	n := int(binary.BigEndian.Uint32(r.b[r.off : r.off+4]))
	r.off += 4
	if n < 0 || r.off+n > len(r.b) {
		r.err = fmt.Errorf("%w: field length %d out of range", ErrCorrupt, n)
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *reader) string() string { return string(r.bytes()) }

func (r *reader) u64() uint64 {
	if r.err != nil {
		return 0
	}
	if r.off+8 > len(r.b) {
		r.err = fmt.Errorf("%w: truncated u64", ErrCorrupt)
		return 0
	}
	v := binary.BigEndian.Uint64(r.b[r.off : r.off+8])
	r.off += 8
	return v
}

func (r *reader) i64() int64 { return int64(r.u64()) }

func (r *reader) boolean() bool {
	if r.err != nil {
		return false
	}
	if r.off+1 > len(r.b) {
		r.err = fmt.Errorf("%w: truncated bool", ErrCorrupt)
		return false
	}
	v := r.b[r.off] == 1
	r.off++
	return v
}

// beginRecord 写记录前缀并返回新的缓冲区。
func beginRecord(kind byte, key string) []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, kind)
	return putString(buf, key)
}

// startReader 跳过记录前缀并校验 kind 与 key。
func startReader(rec []byte, wantKind byte) (*reader, string, error) {
	if len(rec) < 1 || rec[0] != wantKind {
		return nil, "", fmt.Errorf("%w: record kind mismatch (got %q, want %q)",
			ErrCorrupt, kindName(rec), kindName([]byte{wantKind}))
	}
	key, err := indexKeyOf(rec)
	if err != nil {
		return nil, "", err
	}
	r := &reader{b: rec, off: 5 + len(key)}
	return r, key, nil
}

func kindName(rec []byte) string {
	if len(rec) == 0 {
		return "<empty>"
	}
	return string(rec[0:1])
}

// --- 消息表 ---

// Message 是一条聊天记录。
type Message struct {
	// ID 全局唯一（随机生成）。
	ID string
	// PeerFP 是会话对端指纹（hex）。
	PeerFP string
	// Outgoing 表示本机发出。
	Outgoing bool
	// Text 是明文正文；落盘时已加密（页级加密覆盖整页）。
	Text string
	// SentAtMS 是发送/接收时间（Unix 毫秒）。
	SentAtMS int64
	// State 见 StatePending / StateSent / StateFailed / StateReceived。
	State int
}

// 消息状态，与 core 的 MessageState 数值一致。
const (
	StatePending  = 0
	StateSent     = 1
	StateFailed   = 2
	StateReceived = 3
)

func encodeMessage(m Message) []byte {
	buf := beginRecord(recMessage, m.ID)
	buf = putString(buf, m.PeerFP)
	buf = putBool(buf, m.Outgoing)
	buf = putString(buf, m.Text)
	buf = putI64(buf, m.SentAtMS)
	buf = putU64(buf, uint64(m.State))
	return buf
}

func decodeMessage(rec []byte) (Message, error) {
	r, id, err := startReader(rec, recMessage)
	if err != nil {
		return Message{}, err
	}
	m := Message{ID: id}
	m.PeerFP = r.string()
	m.Outgoing = r.boolean()
	m.Text = r.string()
	m.SentAtMS = r.i64()
	m.State = int(r.u64())
	if r.err != nil {
		return Message{}, r.err
	}
	return m, nil
}

// Messages 返回消息表的访问器。
func (d *DB) Messages() *MessageTable { return &MessageTable{d: d} }

// MessageTable 是消息表的类型化封装。
type MessageTable struct{ d *DB }

// Put 插入或按 ID 覆盖一条消息。
//
// 同一 ID 已存在时**就地更新**（状态变更走这条路径）。
func (t *MessageTable) Put(m Message) error {
	d := t.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.requireTx(); err != nil {
		return err
	}
	tbl, err := d.openTable("messages", true)
	if err != nil {
		return err
	}
	rec := encodeMessage(m)

	// 先找同 ID 的既有记录。
	refs, err := d.indexLookup(tbl, m.ID)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		got, err := d.recordAt(tbl, ref)
		if err != nil {
			return err
		}
		old, err := decodeMessage(got)
		if err != nil {
			return err
		}
		if old.ID != m.ID {
			continue // 哈希碰撞，跳过
		}
		if err := d.updateAt(tbl, ref, rec); err != nil {
			return err
		}
		return nil
	}

	_, err = d.insert(tbl, rec)
	return err
}

// All 返回全部消息，按 (SentAtMS, ID) 升序。
func (t *MessageTable) All() ([]Message, error) {
	d := t.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.requireTx(); err != nil {
		return nil, err
	}
	tbl, err := d.openTable("messages", true)
	if err != nil {
		return nil, err
	}
	var out []Message
	err = d.scan(tbl, func(rec []byte, _ recordRef) (bool, error) {
		m, err := decodeMessage(rec)
		if err != nil {
			return true, err
		}
		out = append(out, m)
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SentAtMS != out[j].SentAtMS {
			return out[i].SentAtMS < out[j].SentAtMS
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ByPeer 返回某个会话的全部消息，按时间升序。
//
// 走索引：索引键是消息 ID，所以这里先用全表扫拿到候选，
// 再按 PeerFP 过滤。**诚实说明**：会话维度的检索目前是全表扫，
// 因为索引键选了 ID（保证按 ID 更新的 O(1)）。数据量大时
// 应当把索引键改成 peerFP‖sentAt。见 docs 的取舍记录。
func (t *MessageTable) ByPeer(peerFP string) ([]Message, error) {
	all, err := t.All()
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(all))
	for _, m := range all {
		if m.PeerFP == peerFP {
			out = append(out, m)
		}
	}
	return out, nil
}

// ByID 按 ID 取一条消息。
func (t *MessageTable) ByID(id string) (Message, bool, error) {
	d := t.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.requireTx(); err != nil {
		return Message{}, false, err
	}
	tbl, err := d.openTable("messages", true)
	if err != nil {
		return Message{}, false, err
	}
	refs, err := d.indexLookup(tbl, id)
	if err != nil {
		return Message{}, false, err
	}
	for _, ref := range refs {
		rec, err := d.recordAt(tbl, ref)
		if err != nil {
			return Message{}, false, err
		}
		m, err := decodeMessage(rec)
		if err != nil {
			return Message{}, false, err
		}
		if m.ID == id {
			return m, true, nil
		}
	}
	return Message{}, false, nil
}

// --- 联系人表 ---

// Contact 是一个通讯录条目。
type Contact struct {
	// Fingerprint 是完整指纹（hex），作主键。
	Fingerprint string
	Name        string
	// PublicKey 是 armored 公钥。
	PublicKey string
	// Verified 表示已带外核对过指纹。
	Verified bool
	// AddedAtMS 是加入时间。
	AddedAtMS int64
}

func encodeContact(c Contact) []byte {
	buf := beginRecord(recContact, c.Fingerprint)
	buf = putString(buf, c.Name)
	buf = putString(buf, c.PublicKey)
	buf = putBool(buf, c.Verified)
	buf = putI64(buf, c.AddedAtMS)
	return buf
}

func decodeContact(rec []byte) (Contact, error) {
	r, fp, err := startReader(rec, recContact)
	if err != nil {
		return Contact{}, err
	}
	c := Contact{Fingerprint: fp}
	c.Name = r.string()
	c.PublicKey = r.string()
	c.Verified = r.boolean()
	c.AddedAtMS = r.i64()
	if r.err != nil {
		return Contact{}, r.err
	}
	return c, nil
}

// Contacts 返回联系人表访问器。
func (d *DB) Contacts() *ContactTable { return &ContactTable{d: d} }

// ContactTable 是联系人表的类型化封装。
type ContactTable struct{ d *DB }

// Upsert 插入或按指纹覆盖一个联系人。
func (t *ContactTable) Upsert(c Contact) error {
	d := t.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.requireTx(); err != nil {
		return err
	}
	tbl, err := d.openTable("contacts", true)
	if err != nil {
		return err
	}
	rec := encodeContact(c)
	refs, err := d.indexLookup(tbl, c.Fingerprint)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		got, err := d.recordAt(tbl, ref)
		if err != nil {
			return err
		}
		old, err := decodeContact(got)
		if err != nil {
			return err
		}
		if old.Fingerprint != c.Fingerprint {
			continue
		}
		return d.updateAt(tbl, ref, rec)
	}
	_, err = d.insert(tbl, rec)
	return err
}

// All 返回全部联系人。
func (t *ContactTable) All() ([]Contact, error) {
	d := t.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.requireTx(); err != nil {
		return nil, err
	}
	tbl, err := d.openTable("contacts", true)
	if err != nil {
		return nil, err
	}
	var out []Contact
	err = d.scan(tbl, func(rec []byte, _ recordRef) (bool, error) {
		c, err := decodeContact(rec)
		if err != nil {
			return true, err
		}
		out = append(out, c)
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, nil
}

// --- 附件表 ---

// Attachment 是附件元数据。正文在 blobs/<BlobID>.bin，分块加密。
type Attachment struct {
	// ID 是附件记录主键。
	ID string
	// MessageID 关联的消息。
	MessageID string
	// BlobID 是正文文件名（不含扩展名）。
	BlobID string
	// Name 是原始文件名（落盘时由页级加密保护）。
	Name string
	// MIME 是 MIME 类型。
	MIME string
	// Size 是明文字节数。
	Size int64
	// SHA256 是明文的哈希，用于完整性校验（hex）。
	SHA256 string
}

func encodeAttachment(a Attachment) []byte {
	buf := beginRecord(recAttachment, a.ID)
	buf = putString(buf, a.MessageID)
	buf = putString(buf, a.BlobID)
	buf = putString(buf, a.Name)
	buf = putString(buf, a.MIME)
	buf = putI64(buf, a.Size)
	buf = putString(buf, a.SHA256)
	return buf
}

func decodeAttachment(rec []byte) (Attachment, error) {
	r, id, err := startReader(rec, recAttachment)
	if err != nil {
		return Attachment{}, err
	}
	a := Attachment{ID: id}
	a.MessageID = r.string()
	a.BlobID = r.string()
	a.Name = r.string()
	a.MIME = r.string()
	a.Size = r.i64()
	a.SHA256 = r.string()
	if r.err != nil {
		return Attachment{}, r.err
	}
	return a, nil
}

// Attachments 返回附件表访问器。
func (d *DB) Attachments() *AttachmentTable { return &AttachmentTable{d: d} }

// AttachmentTable 是附件表的类型化封装。
type AttachmentTable struct{ d *DB }

// Put 插入或按 ID 覆盖一条附件记录。
func (t *AttachmentTable) Put(a Attachment) error {
	d := t.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.requireTx(); err != nil {
		return err
	}
	tbl, err := d.openTable("attachments", true)
	if err != nil {
		return err
	}
	rec := encodeAttachment(a)
	refs, err := d.indexLookup(tbl, a.ID)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		got, err := d.recordAt(tbl, ref)
		if err != nil {
			return err
		}
		old, err := decodeAttachment(got)
		if err != nil {
			return err
		}
		if old.ID != a.ID {
			continue
		}
		return d.updateAt(tbl, ref, rec)
	}
	_, err = d.insert(tbl, rec)
	return err
}

// ByMessage 返回挂在某条消息下的附件。
func (t *AttachmentTable) ByMessage(messageID string) ([]Attachment, error) {
	d := t.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.requireTx(); err != nil {
		return nil, err
	}
	tbl, err := d.openTable("attachments", true)
	if err != nil {
		return nil, err
	}
	var out []Attachment
	err = d.scan(tbl, func(rec []byte, _ recordRef) (bool, error) {
		a, err := decodeAttachment(rec)
		if err != nil {
			return true, err
		}
		if a.MessageID == messageID {
			out = append(out, a)
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// requireTx 断言当前在事务中。
func (d *DB) requireTx() error {
	if d.closed {
		return ErrClosed
	}
	if !d.inTx {
		return errors.New("db: operation requires a transaction (call Begin first)")
	}
	return nil
}
