package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

// metaState 是元数据页的内容。
type metaState struct {
	// NextPage 是下一次分配将要使用的页号。
	//
	// 页 0 保留给元数据页，因此它从 1 开始。
	NextPage uint32 `json:"next_page"`
	// FreePages 是被释放、可复用的页号。
	FreePages []uint32 `json:"free_pages,omitempty"`
	// Tables 记录每张表的根页与是否带索引。
	Tables map[string]tableMeta `json:"tables"`
}

// tableMeta 是一张表在磁盘上的位置。
type tableMeta struct {
	Root  uint32 `json:"root"`
	Index uint32 `json:"index,omitempty"` // 0 表示无索引
}

// DB 是一个打开的加密数据库。
//
// 并发模型：单写者、多读者的读写锁。**不是**多进程安全的——
// 打开时会加独占文件锁（见 lock.go）。这是有意的取舍：
// 聊天应用的库只该被本进程写。
type DB struct {
	path string
	f    *os.File

	mu   sync.RWMutex
	mk   []byte
	hdr  header
	meta metaState

	// dirty 记录本次事务内被改写的页（页号 → 明文）。
	dirty map[uint32][]byte
	// freed 记录本次事务内释放的页。
	freed []uint32
	// cached 是已解密页的只读缓存（页号 → 明文）。
	// 事务开始或提交后整体失效，避免读到旧页。
	cached map[uint32][]byte
	// pageCount 是当前文件中已分配的页数（用于读取边界检查）。
	pageCount uint32

	inTx bool
	// metaSnapshot 是事务开始时的元数据快照，回滚时还原。
	metaSnapshot metaState
	closed       bool
	lock         *fileLock
}

// Open 打开（或创建）dir 下的 chat.db。
//
// mk 为 32 字节主密钥。它会被本对象复制一份并在 Close 时擦除；
// 调用方应自行擦除它持有的那份。
//
// 文件不存在时创建新库；存在时校验 KCV，口令/MK 不对返回 ErrWrongKey。
func Open(dir string, mk []byte) (*DB, error) {
	if len(mk) == 0 {
		return nil, errors.New("db: empty master key")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("db: creating %s: %w", dir, err)
	}
	path := dir + string(os.PathSeparator) + "chat.db"

	d := &DB{
		path:   path,
		mk:     append([]byte(nil), mk...),
		dirty:  map[uint32][]byte{},
		cached: map[uint32][]byte{},
	}

	// 独占文件锁：防止两个进程同时写同一个库。
	lk, err := lockFile(path + ".lock")
	if err != nil {
		return nil, err
	}
	d.lock = lk

	_, statErr := os.Stat(path)
	if os.IsNotExist(statErr) {
		if err := d.create(); err != nil {
			d.cleanup()
			return nil, err
		}
		return d, nil
	}
	if statErr != nil {
		d.cleanup()
		return nil, fmt.Errorf("db: stat %s: %w", path, statErr)
	}
	if err := d.load(); err != nil {
		d.cleanup()
		return nil, err
	}
	return d, nil
}

// cleanup 释放 Open 失败时已占用的资源。
func (d *DB) cleanup() {
	if d.f != nil {
		_ = d.f.Close()
	}
	if d.lock != nil {
		_ = d.lock.release()
	}
	if d.mk != nil {
		zeroBytes(d.mk)
	}
}

// create 初始化一个空库：写文件头 + 一个空元数据页。
func (d *DB) create() error {
	h, err := newFile(d.path, d.mk)
	if err != nil {
		return err
	}
	d.hdr = h

	f, err := os.OpenFile(d.path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("db: reopening new file: %w", err)
	}
	d.f = f

	d.meta = metaState{NextPage: 1, Tables: map[string]tableMeta{}}

	// 写页 0（元数据页）。
	if err := d.writeMetaPage(); err != nil {
		return err
	}
	d.pageCount = 1
	return d.syncFile()
}

// load 读取并校验已有库。
func (d *DB) load() error {
	f, err := os.OpenFile(d.path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("db: opening %s: %w", d.path, err)
	}
	d.f = f

	hdrBytes := make([]byte, HeaderSize)
	if _, err := f.ReadAt(hdrBytes, 0); err != nil {
		return fmt.Errorf("%w: reading header: %v", ErrNotADB, err)
	}
	h, err := parseHeader(hdrBytes)
	if err != nil {
		return err
	}
	d.hdr = h

	// 钥匙校验：在解密任何页之前就判定对错。
	if computeKCV(d.mk, h.salt[:]) != h.kcv {
		return ErrWrongKey
	}

	// 页数 = (文件大小 - 头) / 页记录大小。但页记录是变长的
	// （密文长度取决于明文长度），所以页数是记在元数据里的。
	// 元数据页固定在页号 0。
	plain, err := d.readPageRaw(0)
	if err != nil {
		return err
	}
	if len(plain) == 0 || plain[0] != typeMeta {
		return fmt.Errorf("%w: page 0 is not a metadata page", ErrCorrupt)
	}
	// 用 Decoder 而不是 Unmarshal：页被填充到 4096 字节，
	// 正文之后全是 0x00，而 Unmarshal 会报"有多余字符"。
	// Decoder 读完第一个 JSON 值就停，正好忽略填充。
	if err := json.NewDecoder(bytes.NewReader(plain[1:])).Decode(&d.meta); err != nil {
		return fmt.Errorf("%w: parsing metadata: %v", ErrCorrupt, err)
	}
	if d.meta.Tables == nil {
		d.meta.Tables = map[string]tableMeta{}
	}
	d.pageCount = d.meta.NextPage

	// 打开时**主动校验整库**。
	//
	// 为什么不做惰性校验：如果只在读到某一页时才发现它坏了，
	// 用户会在聊天到一半时收到一个莫名其妙的错误，且无法判断
	// 是"库坏了"还是"程序坏了"。在打开时一次性校验，坏库就在
	// 门口被拦住，错误信息也能说清"第 N 页校验失败"。
	//
	// 代价是每次启动多一次全库解密。聊天数据量下这是毫秒级；
	// 若将来库大到不能接受，再改成"抽样校验 + 惰性全校验"。
	if err := d.verifyAllPages(); err != nil {
		return err
	}
	return nil
}

// verifyAllPages 校验文件长度并逐页 AEAD 验签。
//
// 页数取自元数据，因此文件被截断会在长度检查里暴露；
// 页被篡改或搬移会在解密时暴露。
func (d *DB) verifyAllPages() error {
	fi, err := d.f.Stat()
	if err != nil {
		return fmt.Errorf("db: stat: %w", err)
	}
	want := pageOffset(d.pageCount)
	if fi.Size() < want {
		return fmt.Errorf("%w: file is %d bytes but metadata requires %d "+
			"(%d pages); it was truncated or a write was interrupted",
			ErrCorrupt, fi.Size(), want, d.pageCount)
	}
	if fi.Size() > want {
		// 尾部多出字节：可能是更早的崩溃留下了未提交的页。
		// 不视为损坏（元数据没指向它们），但要修掉，
		// 否则后续写入的偏移会错位。
		if err := d.f.Truncate(want); err != nil {
			return fmt.Errorf("db: truncating trailing bytes: %w", err)
		}
	}
	for no := uint32(0); no < d.pageCount; no++ {
		if _, err := d.readPageRaw(no); err != nil {
			return fmt.Errorf("%w (page %d of %d)", err, no, d.pageCount)
		}
	}
	return nil
}

// readPageRaw 读取并解密一页，绕过脏页与缓存。
func (d *DB) readPageRaw(no uint32) ([]byte, error) {
	rec, err := d.readPageRecord(no)
	if err != nil {
		return nil, err
	}
	return decodePage(d.mk, d.hdr.salt[:], no, rec)
}

// Close 提交未完成的事务（如果有）后关闭并擦除密钥。
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	if d.inTx {
		// 未提交的事务在关闭时丢弃，而不是隐式提交：
		// 隐式提交会让"忘了 Commit"变成数据已写的假象。
		d.discardTxLocked(true)
	}
	d.closed = true
	d.cached = nil
	if d.f != nil {
		_ = d.f.Close()
	}
	if d.lock != nil {
		_ = d.lock.release()
	}
	zeroBytes(d.mk)
	d.mk = nil
	return nil
}

// --- 事务 ---

// Begin 开始一个事务。已在事务中则返回错误（不支持嵌套）。
func (d *DB) Begin() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	if d.inTx {
		return errors.New("db: transaction already open (nesting is not supported)")
	}
	d.inTx = true
	d.dirty = map[uint32][]byte{}
	d.freed = nil
	d.cached = map[uint32][]byte{}
	// 快照元数据。allocPage/freePage/openTable 直接改 d.meta，
	// 若不在回滚时还原，一次被放弃的事务就会让 NextPage 指向
	// 从未落盘的页——下次打开直接在"页被截断"上炸掉。
	d.metaSnapshot = d.cloneMeta()
	return nil
}

// cloneMeta 深拷贝元数据（Tables 是 map，必须复制）。
func (d *DB) cloneMeta() metaState {
	out := metaState{
		NextPage: d.meta.NextPage,
		Tables:   make(map[string]tableMeta, len(d.meta.Tables)),
	}
	if len(d.meta.FreePages) > 0 {
		out.FreePages = append([]uint32(nil), d.meta.FreePages...)
	}
	for k, v := range d.meta.Tables {
		out.Tables[k] = v
	}
	return out
}

// Commit 把事务内的改写落盘并 fsync。
//
// 写入顺序刻意是：先写数据页，再写元数据页（它记录新增页数），
// 最后 fsync。这样崩溃在任何一点，元数据都不会指向未落盘的页。
func (d *DB) Commit() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	if !d.inTx {
		return errors.New("db: Commit without Begin")
	}

	// 1. 先写所有脏数据页（不含页 0）。
	pages := make([]uint32, 0, len(d.dirty))
	for no := range d.dirty {
		if no != 0 {
			pages = append(pages, no)
		}
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i] < pages[j] })
	for _, no := range pages {
		if err := d.writePageNow(no, d.dirty[no]); err != nil {
			return err
		}
	}

	// 2. 再写元数据页。它的 NextPage 必须覆盖本次新分配的页。
	if err := d.writeMetaPageNow(); err != nil {
		return err
	}

	// 3. 落盘。
	if err := d.syncFile(); err != nil {
		return err
	}

	d.discardTxLocked(false) // 提交：保留新元数据
	return nil
}

// Rollback 丢弃事务内的所有改写。
func (d *DB) Rollback() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	if !d.inTx {
		return errors.New("db: Rollback without Begin")
	}
	d.discardTxLocked(true)
	return nil
}

// discardTxLocked 清理事务状态。
//
// restoreMeta 为 true 时把元数据回退到事务开始时的快照
// （回滚路径）；为 false 时保留当前元数据（提交路径已经把它写盘）。
func (d *DB) discardTxLocked(restoreMeta bool) {
	d.inTx = false
	d.dirty = map[uint32][]byte{}
	d.freed = nil
	d.cached = map[uint32][]byte{}
	if restoreMeta {
		d.meta = d.metaSnapshot
		if d.meta.Tables == nil {
			d.meta.Tables = map[string]tableMeta{}
		}
		// pageCount 跟随回退后的 NextPage，否则会去读不存在的页。
		d.pageCount = d.meta.NextPage
	}
	d.metaSnapshot = metaState{}
}

// --- 页读写（作用于 dirty / cached） ---

// getPage 取一页的明文，优先脏页、其次缓存、最后磁盘。
//
// 调用方需持有 d.mu（读或写）。
func (d *DB) getPage(no uint32) ([]byte, error) {
	if no >= d.pageCount {
		return nil, fmt.Errorf("%w: page %d beyond page count %d", ErrCorrupt, no, d.pageCount)
	}
	if p, ok := d.dirty[no]; ok {
		return p, nil
	}
	if p, ok := d.cached[no]; ok {
		return p, nil
	}
	p, err := d.readPageRaw(no)
	if err != nil {
		return nil, err
	}
	d.cached[no] = p
	return p, nil
}

// allocPage 分配一个新页号。
//
// 调用方需持有写锁。
func (d *DB) allocPage() uint32 {
	if n := len(d.meta.FreePages); n > 0 {
		no := d.meta.FreePages[n-1]
		d.meta.FreePages = d.meta.FreePages[:n-1]
		d.dirty[no] = make([]byte, PageSize)
		if no >= d.pageCount {
			d.pageCount = no + 1
		}
		return no
	}
	no := d.meta.NextPage
	d.meta.NextPage++
	d.pageCount = d.meta.NextPage
	d.dirty[no] = make([]byte, PageSize)
	return no
}

// freePage 释放一个页。
func (d *DB) freePage(no uint32) {
	if no == 0 {
		return
	}
	delete(d.dirty, no)
	delete(d.cached, no)
	d.freed = append(d.freed, no)
	d.meta.FreePages = append(d.meta.FreePages, no)
}

// setPage 标记一个页为已改写。
func (d *DB) setPage(no uint32, plain []byte) error {
	if len(plain) != PageSize {
		return fmt.Errorf("db: page %d must be exactly %d bytes, got %d", no, PageSize, len(plain))
	}
	if !d.inTx {
		return errors.New("db: write outside a transaction")
	}
	d.dirty[no] = plain
	return nil
}

// --- 元数据页 ---

// writeMetaPage 在**创建**阶段直接写元数据页（无事务）。
func (d *DB) writeMetaPage() error {
	if err := d.writeMetaPageNow(); err != nil {
		return err
	}
	return nil
}

// writeMetaPageNow 序列化并写入页 0。
func (d *DB) writeMetaPageNow() error {
	body, err := json.Marshal(d.meta)
	if err != nil {
		return err
	}
	if len(body)+1 > PageSize {
		return fmt.Errorf("db: metadata does not fit in one page (%d bytes)", len(body)+1)
	}
	page := make([]byte, PageSize)
	page[0] = typeMeta
	copy(page[1:], body)
	return d.writePageNow(0, page)
}
