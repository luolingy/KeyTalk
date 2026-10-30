package db

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
)

// table 是一个逻辑表：一条表页链 + 一条可选的索引页链。
type table struct {
	name  string
	root  uint32
	index uint32
}

// openTable 取得（或创建）一张表，需在事务中调用。
func (d *DB) openTable(name string, withIndex bool) (*table, error) {
	if !d.inTx {
		return nil, errors.New("db: table access requires a transaction")
	}
	tm, ok := d.meta.Tables[name]
	if !ok {
		// 建一张空表：一个空表页。
		root := d.allocPage()
		empty, err := putTablePage(&tablePage{})
		if err != nil {
			return nil, err
		}
		if err := d.setPage(root, empty); err != nil {
			return nil, err
		}
		tm = tableMeta{Root: root}
		if withIndex {
			idx := d.allocPage()
			emptyIdx, err := putIndexPage(&indexPage{})
			if err != nil {
				return nil, err
			}
			if err := d.setPage(idx, emptyIdx); err != nil {
				return nil, err
			}
			tm.Index = idx
		}
		d.meta.Tables[name] = tm
	}
	return &table{name: name, root: tm.Root, index: tm.Index}, nil
}

// recordRef 指向一条记录在表链里的位置。
type recordRef struct {
	page uint32
	slot uint16
}

// scan 遍历表内所有记录，对每条调用 fn。
//
// fn 返回 stop=true 时提前结束。
func (d *DB) scan(t *table, fn func(rec []byte, ref recordRef) (stop bool, err error)) error {
	pageNo := t.root
	seen := map[uint32]bool{}
	for pageNo != 0 {
		if seen[pageNo] {
			// 页链成环 = 文件损坏。不能无限循环。
			return fmt.Errorf("%w: table %q page chain loops at page %d", ErrCorrupt, t.name, pageNo)
		}
		seen[pageNo] = true

		plain, err := d.getPage(pageNo)
		if err != nil {
			return err
		}
		tp, err := getTablePage(plain)
		if err != nil {
			return err
		}
		for i, rec := range tp.records {
			stop, err := fn(rec, recordRef{page: pageNo, slot: uint16(i)})
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		pageNo = tp.nextPage
	}
	return nil
}

// insert 追加一条记录到表尾，必要时分配新页。
//
// 返回它的位置，供索引记录。
func (d *DB) insert(t *table, rec []byte) (recordRef, error) {
	if len(rec)+tableHeaderSize+4 > PageSize {
		return recordRef{}, fmt.Errorf("db: record of %d bytes does not fit in a page", len(rec))
	}

	// 走到最后一页。
	lastNo := t.root
	var last *tablePage
	for {
		plain, err := d.getPage(lastNo)
		if err != nil {
			return recordRef{}, err
		}
		lp, err := getTablePage(plain)
		if err != nil {
			return recordRef{}, err
		}
		if lp.nextPage == 0 {
			last = lp
			break
		}
		lastNo = lp.nextPage
	}

	// 先试着塞进最后一页。
	trial := &tablePage{nextPage: last.nextPage, records: append(last.records, rec)}
	if plain, err := putTablePage(trial); err == nil {
		if err := d.setPage(lastNo, plain); err != nil {
			return recordRef{}, err
		}
		ref := recordRef{page: lastNo, slot: uint16(len(last.records))}
		if t.index != 0 {
			if err := d.indexAdd(t, ref, rec); err != nil {
				return recordRef{}, err
			}
		}
		return ref, nil
	}

	// 塞不下：新开一页。
	newNo := d.allocPage()
	fresh := &tablePage{records: [][]byte{rec}}
	freshPlain, err := putTablePage(fresh)
	if err != nil {
		return recordRef{}, err
	}
	if err := d.setPage(newNo, freshPlain); err != nil {
		return recordRef{}, err
	}
	// 把上一页的 next 指向新页。
	last.nextPage = newNo
	lastPlain, err := putTablePage(last)
	if err != nil {
		return recordRef{}, err
	}
	if err := d.setPage(lastNo, lastPlain); err != nil {
		return recordRef{}, err
	}

	ref := recordRef{page: newNo, slot: 0}
	if t.index != 0 {
		if err := d.indexAdd(t, ref, rec); err != nil {
			return recordRef{}, err
		}
	}
	return ref, nil
}

// updateAt 覆盖某页某槽的记录。
//
// 换长度可能装不下，因此实现为：若同长度则就地替换，
// 否则报错并让上层用 delete+insert（聊天场景里消息几乎不可变，
// 只有状态位会变，而状态位是定长编码）。
func (d *DB) updateAt(t *table, ref recordRef, rec []byte) error {
	plain, err := d.getPage(ref.page)
	if err != nil {
		return err
	}
	tp, err := getTablePage(plain)
	if err != nil {
		return err
	}
	if int(ref.slot) >= len(tp.records) {
		return fmt.Errorf("%w: table %q slot %d out of range", ErrCorrupt, t.name, ref.slot)
	}
	tp.records[ref.slot] = rec
	out, err := putTablePage(tp)
	if err != nil {
		return fmt.Errorf("db: updated record does not fit back into its page: %w", err)
	}
	return d.setPage(ref.page, out)
}

// keyHash 把索引键映射为一个 64 位哈希。
//
// 索引只用来缩小候选集，命中后仍要取出真实记录比对，
// 因此哈希碰撞只影响性能、不影响正确性。
func keyHash(key string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return h.Sum64()
}

// indexAdd 为一条新记录追加索引项。
func (d *DB) indexAdd(t *table, ref recordRef, rec []byte) error {
	key, err := indexKeyOf(rec)
	if err != nil {
		return err
	}
	entry := indexEntry{keyHash: keyHash(key), page: ref.page, slot: ref.slot}

	// 走到索引链尾页。
	lastNo := t.index
	var last *indexPage
	for {
		plain, err := d.getPage(lastNo)
		if err != nil {
			return err
		}
		ip, err := getIndexPage(plain)
		if err != nil {
			return err
		}
		if ip.nextPage == 0 {
			last = ip
			break
		}
		lastNo = ip.nextPage
	}

	trial := &indexPage{nextPage: last.nextPage, entries: append(last.entries, entry)}
	if plain, err := putIndexPage(trial); err == nil {
		return d.setPage(lastNo, plain)
	}

	newNo := d.allocPage()
	fresh := &indexPage{entries: []indexEntry{entry}}
	freshPlain, err := putIndexPage(fresh)
	if err != nil {
		return err
	}
	if err := d.setPage(newNo, freshPlain); err != nil {
		return err
	}
	last.nextPage = newNo
	lastPlain, err := putIndexPage(last)
	if err != nil {
		return err
	}
	return d.setPage(lastNo, lastPlain)
}

// indexLookup 返回与 key 匹配的候选位置。
func (d *DB) indexLookup(t *table, key string) ([]recordRef, error) {
	if t.index == 0 {
		return nil, errors.New("db: table has no index")
	}
	want := keyHash(key)
	var refs []recordRef
	pageNo := t.index
	seen := map[uint32]bool{}
	for pageNo != 0 {
		if seen[pageNo] {
			return nil, fmt.Errorf("%w: index of %q loops at page %d", ErrCorrupt, t.name, pageNo)
		}
		seen[pageNo] = true
		plain, err := d.getPage(pageNo)
		if err != nil {
			return nil, err
		}
		ip, err := getIndexPage(plain)
		if err != nil {
			return nil, err
		}
		for _, e := range ip.entries {
			if e.keyHash == want {
				refs = append(refs, recordRef{page: e.page, slot: e.slot})
			}
		}
		pageNo = ip.nextPage
	}
	return refs, nil
}

// recordAt 取一条记录。
func (d *DB) recordAt(t *table, ref recordRef) ([]byte, error) {
	plain, err := d.getPage(ref.page)
	if err != nil {
		return nil, err
	}
	tp, err := getTablePage(plain)
	if err != nil {
		return nil, err
	}
	if int(ref.slot) >= len(tp.records) {
		return nil, fmt.Errorf("%w: table %q slot %d out of range", ErrCorrupt, t.name, ref.slot)
	}
	return tp.records[ref.slot], nil
}

// firstByte 是记录首字节的约定：记录的第一字节指出它属于哪张表，
// 以防记录被搬到别的表里（跨表混淆）。
//
// 这不是安全边界（真正的安全边界是页级 AAD），只是一个
// 快速的自检，让"把联系人记录塞进消息表"这种事立刻报错。
const (
	recContact    byte = 'c'
	recMessage    byte = 'm'
	recAttachment byte = 'a'
)

// indexKeyOf 从记录里取出索引键。
//
// 记录的编码格式（见各 typed 表的 encode）是：
//
//	[0]      recordKind
//	[1:5]    keyLen (uint32, 大端)
//	[5:...]  key bytes
//	...      其余字段
//
// 索引统一按这个前缀取键，与具体表无关。
func indexKeyOf(rec []byte) (string, error) {
	if len(rec) < 5 {
		return "", fmt.Errorf("%w: record too short for a key", ErrCorrupt)
	}
	n := int(binary.BigEndian.Uint32(rec[1:5]))
	if n <= 0 || 5+n > len(rec) {
		return "", fmt.Errorf("%w: record key length %d out of range", ErrCorrupt, n)
	}
	return string(rec[5 : 5+n]), nil
}
