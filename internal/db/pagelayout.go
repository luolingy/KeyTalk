package db

import (
	"encoding/binary"
	"fmt"
)

// 页内布局（明文，加密前的形态）。
//
// 一个明文页要么是**表页**、要么是**索引页**、要么是**元数据页**。
// 首字节是页类型，其余按类型解释。
//
//	tablePage:
//	  [0]      type     = typeTable
//	  [1:3]    slotCount uint16
//	  [3:7]    nextPage  uint32   (0 = 无后继；页链)
//	  [7:9]    freeBytes uint16   (仅用于自检)
//	  [9:...]  slots: 每个 [off uint16][len uint16]（相对页尾）
//	  页尾向中间增长：记录体从页尾往前放。
//
//	indexPage:
//	  [0]      type     = typeIndex
//	  [1:3]    entryCount uint16
//	  [3:7]    nextPage  uint32
//	  [7:...]  entries: 每条 [keyHash uint64][page uint32][slot uint16]
//	          （索引只存"排好序的指针"，真数据在表页里）
//
//	metaPage:
//	  [0]      type     = typeMeta
//	  其余为序列化后的元数据（表根页、页计数、空闲页表）
const (
	typeTable byte = 1
	typeIndex byte = 2
	typeMeta  byte = 3
)

const (
	tableHeaderSize = 9
	indexEntrySize  = 8 + 4 + 2 // keyHash + page + slot
	indexHeaderSize = 7
)

// tablePage 是一个解码后的表页。
type tablePage struct {
	nextPage uint32
	records  [][]byte
}

// putTablePage 把一个表页编码为明文页。
//
// 记录按顺序从页头之后连续摆放，槽表紧随其后；装不下时返回错误，
// 由上层把多余记录分到下一页。
func putTablePage(p *tablePage) ([]byte, error) {
	page := make([]byte, PageSize)
	page[0] = typeTable
	binary.BigEndian.PutUint16(page[1:3], uint16(len(p.records)))
	binary.BigEndian.PutUint32(page[3:7], p.nextPage)

	off := tableHeaderSize
	// 记录体从页尾往前放。
	tail := PageSize
	slots := make([]byte, 0, len(p.records)*4)
	for _, rec := range p.records {
		tail -= len(rec)
		if tail < off+4 { // 4 = 本槽自身占用的 4 字节
			return nil, fmt.Errorf("db: table page overflow (%d records)", len(p.records))
		}
		copy(page[tail:], rec)
		var s [4]byte
		binary.BigEndian.PutUint16(s[0:2], uint16(tail))
		binary.BigEndian.PutUint16(s[2:4], uint16(len(rec)))
		slots = append(slots, s[:]...)
		off += 4
	}
	copy(page[tableHeaderSize:], slots)
	binary.BigEndian.PutUint16(page[7:9], uint16(tail-off))
	return page, nil
}

// getTablePage 解码一个表页。
func getTablePage(page []byte) (*tablePage, error) {
	if len(page) < tableHeaderSize || page[0] != typeTable {
		return nil, fmt.Errorf("%w: not a table page", ErrCorrupt)
	}
	n := int(binary.BigEndian.Uint16(page[1:3]))
	tp := &tablePage{nextPage: binary.BigEndian.Uint32(page[3:7])}
	tp.records = make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		base := tableHeaderSize + i*4
		if base+4 > len(page) {
			return nil, fmt.Errorf("%w: slot %d out of range", ErrCorrupt, i)
		}
		off := int(binary.BigEndian.Uint16(page[base : base+2]))
		ln := int(binary.BigEndian.Uint16(page[base+2 : base+4]))
		if off < tableHeaderSize || ln < 0 || off+ln > len(page) {
			return nil, fmt.Errorf("%w: slot %d points outside the page", ErrCorrupt, i)
		}
		tp.records = append(tp.records, append([]byte(nil), page[off:off+ln]...))
	}
	return tp, nil
}

// indexEntry 是索引页里的一条。
type indexEntry struct {
	keyHash uint64
	page    uint32
	slot    uint16
}

// indexPage 是一个解码后的索引页。
type indexPage struct {
	nextPage uint32
	entries  []indexEntry
}

// putIndexPage 编码一个索引页。
func putIndexPage(p *indexPage) ([]byte, error) {
	page := make([]byte, PageSize)
	page[0] = typeIndex
	binary.BigEndian.PutUint16(page[1:3], uint16(len(p.entries)))
	binary.BigEndian.PutUint32(page[3:7], p.nextPage)

	off := indexHeaderSize
	for _, e := range p.entries {
		if off+indexEntrySize > PageSize {
			return nil, fmt.Errorf("db: index page overflow (%d entries)", len(p.entries))
		}
		binary.BigEndian.PutUint64(page[off:off+8], e.keyHash)
		binary.BigEndian.PutUint32(page[off+8:off+12], e.page)
		binary.BigEndian.PutUint16(page[off+12:off+14], e.slot)
		off += indexEntrySize
	}
	return page, nil
}

// getIndexPage 解码一个索引页。
func getIndexPage(page []byte) (*indexPage, error) {
	if len(page) < indexHeaderSize || page[0] != typeIndex {
		return nil, fmt.Errorf("%w: not an index page", ErrCorrupt)
	}
	n := int(binary.BigEndian.Uint16(page[1:3]))
	ip := &indexPage{nextPage: binary.BigEndian.Uint32(page[3:7])}
	ip.entries = make([]indexEntry, 0, n)
	for i := 0; i < n; i++ {
		off := indexHeaderSize + i*indexEntrySize
		if off+indexEntrySize > len(page) {
			return nil, fmt.Errorf("%w: index entry %d out of range", ErrCorrupt, i)
		}
		ip.entries = append(ip.entries, indexEntry{
			keyHash: binary.BigEndian.Uint64(page[off : off+8]),
			page:    binary.BigEndian.Uint32(page[off+8 : off+12]),
			slot:    binary.BigEndian.Uint16(page[off+12 : off+14]),
		})
	}
	return ip, nil
}
