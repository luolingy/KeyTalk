package sas

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// TestFromHandshakeHashIsDeterministic 验证同一哈希总是派生出同一组 emoji。
//
// 这是整个功能的前提：双方各自计算，必须得到相同结果。
func TestFromHandshakeHashIsDeterministic(t *testing.T) {
	h := sha256.Sum256([]byte("shared transcript"))
	a, err := FromHandshakeHash(h[:])
	if err != nil {
		t.Fatalf("FromHandshakeHash: %v", err)
	}
	for i := 0; i < 20; i++ {
		b, err := FromHandshakeHash(h[:])
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if !Matches(a, b) {
			t.Fatalf("iteration %d: non-deterministic result\n a=%s\n b=%s",
				i, Format(a), Format(b))
		}
	}
}

// TestFromHandshakeHashDiffersOnDifferentInput 验证不同哈希给出不同 emoji。
//
// 若这个性质不成立（例如实现总是返回同一组），核对就完全没有意义。
func TestFromHandshakeHashDiffersOnDifferentInput(t *testing.T) {
	seen := map[string]int{}
	collisions := 0
	const trials = 200

	for i := 0; i < trials; i++ {
		h := sha256.Sum256([]byte{byte(i), byte(i >> 8), 0xAB})
		e, err := FromHandshakeHash(h[:])
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		key := Format(e)
		if prev, dup := seen[key]; dup {
			collisions++
			t.Logf("collision between trials %d and %d: %s", prev, i, key)
		}
		seen[key] = i
	}

	// 7 个 6-bit 符号 = 2^42 空间，200 次抽样出现碰撞的概率
	// 约 200^2 / 2^43 ≈ 4.5e-9。出现碰撞说明派生有缺陷。
	if collisions > 0 {
		t.Fatalf("saw %d collision(s) in %d trials; the derivation is not "+
			"spreading inputs across the emoji space", collisions, trials)
	}
}

// TestEmojiCountAndStrength 验证数量与声称的安全强度一致。
//
// 注释里声称 2^-42，这个测试保证代码与注释不会各说各话。
func TestEmojiCountAndStrength(t *testing.T) {
	if EmojiCount != 7 {
		t.Fatalf("EmojiCount = %d; the documented security argument "+
			"assumes 7 (64^7 = 2^42)", EmojiCount)
	}
	// 64 项表 → 每个 6 bit。
	if TableSize != 64 {
		t.Fatalf("TableSize = %d; must be 64 so that `x & 0x3F` maps "+
			"uniformly without modulo bias", TableSize)
	}
}

// TestEmojiNamesAreUnique 验证表内名称唯一。
//
// 名称用于口头核对。若两项同名，两个人可能念出同一个词
// 却指着不同的图案——核对就失效了。
func TestEmojiNamesAreUnique(t *testing.T) {
	byName := map[string]string{}
	byChar := map[string]string{}

	for _, e := range emojiTable {
		if e.Char == "" || e.Name == "" {
			t.Fatalf("table entry %+v has an empty field", e)
		}
		if prev, dup := byName[e.Name]; dup {
			t.Errorf("duplicate name %q used by both %q and %q; "+
				"verbal comparison would be ambiguous", e.Name, prev, e.Char)
		}
		byName[e.Name] = e.Char

		if prev, dup := byChar[e.Char]; dup {
			t.Errorf("duplicate emoji %q appears twice (names %q and %q); "+
				"this would reduce the effective symbol space", e.Char, prev, e.Name)
		}
		byChar[e.Char] = e.Name
	}

	if len(emojiTable) != TableSize {
		t.Errorf("emojiTable has %d entries but TableSize is %d; "+
			"the `& 0x3F` index would read out of range or waste "+
			"part of the space", len(emojiTable), TableSize)
	}
}

// TestAllTableEntriesAreReachable 验证表里每一项都可能被选中。
//
// 若某个索引因为位运算写错而永远不会出现，实际符号空间就变小了。
func TestAllTableEntriesAreReachable(t *testing.T) {
	seen := make([]bool, TableSize)
	for i := 0; i < 4096 && !allTrue(seen); i++ {
		h := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		e, err := FromHandshakeHash(h[:])
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		// 只统计第一个位置：它的索引来自 sum[0]&0x3F，
		// 覆盖 64 个取值应当很快。
		idx := -1
		for j, cand := range emojiTable {
			if cand.Char == e[0].Char {
				idx = j
				break
			}
		}
		if idx < 0 {
			t.Fatalf("derived emoji %q is not in the table", e[0].Char)
		}
		seen[idx] = true
	}
	for i, ok := range seen {
		if !ok {
			t.Errorf("table index %d (%s %s) was never selected in 4096 "+
				"trials; the index derivation is skipping part of the space",
				i, emojiTable[i].Char, emojiTable[i].Name)
		}
	}
}

func allTrue(b []bool) bool {
	for _, v := range b {
		if !v {
			return false
		}
	}
	return true
}

// TestFromHandshakeHashRejectsEmpty 验证空哈希被拒绝。
//
// 若允许空输入，一次握手失败（哈希尚未计算）会派生出
// 一组"有效"的 emoji，用户可能误以为核对成功了。
func TestFromHandshakeHashRejectsEmpty(t *testing.T) {
	if _, err := FromHandshakeHash(nil); err == nil {
		t.Error("FromHandshakeHash(nil) returned no error; an empty hash " +
			"must not produce a seemingly-valid comparison string")
	}
	if _, err := FromHandshakeHash([]byte{}); err == nil {
		t.Error("FromHandshakeHash(empty slice) returned no error")
	}
}

// TestMatchesRequiresExactEquality 验证比对是**全等**，不做部分匹配。
func TestMatchesRequiresExactEquality(t *testing.T) {
	h := sha256.Sum256([]byte("x"))
	a, _ := FromHandshakeHash(h[:])

	// 完全相同 → true
	if !Matches(a, a) {
		t.Error("Matches(a, a) = false; identical sets must match")
	}

	// 前缀相同但长度不同 → 必须 false。
	// 部分匹配没有安全意义：攻击者可以构造出相同前缀。
	if Matches(a, a[:len(a)-1]) {
		t.Error("Matches accepted a shorter prefix; partial matches have " +
			"no security meaning and must not be treated as a match")
	}
	if Matches(a[:3], a) {
		t.Error("Matches accepted a truncated left operand")
	}

	// 一项不同 → 必须 false
	b := append([]Emoji(nil), a...)
	b[3] = emojiTable[(indexOf(a[3].Char)+1)%TableSize]
	if Matches(a, b) {
		t.Error("Matches accepted two sets differing in one emoji; " +
			"a single differing symbol means possible MITM")
	}

	// 空集合绝不等于匹配
	if Matches(nil, nil) {
		t.Error("Matches(nil, nil) = true; an absence of evidence must " +
			"not be reported as a successful verification")
	}
}

func indexOf(char string) int {
	for i, e := range emojiTable {
		if e.Char == char {
			return i
		}
	}
	return 0
}

// TestFormatIsHumanReadable 验证格式化输出便于核对。
func TestFormatIsHumanReadable(t *testing.T) {
	h := sha256.Sum256([]byte("format check"))
	e, _ := FromHandshakeHash(h[:])

	s := Format(e)
	if s == "" {
		t.Fatal("Format returned empty string")
	}
	// 7 个符号之间应有 6 个空格。
	if got := strings.Count(s, " "); got != EmojiCount-1 {
		t.Errorf("Format produced %d separators, want %d\n%s",
			got, EmojiCount-1, s)
	}

	names := FormatNames(e)
	if names == "" {
		t.Fatal("FormatNames returned empty string")
	}
	if strings.Count(names, ",") != EmojiCount-1 {
		t.Errorf("FormatNames produced %d separators, want %d\n%s",
			strings.Count(names, ","), EmojiCount-1, names)
	}
}

// TestDomainSeparation 验证展示值与协议哈希没有直接复用。
//
// 派生时对输入再做一次带标签的散列，避免把"协议用的值"
// 直接暴露成"人类看到的值"。
func TestDomainSeparation(t *testing.T) {
	h := sha256.Sum256([]byte("domain separation"))
	e, _ := FromHandshakeHash(h[:])

	// 直接对原始哈希取低 6 bit 得到的结果，
	// 不应当与带域标签派生出的结果相等（概率上极不可能相等，
	// 万一相等也只是巧合；这里检查的是"实现没有偷懒直接切片"）。
	direct := int(h[0]) & 0x3F
	if emojiTable[direct].Char == e[0].Char && emojiTable[int(h[1])&0x3F].Char == e[1].Char {
		t.Error("derived emojis match a plain slice of the raw handshake hash; " +
			"domain separation appears to be missing")
	}
}
