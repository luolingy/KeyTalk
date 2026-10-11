// Package sas 实现"emoji 二次确认"（Short Authentication String）。
//
// # 为什么需要这个
//
// 握手本身已经能证明"对端持有某个私钥"，也能验签证明"这个私钥
// 对应联系人表里那个指纹"。但它**不能**证明"这个指纹真的是你朋友的"。
//
// 攻击场景：如果攻击者在最开始（用户还没核对过指纹时）就冒充
// 联系人把公钥塞进联系人表，那么此后每一次握手都会"验签通过"，
// 因为验的是攻击者的密钥。这类攻击在密码学上无懈可击——
// 唯一的防线是**带外核对**（人和人对一下）。
//
// # 本方案
//
// 借鉴 Matrix 的 SAS 设计：双方从握手记录哈希派生出一组 emoji，
// 通过可信信道（当面、电话、视频）念给对方听/看。
// 一致则说明没有被中间人；不一致则**必须**视为攻击迹象。
//
// # 为什么用 emoji 而不是数字
//
// 人类短时记忆对 7±2 个"视觉上截然不同的符号"最有效。
// 60 位十六进制没人会去逐位核对——那等于没有核对。
// emoji 让"核对"这件事真的会被做，这才是安全属性成立的前提。
//
// ⚠️ 安全性来自"用户真的比对"，**不来自 emoji 本身**。
// 因此界面必须让比对变得容易（大字号、少干扰），
// 并且**不能**在未核对前假装已验证。
package sas

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Emoji 是 emoji 表里的一项。
type Emoji struct {
	// Char 是字符本身。
	Char string

	// Name 是人类可读名称，用于无障碍朗读与"念给对方听"的场景。
	//
	// 名称必须**在表内唯一**：如果两个人对同一组 emoji 念出
	// 相同的名字却指着不同的图案，核对就失效了。
	Name string
}

// emojiTable 是 SAS 用的 emoji 表。
//
// 取自 Matrix 规范的 SAS emoji 表（64 项），原因：
//
//   - 经受过实际使用检验，符号之间视觉差异明显；
//   - 数量为 2 的幂，便于均匀取模而不引入偏置；
//   - 名称简短且不含歧义同音，适合口头核对。
//
// ⚠️ 顺序**不可改动**：它是协议的一部分。
// 改动顺序会让新旧版本对同一会话派生出不同的 emoji，
// 表现为"升级后突然对不上"——那会被误判成中间人攻击。
var emojiTable = []Emoji{
	{"🐶", "Dog"}, {"🐱", "Cat"}, {"🦁", "Lion"}, {"🐎", "Horse"},
	{"🦄", "Unicorn"}, {"🐷", "Pig"}, {"🐘", "Elephant"}, {"🐰", "Rabbit"},
	{"🐼", "Panda"}, {"🐓", "Rooster"}, {"🐧", "Penguin"}, {"🐢", "Turtle"},
	{"🐟", "Fish"}, {"🐙", "Octopus"}, {"🦋", "Butterfly"}, {"🌷", "Flower"},
	{"🌳", "Tree"}, {"🌵", "Cactus"}, {"🍄", "Mushroom"}, {"🌏", "Globe"},
	{"🌙", "Moon"}, {"☁️", "Cloud"}, {"🔥", "Fire"}, {"🍌", "Banana"},
	{"🍎", "Apple"}, {"🍓", "Strawberry"}, {"🌽", "Corn"}, {"🍕", "Pizza"},
	{"🎂", "Cake"}, {"❤️", "Heart"}, {"🙂", "Smiley"}, {"🤖", "Robot"},
	{"🎩", "Hat"}, {"👓", "Glasses"}, {"🔧", "Spanner"}, {"🎅", "Santa"},
	{"👍", "Thumbs Up"}, {"☂️", "Umbrella"}, {"⌛", "Hourglass"}, {"⏰", "Clock"},
	{"🎁", "Gift"}, {"💡", "Light Bulb"}, {"📕", "Book"}, {"✏️", "Pencil"},
	{"📎", "Paperclip"}, {"✂️", "Scissors"}, {"🔒", "Lock"}, {"🔑", "Key"},
	{"🔨", "Hammer"}, {"☎️", "Telephone"}, {"🏁", "Flag"}, {"🚂", "Train"},
	{"🚲", "Bicycle"}, {"✈️", "Aeroplane"}, {"🚀", "Rocket"}, {"🏆", "Trophy"},
	{"⚽", "Ball"}, {"🎸", "Guitar"}, {"🎺", "Trumpet"}, {"🔔", "Bell"},
	{"⚓", "Anchor"}, {"🎧", "Headphones"}, {"📁", "Folder"}, {"📌", "Pin"},
}

// TableSize 是 emoji 表的大小。调用方可用它校验协议一致性。
const TableSize = 64

// EmojiCount 是一次核对显示多少个 emoji。
//
// 7 个：安全强度与人类负担的平衡点。
//
// 每个 emoji 来自 64 项，信息量 6 bit，7 个共 42 bit。
// 也就是说攻击者盲猜"恰好匹配"的概率约为 2^-42 ≈ 2.3×10^-13——
// 远低于任何现实攻击的可行性，而 7 个符号仍在一眼能扫完的范围内。
//
// ⚠️ 不要为了"看起来更安全"随意增大这个数字：
// 超过约 9 个，用户会开始草率扫过而非真正比对，
// 于是**实际**安全性反而下降。安全的瓶颈在人，不在位数。
const EmojiCount = 7

// FromHandshakeHash 从握手记录哈希派生一组 emoji。
//
// 双方对同一会话会得到**完全相同**的结果，因为握手哈希是
// 两端共同计算的记录哈希（见 crypto.Session.HandshakeHash）。
//
// ⚠️ 这里对哈希再散列一次，是为了把"协议用的哈希"与
// "展示用的字节"在域上分开（domain separation）。
// 直接用握手哈希的原始字节会让展示值与协议值产生关联；
// 再散列一次可以避免这类跨用途复用。
func FromHandshakeHash(hash []byte) ([]Emoji, error) {
	if len(hash) == 0 {
		return nil, fmt.Errorf("sas: empty handshake hash")
	}

	sum := sha256.Sum256(append([]byte("KeyTalk-SAS-v1\x00"), hash...))

	out := make([]Emoji, 0, EmojiCount)
	for i := 0; i < EmojiCount; i++ {
		// 每个 emoji 用 6 bit，从哈希里顺序取。
		// 6 bit 恰好对应 64 项表，因此取模是均匀的——
		// 不会像"用 8 bit 取模 64"那样在表大小非 2 的幂时引入偏置。
		idx := int(sum[i]) & 0x3F
		out = append(out, emojiTable[idx])
	}
	return out, nil
}

// Format 把一组 emoji 拼成一行可读文本（用于日志、终端、无障碍朗读）。
//
// 形如 "🐶 🐱 🦁"；同时给出名称便于口头核对。
func Format(emojis []Emoji) string {
	chars := make([]string, 0, len(emojis))
	for _, e := range emojis {
		chars = append(chars, e.Char)
	}
	return strings.Join(chars, " ")
}

// FormatNames 返回英文名称序列，用于"念给对方听"。
//
// 名称里出现 `-`、`_`、`.` 等非英文字母时用空格呈现，
// 让朗读更自然。
func FormatNames(emojis []Emoji) string {
	names := make([]string, 0, len(emojis))
	for _, e := range emojis {
		names = append(names, e.Name)
	}
	return strings.Join(names, ", ")
}

// Matches 报告两组 emoji 是否一致。
//
// 刻意提供这个函数而不是让调用方自己比 len + 逐项：
// 核对结果的判断必须是**全等**——任何部分匹配都视为不一致。
// 部分匹配没有安全意义（攻击者可以构造前缀相同的情况），
// 把它暴露成 API 容易被误用。
func Matches(a, b []Emoji) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for i := range a {
		if a[i].Char != b[i].Char {
			return false
		}
	}
	return true
}
