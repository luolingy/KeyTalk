// Package crypto 提供 KeyTalk 的密码学原语。
//
// 设计约束（见 docs/crypto-protocol.md）：
//
//   - 本包**不依赖任何其他内部包**（不 import wire/transport/storage/ui），因此可独立单测。
//   - 本包不感知网络：传入字节、传出字节。
//   - 不自行发明密码学原语，只组合成熟的 OpenPGP / X25519 / HKDF / ChaCha20-Poly1305。
//   - 任何解密或认证失败都必须返回错误，**禁止静默丢弃**。
//   - 所有密钥材料来自 crypto/rand，禁止 math/rand。
package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// 协议版本与尺寸常量。
const (
	// Version 与 wire.Version 必须保持一致。此处独立定义以避免包间依赖。
	Version byte = 0x01

	// SessionIDLen 是会话标识的字节数。
	SessionIDLen = 8
	// ECDHPubLen 是 X25519 公钥的字节数。
	ECDHPubLen = 32
	// KeyLen 是对称密钥的字节数（ChaCha20-Poly1305）。
	KeyLen = 32
	// NonceLen 是 ChaCha20-Poly1305 的 nonce 字节数。
	NonceLen = 12
	// TagLen 是 Poly1305 认证标签的字节数。
	TagLen = 16
	// HashLen 是 SHA-256 输出长度。
	HashLen = 32
	// SaltLen 是 HKDF salt 的最小长度。
	SaltLen = 32
)

// KDF 标签。改变这些字符串会破坏线上兼容性。
const (
	kdfInfoI2R = "keytalk/v1/i2r"
	kdfInfoR2I = "keytalk/v1/r2i"
	kdfInfoMAC = "keytalk/v1/mac"
)

// handshakeContextLabel 用于握手记录哈希的域分隔。
const handshakeContextLabel = "keytalk/v1/handshake"

// 本包的错误。调用方（尤其 UI）应能区分这些情况并给出不同提示。
var (
	// ErrDecrypt 表示 AEAD 解封失败（密文被篡改、密钥不匹配或 nonce 错配）。
	ErrDecrypt = errors.New("crypto: decryption failed")
	// ErrAuthFailed 表示身份认证失败（签名无效或指纹不匹配）。
	ErrAuthFailed = errors.New("crypto: authentication failed")
	// ErrReplay 表示检测到重放（重复的 seq）。
	ErrReplay = errors.New("crypto: replay detected")
	// ErrTooOld 表示帧的 seq 超出重放窗口下界（可能是严重乱序，未必是攻击）。
	ErrTooOld = errors.New("crypto: sequence too old for replay window")
	// ErrBadEpoch 表示帧携带了未知的密钥代次。
	ErrBadEpoch = errors.New("crypto: unknown key epoch")
	// ErrNoKey 表示会话已关闭或不持有对应密钥。
	ErrNoKey = errors.New("crypto: no key available")
	// ErrWrongVersion 表示协议版本不受支持。
	ErrWrongVersion = errors.New("crypto: unsupported version")
	// ErrStale 表示时间戳超出容忍窗口（陈旧的握手帧）。
	ErrStale = errors.New("crypto: timestamp outside tolerance window")
	// ErrSelfAddressed 表示收到发给自己的握手载荷之外的情况（如指纹相同）。
	ErrSelfAddressed = errors.New("crypto: peer fingerprint equals our own")
	// ErrMalformed 表示载荷结构非法。
	ErrMalformed = errors.New("crypto: malformed payload")
)

// Fingerprint 是全量 OpenPGP 指纹（hex，大写无分隔）。
//
// 安全判定一律使用全量指纹；短 ID 仅可用于 UI 展示。
type Fingerprint string

// NewFingerprint 从原始字节构造指纹。
func NewFingerprint(raw []byte) Fingerprint {
	return Fingerprint(strings.ToUpper(hex.EncodeToString(raw)))
}

// String 返回规范形式（大写 hex，无分隔符）。
func (f Fingerprint) String() string { return string(f) }

// Valid 报告指纹是否非空。
func (f Fingerprint) Valid() bool { return f != "" }

// Display 返回四位分组的展示形式，便于人工比对。
func (f Fingerprint) Display() string { return GroupHex(string(f)) }

// GroupHex 把 hex 字符串按四位分组，用空格分隔。
// 输入可以是任意 hex 字符串（大写小写均可）。
func GroupHex(s string) string {
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// Less 按字典序比较指纹，用于确定握手发起方（见 docs/wire-protocol.md §8.2）。
//
// 指纹字典序是全序，因此双方必得出**一致且互斥**的角色结论。
func (f Fingerprint) Less(other Fingerprint) bool { return string(f) < string(other) }

// ParseFingerprint 解析用户输入或文件里的指纹。
//
// 接受四位分组空格与小写：指纹是给人读的，要求用户自己去掉空格
// 或改成大写是没有理由的苛刻。一律规范化为大写无分隔形式，
// 使后续比较永远在同一个表示上进行。
//
// ⚠️ 只做格式校验，**不**验证长度或校验和——
// 指纹是否对应某把真实密钥，只能由实际导入公钥来断定。
func ParseFingerprint(s string) (Fingerprint, error) {
	clean := strings.ToUpper(strings.Join(strings.Fields(s), ""))
	if clean == "" {
		return "", errors.New("crypto: empty fingerprint")
	}
	if _, err := hex.DecodeString(clean); err != nil {
		return "", fmt.Errorf("crypto: fingerprint is not valid hex: %w", err)
	}
	return Fingerprint(clean), nil
}

// randomBytes 读取密码学安全随机数。失败即 panic —— rand.Read 失败意味着
// 系统熵源已不可用，此时继续运行会生成可预测的密钥，必须立即中止。
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto: entropy source unavailable: %v", err))
	}
	return b
}

// RandomBytes32 返回 32 字节密码学安全随机数（群组密钥等对称密钥用）。
//
// 导出它是为了让上层（如 group 包）无需自行挑选随机源——随机数用错
// 源是密码学实现里最常见的灾难，把"正确的那一个"暴露出去更安全。
func RandomBytes32() []byte { return randomBytes(32) }

// RandomNonce 返回一个 NonceLen 字节的随机 nonce。
func RandomNonce() []byte { return randomBytes(NonceLen) }

// zero 尽力清除敏感缓冲。
//
// 注意（见 docs/crypto-protocol.md §10.5）：Go 无法保证内存清零——
// GC 可能在复制 []byte 时留下未清零副本，编译器可能优化掉死代码。
// 这能减少密钥驻留时间，但**不构成**抗内存取证的保证。
func zero(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	// 防止编译器把上面的写入判定为死代码。
	//
	// ⚠️ 这里**不能**用一个包级全局变量来"逃逸"这个切片。
	//
	// 早期实现写的是 `escapeSink = b`（一个 var escapeSink []byte）。
	// 那是错的，而且是安全相关的错误，不只是数据竞争：
	//
	//   1. **数据竞争**：每个并发的握手 goroutine 都会写同一个全局变量，
	//      竞争检测器直接报 DATA RACE（实测两个并发 Respond 就触发）。
	//   2. **更严重的语义问题**：那个全局变量会**持有**最后写入的切片。
	//      也就是说，被"清零"的那块临时密钥缓冲反而多了一个全局引用，
	//      在下次 zero() 覆盖它之前一直不能被 GC 回收——
	//      清零的目的（缩短密钥驻留时间）被这个引用抵消了一部分。
	//
	// 正确做法：让切片经由一个**函数局部**的、编译器无法证明死掉的
	// 操作逃逸。用 runtime.KeepAlive 表达"到这里为止 b 仍被使用"，
	// 既阻止了死代码消除，又不引入任何跨 goroutine 的共享状态。
	runtime.KeepAlive(b)
}
