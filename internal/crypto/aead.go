package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// 分块 AEAD 的约束（见 docs/attachments.md §3）。
const (
	// ChunkSize 是附件分块的明文大小。
	//
	// 选 64 KiB 的理由：附件块与聊天消息共享发送通道，块越小，
	// 聊天消息被插入的机会越多、等待越短。每块固定开销约 45B（帧头+tag），
	// 对 64 KiB 仅占约 0.07%，可忽略。
	ChunkSize = 64 << 10

	// MaxChunks 是单文件分块数的上界，防止 total_chunks 字段被滥用。
	MaxChunks = 1 << 32
)

// 分块 AEAD 的错误。
var (
	// ErrChunkTampered 表示某一块的解密或位置校验失败。
	ErrChunkTampered = errors.New("crypto: chunk failed authentication")
	// ErrChunkIndex 表示块序号超出声明范围。
	ErrChunkIndex = errors.New("crypto: chunk index out of range")
	// ErrFinalFlag 表示末块标志不符合预期。
	ErrFinalFlag = errors.New("crypto: unexpected final-chunk flag")
	// ErrChunkSize 表示块长度非法。
	ErrChunkSize = errors.New("crypto: invalid chunk size")
)

// DeriveKey 用 HKDF-SHA256 从 ikm 派生出 n 字节密钥。
func DeriveKey(ikm, salt []byte, info string, n int) []byte {
	r := hkdf.New(sha256.New, ikm, salt, []byte(info))
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		// hkdf.New 的 Read 只在底层 hash 出错时返回错误，SHA-256 不会。
		panic(fmt.Sprintf("crypto: hkdf read failed: %v", err))
	}
	return out
}

// DeriveSessionKeys 从 ECDH 共享密钥派生方向独立的双向密钥。
//
// context 必须绑定双方身份与全部握手参数（防未知密钥共享攻击），
// 构造方式见 SessionContext。
//
// 两条密钥**必须不同**：若双向共享密钥，会导致 nonce 重用——
// 这是 AEAD 下的灾难性错误。
func DeriveSessionKeys(shared, salt, context []byte) (i2r, r2i []byte) {
	i2rInfo := make([]byte, 0, len(kdfInfoI2R)+len(context))
	i2rInfo = append(i2rInfo, kdfInfoI2R...)
	i2rInfo = append(i2rInfo, context...)

	r2iInfo := make([]byte, 0, len(kdfInfoR2I)+len(context))
	r2iInfo = append(r2iInfo, kdfInfoR2I...)
	r2iInfo = append(r2iInfo, context...)

	i2r = DeriveKey(shared, salt, string(i2rInfo), KeyLen)
	r2i = DeriveKey(shared, salt, string(r2iInfo), KeyLen)
	return i2r, r2i
}

// DeriveMACKey 从会话密钥派生用于 ratchet 链式认证的 MAC 密钥。
func DeriveMACKey(key []byte) []byte {
	return DeriveKey(key, nil, kdfInfoMAC, KeyLen)
}

// SessionContext 构造绑定上下文，使派生出的密钥与"谁和谁、用什么参数"强绑定。
//
// 若不绑定，攻击者可能诱导双方进入参数不一致的会话（unknown key share）。
func SessionContext(sessionID []byte, fpA, fpB Fingerprint, ephPubA, ephPubB []byte) []byte {
	h := sha256.New()
	h.Write([]byte("keytalk/v1/context"))
	w := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	w(sessionID)
	w([]byte(fpA))
	w([]byte(fpB))
	w(ephPubA)
	w(ephPubB)
	return h.Sum(nil)
}

// HandshakeHash 计算握手记录哈希，供双方确认对同一份握手记录达成一致。
//
// 不一致意味着协议实现不匹配或存在参数降级攻击，必须终止会话。
func HandshakeHash(kemPlaintext, ackPlaintext []byte) []byte {
	h := sha256.New()
	h.Write([]byte(handshakeContextLabel))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(kemPlaintext)))
	h.Write(n[:])
	h.Write(kemPlaintext)
	binary.BigEndian.PutUint32(n[:], uint32(len(ackPlaintext)))
	h.Write(n[:])
	h.Write(ackPlaintext)
	return h.Sum(nil)
}

// BuildNonce 由 seq 构造 AEAD nonce。
//
//	nonce = seq(8B, big-endian) ‖ 0x00000000(4B)
//
// 唯一性依据：一个 key 唯一对应一组 (SessionID, Epoch)，而 seq 在该组内
// 严格单调递增且不回绕，因此 (key, nonce) 组合永不重复。
func BuildNonce(seq uint64) []byte {
	n := make([]byte, NonceLen)
	binary.BigEndian.PutUint64(n[0:8], seq)
	// 后 4 字节保持为 0。
	return n
}

// SealedSize 返回明文经 AEAD 封装后的密文长度。
func SealedSize(plaintextLen int) int { return plaintextLen + TagLen }

// Seal 用 key 加密 plaintext，aad 参与认证。
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w: %v", ErrNoKey, err)
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open 用 key 解封 ciphertext，aad 参与认证。
// 认证失败返回 ErrDecrypt（包内不含任何明文信息）。
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w: %v", ErrNoKey, err)
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// ChunkAAD 构造某一分块的附加认证数据。
//
//	aad = ver ‖ fileID ‖ index ‖ totalChunks ‖ fileSize
//
// 把 index / totalChunks 纳入 AAD 是防重排与防截断的核心：
//   - 重排：交换块 i 与 j 后，位置上的密文与 AAD 中的 index 不匹配 → 解密失败
//   - 截断：totalChunks 固定，接收方知道自己应收多少块
func ChunkAAD(version byte, fileID []byte, index, totalChunks, fileSize uint64) []byte {
	buf := make([]byte, 0, 1+16+8+8+8)
	buf = append(buf, version)
	buf = append(buf, fileID...)
	buf = binary.BigEndian.AppendUint64(buf, index)
	buf = binary.BigEndian.AppendUint64(buf, totalChunks)
	buf = binary.BigEndian.AppendUint64(buf, fileSize)
	return buf
}

// ChunkNonce 构造分块的 nonce。
//
//	nonce = index(11B, big-endian) ‖ isFinal(1B)
//
// index 占据前 11 字节：高 3 字节为 0，低 8 字节为大端的 index。
// 末块标志放在最后一字节，使攻击者无法把非末块伪装成末块（反之亦然）：
// 标志参与 nonce，改变它必然导致解密失败。
func ChunkNonce(index uint64, isFinal bool) []byte {
	n := make([]byte, NonceLen)
	// nonce[0..2] 保持为 0（高 3 字节）；nonce[3..10] 为大端 index。
	binary.BigEndian.PutUint64(n[3:11], index)
	if isFinal {
		n[11] = 1
	}
	return n
}

// SealChunk 加密一个分块。
func SealChunk(fileKey []byte, fileID []byte, index, totalChunks, fileSize uint64, chunk []byte, isFinal bool) ([]byte, error) {
	if len(chunk) == 0 && !isFinal {
		return nil, ErrChunkSize
	}
	if len(chunk) > ChunkSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrChunkSize, len(chunk), ChunkSize)
	}
	nonce := ChunkNonce(index, isFinal)
	aad := ChunkAAD(Version, fileID, index, totalChunks, fileSize)
	return Seal(fileKey, nonce, chunk, aad)
}

// OpenChunk 解密一个分块。
//
// 调用方必须传入自己期望的 index（来自接收顺序或位图重传请求），
// 而不是从网络读取的值——这正是防重排的关键。
func OpenChunk(fileKey, fileID []byte, expectIndex, totalChunks, fileSize uint64, ciphertext []byte, isFinal bool) ([]byte, error) {
	if totalChunks > MaxChunks || expectIndex >= totalChunks {
		return nil, fmt.Errorf("%w: index %d, total %d", ErrChunkIndex, expectIndex, totalChunks)
	}
	nonce := ChunkNonce(expectIndex, isFinal)
	aad := ChunkAAD(Version, fileID, expectIndex, totalChunks, fileSize)
	pt, err := Open(fileKey, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChunkTampered, err)
	}
	return pt, nil
}

// ChunkCount 计算给定文件大小所需的分块数。
//
// 空文件（size == 0）定义为 1 个空块，且该块带 is_final 标志。
// 这样"收齐 = 收到 index 0..total-1 且末块带 final"这一不变式无需特例。
func ChunkCount(fileSize uint64) uint64 {
	if fileSize == 0 {
		return 1
	}
	return (fileSize + ChunkSize - 1) / ChunkSize
}

// ChunkPlaintextLen 返回指定分块的明文长度。
func ChunkPlaintextLen(fileSize, index uint64) int {
	start := index * ChunkSize
	if start >= fileSize {
		return 0
	}
	remaining := fileSize - start
	if remaining > ChunkSize {
		return ChunkSize
	}
	return int(remaining)
}
