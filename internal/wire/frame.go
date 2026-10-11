// Package wire 定义 KeyTalk 的线上帧格式与编解码。
//
// 设计约束（见 docs/wire-protocol.md）：
//
//   - 本包是纯函数层：不做 IO、不加锁、不访问全局状态、不依赖任何其他内部包。
//   - 所有解码路径必须先校验长度上界，再分配内存（防 OOM DoS）。
//   - 编解码必须可通过 fuzz 测试无 panic、无超大分配。
//
// 帧结构：
//
//	┌──────────────┬──────────┬─────────────────────────────┐
//	│ Length (4B)  │ Type(1B) │ Body (Length-1 字节)        │
//	└──────────────┴──────────┴─────────────────────────────┘
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// 协议常量。
const (
	// Version 是当前的线上协议版本号。
	Version byte = 0x01

	// MaxFrame 是单帧 Body 的硬上界。解码时必须在分配内存前校验。
	MaxFrame = 1 << 20 // 1 MiB

	// LengthPrefixLen 是长度前缀的字节数。
	LengthPrefixLen = 4
	// TypeLen 是类型字段的字节数。
	TypeLen = 1
	// HeaderLen 是帧头的总字节数（长度前缀 + 类型）。
	HeaderLen = LengthPrefixLen + TypeLen

	// SecureHeaderLen 是 KEM_ACK / SECURE 帧额外的固定头长度：
	// SessionID(8) + Epoch(8) + Seq(8)。
	SecureHeaderLen = 8 + 8 + 8

	// RevisionLen 是 SessionID 的字节数。
	RevisionLen = 8
)

// Type 是帧类型。只有四种，会话内一切靠 Kind 区分（见 docs/wire-protocol.md §2）。
type Type byte

const (
	// TypeKEMInit 携带 OpenPGP 加密并签名的握手载荷。会话建立前发送。
	TypeKEMInit Type = 0x01
	// TypeKEMACK 携带 responder 的临时公钥，用 key_r2i 加密。Epoch=0, Seq=0。
	TypeKEMACK Type = 0x02
	// TypeSecure 是会话建立后的唯一数据类型，内部用 Kind 区分语义。
	TypeSecure Type = 0x03
	// TypeError 是错误帧。会话建立前为明文，建立后为 AEAD 密文。
	TypeError Type = 0x04
)

var typeNames = map[Type]string{
	TypeKEMInit: "KEM_INIT",
	TypeKEMACK:  "KEM_ACK",
	TypeSecure:  "SECURE",
	TypeError:   "ERROR",
}

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("Type(0x%02x)", byte(t))
}

// Known 报告该 Type 是否被本版本协议识别。
func (t Type) Known() bool {
	_, ok := typeNames[t]
	return ok
}

// HasSecureHeader 报告该 Type 的 Body 是否以 SessionID/Epoch/Seq 开头。
func (t Type) HasSecureHeader() bool {
	return t == TypeKEMACK || t == TypeSecure
}

// 解码错误。调用方应据此决定是否断开连接。
var (
	// ErrShortFrame 表示数据不足以构成一个完整帧（可能是 TCP 拆包，应继续读）。
	ErrShortFrame = errors.New("wire: frame shorter than declared length")
	// ErrBadLength 表示长度字段非法（0 或超过 MaxFrame）。
	ErrBadLength = errors.New("wire: invalid frame length")
	// ErrUnknownType 表示 Type 不在已知范围内。
	ErrUnknownType = errors.New("wire: unknown frame type")
	// ErrBadBody 表示 Body 结构与 Type 不符（过短或字段越界）。
	ErrBadBody = errors.New("wire: malformed frame body")
)

// Frame 是一个已解码的帧。
//
// Body 的语义随 Type 变化：
//
//	TypeKEMInit → OpenPGP 二进制 packet
//	TypeKEMACK  → AEAD 密文（plaintext 中含 responder 的临时公钥）
//	TypeSecure  → AEAD 密文（明文以 Kind 开头）
//	TypeError   → 错误码 ‖ 消息（会话建立前为明文）
type Frame struct {
	Type Type

	// 以下三个字段仅当 Type.HasSecureHeader() 为真时有效。
	SessionID [RevisionLen]byte
	Epoch     uint64
	Seq       uint64

	Body []byte
}

// AAD 构造该帧的附加认证数据（见 docs/wire-protocol.md §3.4）。
//
// 注意：ver 必须是**常量** wire.Version，绝不能取自密文内部。
// 因为 AAD 必须在解密前构造，而密文内的版本字段此时还不可读。
func (f *Frame) AAD() []byte {
	buf := make([]byte, 0, 1+1+RevisionLen+8+8)
	return f.appendAAD(buf)
}

func (f *Frame) appendAAD(dst []byte) []byte {
	dst = append(dst, Version, byte(f.Type))
	return f.appendHeaderTo(dst)
}

// appendHeaderTo 把 SessionID/Epoch/Seq 追加到 dst。
func (f *Frame) appendHeaderTo(dst []byte) []byte {
	dst = append(dst, f.SessionID[:]...)
	dst = binary.BigEndian.AppendUint64(dst, f.Epoch)
	dst = binary.BigEndian.AppendUint64(dst, f.Seq)
	return dst
}

// Size 返回该帧编码后的总字节数。
//
// 编码布局：[Length(4B)][Type(1B)][Body]
// 其中 Length = 1(Type) + len(Body)，**不含** Length 自身。
func (f *Frame) Size() int {
	return LengthPrefixLen + f.wireBodyLen()
}

// wireBodyLen 返回 Length 字段应写入的值，即 Type 字节加 Body 长度。
func (f *Frame) wireBodyLen() int {
	n := TypeLen + len(f.Body)
	if f.Type.HasSecureHeader() {
		n += SecureHeaderLen
	}
	return n
}

// Encode 把帧序列化到 dst 并返回结果。
// 若 dst 容量足够则复用其底层数组，避免每条消息一次分配。
func (f *Frame) Encode(dst []byte) ([]byte, error) {
	bodyLen := f.wireBodyLen()
	if bodyLen < 1 || bodyLen > MaxFrame {
		return nil, fmt.Errorf("wire: frame body length %d out of range", bodyLen)
	}

	total := LengthPrefixLen + bodyLen
	if cap(dst) < total {
		dst = make([]byte, total)
	}
	dst = dst[:total]

	binary.BigEndian.PutUint32(dst[0:LengthPrefixLen], uint32(bodyLen))
	dst[LengthPrefixLen] = byte(f.Type)
	off := HeaderLen

	if f.Type.HasSecureHeader() {
		// 注意：必须按 SessionID 的**完整长度**（RevisionLen=8）前进。
		// 早期版本误用了一个更小的步长，导致 Epoch/Seq 覆盖掉
		// SessionID 的后半部分，并越界写入 8 字节——
		// 表现为"Transport 声明的长度比实际少 8 字节"，
		// 接收端因此永久等待不会到来的字节，握手静默挂死。
		copy(dst[off:off+RevisionLen], f.SessionID[:])
		off += RevisionLen
		binary.BigEndian.PutUint64(dst[off:off+8], f.Epoch)
		off += 8
		binary.BigEndian.PutUint64(dst[off:off+8], f.Seq)
		off += 8
	}
	copy(dst[off:], f.Body)

	// 未写入的尾部字节（若有）必须清零，避免复用缓冲时泄露上一帧内容。
	for i := off + len(f.Body); i < total; i++ {
		dst[i] = 0
	}
	return dst, nil
}

// AppendTo 把帧追加到 dst，便于无分配地拼接多个帧。
func (f *Frame) AppendTo(dst []byte) ([]byte, error) {
	buf, err := f.Encode(nil)
	if err != nil {
		return dst, err
	}
	return append(dst, buf...), nil
}

// DecodeFrame 从 buf 起始处解码一个帧。
//
// 返回 (frame, n, nil) 表示成功，n 为消耗的字节数；
// 返回 ErrShortFrame 表示 buf 不足以构成完整帧，调用方应继续读取；
// 其他错误表示帧非法，调用方应立即断开连接。
func DecodeFrame(buf []byte) (Frame, int, error) {
	var f Frame
	if len(buf) < LengthPrefixLen {
		return f, 0, ErrShortFrame
	}

	bodyLen := int(binary.BigEndian.Uint32(buf[0:4]))
	// 先校验上界，再分配任何内存。
	if bodyLen < 1 || bodyLen > MaxFrame {
		return f, 0, fmt.Errorf("%w: %d", ErrBadLength, bodyLen)
	}

	total := LengthPrefixLen + bodyLen
	if len(buf) < total {
		return f, 0, ErrShortFrame
	}

	f.Type = Type(buf[4])
	if !f.Type.Known() {
		return f, 0, fmt.Errorf("%w: 0x%02x", ErrUnknownType, buf[4])
	}

	off := HeaderLen
	if f.Type.HasSecureHeader() {
		if bodyLen < 1+SecureHeaderLen {
			return f, 0, fmt.Errorf("%w: %s needs %d body bytes, got %d",
				ErrBadBody, f.Type, 1+SecureHeaderLen, bodyLen)
		}
		copy(f.SessionID[:], buf[off:off+RevisionLen])
		off += RevisionLen
		f.Epoch = binary.BigEndian.Uint64(buf[off : off+8])
		off += 8
		f.Seq = binary.BigEndian.Uint64(buf[off : off+8])
		off += 8
	}

	// 复制 Body：调用方通常复用读缓冲，不能持有其切片。
	bodyLenActual := total - off
	f.Body = make([]byte, bodyLenActual)
	copy(f.Body, buf[off:total])

	return f, total, nil
}

// ReadFrame 从 r 读取一个完整帧。
//
// 这是唯一允许在 wire 包中做 IO 的函数；它内部只调用 DecodeFrame，
// 不包含任何协议逻辑，便于在测试中替换为内存 reader。
func ReadFrame(r io.Reader) (Frame, error) {
	var lenBuf [LengthPrefixLen]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Frame{}, err
	}

	bodyLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if bodyLen < 1 || bodyLen > MaxFrame {
		return Frame{}, fmt.Errorf("%w: %d", ErrBadLength, bodyLen)
	}

	// bodyLen 已校验上界，此处分配是安全的。
	buf := make([]byte, LengthPrefixLen+bodyLen)
	copy(buf, lenBuf[:])
	if _, err := io.ReadFull(r, buf[LengthPrefixLen:]); err != nil {
		return Frame{}, err
	}

	f, _, err := DecodeFrame(buf)
	return f, err
}

// WriteFrame 把帧写入 w。
func WriteFrame(w io.Writer, f Frame) error {
	buf, err := f.Encode(nil)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}
