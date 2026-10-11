package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Kind 是 SECURE 帧内明文载荷的消息种类。
//
// 它与 Type 是两个层级：Type 是传输层帧分类，Kind 是应用层语义。
// 这样传输层状态机只需处理 4 种 Type，不会随业务增长而膨胀。
type Kind byte

const (
	// KindText 是聊天文本。
	KindText Kind = 0x01
	// KindReceipt 是对某条消息的送达确认。
	KindReceipt Kind = 0x02
	// KindTyping 是"正在输入"状态。
	KindTyping Kind = 0x03
	// KindRekey 发起密钥轮换。
	KindRekey Kind = 0x04
	// KindRekeyACK 响应密钥轮换。
	KindRekeyACK Kind = 0x05
	// KindPing 是心跳请求。
	KindPing Kind = 0x06
	// KindPong 是心跳响应。
	KindPong Kind = 0x07
	// KindBye 表示主动关闭会话。
	KindBye Kind = 0x08
	// KindHandshakeConfirm 是握手收尾确认，携带双方握手记录哈希。
	KindHandshakeConfirm Kind = 0x09
)

// 附件相关 Kind 保留（见 docs/attachments.md §7）。当前不实现。
const (
	KindFileOffer  Kind = 0x10
	KindFileAccept Kind = 0x11
	KindFileReject Kind = 0x12
	KindFileChunk  Kind = 0x13
	KindFileEnd    Kind = 0x14
	KindFileDone   Kind = 0x15
	KindFileCancel Kind = 0x16
	KindFileError  Kind = 0x17
)

var kindNames = map[Kind]string{
	KindText:             "TEXT",
	KindReceipt:          "RECEIPT",
	KindTyping:           "TYPING",
	KindRekey:            "REKEY",
	KindRekeyACK:         "REKEY_ACK",
	KindPing:             "PING",
	KindPong:             "PONG",
	KindBye:              "BYE",
	KindHandshakeConfirm: "HANDSHAKE_CONFIRM",
}

func (k Kind) String() string {
	if n, ok := kindNames[k]; ok {
		return n
	}
	return fmt.Sprintf("Kind(0x%02x)", byte(k))
}

// Known 报告该 Kind 是否属于当前实现支持的范围。
func (k Kind) Known() bool {
	_, ok := kindNames[k]
	return ok
}

// 载荷长度约束。
const (
	// MaxTextLen 是单条文本消息的上界（UTF-8 字节）。
	MaxTextLen = 64 << 10 // 64 KiB
	// MaxByeReasonLen 是告别原因的显示文本上界。
	MaxByeReasonLen = 256
	// HandshakeHashLen 是握手记录哈希的长度（SHA-256）。
	HandshakeHashLen = 32
	// ECDHPubLen 是 X25519 公钥长度。
	ECDHPubLen = 32
)

// 载荷解码错误。
var (
	// ErrBadKind 表示 Kind 不在已知范围内。
	ErrBadKind = errors.New("wire: unknown message kind")
	// ErrBadPayload 表示载荷结构非法。
	ErrBadPayload = errors.New("wire: malformed payload")
)

// Plaintext 是 SECURE 帧解密后的内容。
//
// 编码布局：Ver(1) ‖ Kind(1) ‖ SentAt(8) ‖ 按 Kind 变化的负载
type Plaintext struct {
	Kind   Kind
	SentAt int64 // unix 毫秒。仅用于 UI 展示，不得用于安全判定。

	// 以下字段按 Kind 择一使用。
	Text          string // KindText
	RefEpoch      uint64 // KindReceipt
	RefSeq        uint64 // KindReceipt
	TypingState   byte   // KindTyping: 0 停止 / 1 正在输入
	EphPub        []byte // KindRekey / KindRekeyACK: X25519 公钥
	ByeReason     string // KindBye
	HandshakeHash []byte // KindHandshakeConfirm
}

// Encode 序列化载荷。
func (p *Plaintext) Encode() ([]byte, error) {
	if !p.Kind.Known() {
		return nil, fmt.Errorf("%w: 0x%02x", ErrBadKind, byte(p.Kind))
	}

	buf := make([]byte, 0, 64+len(p.Text))
	buf = append(buf, Version, byte(p.Kind))
	buf = binary.BigEndian.AppendUint64(buf, uint64(p.SentAt))

	switch p.Kind {
	case KindText:
		if len(p.Text) > MaxTextLen {
			return nil, fmt.Errorf("%w: text too long (%d)", ErrBadPayload, len(p.Text))
		}
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(p.Text)))
		buf = append(buf, p.Text...)

	case KindReceipt:
		buf = binary.BigEndian.AppendUint64(buf, p.RefEpoch)
		buf = binary.BigEndian.AppendUint64(buf, p.RefSeq)

	case KindTyping:
		buf = append(buf, p.TypingState)

	case KindRekey, KindRekeyACK:
		if len(p.EphPub) != ECDHPubLen {
			return nil, fmt.Errorf("%w: eph pub must be %d bytes, got %d",
				ErrBadPayload, ECDHPubLen, len(p.EphPub))
		}
		buf = append(buf, p.EphPub...)

	case KindBye:
		if len(p.ByeReason) > MaxByeReasonLen {
			return nil, fmt.Errorf("%w: bye reason too long", ErrBadPayload)
		}
		buf = append(buf, byte(len(p.ByeReason)))
		buf = append(buf, p.ByeReason...)

	case KindHandshakeConfirm:
		if len(p.HandshakeHash) != HandshakeHashLen {
			return nil, fmt.Errorf("%w: handshake hash must be %d bytes, got %d",
				ErrBadPayload, HandshakeHashLen, len(p.HandshakeHash))
		}
		buf = append(buf, p.HandshakeHash...)

	case KindPing, KindPong:
		// 无负载。
	}

	return buf, nil
}

// DecodePlaintext 解析 SECURE 帧的明文载荷。
//
// 必须在 AEAD 解密成功之后调用——本函数不做任何认证。
func DecodePlaintext(data []byte) (Plaintext, error) {
	var p Plaintext
	if len(data) < 2 {
		return p, fmt.Errorf("%w: payload too short", ErrBadPayload)
	}
	if data[0] != Version {
		return p, fmt.Errorf("%w: unsupported version 0x%02x", ErrBadPayload, data[0])
	}
	p.Kind = Kind(data[1])
	if !p.Kind.Known() {
		return p, fmt.Errorf("%w: 0x%02x", ErrBadKind, data[1])
	}

	rest := data[2:]
	if len(rest) < 8 {
		return p, fmt.Errorf("%w: %s missing timestamp", ErrBadPayload, p.Kind)
	}
	p.SentAt = int64(binary.BigEndian.Uint64(rest[0:8]))
	rest = rest[8:]

	switch p.Kind {
	case KindText:
		if len(rest) < 4 {
			return p, fmt.Errorf("%w: TEXT missing length", ErrBadPayload)
		}
		n := int(binary.BigEndian.Uint32(rest[0:4]))
		rest = rest[4:]
		if n < 0 || n > MaxTextLen {
			return p, fmt.Errorf("%w: TEXT length %d out of range", ErrBadPayload, n)
		}
		if len(rest) != n {
			return p, fmt.Errorf("%w: TEXT declares %d bytes, has %d", ErrBadPayload, n, len(rest))
		}
		if !utf8.Valid(rest) {
			return p, fmt.Errorf("%w: TEXT is not valid UTF-8", ErrBadPayload)
		}
		p.Text = string(rest)

	case KindReceipt:
		if len(rest) != 16 {
			return p, fmt.Errorf("%w: RECEIPT needs 16 bytes, got %d", ErrBadPayload, len(rest))
		}
		p.RefEpoch = binary.BigEndian.Uint64(rest[0:8])
		p.RefSeq = binary.BigEndian.Uint64(rest[8:16])

	case KindTyping:
		if len(rest) != 1 {
			return p, fmt.Errorf("%w: TYPING needs 1 byte, got %d", ErrBadPayload, len(rest))
		}
		if rest[0] > 1 {
			return p, fmt.Errorf("%w: TYPING state %d invalid", ErrBadPayload, rest[0])
		}
		p.TypingState = rest[0]

	case KindRekey, KindRekeyACK:
		if len(rest) != ECDHPubLen {
			return p, fmt.Errorf("%w: %s needs %d bytes, got %d",
				ErrBadPayload, p.Kind, ECDHPubLen, len(rest))
		}
		p.EphPub = append([]byte(nil), rest...)

	case KindBye:
		if len(rest) < 1 {
			return p, fmt.Errorf("%w: BYE missing reason length", ErrBadPayload)
		}
		n := int(rest[0])
		rest = rest[1:]
		if len(rest) != n {
			return p, fmt.Errorf("%w: BYE declares %d bytes, has %d", ErrBadPayload, n, len(rest))
		}
		if !utf8.Valid(rest) {
			return p, fmt.Errorf("%w: BYE reason is not valid UTF-8", ErrBadPayload)
		}
		p.ByeReason = string(rest)

	case KindHandshakeConfirm:
		if len(rest) != HandshakeHashLen {
			return p, fmt.Errorf("%w: HANDSHAKE_CONFIRM needs %d bytes, got %d",
				ErrBadPayload, HandshakeHashLen, len(rest))
		}
		p.HandshakeHash = append([]byte(nil), rest...)

	case KindPing, KindPong:
		if len(rest) != 0 {
			return p, fmt.Errorf("%w: %s carries %d unexpected bytes", ErrBadPayload, p.Kind, len(rest))
		}
	}

	return p, nil
}
