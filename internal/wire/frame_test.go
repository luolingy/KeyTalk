package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func mustEncode(t *testing.T, f Frame) []byte {
	t.Helper()
	buf, err := f.Encode(nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return buf
}

func TestFrameRoundTripSecure(t *testing.T) {
	f := Frame{
		Type:  TypeSecure,
		Epoch: 7,
		Seq:   42,
		Body:  []byte("ciphertext-bytes"),
	}
	f.SessionID = [RevisionLen]byte{1, 2, 3, 4, 5, 6, 7, 8}

	buf := mustEncode(t, f)
	if len(buf) != f.Size() {
		t.Fatalf("Size()=%d but encoded %d bytes", f.Size(), len(buf))
	}

	got, n, err := DecodeFrame(buf)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("consumed %d, want %d", n, len(buf))
	}
	if got.Type != f.Type {
		t.Errorf("Type = %v, want %v", got.Type, f.Type)
	}
	if got.SessionID != f.SessionID {
		t.Errorf("SessionID = %x, want %x", got.SessionID, f.SessionID)
	}
	if got.Epoch != f.Epoch || got.Seq != f.Seq {
		t.Errorf("Epoch/Seq = %d/%d, want %d/%d", got.Epoch, got.Seq, f.Epoch, f.Seq)
	}
	if !bytes.Equal(got.Body, f.Body) {
		t.Errorf("Body = %q, want %q", got.Body, f.Body)
	}
}

func TestFrameRoundTripKEMInit(t *testing.T) {
	// KEM_INIT 没有 SessionID/Epoch/Seq 头。
	f := Frame{Type: TypeKEMInit, Body: []byte("openpgp-blob")}
	buf := mustEncode(t, f)

	got, _, err := DecodeFrame(buf)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if got.Type != TypeKEMInit {
		t.Errorf("Type = %v, want KEM_INIT", got.Type)
	}
	if !bytes.Equal(got.Body, f.Body) {
		t.Errorf("Body = %q, want %q", got.Body, f.Body)
	}
	if got.Epoch != 0 || got.Seq != 0 {
		t.Errorf("KEM_INIT should not carry Epoch/Seq, got %d/%d", got.Epoch, got.Seq)
	}
}

// TestLengthZeroRejected 覆盖 docs/wire-protocol.md §11.1 的该用例。
func TestLengthZeroRejected(t *testing.T) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 0)
	_, _, err := DecodeFrame(buf)
	if !errors.Is(err, ErrBadLength) {
		t.Fatalf("err = %v, want ErrBadLength", err)
	}
}

// TestOversizeLengthRejected 关键：必须在不分配大内存的前提下拒绝。
func TestOversizeLengthRejected(t *testing.T) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 0xFFFFFFFF) // 4 GiB
	_, _, err := DecodeFrame(buf)
	if !errors.Is(err, ErrBadLength) {
		t.Fatalf("err = %v, want ErrBadLength", err)
	}

	buf2 := make([]byte, 4)
	binary.BigEndian.PutUint32(buf2, MaxFrame+1)
	if _, _, err := DecodeFrame(buf2); !errors.Is(err, ErrBadLength) {
		t.Fatalf("err = %v, want ErrBadLength", err)
	}
}

func TestUnknownTypeRejected(t *testing.T) {
	f := Frame{Type: Type(0xEE), Body: []byte("x")}
	buf := mustEncode(t, f)
	_, _, err := DecodeFrame(buf)
	if !errors.Is(err, ErrUnknownType) {
		t.Fatalf("err = %v, want ErrUnknownType", err)
	}
}

func TestShortFrame(t *testing.T) {
	f := Frame{Type: TypeSecure, Body: []byte("hello world")}
	buf := mustEncode(t, f)

	// 截断到各种长度，都应返回 ErrShortFrame 而非 panic。
	for i := 0; i < len(buf); i++ {
		_, _, err := DecodeFrame(buf[:i])
		if !errors.Is(err, ErrShortFrame) {
			t.Fatalf("len=%d: err = %v, want ErrShortFrame", i, err)
		}
	}
}

func TestSecureFrameTooShortForHeader(t *testing.T) {
	// 声明 bodyLen=1（仅够放 Type），但 SECURE 需要 1+24 字节。
	buf := make([]byte, 5)
	binary.BigEndian.PutUint32(buf, 1)
	buf[4] = byte(TypeSecure)
	_, _, err := DecodeFrame(buf)
	if !errors.Is(err, ErrBadBody) {
		t.Fatalf("err = %v, want ErrBadBody", err)
	}
}

// TestConsecutiveFrames 验证粘包：一次给多个帧，应能逐个切分。
func TestConsecutiveFrames(t *testing.T) {
	var stream []byte
	want := []string{"first", "second", "third"}
	for i, s := range want {
		f := Frame{Type: TypeSecure, Epoch: 1, Seq: uint64(i), Body: []byte(s)}
		b := mustEncode(t, f)
		stream = append(stream, b...)
	}

	off := 0
	for i, w := range want {
		f, n, err := DecodeFrame(stream[off:])
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if string(f.Body) != w {
			t.Errorf("frame %d body = %q, want %q", i, f.Body, w)
		}
		off += n
	}
	if off != len(stream) {
		t.Errorf("consumed %d of %d bytes", off, len(stream))
	}
}

// TestReadFrameSplitWrites 验证拆包：字节逐个到达也应正确重组。
func TestReadFrameSplitWrites(t *testing.T) {
	f := Frame{Type: TypeSecure, Epoch: 3, Seq: 9, Body: []byte("payload")}
	buf := mustEncode(t, f)

	r := &dripReader{data: buf, chunk: 1}
	got, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got.Body, f.Body) || got.Epoch != f.Epoch || got.Seq != f.Seq {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestReadFrameEOF(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want EOF", err)
	}
}

// AAD 必须与文档定义一致：ver ‖ type ‖ sid ‖ epoch ‖ seq
func TestAADLayout(t *testing.T) {
	f := Frame{Type: TypeSecure, Epoch: 0x0102030405060708, Seq: 0x1112131415161718}
	copy(f.SessionID[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11})

	got := f.AAD()
	want := []byte{
		Version, byte(TypeSecure),
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("AAD =\n%x\nwant\n%x", got, want)
	}
}

// TestEncodeReusesBuffer 确认编码可复用调用方的缓冲，减少每条消息的分配。
func TestEncodeReusesBuffer(t *testing.T) {
	f := Frame{Type: TypeKEMInit, Body: []byte("x")}
	buf := make([]byte, 0, 128)
	base := &buf[:1][0]

	out, err := f.Encode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if &out[0] != base {
		t.Error("Encode should reuse the provided buffer when capacity allows")
	}
}

func TestPlaintextRoundTripAllKinds(t *testing.T) {
	cases := []Plaintext{
		{Kind: KindText, SentAt: 1234, Text: "你好，世界 🌍"},
		{Kind: KindReceipt, SentAt: 1, RefEpoch: 5, RefSeq: 99},
		{Kind: KindTyping, SentAt: 2, TypingState: 1},
		{Kind: KindRekey, SentAt: 3, EphPub: bytes.Repeat([]byte{7}, ECDHPubLen)},
		{Kind: KindRekeyACK, SentAt: 4, EphPub: bytes.Repeat([]byte{8}, ECDHPubLen)},
		{Kind: KindPing, SentAt: 5},
		{Kind: KindPong, SentAt: 6},
		{Kind: KindBye, SentAt: 7, ByeReason: "user quit"},
		{Kind: KindHandshakeConfirm, SentAt: 8, HandshakeHash: bytes.Repeat([]byte{9}, HandshakeHashLen)},
	}

	for _, want := range cases {
		t.Run(want.Kind.String(), func(t *testing.T) {
			enc, err := want.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, err := DecodePlaintext(enc)
			if err != nil {
				t.Fatalf("DecodePlaintext: %v", err)
			}
			if got.Kind != want.Kind {
				t.Errorf("Kind = %v, want %v", got.Kind, want.Kind)
			}
			if got.SentAt != want.SentAt {
				t.Errorf("SentAt = %d, want %d", got.SentAt, want.SentAt)
			}
			if got.Text != want.Text {
				t.Errorf("Text = %q, want %q", got.Text, want.Text)
			}
			if got.RefEpoch != want.RefEpoch || got.RefSeq != want.RefSeq {
				t.Errorf("Ref = %d/%d, want %d/%d",
					got.RefEpoch, got.RefSeq, want.RefEpoch, want.RefSeq)
			}
			if got.TypingState != want.TypingState {
				t.Errorf("TypingState = %d, want %d", got.TypingState, want.TypingState)
			}
			if !bytes.Equal(got.EphPub, want.EphPub) {
				t.Errorf("EphPub = %x, want %x", got.EphPub, want.EphPub)
			}
			if got.ByeReason != want.ByeReason {
				t.Errorf("ByeReason = %q, want %q", got.ByeReason, want.ByeReason)
			}
			if !bytes.Equal(got.HandshakeHash, want.HandshakeHash) {
				t.Errorf("HandshakeHash = %x, want %x", got.HandshakeHash, want.HandshakeHash)
			}
		})
	}
}

func TestPlaintextRejectsTrailingGarbage(t *testing.T) {
	enc, err := (&Plaintext{Kind: KindPing, SentAt: 1}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	// PING 不应携带负载；多出的字节必须被拒绝。
	if _, err := DecodePlaintext(append(enc, 0xAA)); err == nil {
		t.Fatal("expected error for trailing bytes on PING")
	}

	// TEXT 的长度字段与实际内容不符。
	bad := []byte{Version, byte(KindText), 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 5, 'a', 'b'}
	if _, err := DecodePlaintext(bad); err == nil {
		t.Fatal("expected error for TEXT length mismatch")
	}
}

func TestPlaintextRejectsBadUTF8(t *testing.T) {
	body := []byte{0xFF, 0xFE}
	buf := []byte{Version, byte(KindText), 0, 0, 0, 0, 0, 0, 0, 1}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(body)))
	buf = append(buf, body...)
	if _, err := DecodePlaintext(buf); err == nil {
		t.Fatal("expected error for invalid UTF-8")
	}
}

func TestPlaintextRejectsBadVersionAndKind(t *testing.T) {
	if _, err := DecodePlaintext([]byte{0x99, byte(KindPing)}); err == nil {
		t.Fatal("expected error for bad version")
	}
	if _, err := DecodePlaintext([]byte{Version, 0xEE}); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

// FuzzDecodeFrame 保证任意输入都不 panic、不超大分配。
func FuzzDecodeFrame(f *testing.F) {
	seeds := []Frame{
		{Type: TypeKEMInit, Body: []byte("a")},
		{Type: TypeKEMACK, Epoch: 0, Seq: 0, Body: []byte("b")},
		{Type: TypeSecure, Epoch: 1, Seq: 2, Body: []byte("c")},
		{Type: TypeError, Body: []byte("d")},
	}
	for _, s := range seeds {
		b, err := s.Encode(nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x03})
	f.Add([]byte{0, 0, 0, 25, 3})

	f.Fuzz(func(t *testing.T, data []byte) {
		fr, _, err := DecodeFrame(data)
		if err != nil {
			return
		}
		// 能解出来就必须能重新编码回去。
		if _, err := fr.Encode(nil); err != nil {
			t.Fatalf("re-encode failed: %v", err)
		}
	})
}

// FuzzDecodePlaintext 保证载荷解析对任意输入健壮。
func FuzzDecodePlaintext(f *testing.F) {
	for _, k := range []Kind{KindText, KindReceipt, KindTyping, KindRekey, KindBye, KindPing} {
		b, err := (&Plaintext{Kind: k, SentAt: 1, Text: "x",
			EphPub: bytes.Repeat([]byte{1}, ECDHPubLen), ByeReason: "y"}).Encode()
		if err != nil {
			continue
		}
		f.Add(b)
	}
	f.Add([]byte{Version, byte(KindText)})

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := DecodePlaintext(data)
		if err != nil {
			return
		}
		if _, err := p.Encode(); err != nil {
			t.Fatalf("re-encode failed: %v", err)
		}
	})
}

// dripReader 每次只返回 chunk 字节，模拟 TCP 拆包。
type dripReader struct {
	data  []byte
	off   int
	chunk int
}

func (r *dripReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := r.chunk
	if n > len(p) {
		n = len(p)
	}
	if r.off+n > len(r.data) {
		n = len(r.data) - r.off
	}
	copy(p, r.data[r.off:r.off+n])
	r.off += n
	return n, nil
}
