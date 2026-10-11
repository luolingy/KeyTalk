package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/curve25519"
)

// State 是会话的状态。
type State int

const (
	// StateInit 表示尚未开始握手。
	StateInit State = iota
	// StateSentInit 表示已发送 KEM_INIT，等待对端应答。
	StateSentInit
	// StateRecvInit 表示已收到 KEM_INIT 并发出 KEM_ACK，等待确认。
	StateRecvInit
	// StateEstablished 表示会话可用。
	StateEstablished
	// StateRatcheting 表示已发出 REKEY，等待 REKEY_ACK。
	StateRatcheting
	// StateClosed 表示会话已关闭，所有密钥已销毁。
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateInit:
		return "init"
	case StateSentInit:
		return "sent-init"
	case StateRecvInit:
		return "recv-init"
	case StateEstablished:
		return "established"
	case StateRatcheting:
		return "ratcheting"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// epochState 持有一代密钥及其收发状态。
//
// seq 在每个 epoch 内独立计数，因此重放窗口也必须按 epoch 划分。
type epochState struct {
	epoch   uint64
	sendKey []byte
	recvKey []byte
	sendSeq uint64
	recvWin ReplayWindow
}

// wipe 清零该代的密钥材料。
func (e *epochState) wipe() {
	zero(e.sendKey)
	zero(e.recvKey)
	e.sendKey, e.recvKey = nil, nil
}

// Session 是一次加密会话。
//
// 并发约束（见 docs/crypto-protocol.md §11）：
//   - Seal 只应由 writer goroutine 调用。
//   - Open 只应由 reader goroutine 调用。
//
// 内部用 mutex 保护，但这只是防御性措施——**不要**依赖它做跨 goroutine 的
// 自由并发，因为 seq 与重放窗口的语义要求单一读写者。
type Session struct {
	mu sync.Mutex

	id        [SessionIDLen]byte
	peerFP    Fingerprint
	state     State
	cur       *epochState
	prev      *epochState // 上一代，仅用于接收 ratchet 切换瞬间的在途帧
	isInit    bool        // true 表示本机是 initiator
	handshake []byte      // 握手记录哈希，供双方比对

	// pendingEphPriv 是 initiator 在等待 KEM_ACK 期间持有的临时私钥。
	// 收到 ACK 并完成 ECDH 后立即清零——这是前向保密的实现要点。
	pendingEphPriv []byte

	// macKey 用于 ratchet 的链式认证。
	macKey []byte
}

// ID 返回会话标识的副本。
func (s *Session) ID() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, SessionIDLen)
	copy(out, s.id[:])
	return out
}

// PeerFingerprint 返回对端指纹。
func (s *Session) PeerFingerprint() Fingerprint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerFP
}

// State 返回当前会话状态。
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Epoch 返回当前密钥代次。
func (s *Session) Epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return 0
	}
	return s.cur.epoch
}

// HandshakeHash 返回协商出的握手记录哈希。
func (s *Session) HandshakeHash() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handshake == nil {
		return nil
	}
	out := make([]byte, len(s.handshake))
	copy(out, s.handshake)
	return out
}

// Close 关闭会话并销毁所有密钥材料。
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *Session) closeLocked() {
	if s.cur != nil {
		s.cur.wipe()
	}
	if s.prev != nil {
		s.prev.wipe()
	}
	zero(s.pendingEphPriv)
	zero(s.macKey)
	s.pendingEphPriv = nil
	s.macKey = nil
	s.handshake = nil
	s.cur, s.prev = nil, nil
	s.state = StateClosed
}

// SealedFrame 是一次加密封装的结果。
//
// Epoch 与 Seq 必须置于帧头（明文），因为接收方需要它们来选择密钥
// 并重建 nonce，之后才能解密。它们受 AAD 保护，篡改会导致解密失败。
type SealedFrame struct {
	SessionID [SessionIDLen]byte
	Epoch     uint64
	Seq       uint64
	Body      []byte // AEAD 密文（含 tag）
}

// Seal 加密一条会话内载荷。
//
// aadFor 由调用方提供，用于把帧头（Type 等）纳入认证范围。
// 本包不依赖 wire，因此不能自行构造完整 AAD——这是有意的解耦：
// 调用方传入一个函数，把 (sessionID, epoch, seq) 组装成它自己的 AAD 形式。
func (s *Session) Seal(plaintext []byte, aadFor func(sid [SessionIDLen]byte, epoch, seq uint64) []byte) (*SealedFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateEstablished && s.state != StateRecvInit {
		return nil, fmt.Errorf("crypto: cannot seal in state %s", s.state)
	}
	if s.cur == nil || s.cur.sendKey == nil {
		return nil, ErrNoKey
	}

	// seq 单调递增且不允许回绕。达到上限必须强制结束该代次——
	// 回绕会导致 nonce 重用，那是 AEAD 下的灾难性错误。
	if s.cur.sendSeq == ^uint64(0) {
		return nil, fmt.Errorf("crypto: sequence exhausted for epoch %d; rekey required", s.cur.epoch)
	}
	s.cur.sendSeq++
	seq := s.cur.sendSeq

	frame := &SealedFrame{
		SessionID: s.id,
		Epoch:     s.cur.epoch,
		Seq:       seq,
	}

	var aad []byte
	if aadFor != nil {
		aad = aadFor(s.id, s.cur.epoch, seq)
	}
	ct, err := Seal(s.cur.sendKey, BuildNonce(seq), plaintext, aad)
	if err != nil {
		return nil, err
	}
	frame.Body = ct
	return frame, nil
}

// Open 解密一条会话内载荷。
//
// epoch 与 seq 来自帧头。若 epoch 既非当前也非上一代，返回 ErrBadEpoch。
//
// 调用顺序（见 docs/crypto-protocol.md §7.5）：
//  1. 按 epoch 选密钥
//  2. 重放检查（在解密之前，避免重放包消耗算力）
//  3. 解密
//  4. 若解密失败，撤销第 2 步的标记（否则攻击者可用伪帧挤掉合法帧）
func (s *Session) Open(epoch, seq uint64, ciphertext []byte, aadFor func(sid [SessionIDLen]byte, epoch, seq uint64) []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateClosed {
		return nil, ErrNoKey
	}

	es := s.epochStateForLocked(epoch)
	if es == nil {
		return nil, fmt.Errorf("%w: %d", ErrBadEpoch, epoch)
	}

	// 先做重放检查。
	switch es.recvWin.Accept(seq) {
	case AcceptReplay:
		return nil, fmt.Errorf("%w: epoch %d seq %d", ErrReplay, epoch, seq)
	case AcceptTooOld:
		// 过旧不等于攻击：可能是严重乱序或对端行为异常。
		return nil, fmt.Errorf("%w: epoch %d seq %d (highest %d)",
			ErrTooOld, epoch, seq, es.recvWin.Highest())
	}

	var aad []byte
	if aadFor != nil {
		aad = aadFor(s.id, epoch, seq)
	}
	pt, err := Open(es.recvKey, BuildNonce(seq), ciphertext, aad)
	if err != nil {
		// 回滚重放标记：否则一个伪造的 (epoch,seq) 就能永久拒绝真正的合法帧。
		es.recvWin.Revoke(seq)
		return nil, err
	}
	return pt, nil
}

// epochStateForLocked 按 epoch 找到对应的密钥代次。
func (s *Session) epochStateForLocked(epoch uint64) *epochState {
	if s.cur != nil && s.cur.epoch == epoch {
		return s.cur
	}
	if s.prev != nil && s.prev.epoch == epoch {
		return s.prev
	}
	return nil
}

// DropPrevious 销毁上一代密钥。
//
// 应在收到首个新代次的合法帧后立即调用（见 docs/wire-protocol.md §5.2）。
func (s *Session) DropPrevious() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prev != nil {
		s.prev.wipe()
		s.prev = nil
	}
}

// newSessionID 生成随机会话标识。
func newSessionID() [SessionIDLen]byte {
	var id [SessionIDLen]byte
	copy(id[:], randomBytes(SessionIDLen))
	return id
}

// generateECDH 生成一对 X25519 密钥。
func generateECDH() (priv, pub []byte, err error) {
	priv = randomBytes(ECDHPubLen)
	// curve25519.X25519 内部会做 clamp，此处直接使用随机私钥即可。
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		zero(priv)
		return nil, nil, fmt.Errorf("crypto: ecdh keygen: %w", err)
	}
	return priv, pub, nil
}

// ecdh 计算共享密钥。
func ecdh(priv, peerPub []byte) ([]byte, error) {
	if len(peerPub) != ECDHPubLen {
		return nil, fmt.Errorf("%w: ecdh pub must be %d bytes", ErrMalformed, ECDHPubLen)
	}
	shared, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		// 对端公钥是低阶点，或长度非法。
		return nil, fmt.Errorf("%w: ecdh: %v", ErrAuthFailed, err)
	}
	return shared, nil
}

// KEMPlaintext 是 KEM_INIT 帧内被 OpenPGP 保护的载荷。
//
// 该结构在 OpenPGP 的机密性与完整性保护之内，
// 因此其内部字段无需单独加密。
type KEMPlaintext struct {
	SessionID   [SessionIDLen]byte
	SenderFP    Fingerprint
	RecipientFP Fingerprint
	Timestamp   int64
	EphPub      []byte
	Flags       byte

	// encoded 保存原始编码，用于计算握手记录哈希。
	// 必须先解析出该字节序列再计算哈希，才能保证双方对同一份
	// 字节串达成一致（重新序列化可能因字段顺序不同而产生差异）。
	encoded []byte
}

// Encode 序列化 KEM 载荷。
//
//	ver(1) | sid(8) | senderFP(len2+bytes) | recipientFP(len2+bytes)
//	| ts(8) | ephPub(32) | flags(1)
func (k *KEMPlaintext) Encode() []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, Version)
	buf = append(buf, k.SessionID[:]...)
	buf = appendFP(buf, k.SenderFP)
	buf = appendFP(buf, k.RecipientFP)
	buf = binary.BigEndian.AppendUint64(buf, uint64(k.Timestamp))
	buf = append(buf, k.EphPub...)
	buf = append(buf, k.Flags)
	return buf
}

func appendFP(dst []byte, fp Fingerprint) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(fp)))
	return append(dst, fp...)
}

// DecodeKEMPlaintext 解析 KEM 载荷。
func DecodeKEMPlaintext(data []byte) (*KEMPlaintext, error) {
	k := &KEMPlaintext{encoded: append([]byte(nil), data...)}

	if len(data) < 1+SessionIDLen {
		return nil, fmt.Errorf("%w: kem payload too short", ErrMalformed)
	}
	if data[0] != Version {
		return nil, fmt.Errorf("%w: 0x%02x", ErrWrongVersion, data[0])
	}
	off := 1
	copy(k.SessionID[:], data[off:off+SessionIDLen])
	off += SessionIDLen

	var err error
	if k.SenderFP, off, err = readFP(data, off); err != nil {
		return nil, err
	}
	if k.RecipientFP, off, err = readFP(data, off); err != nil {
		return nil, err
	}
	if len(data)-off < 8+ECDHPubLen+1 {
		return nil, fmt.Errorf("%w: kem payload truncated", ErrMalformed)
	}
	k.Timestamp = int64(binary.BigEndian.Uint64(data[off : off+8]))
	off += 8
	k.EphPub = append([]byte(nil), data[off:off+ECDHPubLen]...)
	off += ECDHPubLen
	k.Flags = data[off]
	off++

	if off != len(data) {
		return nil, fmt.Errorf("%w: kem payload has %d trailing bytes", ErrMalformed, len(data)-off)
	}
	return k, nil
}

func readFP(data []byte, off int) (Fingerprint, int, error) {
	if len(data)-off < 2 {
		return "", off, fmt.Errorf("%w: fingerprint length truncated", ErrMalformed)
	}
	n := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if n == 0 {
		return "", off, fmt.Errorf("%w: empty fingerprint", ErrMalformed)
	}
	if len(data)-off < n {
		return "", off, fmt.Errorf("%w: fingerprint declares %d, has %d", ErrMalformed, n, len(data)-off)
	}
	fp := Fingerprint(data[off : off+n])
	off += n
	return fp, off, nil
}

// ACKPlaintext 是 KEM_ACK 内被 AEAD 保护的载荷。
//
//	ver(1) | responderFP(len2+bytes) | ts(8) | ephPub(32) | handshakeHash(32)
type ACKPlaintext struct {
	ResponderFP Fingerprint
	Timestamp   int64
	EphPub      []byte
	Handshake   []byte
}

// Encode 序列化 ACK 载荷。
func (a *ACKPlaintext) Encode() []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, Version)
	buf = appendFP(buf, a.ResponderFP)
	buf = binary.BigEndian.AppendUint64(buf, uint64(a.Timestamp))
	buf = append(buf, a.EphPub...)
	buf = append(buf, a.Handshake...)
	return buf
}

// DecodeACKPlaintext 解析 ACK 载荷。
func DecodeACKPlaintext(data []byte) (*ACKPlaintext, error) {
	a := &ACKPlaintext{}
	if len(data) < 1 {
		return nil, fmt.Errorf("%w: ack payload empty", ErrMalformed)
	}
	if data[0] != Version {
		return nil, fmt.Errorf("%w: 0x%02x", ErrWrongVersion, data[0])
	}
	off := 1
	var err error
	if a.ResponderFP, off, err = readFP(data, off); err != nil {
		return nil, err
	}
	if len(data)-off < 8+ECDHPubLen+HashLen {
		return nil, fmt.Errorf("%w: ack payload truncated", ErrMalformed)
	}
	a.Timestamp = int64(binary.BigEndian.Uint64(data[off : off+8]))
	off += 8
	a.EphPub = append([]byte(nil), data[off:off+ECDHPubLen]...)
	off += ECDHPubLen
	a.Handshake = append([]byte(nil), data[off:off+HashLen]...)
	off += HashLen

	if off != len(data) {
		return nil, fmt.Errorf("%w: ack payload has %d trailing bytes", ErrMalformed, len(data)-off)
	}
	return a, nil
}

// KEMACK 是完整的 KEM_ACK 线上结构。
//
//	ephPub(32, 明文) | ciphertext(nonce 为 seq=0)
//
// 为什么把响应方的临时公钥放在**密文之外**：
//
//	这是握手不可避免的一步。initiator 必须先用 (自己的临时私钥,
//	响应方的临时公钥) 做 ECDH 才能派生会话密钥，而 ACK 恰恰是用
//	该会话密钥加密的——两者互相依赖，形成循环。
//
//	因此响应方临时公钥必须以明文发送。这**不是**安全弱点：
//
//	1. 它本来就是公开信息（ECDH 公钥无需保密）。
//	2. 它参与 AAD，攻击者替换它会导致 ACK 解密失败。
//	3. 它参与派生 initiator 的密钥，而 ACK 中的握手哈希会被
//	   initiator 覆核，攻破它需要同时伪造一致的哈希。
//
//	真正需要保密的是响应方的临时**私**钥，它从未离开响应方内存。
type KEMACK struct {
	EphPub     []byte // 明文，32 字节
	Ciphertext []byte // AEAD 密文（含 tag）
}

// Encode 序列化 KEM_ACK 线上结构。
func (k *KEMACK) Encode() []byte {
	out := make([]byte, 0, ECDHPubLen+len(k.Ciphertext))
	out = append(out, k.EphPub...)
	out = append(out, k.Ciphertext...)
	return out
}

// DecodeKEMACK 解析 KEM_ACK 线上结构。
func DecodeKEMACK(data []byte) (*KEMACK, error) {
	if len(data) < ECDHPubLen+TagLen {
		return nil, fmt.Errorf("%w: kem_ack too short (%d bytes)", ErrMalformed, len(data))
	}
	return &KEMACK{
		EphPub:     append([]byte(nil), data[:ECDHPubLen]...),
		Ciphertext: append([]byte(nil), data[ECDHPubLen:]...),
	}, nil
}

// TimestampToleranceMS 是握手帧允许的时间偏差。
const TimestampToleranceMS int64 = 300_000 // ±300s

// CheckTimestamp 校验时间戳是否在容忍窗口内。
//
// 作用：拒绝被录制后重放的整个握手交互。
func CheckTimestamp(ts, nowMSv int64) error {
	diff := nowMSv - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > TimestampToleranceMS {
		return fmt.Errorf("%w: skew %dms", ErrStale, diff)
	}
	return nil
}

// HandshakeConfig 汇总握手所需的全部外部输入。
//
// 以结构体传入而非长参数列表，便于后续扩展（如硬件后端、多设备）而不破坏签名。
type HandshakeConfig struct {
	// Identity 是本机长期身份。
	Identity IdentityProvider

	// Importer 用于导入对端公钥。
	Importer PublicKeyImporter

	// PeerPublicKey 是对端公钥的可分发表示。
	PeerPublicKey []byte

	// PeerFingerprint 是**预期**的对端指纹（来自联系人表）。
	//
	// 必须提供：握手结果会与此值比对，不一致即拒绝。
	// 这是防止"mDNS 广播他人指纹诱导连接"的关键。
	PeerFingerprint Fingerprint

	// NowMS 返回当前时间（unix 毫秒）。注入以便测试。
	NowMS func() int64
}

func (c *HandshakeConfig) now() int64 {
	if c.NowMS != nil {
		return c.NowMS()
	}
	return nowMS()
}

// validate 检查配置完整性。
func (c *HandshakeConfig) validate() error {
	if c.Identity == nil {
		return fmt.Errorf("%w: identity is nil", ErrProviderUnavailable)
	}
	if !c.PeerFingerprint.Valid() {
		return fmt.Errorf("%w: peer fingerprint required", ErrAuthFailed)
	}
	if c.Identity.Fingerprint().String() == c.PeerFingerprint.String() {
		return ErrSelfAddressed
	}
	return nil
}

// InitiateResult 是发起握手的结果。
type InitiateResult struct {
	Session   *Session
	KEMInit   []byte // 待发送的 KEM_INIT 载荷（已由 OpenPGP 保护）
	SessionID [SessionIDLen]byte

	// ephPub 是 initiator 的临时公钥，用于派生会话密钥的绑定上下文。
	// 只在本地使用，不通过网络发送（它已在 KEM 载荷内）。
	ephPub []byte

	// kemPlaintext 是 KEM 载荷的编码字节，用于复算握手哈希。
	// 必须保留原文而非重新序列化——重新编码可能因字段顺序差异
	// 产生不同字节串，导致双方哈希不一致。
	kemPlaintext []byte
}

// Initiate 作为 initiator 发起握手。
//
// 流程（见 docs/crypto-protocol.md §5）：
//  1. 生成临时 ECDH 密钥对
//  2. 构造 KEM 载荷并封装（加密 + 签名）
//  3. 保存私钥等待 ACK
//
// 注意：此时**尚未**派生会话密钥——那需要等拿到对端的临时公钥。
// 这正是前向保密的关键：密钥由双方临时密钥共同决定，而非发送方单方生成。
func Initiate(cfg HandshakeConfig) (*InitiateResult, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	ephPriv, ephPub, err := generateECDH()
	if err != nil {
		return nil, err
	}

	sid := newSessionID()
	kp := &KEMPlaintext{
		SessionID:   sid,
		SenderFP:    cfg.Identity.Fingerprint(),
		RecipientFP: cfg.PeerFingerprint,
		Timestamp:   cfg.now(),
		EphPub:      ephPub,
	}
	encoded := kp.Encode()

	entity, _, err := cfg.Importer.ImportPublicKey(cfg.PeerPublicKey)
	if err != nil {
		zero(ephPriv)
		return nil, fmt.Errorf("crypto: import peer key: %w", err)
	}
	blob, err := cfg.Identity.Wrap(entity, encoded)
	if err != nil {
		zero(ephPriv)
		return nil, fmt.Errorf("crypto: wrap kem payload: %w", err)
	}

	s := &Session{
		id:             sid,
		peerFP:         cfg.PeerFingerprint,
		state:          StateSentInit,
		isInit:         true,
		pendingEphPriv: ephPriv,
	}

	return &InitiateResult{
		Session:      s,
		KEMInit:      blob,
		SessionID:    sid,
		ephPub:       append([]byte(nil), ephPub...),
		kemPlaintext: encoded,
	}, nil
}

// nowMS 返回当前 unix 毫秒。
func nowMS() int64 { return timeNow().UnixMilli() }

// deriveKeysLocked 由双方临时公钥派生会话密钥，并销毁临时私钥。
//
// 前向保密的实现要点就在开头：临时私钥用完立即清零。
// 即使攻击者日后拿到长期私钥，也无法重建这里派生出的密钥。
//
// 上下文顺序约定：发起方的身份与临时公钥始终排在前面。
// 这一点与本机视角无关，因此双方独立计算会得到同一结果。
func (s *Session) deriveKeysLocked(cfg HandshakeConfig, myEphPub, peerEphPub []byte) error {
	shared, err := ecdh(s.pendingEphPriv, peerEphPub)
	if err != nil {
		return err
	}
	defer zero(shared)

	// 临时私钥用完即毁。
	zero(s.pendingEphPriv)
	s.pendingEphPriv = nil

	salt := DeriveKey(shared, nil, "keytalk/v1/salt", SaltLen)

	var fpA, fpB Fingerprint
	var ephA, ephB []byte
	if s.isInit {
		fpA, fpB = cfg.Identity.Fingerprint(), s.peerFP
		ephA, ephB = myEphPub, peerEphPub
	} else {
		fpA, fpB = s.peerFP, cfg.Identity.Fingerprint()
		ephA, ephB = peerEphPub, myEphPub
	}
	ctx := SessionContext(s.id[:], fpA, fpB, ephA, ephB)

	i2r, r2i := DeriveSessionKeys(shared, salt, ctx)

	if s.isInit {
		// initiator：发送用 i2r，接收用 r2i。
		s.cur = &epochState{epoch: 0, sendKey: i2r, recvKey: r2i}
		s.macKey = DeriveMACKey(i2r)
	} else {
		// responder：接收用 i2r，发送用 r2i（与 initiator 方向相反）。
		s.cur = &epochState{epoch: 0, sendKey: r2i, recvKey: i2r}
		s.macKey = DeriveMACKey(r2i)
	}
	return nil
}

// CompleteInitiate 完成 initiator 侧握手。
//
// 输入是响应方发来的完整 KEM_ACK 线上结构（含明文临时公钥）。
//
// 顺序（不能颠倒）：
//  1. 取明文响应方临时公钥，与自己持有的临时私钥做 ECDH → 派生会话密钥
//  2. 用派生的密钥解密 ACK 密文（ACK 正是用它加密的）
//  3. 校验响应方身份、时间戳，以及 ACK 内临时公钥与明文一致
//  4. 复算握手哈希并与 ACK 中的值比对（防降级 / 防中间人改参数）
func CompleteInitiate(cfg HandshakeConfig, init *InitiateResult, ackWire []byte) (*ACKPlaintext, error) {
	wire, err := DecodeKEMACK(ackWire)
	if err != nil {
		return nil, err
	}

	s := init.Session
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateSentInit {
		return nil, fmt.Errorf("crypto: CompleteInitiate in state %s", s.state)
	}
	if len(s.pendingEphPriv) != ECDHPubLen {
		return nil, fmt.Errorf("%w: missing pending ephemeral key", ErrNoKey)
	}

	// 步骤 1：派生密钥。
	if err := s.deriveKeysLocked(cfg, init.ephPub, wire.EphPub); err != nil {
		return nil, err
	}

	// 步骤 2：解密 ACK。
	pt, err := Open(s.cur.recvKey, BuildNonce(0), wire.Ciphertext,
		ackAAD(s.id, cfg.PeerFingerprint, cfg.Identity.Fingerprint(), wire.EphPub))
	if err != nil {
		return nil, fmt.Errorf("%w: kem_ack: %v", ErrAuthFailed, err)
	}
	ackPT, err := DecodeACKPlaintext(pt)
	if err != nil {
		return nil, err
	}

	// 步骤 3：校验响应方身份与时间戳。
	if ackPT.ResponderFP.String() != s.peerFP.String() {
		return nil, fmt.Errorf("%w: ack responder %s != expected %s",
			ErrAuthFailed, ackPT.ResponderFP.Display(), s.peerFP.Display())
	}
	if err := CheckTimestamp(ackPT.Timestamp, cfg.now()); err != nil {
		return nil, err
	}
	// ACK 内声明的临时公钥必须与明文中的一致，
	// 否则说明明文字段与实际协商内容不符（可能被篡改）。
	if !bytes.Equal(ackPT.EphPub, wire.EphPub) {
		return nil, fmt.Errorf("%w: ack ephemeral key mismatch", ErrAuthFailed)
	}

	// 步骤 4：复算握手哈希并比对。
	expect := HandshakeHash(init.kemPlaintext, handshakeInput(ackPT))
	if !bytes.Equal(expect, ackPT.Handshake) {
		return nil, fmt.Errorf("%w: handshake hash mismatch (possible downgrade attack)",
			ErrAuthFailed)
	}

	s.handshake = append([]byte(nil), ackPT.Handshake...)
	s.state = StateEstablished
	return ackPT, nil
}

// handshakeInput 返回参与握手哈希计算的 ACK 载荷编码。
//
// 关键：**排除** Handshake 字段本身。若把它包含进去，就会形成
// "哈希值参与自身计算"的循环定义，导致 initiator 无法复现
// responder 算出的值（他不知道对方填了什么）。
func handshakeInput(a *ACKPlaintext) []byte {
	return (&ACKPlaintext{
		ResponderFP: a.ResponderFP,
		Timestamp:   a.Timestamp,
		EphPub:      a.EphPub,
		Handshake:   make([]byte, HashLen),
	}).Encode()
}

// RespondResult 是响应握手的结果。
type RespondResult struct {
	Session   *Session
	KEMACK    []byte // 待发送的 KEM_ACK 线上结构
	SessionID [SessionIDLen]byte
	Handshake []byte // 本机计算的握手哈希，待与 HANDSHAKE_CONFIRM 比对
}

// Respond 作为 responder 处理收到的 KEM_INIT。
//
// 步骤（见 docs/crypto-protocol.md §5）：
//  1. 解封 KEM 载荷（解密 + 验签）
//  2. 四道校验：签名者 / recipient_fp / sender_fp / ts 窗口
//  3. 生成临时 ECDH 密钥对
//  4. 派生会话密钥
//  5. 构造并加密 KEM_ACK
func Respond(cfg HandshakeConfig, kemBlob []byte) (*RespondResult, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// 注册对端公钥，使 Unwrap 能验证签名者身份。
	//
	// 这是必需的：OpenPGP 的内联签名需要签名者公钥才能解析出身份
	// （见 pgp_provider.go 中 Unwrap 的说明）。
	// 我们只信任调用方提供的 PeerPublicKey，绝不信任消息自称的公钥。
	if reg, ok := cfg.Identity.(interface {
		AddPeerKey([]byte) (Fingerprint, error)
	}); ok {
		fp, err := reg.AddPeerKey(cfg.PeerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("crypto: register peer key: %w", err)
		}
		// 注册的公钥必须正是我们预期的对端，否则后续校验失去意义。
		if fp.String() != cfg.PeerFingerprint.String() {
			return nil, fmt.Errorf("%w: peer key fingerprint %s != expected %s",
				ErrAuthFailed, fp.Display(), cfg.PeerFingerprint.Display())
		}
	}

	data, sender, err := cfg.Identity.Unwrap(kemBlob)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap: %v", ErrAuthFailed, err)
	}

	kp, err := DecodeKEMPlaintext(data)
	if err != nil {
		return nil, err
	}

	// 校验 1：载荷声明的发送者必须与签名者一致。
	// 若不一致，攻击者可构造"用自己密钥签名但声称是他人"的载荷。
	if kp.SenderFP.String() != sender.String() {
		return nil, fmt.Errorf("%w: kem declares sender %s but signed by %s",
			ErrAuthFailed, kp.SenderFP.Display(), sender.Display())
	}
	// 校验 2：载荷必须确实是发给本机的，否则一个被转发的 blob 仍会生效。
	if kp.RecipientFP.String() != cfg.Identity.Fingerprint().String() {
		return nil, fmt.Errorf("%w: kem addressed to %s, we are %s",
			ErrAuthFailed, kp.RecipientFP.Display(), cfg.Identity.Fingerprint().Display())
	}
	// 校验 3：发送者必须是预期对端。
	if kp.SenderFP.String() != cfg.PeerFingerprint.String() {
		return nil, fmt.Errorf("%w: kem sender %s != expected %s",
			ErrAuthFailed, kp.SenderFP.Display(), cfg.PeerFingerprint.Display())
	}
	// 校验 4：时间戳新鲜度，拒绝重放的整个握手交互。
	if err := CheckTimestamp(kp.Timestamp, cfg.now()); err != nil {
		return nil, err
	}

	ephPriv, ephPub, err := generateECDH()
	if err != nil {
		return nil, err
	}
	defer zero(ephPriv)

	shared, err := ecdh(ephPriv, kp.EphPub)
	if err != nil {
		return nil, err
	}
	defer zero(shared)

	salt := DeriveKey(shared, nil, "keytalk/v1/salt", SaltLen)
	// 上下文顺序约定：发起方（kp.SenderFP / kp.EphPub）在前，
	// 与 initiator 侧保持一致。
	ctx := SessionContext(kp.SessionID[:], kp.SenderFP, cfg.Identity.Fingerprint(),
		kp.EphPub, ephPub)

	i2r, r2i := DeriveSessionKeys(shared, salt, ctx)

	s := &Session{
		id:     kp.SessionID,
		peerFP: kp.SenderFP,
		state:  StateEstablished,
		isInit: false,
		cur: &epochState{
			epoch: 0,
			// responder：接收用 i2r，发送用 r2i（与 initiator 相反）。
			sendKey: r2i,
			recvKey: i2r,
		},
	}
	s.macKey = DeriveMACKey(r2i)

	// 构造 ACK 载荷。
	ackPT := &ACKPlaintext{
		ResponderFP: cfg.Identity.Fingerprint(),
		Timestamp:   cfg.now(),
		EphPub:      ephPub,
		Handshake:   make([]byte, HashLen),
	}
	h := HandshakeHash(kp.encoded, handshakeInput(ackPT))
	copy(ackPT.Handshake, h)
	ackEncoded := ackPT.Encode()

	// 用 r2i 加密 ACK，nonce = seq 0（这是该密钥下的第一帧，永不复用）。
	// AAD 绑定 sessionID、双方身份与明文临时公钥——
	// 最后一项确保攻击者无法替换明文中的临时公钥。
	ct, err := Seal(r2i, BuildNonce(0), ackEncoded,
		ackAAD(s.id, cfg.Identity.Fingerprint(), kp.SenderFP, ephPub))
	if err != nil {
		return nil, err
	}

	s.handshake = h
	wire := &KEMACK{EphPub: ephPub, Ciphertext: ct}
	return &RespondResult{
		Session:   s,
		KEMACK:    wire.Encode(),
		SessionID: kp.SessionID,
		Handshake: h,
	}, nil
}

// ackAAD 构造 KEM_ACK 的 AAD。
//
// KEM_ACK 在会话建立前发送，此时还没有协商出的会话 ID 可依赖，
// 因此 AAD 绑定 sessionID 与双方身份，防止 ACK 被跨会话重放。
//
// 同时绑定明文的响应方临时公钥（peerEphPub）：该字段以明文传输
// （initiator 需要它来派生密钥），必须在 AAD 中认证，否则攻击者
// 可以替换它，诱导 initiator 派生出错误的密钥。
func ackAAD(sid [SessionIDLen]byte, responder, initiator Fingerprint, peerEphPub []byte) []byte {
	buf := make([]byte, 0, 1+SessionIDLen+2+len(responder)+2+len(initiator)+ECDHPubLen)
	buf = append(buf, Version)
	buf = append(buf, sid[:]...)
	buf = appendFP(buf, responder)
	buf = appendFP(buf, initiator)
	buf = append(buf, peerEphPub...)
	return buf
}

// VerifyHandshake 比对双方握手哈希。
//
// 不一致意味着协议实现不匹配或存在参数降级攻击，**必须终止会话**。
func (s *Session) VerifyHandshake(peerHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handshake == nil {
		return errors.New("crypto: handshake hash not set")
	}
	if len(peerHash) != len(s.handshake) {
		return fmt.Errorf("%w: handshake hash length %d != %d",
			ErrAuthFailed, len(peerHash), len(s.handshake))
	}
	if !bytes.Equal(peerHash, s.handshake) {
		return fmt.Errorf("%w: handshake hash mismatch (possible downgrade attack)",
			ErrAuthFailed)
	}
	return nil
}
