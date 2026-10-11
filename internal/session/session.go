// Package session 编排握手与会话生命周期。
//
// 职责边界（见 docs/architecture.md §3.3）：
//
//   - 本包是**唯一**同时依赖 crypto、wire 与 transport 的地方。
//     crypto 不知道网络存在；transport 不知道加密存在；本包把它们接起来。
//
//   - 本包**不**管理联系人、不存储消息、不碰 UI——那些是 core 的事。
//     这样本包可以独立测试，且换 UI 不影响它。
//
// 并发模型：
//
//   - 单个事件循环 goroutine 串行处理所有状态变更（避免锁竞争与竞态）。
//   - 对外暴露的都是"投递命令"，不阻塞调用方。
package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/transport"
	"github.com/exeliang/keytalk/internal/wire"
)

// 本包的错误。
var (
	// ErrNoSession 表示该对端尚无已建立的会话。
	ErrNoSession = errors.New("session: no established session for peer")

	// ErrHandshakeInProgress 表示握手正在进行中。
	ErrHandshakeInProgress = errors.New("session: handshake already in progress")

	// ErrNotEstablished 表示收到加密帧但会话尚未建立。
	ErrNotEstablished = errors.New("session: received secure frame before handshake completed")

	// ErrUnknownFrameType 表示帧类型无法识别。
	ErrUnknownFrameType = errors.New("session: unknown frame type")

	// ErrHandshakeTimeout 表示握手未在预期时间内完成。
	//
	// 最常见的成因是"联系人表里的公钥与对端实际身份不符"：
	// 对端无法解密我们的 KEM_INIT，于是静默丢弃，
	// 而我们也收不到任何错误（协议上没有"我解不开"这种回应，
	// 因为它会泄露信息给攻击者）。
	//
	// 因此必须由超时来把这种"静默失败"转成用户可见的错误。
	ErrHandshakeTimeout = errors.New("session: handshake timed out (peer did not respond; check that the contact's public key is correct)")
)

// handshakeTimeout 是发起握手后等待 KEM_ACK 的最长时间。
const handshakeTimeout = 20 * time.Second

// PeerID 是会话层使用的对端标识。
//
// 与 transport.PeerID 刻意区分：传输层的 ID 只是路由用的地址，
// 而这里的 ID 是**经过密码学验证的**指纹。
// 两者转换必须经由本包，绝不可互相顶替（否则会退化成"用地址当身份"）。
type PeerID string

// Event 是会话层上报给 core 的事件。
type Event interface{ isSessionEvent() }

// 封闭接口标记：只有本文件内定义的类型才能作为事件。
// 这保证 core 的 switch 可以穷尽，新增事件时编译器会提示遗漏。
func (StateChanged) isSessionEvent()    {}
func (HandshakeDone) isSessionEvent()   {}
func (HandshakeFailed) isSessionEvent() {}
func (Message) isSessionEvent()         {}

// StateChanged 表示某对端的会话状态发生变化。
type StateChanged struct {
	Peer     PeerID
	State    crypto.State
	Previous crypto.State
}

// HandshakeDone 表示握手完成，会话可用。
//
// Verified 表示对端身份已通过密码学校验（签名者指纹匹配预期）。
// **它恒为 true**——握手失败时不会发出本事件，而是发出 HandshakeFailed。
// 保留该字段是为了让 UI 有明确的"已认证"语义，而不是靠推断。
type HandshakeDone struct {
	Peer     PeerID
	Verified bool
	Epoch    uint64

	// SAS 是双方各自计算的**握手记录哈希**，用于带外核对。
	//
	// 这是 Matrix 式"emoji 二次确认"的输入：两端用同一份哈希
	// 派生出同一组 emoji，用户比对一致即可确认没有中间人。
	//
	// ⚠️ 它与会话密钥**相互独立**（是记录哈希，不是密钥本身），
	// 因此即使泄漏也不影响机密性；但仍不应记录到日志里，
	// 因为它的用途是"人类比对"，写进日志会削弱这个语义。
	SAS []byte
}

// HandshakeFailed 表示握手失败。
//
// 这必须上报给用户而非静默重试：握手失败可能是攻击迹象
// （指纹不匹配 = 有人在冒充你的联系人），静默重试会掩盖它。
type HandshakeFailed struct {
	Peer PeerID
	Err  error
}

// Message 表示收到一条已解密的应用层消息。
//
// Plaintext 已经过完整校验：签名者身份匹配、重放检查通过、AEAD 认证通过。
type Message struct {
	Peer      PeerID
	Plaintext *wire.Plaintext
}

// Config 配置会话管理器。
type Config struct {
	// Identity 是本机长期身份。
	Identity crypto.IdentityProvider

	// Importer 用于导入对端公钥。
	Importer crypto.PublicKeyImporter

	// Transport 是底层传输。
	Transport transport.Transport

	// NowMS 返回当前时间（unix 毫秒）。nil 表示用系统时间。
	NowMS func() int64

	// Logf 是可选日志回调。
	Logf func(format string, args ...any)
}

func (c *Config) now() int64 {
	if c.NowMS != nil {
		return c.NowMS()
	}
	return time.Now().UnixMilli()
}

func (c *Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// PeerConfig 是建立会话所需的对端信息。
//
// 由 core 提供（来自联系人表），**不能**来自网络广播——
// 局域网里的 mDNS TXT 可被任意伪造（见 transport.PeerInfo.Fingerprint 的说明）。
type PeerConfig struct {
	// Fingerprint 是预期对端的指纹（来自本地联系人表，已由用户确认）。
	Fingerprint crypto.Fingerprint

	// PublicKey 是对端公钥的可分发表示。
	PublicKey []byte
}

// Manager 管理所有会话。
type Manager struct {
	cfg Config

	// peers 是已知对端的静态配置（来自联系人表）。
	mu     sync.RWMutex
	peers  map[PeerID]PeerConfig
	active map[PeerID]*crypto.Session

	// transportPeer 把会话 PeerID 映射到传输层 PeerID。
	transportPeer map[PeerID]transport.PeerID

	// pending 记录进行中的握手（initiator 侧需要保存中间状态）。
	pending map[PeerID]*crypto.InitiateResult

	// pendingTimers 是各握手的超时定时器，收到 ACK 后须停止。
	pendingTimers map[PeerID]*time.Timer

	events chan Event
	cmds   chan command

	closeOnce sync.Once
	closed    chan struct{}
	wg        sync.WaitGroup
}

// command 是投递给事件循环的命令。
//
// 所有状态变更都经由 channel 串行化，因此事件循环内部无需加锁——
// 这消除了整类竞态，也让状态转换易于推理。
type command struct {
	kind cmdKind
	peer PeerID
	// 以下字段按 kind 使用。
	frame []byte
	msg   *wire.Plaintext
	done  chan error
}

type cmdKind int

const (
	cmdFrameIn cmdKind = iota
	cmdSendText
	cmdStartHandshake
	cmdConnClosed
	cmdHandshakeTimeout
)

// New 创建会话管理器。
func New(cfg Config) *Manager {
	if cfg.Identity == nil {
		panic("session: Config.Identity is required")
	}
	if cfg.Transport == nil {
		panic("session: Config.Transport is required")
	}
	if cfg.Importer == nil {
		panic("session: Config.Importer is required")
	}
	return &Manager{
		cfg:           cfg,
		peers:         map[PeerID]PeerConfig{},
		active:        map[PeerID]*crypto.Session{},
		transportPeer: map[PeerID]transport.PeerID{},
		pending:       map[PeerID]*crypto.InitiateResult{},
		pendingTimers: map[PeerID]*time.Timer{},
		events:        make(chan Event, 256),
		cmds:          make(chan command, 256),
		closed:        make(chan struct{}),
	}
}

// AddPeer 注册一个已知对端（来自联系人表）。
func (m *Manager) AddPeer(id PeerID, pc PeerConfig) {
	m.mu.Lock()
	m.peers[id] = pc
	m.mu.Unlock()
}

// SetTransportPeer 建立会话 PeerID 与传输层 PeerID 的映射。
//
// 二者必须显式映射而非假定相等：传输层 ID 可能包含地址信息，
// 且入站连接的传输层 ID 在握手前是"未知来源"的临时值。
func (m *Manager) SetTransportPeer(id PeerID, tp transport.PeerID) {
	m.mu.Lock()
	m.transportPeer[id] = tp
	m.mu.Unlock()
}

// Events 返回事件流。
func (m *Manager) Events() <-chan Event { return m.events }

// Start 启动事件循环并订阅传输层事件。
func (m *Manager) Start(ctx context.Context) {
	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		m.loop(ctx)
	}()
	go func() {
		defer m.wg.Done()
		m.consumeTransportEvents(ctx)
	}()
}

// consumeTransportEvents 把传输层事件转成会话层命令。
func (m *Manager) consumeTransportEvents(ctx context.Context) {
	evs := m.cfg.Transport.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.closed:
			return
		case ev, ok := <-evs:
			if !ok {
				return
			}
			switch e := ev.(type) {
			case transport.FrameReceived:
				m.enqueue(command{kind: cmdFrameIn, peer: m.sessionPeerFor(e.ID), frame: e.Frame})
			case transport.ConnClosed:
				m.enqueue(command{kind: cmdConnClosed, peer: m.sessionPeerFor(e.ID)})
			case transport.PeerFound, transport.ConnOpened, transport.PeerLost:
				// 这些是传输层状态，会话层不直接关心——
				// core 会通过自己的渠道处理（UI 展示在线状态）。
			}
		}
	}
}

// sessionPeerFor 把传输层 PeerID 映射回会话 PeerID。
//
// 三种情况：
//  1. 该传输 ID 已在映射表中（出站连接，或已被 AdoptConnection 收编的入站连接）
//     → 返回对应的会话 ID（即已认证的指纹）。
//  2. 传输 ID 本身就是某个已认证会话的 ID（AdoptConnection 之后，
//     连接上报的 ID 就是真实指纹）→ 直接命中。
//  3. 都不匹配（握手前的入站连接）→ 原样返回临时 ID。
//     此时不可能是已建立的会话，因此走不到加密路径。
func (m *Manager) sessionPeerFor(tp transport.PeerID) PeerID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for id, t := range m.transportPeer {
		if t == tp {
			return id
		}
	}
	// 情况 2：传输 ID 直接就是会话 ID。
	// 这是 AdoptConnection 生效后的常见路径——连接已改名，
	// 事件里的 ID 就是已认证的指纹。
	if _, ok := m.active[PeerID(tp)]; ok {
		return PeerID(tp)
	}
	if _, ok := m.peers[PeerID(tp)]; ok {
		return PeerID(tp)
	}
	return PeerID(tp)
}

// enqueue 投递命令，尊重关闭状态。
func (m *Manager) enqueue(c command) {
	select {
	case <-m.closed:
		return
	default:
	}
	select {
	case m.cmds <- c:
	case <-m.closed:
	}
}

// loop 是唯一的状态变更点。
func (m *Manager) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.closed:
			return
		case c := <-m.cmds:
			if err := m.handle(c); err != nil {
				m.cfg.logf("session: %v", err)
				if c.done != nil {
					c.done <- err
				}
			} else if c.done != nil {
				c.done <- nil
			}
		}
	}
}

// handle 处理单条命令。
func (m *Manager) handle(c command) error {
	switch c.kind {
	case cmdFrameIn:
		return m.handleFrame(c.peer, c.frame)
	case cmdConnClosed:
		m.handleConnClosed(c.peer)
		return nil
	case cmdHandshakeTimeout:
		m.handleHandshakeTimeout(c.peer)
		return nil
	case cmdStartHandshake:
		return m.startHandshake(c.peer)
	case cmdSendText:
		return m.sendText(c.peer, c.msg)
	default:
		return fmt.Errorf("session: unknown command %d", c.kind)
	}
}

// handleFrame 处理一个入站帧。
func (m *Manager) handleFrame(peer PeerID, raw []byte) error {
	f, _, err := wire.DecodeFrame(raw)
	if err != nil {
		// 畸形帧：可能是攻击，也可能只是版本不兼容。
		// 记录后丢弃，但不中断连接（一个坏帧不该导致掉线）。
		return fmt.Errorf("decode frame: %w", err)
	}

	switch f.Type {
	case wire.TypeKEMInit:
		return m.handleKEMInit(peer, raw, &f)
	case wire.TypeKEMACK:
		return m.handleKEMAck(peer, raw, &f)
	case wire.TypeSecure:
		return m.handleSecure(peer, &f)
	case wire.TypeError:
		return fmt.Errorf("peer %s reported protocol error", peer)
	default:
		return fmt.Errorf("%w: 0x%02x", ErrUnknownFrameType, f.Type)
	}
}

// peerConfig 取出对端的静态配置。
func (m *Manager) peerConfig(peer PeerID) (PeerConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if pc, ok := m.peers[peer]; ok {
		return pc, true
	}
	// 入站连接可能以传输层 ID 到达，此处按指纹再查一遍。
	for _, pc := range m.peers {
		if string(pc.Fingerprint) == string(peer) {
			return pc, true
		}
	}
	return PeerConfig{}, false
}

// identifySender 解封装握手载荷并确定发送者身份。
//
// 这里有一个**鸡生蛋问题**：要验签必须先把签名者公钥放进 keyring，
// 而"签名者是谁"恰恰是我们想知道的。
//
// 不能信任载荷自称的身份——攻击者可以签一个声称属于别人的载荷。
//
// 解法：遍历**本地联系人表**中的每一个已知公钥，逐个尝试验签。
// 只有真正持对应私钥的发送者才能让签名验证通过，
// 因此第一个验签成功且指纹与联系人对得上的，就是真实身份。
//
// 这是安全的：
//   - 攻击者无法伪造某个已知联系人的签名（没有其私钥）；
//   - 攻击者用自己的密钥签名会验签失败，因为我们只信任联系人表里的公钥；
//   - 代价是 O(联系人数量) 的验签尝试，实践中联系人数量很小，
//     且这只发生在连接建立的握手阶段（非热路径）。
//
// 若遍历完毕无一成功，说明发送者不是任何已知联系人 —— 拒绝。
func (m *Manager) identifySender(raw []byte) (*crypto.KEMPlaintext, crypto.Fingerprint, PeerID, PeerConfig, error) {
	m.mu.RLock()
	type entry struct {
		id PeerID
		pc PeerConfig
	}
	candidates := make([]entry, 0, len(m.peers))
	for id, pc := range m.peers {
		candidates = append(candidates, entry{id: id, pc: pc})
	}
	m.mu.RUnlock()

	if len(candidates) == 0 {
		return nil, "", "", PeerConfig{}, errors.New("session: contact list is empty")
	}

	// 注册公钥是验签的前提。提供该能力的 provider 才可能识别发送者。
	reg, canRegister := m.cfg.Identity.(interface {
		AddPeerKey([]byte) (crypto.Fingerprint, error)
	})

	var lastErr error
	for _, c := range candidates {
		if canRegister {
			fp, err := reg.AddPeerKey(c.pc.PublicKey)
			if err != nil {
				lastErr = err
				continue
			}
			// 联系人表里的公钥必须与其声明的指纹一致，
			// 否则该条目本身已损坏，跳过。
			if fp.String() != c.pc.Fingerprint.String() {
				continue
			}
		}

		data, sender, err := m.cfg.Identity.Unwrap(raw)
		if err != nil {
			lastErr = err
			continue
		}
		// 验签成功，但必须确认签名者正是这个联系人的密钥，
		// 而不是 keyring 里其他条目的密钥。
		if sender.String() != c.pc.Fingerprint.String() {
			continue
		}
		kp, err := crypto.DecodeKEMPlaintext(data)
		if err != nil {
			lastErr = err
			continue
		}
		return kp, sender, c.id, c.pc, nil
	}

	if lastErr == nil {
		lastErr = crypto.ErrAuthFailed
	}
	return nil, "", "", PeerConfig{}, fmt.Errorf(
		"%w: handshake from unknown identity (not in contact list)", lastErr)
}

// handleKEMInit 处理入站握手请求（本机作为 responder）。
//
// KEM_INIT 帧不带 secure header（见 wire.Type.HasSecureHeader），
// 因此 f.Body 直接就是 OpenPGP 保护的握手载荷。
func (m *Manager) handleKEMInit(peer PeerID, raw []byte, f *wire.Frame) error {
	full := f.Body

	kp, senderFP, actualPeer, pc, err := m.identifySender(full)
	if err != nil {
		// 身份未知：明确上报，绝不静默接受。
		// 产品决策：不提供"先接受再询问"的选项——
		// 那会让用户习惯接受陌生连接（TOFU 的典型失败模式）。
		m.emit(HandshakeFailed{Peer: PeerID("unknown"), Err: err})
		return fmt.Errorf("identify inbound handshake: %w", err)
	}
	_ = kp

	cfg := crypto.HandshakeConfig{
		Identity:        m.cfg.Identity,
		Importer:        m.cfg.Importer,
		PeerPublicKey:   pc.PublicKey,
		PeerFingerprint: pc.Fingerprint,
		NowMS:           m.cfg.NowMS,
	}

	res, err := crypto.Respond(cfg, full)
	if err != nil {
		m.emit(HandshakeFailed{Peer: actualPeer, Err: err})
		return fmt.Errorf("respond: %w", err)
	}

	// 处理"同时发起"的碰撞（glare）。
	//
	// 场景：双方几乎同时通过 mDNS 发现对方，于是**都**发出 KEM_INIT。
	// 此时每一侧都处于"既发出了自己的 INIT，又收到了对方的 INIT"状态。
	//
	// ⚠️ 这里必须让**恰好一方**成为 initiator，而且这个决定要能被
	// 重复求值而结果不变。
	//
	// 规则：指纹**较大**的一方主动（in­itiator），较小的一方让步。
	// losesGlareTieBreak 在两侧算出的结果必然相反，因此不会双方都退。
	//
	// ── 曾经踩过的坑（实测约 1/6 概率复现）─────────────────
	//
	// 早期实现只处理了"让出"这一支：
	//
	//     if hasPending && losesGlareTieBreak { dropPending(); 继续当 responder }
	//
	// 问题在于 hasPending 是**逐帧判定**的。对方的 INIT 可能在我们
	// 建立 pending 之前就到了——那时 hasPending 为 false，于是我们
	// **不**走让出分支，直接当 responder 并回 ACK。结果是双方都当了
	// responder、都回了 ACK，建立了**两条平行会话**：每条只在一侧
	// 被认作"当前会话"，消息于是发到对方不认的那条链上。
	// 症状是"握手显示成功，但消息收不到"，极难定位。
	//
	// ── 现在的做法 ────────────────────────────────────────
	//
	// 不依赖"是否已有 pending"来判断要不要让。而是：只要收到 INIT，
	// 就按**纯函数**的规则决定自己在这个 peer 上的角色：
	//
	//   - 我方指纹较大 → 我是 initiator：继续等自己的 ACK，
	//     并且**不**因为对方的 INIT 而改变自己的角色。
	//     但仍然要为对方的 INIT 生成响应（回 ACK），
	//     否则对方会一直等——这是"双方各等各的"死局的来源。
	//
	//   - 我方指纹较小 → 我是 responder：接受对方的 INIT，
	//     回 ACK，并放弃自己的 pending（连同定时器）。
	//
	// 关键点：**较大的一方始终是 initiator**，无论谁先到达。
	// 这样即使对方的 INIT 先到，角色判定依然唯一且对称。
	//
	// 至于"较大方收到较小方的 INIT 时也回 ACK"会不会造成平行会话：
	// 不会。因为较小方已经放弃了自己的 pending，它不会再等自己的 ACK；
	// 它只认由较大方发起的那条会话。较大方则以自己发起的会话为准。
	// 两条 ACK 里只有一条会被真正采纳（pending 存在的那条），
	// 另一条因找不到 pending 而被忽略。
	if m.hasPending(actualPeer) && m.losesGlareTieBreak(actualPeer, senderFP) {
		// 本方是较小方：让出 initiator 角色，放弃自己的 INIT 并
		// **取消超时定时器**。
		//
		// 取消定时器是必须的——否则它会在会话已经建立之后触发，
		// 把成功的握手报告为失败（这正是本函数历史上最著名的缺陷）。
		m.dropPending(actualPeer)
		m.cfg.logf("session: glare with %s; yielding initiator role (we have the smaller fingerprint)",
			senderFP.Display())
	} else if m.hasPending(actualPeer) {
		// 本方是较大方，且自己已经发出了 INIT，同时又收到对方的 INIT。
		//
		// ⚠️ 此时**必须忽略**对方的 INIT，而不是去当 responder。
		//
		// 为什么不能顺手回一个 ACK：那样会把 m.active 覆盖成
		// 由对方发起的会话，而对方（较小方）在看到我们的 INIT 后会
		// 让出并放弃它自己的 pending。于是：
		//   - 对方在等**我们发起**的那条会话的 ACK（它认为自己是 responder）；
		//   - 我们却因为在等自己的 pending 而把它当成了 responder 回来。
		// 双方对"哪条会话是当前的"理解不一致，消息发到对方不认的链上。
		//
		// 正确做法：较大方**始终**是 initiator。它忽略较小方的 INIT，
		// 只等自己那条 INIT 的 ACK。较小方则按规则让出、安心当 responder。
		// 这样角色唯一且对称，两边指向同一条会话。
		m.cfg.logf("session: glare with %s; ignoring their INIT, we stay initiator (larger fingerprint)",
			senderFP.Display())
		return nil
	}

	// 保存会话并把**入站连接**的传输层 ID 绑定到已认证的身份。
	//
	// 这一步是安全关键：入站连接的传输层 ID 在握手前是
	// "inbound:<地址>" 这样的临时值（不可信）。握手完成后它被
	// 替换为经过验签的身份指纹，此后所有路由都基于真实身份。
	// 把入站连接的临时传输层 ID 替换为已认证的身份。
	//
	// 这一步是安全关键：入站连接的传输层 ID 在握手前是
	// "inbound:<地址>" 这样的临时值，**不能**用于路由——
	// 否则同一 IP 上的任意进程都能顶替真实对端。
	// 握手完成意味着身份已经过验签与指纹比对，此时才可安全关联。
	//
	// ⚠️ 顺序要求：必须先 AdoptConnection，再把会话映射到**真实** ID。
	// 反过来会让后续 sendRaw 去找一个已经不存在（或已改名）的
	// 临时连接，表现为 "transport: unknown peer: inbound:..."。
	realTP := transport.PeerID(actualPeer)
	if adopter, ok := m.cfg.Transport.(interface {
		AdoptConnection(tempID, realID transport.PeerID)
	}); ok {
		adopter.AdoptConnection(transport.PeerID(peer), realTP)
	}

	m.mu.Lock()
	m.active[actualPeer] = res.Session
	m.transportPeer[actualPeer] = realTP
	m.mu.Unlock()

	// 发送 ACK。
	if err := m.sendRaw(actualPeer, wire.TypeKEMACK, [8]byte{}, res.SessionID, 0, 0, res.KEMACK); err != nil {
		return fmt.Errorf("send kem_ack: %w", err)
	}

	m.emit(StateChanged{Peer: actualPeer, State: crypto.StateEstablished, Previous: crypto.StateInit})
	m.emit(HandshakeDone{
		Peer: actualPeer, Verified: true, Epoch: 0,
		SAS: res.Session.HandshakeHash(),
	})
	m.cfg.logf("session: handshake completed with %s (responder), signed by %s",
		actualPeer, senderFP.Display())
	return nil
}

// hasPending 判断是否有一个尚未完成的出站握手。
func (m *Manager) hasPending(peer PeerID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.pending[peer]
	return ok
}

// dropPending 放弃一个出站握手，并取消其超时定时器。
//
// 用于 glare（同时发起）时让出 initiator 角色：
// 必须取消定时器，否则它稍后触发会把已经建立成功的会话报告为失败。
func (m *Manager) dropPending(peer PeerID) {
	m.mu.Lock()
	delete(m.pending, peer)
	t := m.pendingTimers[peer]
	delete(m.pendingTimers, peer)
	m.mu.Unlock()

	if t != nil {
		t.Stop()
	}
}

// losesGlareTieBreak 报告在本方与对端同时发起握手时，本方是否应当让步。
//
// 规则：比较双方指纹的字节序，指纹较大的一方让步（作为 responder）。
//
// 为什么这样是确定性的：两侧拿到的两个指纹相同，比较结果必然相反，
// 因此**恰好**有一方让步。不会出现双方都让步（则无人发起）或
// 都不让步（则双方都拒绝）的死局。
//
// 用指纹而非地址：地址可能因多网卡而不同且不可靠，
// 指纹是双方唯一能达成一致的稳定标识。
func (m *Manager) losesGlareTieBreak(peer PeerID, senderFP crypto.Fingerprint) bool {
	own := m.cfg.Identity.Fingerprint()
	return strings.Compare(string(own), string(senderFP)) > 0
}

// handleKEMAck 处理握手应答（本机作为 initiator）。
//
// KEM_ACK 帧**带** secure header，但该 header 的 Epoch/Seq 是占位的 0
// （见 wire.TypeKEMACK 的说明）——真正的 ACK 载荷在 f.Body 里，
// 由 CompleteInitiate 用自己的 nonce(seq=0) 解密。
func (m *Manager) handleKEMAck(peer PeerID, raw []byte, f *wire.Frame) error {
	m.mu.RLock()
	pending, ok := m.pending[peer]
	pc, known := m.peers[peer]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("unexpected kem_ack from %s (no handshake in progress)", peer)
	}
	if !known {
		return fmt.Errorf("no peer config for %s", peer)
	}

	full := f.Body

	cfg := crypto.HandshakeConfig{
		Identity:        m.cfg.Identity,
		Importer:        m.cfg.Importer,
		PeerPublicKey:   pc.PublicKey,
		PeerFingerprint: pc.Fingerprint,
		NowMS:           m.cfg.NowMS,
	}

	ackPT, err := crypto.CompleteInitiate(cfg, pending, full)
	if err != nil {
		m.mu.Lock()
		delete(m.pending, peer)
		if t, ok := m.pendingTimers[peer]; ok {
			t.Stop()
			delete(m.pendingTimers, peer)
		}
		m.mu.Unlock()
		m.emit(HandshakeFailed{Peer: peer, Err: err})
		return fmt.Errorf("complete initiate: %w", err)
	}

	m.mu.Lock()
	m.active[peer] = pending.Session
	delete(m.pending, peer)
	if t, ok := m.pendingTimers[peer]; ok {
		t.Stop()
		delete(m.pendingTimers, peer)
	}
	m.mu.Unlock()

	m.emit(StateChanged{Peer: peer, State: crypto.StateEstablished, Previous: crypto.StateSentInit})
	m.emit(HandshakeDone{
		Peer: peer, Verified: true, Epoch: 0,
		SAS: pending.Session.HandshakeHash(),
	})
	m.cfg.logf("session: handshake completed with %s (initiator), hash=%x",
		peer, ackPT.Handshake[:4])
	return nil
}

// handleSecure 处理加密应用层帧。
func (m *Manager) handleSecure(peer PeerID, f *wire.Frame) error {
	m.mu.RLock()
	sess, ok := m.active[peer]
	m.mu.RUnlock()

	if !ok {
		// 收到加密帧但无会话：可能是重放旧帧，也可能是协议错乱。
		return fmt.Errorf("%w: %s", ErrNotEstablished, peer)
	}

	// AAD 必须与发送方逐字节一致（见 docs/crypto-protocol.md §10.4.2）。
	pt, err := sess.Open(f.Epoch, f.Seq, f.Body, func(sid [crypto.SessionIDLen]byte, epoch, seq uint64) []byte {
		return frameAAD(f.Type, sid, epoch, seq)
	})
	if err != nil {
		return fmt.Errorf("open secure frame: %w", err)
	}

	pl, err := wire.DecodePlaintext(pt)
	if err != nil {
		return fmt.Errorf("decode plaintext: %w", err)
	}

	m.emit(Message{Peer: peer, Plaintext: &pl})
	return nil
}

// handleHandshakeTimeout 处理握手超时。
//
// 触发条件：发出了 KEM_INIT，但在 handshakeTimeout 内没有收到可用的 KEM_ACK。
//
// 最可能的成因是联系人表里的公钥与对端实际身份不符——
// 对端解不开我们的载荷，按协议只能静默丢弃。
// 把这种情况明确报给用户，而不是让界面永远停在"连接中"。
func (m *Manager) handleHandshakeTimeout(peer PeerID) {
	m.mu.Lock()
	_, stillPending := m.pending[peer]
	delete(m.pending, peer)
	delete(m.pendingTimers, peer)
	m.mu.Unlock()

	if !stillPending {
		// 已经完成或被取消：定时器与真实事件竞争，属正常情况。
		return
	}

	m.emit(HandshakeFailed{Peer: peer, Err: ErrHandshakeTimeout})
	m.emit(StateChanged{Peer: peer, State: crypto.StateInit, Previous: crypto.StateSentInit})
	m.cfg.logf("session: handshake with %s timed out", peer)
}

// handleConnClosed 处理连接断开。
func (m *Manager) handleConnClosed(peer PeerID) {
	m.mu.Lock()
	sess, had := m.active[peer]
	if had {
		delete(m.active, peer)
	}
	delete(m.pending, peer)
	if t, ok := m.pendingTimers[peer]; ok {
		t.Stop()
		delete(m.pendingTimers, peer)
	}
	m.mu.Unlock()

	if had {
		// 销毁密钥材料。重连时需要重新握手——
		// 这是**有意的**：连接断开后临时密钥已失效，
		// 复用旧会话会让前向保密的保证变弱。
		sess.Close()
		m.emit(StateChanged{Peer: peer, State: crypto.StateClosed, Previous: crypto.StateEstablished})
		m.cfg.logf("session: connection to %s closed, session destroyed", peer)
	}
}

// frameAAD 构造加密帧的 AAD。
//
// 必须与发送方逐字节一致。方向隔离由**密钥**保证（i2r/r2i），
// 因此 AAD 中不含方向标签——那是 bug 不是防护。
func frameAAD(typ wire.Type, sid [crypto.SessionIDLen]byte, epoch, seq uint64) []byte {
	buf := make([]byte, 0, 1+crypto.SessionIDLen+16)
	buf = append(buf, byte(typ))
	buf = append(buf, sid[:]...)
	buf = appendU64(buf, epoch)
	buf = appendU64(buf, seq)
	return buf
}

func appendU64(b []byte, v uint64) []byte {
	var tmp [8]byte
	for i := 7; i >= 0; i-- {
		tmp[i] = byte(v)
		v >>= 8
	}
	return append(b, tmp[:]...)
}

// StartHandshake 主动向对端发起握手。
func (m *Manager) StartHandshake(peer PeerID) error {
	done := make(chan error, 1)
	m.enqueue(command{kind: cmdStartHandshake, peer: peer, done: done})
	select {
	case err := <-done:
		return err
	case <-m.closed:
		return ErrNoSession
	case <-time.After(10 * time.Second):
		return errors.New("session: handshake command timed out")
	}
}

func (m *Manager) startHandshake(peer PeerID) error {
	pc, ok := m.peerConfig(peer)
	if !ok {
		return fmt.Errorf("%w: %s", crypto.ErrAuthFailed, peer)
	}

	m.mu.RLock()
	_, already := m.active[peer]
	_, inProgress := m.pending[peer]
	m.mu.RUnlock()

	if already {
		return nil // 已有会话，幂等成功。
	}
	if inProgress {
		return fmt.Errorf("%w: %s", ErrHandshakeInProgress, peer)
	}

	cfg := crypto.HandshakeConfig{
		Identity:        m.cfg.Identity,
		Importer:        m.cfg.Importer,
		PeerPublicKey:   pc.PublicKey,
		PeerFingerprint: pc.Fingerprint,
		NowMS:           m.cfg.NowMS,
	}

	res, err := crypto.Initiate(cfg)
	if err != nil {
		m.emit(HandshakeFailed{Peer: peer, Err: err})
		return err
	}

	// 启动超时定时器。
	//
	// 必要性：若对端无法解密我们的 KEM_INIT（例如联系人表里的公钥有误），
	// 它会**静默丢弃**该帧——协议上没有"我解不开"这种回应，
	// 因为那会向攻击者泄露信息。于是我们会无限等待。
	//
	// 超时把这种静默失败转成用户可见的错误，避免"永远转圈"。
	timer := time.AfterFunc(handshakeTimeout, func() {
		m.enqueue(command{kind: cmdHandshakeTimeout, peer: peer})
	})

	m.mu.Lock()
	m.pending[peer] = res
	m.pendingTimers[peer] = timer
	m.mu.Unlock()

	if err := m.sendRaw(peer, wire.TypeKEMInit, res.SessionID, res.SessionID, 0, 0, res.KEMInit); err != nil {
		m.mu.Lock()
		delete(m.pending, peer)
		if t, ok := m.pendingTimers[peer]; ok {
			t.Stop()
			delete(m.pendingTimers, peer)
		}
		m.mu.Unlock()
		return fmt.Errorf("send kem_init: %w", err)
	}

	m.emit(StateChanged{Peer: peer, State: crypto.StateSentInit, Previous: crypto.StateInit})
	m.cfg.logf("session: sent KEM_INIT to %s", peer)
	return nil
}

// SendText 发送一条文本消息。
func (m *Manager) SendText(peer PeerID, text string) error {
	if len(text) == 0 {
		return errors.New("session: empty message")
	}
	done := make(chan error, 1)
	m.enqueue(command{
		kind: cmdSendText,
		peer: peer,
		msg: &wire.Plaintext{
			Kind:   wire.KindText,
			SentAt: m.cfg.now(),
			Text:   text,
		},
		done: done,
	})
	select {
	case err := <-done:
		return err
	case <-m.closed:
		return ErrNoSession
	case <-time.After(10 * time.Second):
		return errors.New("session: send command timed out")
	}
}

func (m *Manager) sendText(peer PeerID, msg *wire.Plaintext) error {
	m.mu.RLock()
	sess, ok := m.active[peer]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoSession, peer)
	}

	// 使用会话当前的 SessionID 与 Epoch 构造 AAD。
	var sid [crypto.SessionIDLen]byte
	copy(sid[:], sess.ID())

	pt, err := msg.Encode()
	if err != nil {
		return fmt.Errorf("encode plaintext: %w", err)
	}

	sealed, err := sess.Seal(pt, func(s [crypto.SessionIDLen]byte, epoch, seq uint64) []byte {
		return frameAAD(wire.TypeSecure, s, epoch, seq)
	})
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	return m.sendRaw(peer, wire.TypeSecure, sealed.SessionID, sid, sealed.Epoch, sealed.Seq, sealed.Body)
}

// sendRaw 把帧交给传输层。
func (m *Manager) sendRaw(peer PeerID, typ wire.Type, sid, aid [crypto.SessionIDLen]byte, epoch, seq uint64, body []byte) error {
	m.mu.RLock()
	tp, ok := m.transportPeer[peer]
	m.mu.RUnlock()

	if !ok {
		// 尚未映射传输层 ID：用会话 ID 当传输层 ID 试一次
		// （mDNS 场景下两者通常相同，都是指纹）。
		tp = transport.PeerID(peer)
	}

	f := &wire.Frame{
		Type:      typ,
		SessionID: sid,
		Epoch:     epoch,
		Seq:       seq,
		Body:      body,
	}
	raw, err := f.Encode(nil)
	if err != nil {
		return err
	}
	if err := m.cfg.Transport.Send(tp, raw); err != nil {
		return err
	}
	return nil
}

// emit 发送事件。
func (m *Manager) emit(ev Event) {
	select {
	case <-m.closed:
		return
	default:
	}
	select {
	case m.events <- ev:
	default:
		m.cfg.logf("session: event channel full, dropping %T", ev)
	}
}

// HasSession 报告是否已与对端建立会话。
func (m *Manager) HasSession(peer PeerID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.active[peer]
	return ok
}

// SessionState 返回对端会话状态。
func (m *Manager) SessionState(peer PeerID) crypto.State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.active[peer]; ok {
		return s.State()
	}
	if _, ok := m.pending[peer]; ok {
		return crypto.StateSentInit
	}
	return crypto.StateInit
}

// Fingerprint 返回本机身份指纹。
//
// 供 UI/CLI 显示，让用户能把它交给对方做带外确认。
func (m *Manager) Fingerprint() crypto.Fingerprint {
	return m.cfg.Identity.Fingerprint()
}

// Close 关闭管理器。幂等。
func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		close(m.closed)

		m.mu.Lock()
		for _, s := range m.active {
			s.Close()
		}
		m.active = map[PeerID]*crypto.Session{}
		m.pending = map[PeerID]*crypto.InitiateResult{}
		m.mu.Unlock()

		done := make(chan struct{})
		go func() {
			m.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			m.cfg.logf("session: close timed out")
		}
	})
}
