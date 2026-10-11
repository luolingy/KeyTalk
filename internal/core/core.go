// Package core 是应用状态机，负责业务编排。
//
// 它把 crypto / wire / transport / session 四层组装起来，
// 对上（UI/CLI）只暴露两个面：
//
//   - 命令：SendText、AddContact、StartChat…（全部非阻塞）
//   - 事件：Events() 返回一个 channel（全部是值类型，可安全跨 goroutine）
//
// 设计要点：
//
//  1. **UI 线程永不阻塞**。所有命令只是投递到一个内部 channel，
//     真正的状态变更由 core 自己的事件循环 goroutine 完成。
//     Gio 是 immediate mode，任何阻塞调用都会冻结界面。
//
//  2. **状态只有一份，且只被事件循环 goroutine 修改**。
//     读取通过带锁的快照接口（Snapshot），避免 UI 读到撕裂的状态。
//     这与 session.Manager 的做法一致，也避免了锁顺序问题。
//
//  3. **UI 不得绕过 core 直接调用 transport/crypto**（架构硬约束）。
//     本包是唯一的组装点。
//
// 依赖方向：core → {session, transport, crypto, wire}。
// 反向依赖一律禁止（见 docs/architecture.md §1.1）。
package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/session"
	"github.com/exeliang/keytalk/internal/transport"
)

// 本包的错误。全部可通过 errors.Is 判断，
// 便于 UI 用 switch 给出不同的提示文案。
var (
	// ErrUnknownContact 表示对端不在联系人表中。
	//
	// 这不是"找不到人"那么简单：本项目**拒绝**与未知身份通信，
	// 必须先交换公钥。因此这个错误在 UI 上应引导用户去导入公钥，
	// 而不是提供一个"仍然连接"的按钮。
	ErrUnknownContact = errors.New("core: unknown contact")

	// ErrNoSession 表示与该对端尚无已建立的加密会话。
	ErrNoSession = errors.New("core: no established session")

	// ErrClosed 表示 core 已关闭。
	ErrClosed = errors.New("core: closed")

	// ErrInvalidKey 表示导入的公钥无法解析。
	ErrInvalidKey = errors.New("core: invalid public key")

	// ErrEmptyMessage 表示试图发送空消息。
	ErrEmptyMessage = errors.New("core: empty message")

	// ErrMessageTooLong 表示消息超过协议上限。
	//
	// 必须在上层拦下：wire.MaxFrame 是 1 MiB，但消息会被装进
	// 一个帧里，超长会让对端直接断开连接——用户应当看到
	// "消息太长"，而不是"对方掉线了"。
	ErrMessageTooLong = errors.New("core: message too long")
)

// MaxMessageBytes 是单条文本消息的字节上限。
//
// 取 16 KiB 而非直接用到帧上限（1 MiB）：留出充足余量给帧头与
// 未来的字段扩展，同时远大于任何人类输入的文本。
// 超出时明确报错，而不是静默截断——静默截断会让用户以为发全了。
const MaxMessageBytes = 16 * 1024

// ContactStatus 是联系人在 UI 上展示的状态。
type ContactStatus int

const (
	// StatusOffline 表示未在网络上发现该联系人。
	StatusOffline ContactStatus = iota
	// StatusOnline 表示已发现，但尚无加密会话（握手可能在进行中）。
	StatusOnline
	// StatusSecure 表示加密会话已建立，可以收发消息。
	StatusSecure
	// StatusFailed 表示最近一次握手失败（例如对方公钥不匹配）。
	StatusFailed
)

func (s ContactStatus) String() string {
	switch s {
	case StatusOffline:
		return "offline"
	case StatusOnline:
		return "online"
	case StatusSecure:
		return "secure"
	case StatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Contact 是一个联系人及其当前状态（不可变快照）。
type Contact struct {
	// ID 是稳定的会话标识，等于指纹字符串。
	ID string
	// Name 是本地显示名。注意这是**本机**的命名，
	// 不是对方自称的名字——对方自称的名字可以被伪造，不作为身份。
	Name string
	// Fingerprint 是完整指纹，用于带外核对。
	Fingerprint crypto.Fingerprint
	// Status 是当前连接/会话状态。
	Status ContactStatus
	// LastError 是最近一次失败的原因（Status 为 StatusFailed 时有效）。
	LastError string
}

// Message 是一条聊天消息（不可变快照）。
type Message struct {
	// ID 是本地唯一标识，用于 UI 列表 key。
	ID string
	// PeerID 是会话对端。
	PeerID string
	// Outgoing 表示这条消息是本机发出的。
	Outgoing bool
	// Text 是消息正文。
	//
	// ⚠️ 只存在于内存与 UI 中。落盘的版本必须是密文
	// （见 docs/architecture.md §3.6），那是 S6 的工作。
	Text string
	// SentAt 是发送/接收时间。
	SentAt time.Time
	// Pending 表示消息尚未确认送达（仅出站有意义）。
	Pending bool
}

// Event 是 core 向 UI 推送的事件。
//
// 用 sealed interface（未导出方法）的原因：事件类型必须由本包穷举，
// UI 用类型 switch 处理时，编译器能帮助发现遗漏。若允许外部实现，
// UI 就必须有 default 分支吞掉未知事件，那会让
// "新加了事件但 UI 没处理"变成静默失败。
type Event interface{ isCoreEvent() }

// ContactsChanged 表示联系人列表或其状态发生变化。
// UI 收到后应重新调用 Snapshot()。
type ContactsChanged struct{}

// MessageReceived 表示收到一条新的入站消息。
type MessageReceived struct{ Message Message }

// MessageSent 表示本机消息已成功交给传输层。
//
// 注意：这只表示"已发出"，**不**表示对方已收到。
// 纯 P2P 下没有送达回执（那需要协议扩展），UI 不应把它显示成"已读"。
type MessageSent struct{ Message Message }

// MessageFailed 表示本机消息发送失败。
type MessageFailed struct {
	PeerID string
	Text   string
	Err    error
}

// SessionStateChanged 表示某个联系人的会话状态变化。
type SessionStateChanged struct {
	PeerID string
	Status ContactStatus
	Err    error
}

// LogEvent 是一条供 UI/CLI 展示的运行日志。
//
// 存在理由：需求明确要求"失败必须浮出水面"。
// 有些问题（例如 mDNS 不可用）不属于任何单个联系人的状态，
// 但用户必须知道，否则会一直等一个永远不会来的连接。
type LogEvent struct {
	Level   LogLevel
	Message string
}

// LogLevel 是日志级别。
type LogLevel int

const (
	LogInfo LogLevel = iota
	LogWarn
	LogError
)

func (ContactsChanged) isCoreEvent()     {}
func (MessageReceived) isCoreEvent()     {}
func (MessageSent) isCoreEvent()         {}
func (MessageFailed) isCoreEvent()       {}
func (SessionStateChanged) isCoreEvent() {}
func (LogEvent) isCoreEvent()            {}

// Config 是 core 的构造参数。
type Config struct {
	// Identity 是本机身份（必填）。
	Identity crypto.IdentityProvider

	// Importer 用于解析联系人公钥（必填）。
	Importer crypto.PublicKeyImporter

	// Transport 是已启动的传输层（必填）。
	Transport transport.Transport

	// Contacts 是初始联系人列表（来自持久化层）。
	Contacts []ContactConfig

	// TrustedFingerprints 是**已由用户带外核对过**的指纹集合。
	//
	// 必须显式传入而不是默认全部信任：本项目的产品决策是
	// 拒绝与未知身份通信。若这里为空且 Contacts 非空，
	// 说明调用方没有正确的信任信息，我们会拒绝启动——
	// 宁可启动失败，也不要静默地把"未核对"当成"已核对"。
	TrustedFingerprints []string

	// EventBuffer 是事件 channel 的缓冲大小（0 用默认值）。
	EventBuffer int

	// Logf 是底层组件的日志出口（可选）。
	Logf func(string, ...any)
}

// ContactConfig 是一个联系人的持久化配置。
type ContactConfig struct {
	Name string
	// Fingerprint 是完整指纹（40 位十六进制，大写）。
	Fingerprint string
	// PublicKey 是 armored 公钥。
	PublicKey []byte
}

// DefaultEventBuffer 是事件 channel 的默认缓冲。
//
// 取 256：足以吸收一次突发（例如批量消息），
// 又不至于在 UI 卡死时无限制堆积内存。
const DefaultEventBuffer = 256

// App 是应用状态机。
//
// 并发约定：
//   - 命令方法（SendText 等）可被任意 goroutine 调用，不阻塞。
//   - 状态只由 run() 这个 goroutine 修改。
//   - Snapshot() 通过互斥锁读取，可被 UI 线程调用。
type App struct {
	cfg Config

	// 以下字段由 mu 保护。
	//
	// 为什么用锁而不是"全部走事件循环"：UI 每帧都要读状态
	// （Gio 是 immediate mode，Layout 每帧重跑）。若读取也走
	// channel 往返，UI 会为了画一帧而等待事件循环，直接把帧率
	// 拖垮。写路径走事件循环（保证顺序），读路径走快照（保证不阻塞）。
	mu       sync.RWMutex
	contacts map[string]*contactState
	messages map[string][]Message
	order    []string // 联系人顺序，保证 UI 稳定

	cmds   chan command
	events chan Event
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	// mgr 是会话层管理器。它自己也有事件循环。
	mgr *session.Manager

	// cancelWatch 停止 watchPeers 轮询。
	cancelWatch context.CancelFunc

	// seq 是本地消息序号，用于生成 UI 用的消息 ID。
	seq uint64
}

// contactState 是单个联系人的内部状态。
type contactState struct {
	cfg    ContactConfig
	fp     crypto.Fingerprint
	status ContactStatus
	err    string
	// transportID 是传输层对该对端的标识（发现后才有）。
	transportID transport.PeerID
	// started 记录本机是否已把该联系人注册进会话层。
	started bool
}

// New 构造并启动 App。
//
// 返回的 App 已经在运行：事件循环、会话层订阅、传输层订阅都已就绪。
// 调用方应当立即开始消费 Events()，否则事件会堆积在缓冲里。
func New(cfg Config) (*App, error) {
	if cfg.Identity == nil {
		return nil, errors.New("core: Config.Identity is required")
	}
	if cfg.Importer == nil {
		return nil, errors.New("core: Config.Importer is required")
	}
	if cfg.Transport == nil {
		return nil, errors.New("core: Config.Transport is required")
	}
	if len(cfg.Contacts) > 0 && len(cfg.TrustedFingerprints) == 0 {
		// 拒绝启动而不是猜测。见 Config.TrustedFingerprints 的说明。
		return nil, errors.New("core: contacts provided but TrustedFingerprints is empty; " +
			"refusing to assume unverified contacts are trusted")
	}
	if cfg.EventBuffer <= 0 {
		cfg.EventBuffer = DefaultEventBuffer
	}

	trusted := make(map[string]bool, len(cfg.TrustedFingerprints))
	for _, f := range cfg.TrustedFingerprints {
		trusted[normalizeFP(f)] = true
	}

	a := &App{
		cfg:      cfg,
		contacts: map[string]*contactState{},
		messages: map[string][]Message{},
		cmds:     make(chan command, 64),
		events:   make(chan Event, cfg.EventBuffer),
		closed:   make(chan struct{}),
	}

	// 预装载联系人。公钥在这里就注册进会话层，
	// 否则入站握手无法识别对方（见 session.identifySender）。
	for _, c := range cfg.Contacts {
		fp := crypto.Fingerprint(normalizeFP(c.Fingerprint))
		if !fp.Valid() {
			return nil, fmt.Errorf("core: contact %q has invalid fingerprint %q", c.Name, c.Fingerprint)
		}
		if !trusted[normalizeFP(c.Fingerprint)] {
			// 联系人存在但未被标记为已核对：明确报错。
			return nil, fmt.Errorf("core: contact %q (%s) is not in TrustedFingerprints; "+
				"verify the fingerprint out-of-band first", c.Name, fp.Display())
		}
		if len(c.PublicKey) == 0 {
			return nil, fmt.Errorf("core: contact %q has no public key", c.Name)
		}
		id := fp.String()
		a.contacts[id] = &contactState{cfg: c, fp: fp, status: StatusOffline}
		a.order = append(a.order, id)
	}

	a.mgr = session.New(session.Config{
		Identity:  cfg.Identity,
		Importer:  cfg.Importer,
		Transport: cfg.Transport,
		Logf:      cfg.Logf,
	})

	// 把联系人注册进会话层，使入站握手能被识别。
	for id, cs := range a.contacts {
		a.mgr.AddPeer(session.PeerID(id), session.PeerConfig{
			Fingerprint: cs.fp,
			PublicKey:   cs.cfg.PublicKey,
		})
	}

	a.mgr.Start(context.Background())

	a.wg.Add(2)
	go a.run()
	go a.consumeSessionEvents()

	// 记录发现能力状态——用户必须知道发现是否真的可用，
	// 否则会一直等一个永远不会出现的对端。
	if d, ok := cfg.Transport.(interface{ DiscoveryActive() bool }); ok {
		if !d.DiscoveryActive() {
			msg := "局域网发现不可用：无法自动找到对端。"
			if e, ok := cfg.Transport.(interface{ DiscoveryError() error }); ok {
				if err := d0(e); err != nil {
					msg += " 原因：" + err.Error()
				}
			}
			a.emit(LogEvent{Level: LogWarn, Message: msg})
		}
	}
	// 用轮询替代读 Events()——见 watchPeers 的说明。
	// Events() 属于 session.Manager，core 绝不能碰。
	watchCtx, cancel := context.WithCancel(context.Background())
	a.cancelWatch = cancel
	a.wg.Add(1)
	go a.watchPeers(watchCtx)

	return a, nil
}

func d0(e interface{ DiscoveryError() error }) error { return e.DiscoveryError() }

// normalizeFP 归一化指纹字面量：去掉分隔符并转大写。
func normalizeFP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ":", "")
	return strings.ToUpper(s)
}

// Events 返回事件流。调用方（UI/CLI）应当持续消费。
func (a *App) Events() <-chan Event { return a.events }

// Fingerprint 返回本机指纹，供 UI 展示以便用户带外交换。
func (a *App) Fingerprint() crypto.Fingerprint { return a.cfg.Identity.Fingerprint() }

// Snapshot 返回联系人列表的只读快照。
//
// 非阻塞，可被 UI 线程在每一帧调用。
func (a *App) Snapshot() []Contact {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make([]Contact, 0, len(a.order))
	for _, id := range a.order {
		cs, ok := a.contacts[id]
		if !ok {
			continue
		}
		out = append(out, Contact{
			ID:          id,
			Name:        cs.cfg.Name,
			Fingerprint: cs.fp,
			Status:      cs.status,
			LastError:   cs.err,
		})
	}
	return out
}

// Contact 按 ID 返回单个联系人的快照。
func (a *App) Contact(id string) (Contact, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	cs, ok := a.contacts[id]
	if !ok {
		return Contact{}, false
	}
	return Contact{
		ID:          id,
		Name:        cs.cfg.Name,
		Fingerprint: cs.fp,
		Status:      cs.status,
		LastError:   cs.err,
	}, true
}

// Messages 返回与某个联系人的消息记录快照（按时间正序）。
func (a *App) Messages(peerID string) []Message {
	a.mu.RLock()
	defer a.mu.RUnlock()
	src := a.messages[peerID]
	out := make([]Message, len(src))
	copy(out, src)
	return out
}

// SendText 发送一条文本消息。
//
// 非阻塞：校验后投递到命令 channel 即返回。
//
// 返回错误只表示**无法排队**（未知联系人、无会话、消息过长等），
// 不表示对方已收到。发送结果通过 MessageSent/MessageFailed 事件报告。
func (a *App) SendText(peerID, text string) error {
	if text == "" {
		return ErrEmptyMessage
	}
	if !utf8.ValidString(text) {
		// 必须是合法 UTF-8：对端会按 UTF-8 解析，发过去也是乱码。
		return errors.New("core: message is not valid UTF-8")
	}
	if len(text) > MaxMessageBytes {
		return fmt.Errorf("%w: %d > %d bytes", ErrMessageTooLong, len(text), MaxMessageBytes)
	}

	// 先判断是否已关闭。
	//
	// 顺序很重要：已关闭时"没有会话"之类的判断毫无意义，
	// 返回 ErrNoSession 会让调用方以为重试就能成功。
	select {
	case <-a.closed:
		return ErrClosed
	default:
	}

	a.mu.RLock()
	cs, ok := a.contacts[peerID]
	var status ContactStatus
	if ok {
		status = cs.status
	}
	a.mu.RUnlock()

	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownContact, peerID)
	}
	if status != StatusSecure {
		return fmt.Errorf("%w: %s (status %s)", ErrNoSession, peerID, status)
	}

	return a.post(command{kind: cmdSendText, peer: peerID, text: text})
}

// StartChat 主动发起与某联系人的加密会话。
//
// 若已有会话则幂等成功。典型用法是用户点击联系人时调用。
func (a *App) StartChat(peerID string) error {
	select {
	case <-a.closed:
		return ErrClosed
	default:
	}

	a.mu.RLock()
	_, ok := a.contacts[peerID]
	a.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownContact, peerID)
	}
	return a.post(command{kind: cmdStartChat, peer: peerID})
}

// AddContact 导入一个联系人的公钥。
//
// ⚠️ 不提供"仅添加不核对"的路径。
//
// 这是有意的产品决策（见 docs/threat-model.md）：若允许
// "先添加、以后再核对"，用户会习惯性地跳过核对步骤，
// 从而落入 TOFU 的典型失败模式——攻击者只要抢先建立连接
// 就能长期冒名顶替。因此这里要求调用方**显式声明已核对**。
func (a *App) AddContact(name string, armoredPubKey []byte, fingerprintConfirmed bool) (Contact, error) {
	if !fingerprintConfirmed {
		return Contact{}, errors.New("core: fingerprint must be confirmed out-of-band before adding a contact")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Contact{}, errors.New("core: contact name is required")
	}

	_, fp, err := crypto.ImportPGPPublicKey(armoredPubKey)
	if err != nil {
		return Contact{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	id := fp.String()

	a.mu.RLock()
	_, exists := a.contacts[id]
	a.mu.RUnlock()

	if exists {
		// 已存在：幂等成功，返回当前快照。
		c, _ := a.Contact(id)
		return c, nil
	}

	cfg := ContactConfig{
		Name:        name,
		Fingerprint: id,
		PublicKey:   armoredPubKey,
	}

	// 注册进会话层——必须在投递命令**之前**完成，
	// 否则紧接着到达的入站握手会因"身份不在联系人表"被拒绝。
	a.mgr.AddPeer(session.PeerID(id), session.PeerConfig{
		Fingerprint: fp,
		PublicKey:   armoredPubKey,
	})

	a.mu.Lock()
	a.contacts[id] = &contactState{cfg: cfg, fp: fp, status: StatusOffline}
	a.order = append(a.order, id)
	sort.Strings(a.order)
	a.mu.Unlock()

	a.emit(ContactsChanged{})
	c, _ := a.Contact(id)
	return c, nil
}

// Shutdown 关闭 core，释放所有 goroutine。
// 幂等。关闭后所有命令返回 ErrClosed。
func (a *App) Shutdown() {
	a.once.Do(func() {
		close(a.closed)
		if a.cancelWatch != nil {
			a.cancelWatch()
		}
		if a.mgr != nil {
			a.mgr.Close()
		}
		a.wg.Wait()
		close(a.events)
	})
}

// post 投递一个命令。
func (a *App) post(c command) error {
	select {
	case <-a.closed:
		return ErrClosed
	default:
	}
	select {
	case a.cmds <- c:
		return nil
	case <-a.closed:
		return ErrClosed
	default:
		return errors.New("core: command queue full")
	}
}

// emit 投递一个事件。
//
// 队列满时**丢弃并记录**而不是阻塞：阻塞会卡住 core 的事件循环，
// 进而卡住所有会话。丢弃事件只影响展示，不影响协议正确性——
// 这是两者之间正确的取舍方向。
func (a *App) emit(ev Event) {
	select {
	case <-a.closed:
		return
	default:
	}
	select {
	case a.events <- ev:
	default:
		// 不递归 emit（会再次失败），直接走日志出口。
		if a.cfg.Logf != nil {
			a.cfg.Logf("core: event buffer full, dropped %T", ev)
		}
	}
}

func (a *App) logf(format string, args ...any) {
	if a.cfg.Logf != nil {
		a.cfg.Logf(format, args...)
	}
}
