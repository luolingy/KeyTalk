// Package transport 定义传输层接口与共享类型。
//
// 硬性约束（见 docs/architecture.md §1.1）：
//
//   - 本包**不得** import crypto。
//     传输层对明文帧一无所知，只搬运不透明的 []byte。
//     E2EE 是应用层（core）的事——插入中继时，我们不希望传输层
//     有任何机会接触密钥材料。
//
//   - 本包只依赖标准库，保证可独立单测。
//
// 首期实现：transport/lan（mDNS + TCP）。
// 未来实现：transport/ice（pion/webrtc）、transport/libp2p，
// 只要满足同一接口，core 无感。
package transport

import (
	"context"
	"errors"
	"net"
	"time"
)

// PeerID 是传输层的对端标识，**仅用于路由**。
//
// 它不是身份。身份由应用层的 OpenPGP 指纹确定；
// PeerID 可以伪造，因此上层**绝不可**用它做认证决策。
//
// 局域网场景的形态：局域网内同一指纹理论上只应有一个实例，
// 但多网卡/多地址会使同一对端出现多个端点，故用地址区分。
type PeerID string

// PeerInfo 描述一个已发现的对端。
type PeerInfo struct {
	// ID 是传输层路由标识。
	ID PeerID

	// Fingerprint 是 mDNS TXT 中**声明**的指纹。
	//
	// ⚠️ 安全提示：该值来自未认证的局域网广播，**可被任意伪造**。
	// 它的唯一用途是"决定是否值得尝试连接"，**绝不能**用于认证。
	// 真正的身份校验发生在 crypto 握手（recipient_fp / 签名者比对）。
	// 见 docs/threat-model.md §4.1。
	Fingerprint string

	// Addrs 是该对端的候选地址。首期为 TCP 地址；
	// 公网实现会填入多个 ICE 候选地址（见 nat-traversal.md §10.3）。
	Addrs []net.Addr

	// Metadata 是 mDNS TXT 记录中的其他字段（协议版本等）。
	Metadata map[string]string

	// LastSeen 是该对端最近一次被发现的时刻。
	LastSeen time.Time
}

// TransportEvent 是传输层上报给 core 的事件。
//
// 用封闭接口（未导出方法）而非 any，确保只有本包能构造事件——
// 这样 core 的 switch 可以穷尽，新增事件类型时编译器会提示遗漏。
type TransportEvent interface{ isTransportEvent() }

// PeerFound 表示发现了对端（可能是首次，也可能是地址变化后的更新）。
type PeerFound struct {
	ID   PeerID
	Info PeerInfo
}

// PeerLost 表示对端从发现列表中消失（mDNS TTL 过期）。
//
// 注意：对端消失**不等于**连接断开——已建立的 TCP 连接可能仍然可用。
// 上层应分别对待这两个信号。
type PeerLost struct {
	ID PeerID
}

// ConnOpened 表示与对端的连接已建立，可以开始发送帧。
type ConnOpened struct {
	ID PeerID
}

// ConnClosed 表示连接已关闭。
//
// Err 为 nil 表示正常关闭（对端发送了 FIN 或本地主动关闭）；
// 非 nil 表示异常断开（网络问题、对端崩溃）。
// 上层据此决定是否重连，且应向用户显示"连接中断"而非静默丢弃。
type ConnClosed struct {
	ID  PeerID
	Err error
}

// FrameReceived 表示收到一个完整的帧。
//
// Frame 是**不透明字节**：传输层不解析它，也不知道内容是否加密。
// 上层（core）负责把它交给 crypto 解密。
type FrameReceived struct {
	ID    PeerID
	Frame []byte
}

func (PeerFound) isTransportEvent()     {}
func (PeerLost) isTransportEvent()      {}
func (ConnOpened) isTransportEvent()    {}
func (ConnClosed) isTransportEvent()    {}
func (FrameReceived) isTransportEvent() {}

// Transport 是传输层接口。
//
// # Events() 的所有权规则（极其重要）
//
// **Events() 有且只能有一个消费者。**
//
// 该 channel 不做扇出：每个事件只会被某个 goroutine 读到一次。
// 因此第二个读者**不会**看到"相同的事件流"，而是与第一个读者
// **随机瓜分**事件——各拿到大约一半。症状极其具有误导性：
// 传输层日志显示"已读取 192 字节"，而会话层却什么都没收到，
// 看起来完全像底层丢包，实际是上层在互相偷事件。
//
// 本项目在开发中**两次**踩到同一个坑（一次在 cmd/keytalk，
// 一次在 internal/core），因此这条规则写进接口契约：
//
//   - `session.Manager` 是 Events() 的持有者，负责驱动协议状态机。
//   - 其他任何组件（core、UI、CLI）需要感知对端状态时，
//     必须改用 **Peers() 快照轮询**，而**不是**去读 Events()。
//   - 若确实需要第二路事件流，必须在实现内做显式扇出，
//     而不是让多个调用方各自去读同一个 channel。
//
// 实现必须保证：
//
//   - Events() 返回的 channel 由实现方关闭（在 Close 之后），
//     且**绝不**在持锁状态下发送，避免与 Close 死锁。
//   - Peers() 是并发安全的，且不消费任何事件——它只是读快照。
//   - Send 是并发安全的。
//   - Send 在未连接时返回 ErrNotConnected（可重试语义），
//     而不是阻塞或静默丢弃。
//   - Close 是幂等的。
type Transport interface {
	// Start 启动发现与监听。ctx 取消时应停止发现，但不关闭已有连接。
	Start(ctx context.Context) error

	// Send 向对端发送一个帧。
	//
	// 错误语义（见 docs/transport-lan.md §8）：
	//   - ErrNotConnected：暂时不可达，上层可重试
	//   - ErrPeerUnknown：对端从未被发现，通常表示配置问题
	//   - 其他：底层网络错误
	Send(peerID PeerID, frame []byte) error

	// Events 返回事件流。
	//
	// ⚠️ 只允许有一个消费者（见上文的契约说明）。
	// 需要额外观察对端状态的组件请使用 Peers()。
	Events() <-chan TransportEvent

	// Peers 返回当前已知对端的快照。
	//
	// 这是 Events() 之外**唯一**受支持的观察方式：
	// 它不消费事件，因此可以与 Events() 的持有者并存。
	// 返回的切片是拷贝，调用方可安全持有与修改。
	//
	// 典型用法是按固定间隔轮询，据此推导"谁在线"，
	// 而不是去解析 PeerFound/PeerLost 事件流。
	Peers() []PeerInfo

	// Close 关闭传输层，释放监听端口与发现资源。
	Close() error
}

// 传输层错误。
//
// 用哨兵错误而非字符串匹配，让上层能区分"可重试"与"永久失败"——
// 这个区分在公网场景尤其重要（见 nat-traversal.md §8.3）。
var (
	// ErrNotConnected 表示当前没有到该对端的连接，但可以重试。
	ErrNotConnected = errors.New("transport: peer not connected")

	// ErrPeerUnknown 表示该 peerID 从未被发现过。
	ErrPeerUnknown = errors.New("transport: unknown peer")

	// ErrClosed 表示传输层已关闭。
	ErrClosed = errors.New("transport: closed")

	// ErrFrameTooLarge 表示帧超过传输层允许的上限。
	ErrFrameTooLarge = errors.New("transport: frame too large")

	// ErrAlreadyStarted 表示 Start 被重复调用。
	ErrAlreadyStarted = errors.New("transport: already started")
)

// 传输层的容量与超时参数。
//
// 这些对外可见，因为具体实现（lan、未来的 ice）需要用它们，
// 且上层可能需要据此调整行为（例如判断"队列满是暂时的还是持续的"）。
const (
	// MaxFrameSize 是单个帧的字节上限。
	//
	// 与 wire.MaxFrame 保持一致（1 MiB）。传输层独立定义此常量而非
	// import wire，以维持"传输层不依赖任何内部包"的解耦约束。
	// 两者不一致会导致静默截断，故在测试中有断言守护。
	MaxFrameSize = 1 << 20

	// DefaultSendQueue 是每个连接的发送队列长度。
	//
	// 队列存在的意义：区分"网络慢"与"对端不读"。
	// 队列满时 Send 返回错误而非无限缓冲——无限缓冲会把内存耗尽，
	// 且掩盖对端停滞的事实。
	DefaultSendQueue = 64

	// DefaultHeartbeatInterval 是心跳间隔。
	DefaultHeartbeatInterval = 15 * time.Second

	// DefaultHeartbeatTimeout 是心跳超时，超过则判定连接死亡。
	//
	// 同时用作读/写 deadline：任何一次成功的读写都会刷新它，
	// 因此正常情况下不会触发；只有真正静默的连接才会超时。
	DefaultHeartbeatTimeout = 45 * time.Second
)
