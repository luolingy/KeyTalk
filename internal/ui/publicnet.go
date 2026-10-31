package ui

import "context"

// PublicNet 让界面操作"公网（ICE）连接"，而无需了解 transport 实现。
//
// 为什么做成接口由 cmd 实现：只有 cmd 知道具体的传输层与配置
// （STUN/TURN、ICE agent）。ui 只负责呈现与收集输入。
//
// 生命周期约定：
//   - GenerateOffer 启动 ICE 收集并返回本端信令；
//   - Connect 用对端信令建立连接，成功后 cmd 会把它设为接下来
//     构建 App 时使用的传输层；
//   - NatSummary 返回当前 NAT/路径状况供展示。
//
// 三者都可能在界面 goroutine 上调用，实现方必须自己保证并发安全，
// 且 Connect/GenerateOffer 可能阻塞（ICE 收集与连通性检查需要时间），
// 调用方会把它们放到后台 goroutine 里跑。
type PublicNet interface {
	// GenerateOffer 收集本端候选并返回可发给对方的信令文本。
	GenerateOffer(ctx context.Context) (string, error)
	// Connect 用对端信令建立公网连接。
	Connect(ctx context.Context, peerSignal string) (NatSummary, error)
	// Status 返回当前状态快照（不会阻塞）。
	Status() NatSummary
}

// NatSummary 是公网连接状况的展示摘要。
type NatSummary struct {
	// Connected 表示公网连接是否已建立。
	Connected bool
	// PublicAddr 是 STUN 反射到的公网地址（可为空）。
	PublicAddr string
	// Path 是"直连"或"中继"（仅在已连接时有意义）。
	Path string
	// Detail 是一句人话说明。
	Detail string
	// Err 非空表示最近一次操作失败的原因。
	Err string
}
