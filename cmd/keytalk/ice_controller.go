package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/exeliang/keytalk/internal/transport"
	icetr "github.com/exeliang/keytalk/internal/transport/ice"
	"github.com/exeliang/keytalk/internal/ui"
)

// iceController 实现 ui.PublicNet，把界面的公网操作翻译成 ICE 传输层动作。
//
// # 与 BuildApp 的协作
//
// 关键点：公网连接成功后，必须让随后构建的 core.App 使用**这条 ICE
// 传输层**，而不是默认的局域网传输层。做法是：controller 在 Connect
// 成功后把 ICE Transport 存进 chosen 字段，BuildApp 闭包读取它——
// 有就用 ICE，没有就建 LAN。这样"连接方式"在 BuildApp 之前就已定，
// 不需要在运行期热换传输层（那要重启 session.Manager，风险高）。
type iceController struct {
	cfg         options
	logf        func(string, ...any)
	mu          sync.Mutex
	chosen      transport.Transport
	pending     *icetr.Transport
	summary     ui.NatSummary
	fingerprint string
	started     bool
}

// setFingerprint 记录本机指纹（身份就绪后由 runGUI 设置）。
//
// ICE 信令里带上指纹，方便对端确认"这是谁"——虽然指纹最终仍由
// crypto 握手校验，但信令阶段就要能对上联系人。
func (c *iceController) setFingerprint(fp string) {
	c.mu.Lock()
	c.fingerprint = fp
	c.mu.Unlock()
}

func newICEController(cfg options, logf func(string, ...any)) *iceController {
	return &iceController{cfg: cfg, logf: logf}
}

// chosenTransport 返回用户选择公网后建立的传输层（没有则 nil）。
func (c *iceController) chosenTransport() transport.Transport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.chosen
}

// GenerateOffer 收集本端候选，返回信令文本。
func (c *iceController) GenerateOffer(ctx context.Context) (string, error) {
	tr, err := c.ensureTransport(ctx)
	if err != nil {
		return "", err
	}
	sig, err := tr.LocalSignal(30e9) // 30s
	if err != nil {
		c.setErr(err)
		return "", err
	}
	c.mu.Lock()
	c.summary.PublicAddr = tr.NatStatus().PublicAddr
	c.summary.Detail = tr.NatStatus().Detail
	c.mu.Unlock()
	return sig, nil
}

// Connect 用对端信令建立公网连接。
func (c *iceController) Connect(ctx context.Context, peerSignal string) (ui.NatSummary, error) {
	tr, err := c.ensureTransport(ctx)
	if err != nil {
		c.setErr(err)
		return c.Status(), err
	}
	// ICE 角色：用指纹比较**确定性**地决定谁 controlling，而不是
	// "谁点了建立连接"。群组/会话层也遵循同一约定（较大指纹发起），
	// 两端各自点击"建立连接"时不会角色冲突。
	//
	// 若解析不出对端指纹（理论上不该发生，Connect 内部也会再校验），
	// 退回"本端 controlling"。
	controlling := true
	if sig, derr := icetr.DecodeSignal(peerSignal); derr == nil {
		controlling = c.fingerprint > sig.Fingerprint
	}
	if err := tr.Connect(ctx, peerSignal, controlling); err != nil {
		c.setErr(err)
		return c.Status(), err
	}

	nat := tr.NatStatus()
	path := "直连"
	// 若只有 relay 候选可用，路径是中继。这里用是否有 srflx 近似判断：
	// 没有公网映射（且配了 TURN）说明大概率走中继。
	if !nat.STUNReachable && nat.TurnConfigured {
		path = "中继"
	}

	c.mu.Lock()
	c.chosen = tr
	c.summary = ui.NatSummary{
		Connected:  true,
		PublicAddr: nat.PublicAddr,
		Path:       path,
		Detail:     nat.Detail,
	}
	su := c.summary
	c.mu.Unlock()
	return su, nil
}

// Status 返回当前状态快照。
func (c *iceController) Status() ui.NatSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.summary
}

// ensureTransport 惰性创建并启动 ICE 传输层（一次）。
func (c *iceController) ensureTransport(ctx context.Context) (*icetr.Transport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tr, ok := c.chosen.(*icetr.Transport); ok && tr != nil {
		return tr, nil
	}
	// 复用一个"进行中"的实例：chosen 未定但可能已创建。
	if c.pending != nil {
		return c.pending, nil
	}
	tr := icetr.New(icetr.Config{
		Fingerprint: c.fingerprint,
		STUNURLs:    splitList(c.cfg.stun),
		TURNURLs:    splitList(c.cfg.turn),
		TURNCredentials: icetr.Credentials{
			Username: c.cfg.turnUser,
			Password: c.cfg.turnPass,
		},
		Logf: c.logf,
	})
	if err := tr.Start(ctx); err != nil {
		return nil, err
	}
	c.pending = tr
	return tr, nil
}

func (c *iceController) setErr(err error) {
	c.mu.Lock()
	c.summary.Err = err.Error()
	c.mu.Unlock()
}

var _ ui.PublicNet = (*iceController)(nil)

// errNoPending 表示公网传输层尚未创建。
var errNoPending = fmt.Errorf("ice: no pending transport")

// 编译期守护：unused import 防护。
var _ = fmt.Sprintf

// accept 让本端以"较大指纹胜出"之外的一方接受连接。
//
// 生产界面里两端都会点"建立连接"，角色由 Connect 内的指纹比较决定；
// 本方法仅供测试显式指定 receiving 角色。
func (c *iceController) accept(ctx context.Context, peerSignal string) (ui.NatSummary, error) {
	c.mu.Lock()
	tr := c.pending
	c.mu.Unlock()
	if tr == nil {
		return c.Status(), errNoPending
	}
	if err := tr.Connect(ctx, peerSignal, false); err != nil {
		return c.Status(), err
	}
	c.mu.Lock()
	c.chosen = tr
	c.summary = ui.NatSummary{Connected: true, Detail: "accepted"}
	s := c.summary
	c.mu.Unlock()
	return s, nil
}
