package ice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	pionice "github.com/pion/ice/v4"
	"github.com/pion/stun/v4"

	"github.com/exeliang/keytalk/internal/transport"
)

// 编译期断言：ice.Transport 满足 transport.Transport 接口。
var _ transport.Transport = (*Transport)(nil)

// 帧头长度：4 字节大端长度前缀。
//
// ice.Conn 是**数据报**语义（Read 返回一个包的边界），而 transport.Transport
// 的 Send/FrameReceived 是"帧"语义。用长度前缀把数据报流重新切成帧，
// 使上层看到的仍是"整帧"，与 lan 实现的行为一致。
const frameLenSize = 4

// maxFrame 与 transport.MaxFrameSize 一致（1 MiB）。
const maxFrame = transport.MaxFrameSize

// Transport 是基于 pion/ice 的公网传输层。
//
// 一次 ICE 会话对应**一个对端**：因为信令是人工交换的
// （offer/answer 一次一个），天然是一对一的。这与 lan 的"多对端自动发现"
// 模型不同，故 Transport 同一时刻只维护一条活动连接。
type Transport struct {
	cfg Config

	agent *pionice.Agent
	conn  *pionice.Conn

	events chan transport.TransportEvent

	mu     sync.RWMutex
	closed bool
	peerID transport.PeerID

	// 本地信令材料。
	localUfrag string
	localPwd   string

	gatherDone chan struct{}
	nat        NatStatus

	// testLoopback 仅供本机多实例测试：让 agent 收集 loopback 候选。
	// 生产路径永远为 false（见 Start 中的 IncludeLoopback）。
	testLoopback bool

	closeOnce sync.Once
	wg        sync.WaitGroup
	cancel    context.CancelFunc
}

// New 创建 ICE 传输层。
func New(cfg Config) *Transport {
	return &Transport{
		cfg:        cfg,
		events:     make(chan transport.TransportEvent, 64),
		gatherDone: make(chan struct{}),
	}
}

// Start 创建 ICE agent 并开始收集候选。
//
// 收集是异步的：调用方通过 LocalSignal 取得带候选的信号文本。
// 若 WebRTC 环境完全不可用（例如 UDP 全被禁），返回错误而不是假装成功。
func (t *Transport) Start(ctx context.Context) error {
	urls, err := t.cfg.allURLs()
	if err != nil {
		return err
	}

	agent, err := pionice.NewAgent(&pionice.AgentConfig{
		Urls:              urls,
		PortMin:           t.cfg.PortMin,
		PortMax:           t.cfg.PortMax,
		NetworkTypes:      toPionNetworks(t.cfg.Networks),
		CandidateTypes:    []pionice.CandidateType{pionice.CandidateTypeHost, pionice.CandidateTypeServerReflexive, pionice.CandidateTypeRelay},
		IncludeLoopback:   len(t.cfg.Networks) == 0 && false, // 生产不用 loopback
		STUNGatherTimeout: ptrDur(6 * time.Second),
	})
	if err != nil {
		return fmt.Errorf("ice: creating agent: %w", err)
	}
	t.agent = agent

	// 记录连接状态，用于上报 ConnOpened / ConnClosed 与维护 NetStatus。
	_ = agent.OnConnectionStateChange(t.onConnState)

	// pion 要求 gather 前注册 OnCandidate，否则 GatherCandidates 直接报错。
	// 我们不需要逐条回调（收集完一次性读 GetLocalCandidates），故留空实现。
	_ = agent.OnCandidate(func(pionice.Candidate) {})

	t.cfg.logf("ice: gathering candidates (stun=%d turn=%d)", len(urls), len(t.cfg.TURNURLs))

	// 立即抓取本地凭据，供信令使用。
	frag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		_ = agent.Close()
		return fmt.Errorf("ice: local credentials: %w", err)
	}
	t.localUfrag, t.localPwd = frag, pwd

	// 收集完成信号：pion 没有直接的完成回调，用轮询 GatheringState。
	t.wg.Add(1)
	go t.watchGathering(ctx, agent)

	if err := agent.GatherCandidates(); err != nil {
		_ = agent.Close()
		return fmt.Errorf("ice: gather: %w", err)
	}
	return nil
}

// watchGathering 等待候选收集结束，记录 NAT 状态并关闭 gatherDone。
func (t *Transport) watchGathering(ctx context.Context, agent *pionice.Agent) {
	defer t.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gs, err := agent.GetGatheringState()
			if err != nil {
				continue
			}
			if gs == pionice.GatheringStateComplete {
				t.recordNatStatus(agent)
				close(t.gatherDone)
				return
			}
		}
	}
}

// recordNatStatus 从本地候选里推断公网可达性，供 UI 如实展示。
func (t *Transport) recordNatStatus(agent *pionice.Agent) {
	cands, err := agent.GetLocalCandidates()
	if err != nil {
		return
	}
	status := NatStatus{
		TurnConfigured: len(t.cfg.TURNURLs) > 0,
	}
	for _, c := range cands {
		switch c.Type() {
		case pionice.CandidateTypeServerReflexive:
			status.STUNReachable = true
			status.PublicAddr = fmt.Sprintf("%s:%d", c.Address(), c.Port())
		case pionice.CandidateTypeRelay:
			// 有 relay 候选说明 TURN 可用。
			status.TurnConfigured = true
		}
	}
	switch {
	case status.STUNReachable:
		status.Detail = "已获得公网映射，可尝试直连"
	case status.TurnConfigured:
		status.Detail = "未能获得公网映射，将通过中继连接"
	default:
		status.Detail = "无法建立公网连接：STUN 不可达且未配置 TURN（仅限同一局域网）"
	}
	t.mu.Lock()
	t.nat = status
	t.mu.Unlock()
	t.cfg.logf("ice: nat status: %+v", status)
}

// LocalSignal 返回本端的信令文本（候选收集完成后才是完整的）。
//
// 若收集尚未完成会等待，超时返回错误——绝不能给用户一份不含候选的
// 残缺信号，那会让对端永远连不上且毫无提示。
func (t *Transport) LocalSignal(timeout time.Duration) (string, error) {
	select {
	case <-t.gatherDone:
	case <-time.After(timeout):
		return "", errors.New("ice: candidate gathering timed out (no network?)")
	}
	cands, err := t.agent.GetLocalCandidates()
	if err != nil {
		return "", err
	}
	strs := make([]string, 0, len(cands))
	for _, c := range cands {
		strs = append(strs, c.Marshal())
	}
	return encodeSignal(NewSignal(t.cfg.Fingerprint, t.localUfrag, t.localPwd, strs))
}

// NatStatus 返回当前 NAT 状况快照。
func (t *Transport) NatStatus() NatStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.nat
}

// Connect 用对端信令建立连接。controlling 决定 ICE 角色
// （发起方为 true）。成功返回后 Events() 会收到 ConnOpened。
func (t *Transport) Connect(ctx context.Context, peerSignal string, controlling bool) error {
	sig, err := DecodeSignal(peerSignal)
	if err != nil {
		return err
	}
	peerID := transport.PeerID(sig.Fingerprint)
	t.mu.Lock()
	t.peerID = peerID
	t.mu.Unlock()

	if err := t.agent.SetRemoteCredentials(sig.Ufrag, sig.Pwd); err != nil {
		return fmt.Errorf("ice: set remote credentials: %w", err)
	}
	for _, raw := range sig.Candidates {
		cand, err := pionice.UnmarshalCandidate(raw)
		if err != nil {
			// 单个坏候选不应导致整体失败——跳过并记录。
			t.cfg.logf("ice: skipping bad remote candidate: %v", err)
			continue
		}
		if err := t.agent.AddRemoteCandidate(cand); err != nil {
			t.cfg.logf("ice: adding remote candidate: %v", err)
		}
	}

	// 上报发现的对端（含地址），供 core 建立 PeerInfo。
	info := transport.PeerInfo{
		ID: peerID, Fingerprint: sig.Fingerprint,
		Metadata: map[string]string{"transport": "ice"},
		LastSeen: time.Now(),
	}
	for _, raw := range sig.Candidates {
		if cand, err := pionice.UnmarshalCandidate(raw); err == nil {
			info.Addrs = append(info.Addrs, &net.TCPAddr{
				IP: net.ParseIP(cand.Address()), Port: cand.Port(),
			})
		}
	}
	t.emit(transport.PeerFound{ID: peerID, Info: info})

	// 建立连接（阻塞直到连通或失败）。
	var conn *pionice.Conn
	if controlling {
		conn, err = t.agent.Dial(ctx, sig.Ufrag, sig.Pwd)
	} else {
		conn, err = t.agent.Accept(ctx, sig.Ufrag, sig.Pwd)
	}
	if err != nil {
		return fmt.Errorf("ice: %s: %w", roleWord(controlling), err)
	}
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	t.emit(transport.ConnOpened{ID: peerID})

	t.wg.Add(1)
	go t.readLoop(conn, peerID)
	return nil
}

// onConnState 把 pion 的连接状态映射为本层的成功/失败。
func (t *Transport) onConnState(state pionice.ConnectionState) {
	switch state {
	case pionice.ConnectionStateFailed:
		t.cfg.logf("ice: connection failed")
		t.mu.RLock()
		pid := t.peerID
		t.mu.RUnlock()
		if pid != "" {
			t.emit(transport.ConnClosed{ID: pid, Err: errors.New("ice: connection failed")})
		}
	}
}

// readLoop 从 ice.Conn 读数据报，按长度前缀还原成帧，上报 FrameReceived。
func (t *Transport) readLoop(conn *pionice.Conn, peerID transport.PeerID) {
	defer t.wg.Done()
	buf := make([]byte, maxFrame+frameLenSize)

	// 用一个重组缓冲应对"一个帧被拆进多个数据报"（UDP 大帧）。
	var acc []byte
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				t.cfg.logf("ice: read: %v", err)
			}
			t.emit(transport.ConnClosed{ID: peerID, Err: err})
			return
		}
		acc = append(acc, buf[:n]...)
		// 尽可能多地从 acc 中切出完整帧。
		for len(acc) >= frameLenSize {
			flen := int(binary.BigEndian.Uint32(acc[:frameLenSize]))
			if flen < 0 || flen > maxFrame {
				t.cfg.logf("ice: absurd frame length %d; closing", flen)
				t.emit(transport.ConnClosed{ID: peerID, Err: errors.New("ice: bad frame length")})
				return
			}
			if len(acc) < frameLenSize+flen {
				break // 帧还没到齐
			}
			frame := make([]byte, flen)
			copy(frame, acc[frameLenSize:frameLenSize+flen])
			acc = acc[frameLenSize+flen:]
			t.emit(transport.FrameReceived{ID: peerID, Frame: frame})
		}
	}
}

// Send 把一个帧发往对端。
func (t *Transport) Send(peerID transport.PeerID, frame []byte) error {
	if len(frame) > maxFrame {
		return transport.ErrFrameTooLarge
	}
	t.mu.RLock()
	conn := t.conn
	curPeer := t.peerID
	closed := t.closed
	t.mu.RUnlock()

	if closed {
		return transport.ErrClosed
	}
	if conn == nil || curPeer != peerID {
		return transport.ErrNotConnected
	}

	// 加长度前缀后一次写出。
	out := make([]byte, frameLenSize+len(frame))
	binary.BigEndian.PutUint32(out[:frameLenSize], uint32(len(frame)))
	copy(out[frameLenSize:], frame)
	if _, err := conn.Write(out); err != nil {
		return fmt.Errorf("ice: write: %w", err)
	}
	return nil
}

// Events 返回事件流（单一消费者，见 transport.Transport 契约）。
func (t *Transport) Events() <-chan transport.TransportEvent { return t.events }

// Peers 返回当前已知对端快照。
func (t *Transport) Peers() []transport.PeerInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.peerID == "" {
		return nil
	}
	return []transport.PeerInfo{{
		ID: t.peerID, Fingerprint: string(t.peerID),
		Metadata: map[string]string{"transport": "ice"}, LastSeen: time.Now(),
	}}
}

// Close 关闭连接与 agent。
func (t *Transport) Close() error {
	var retErr error
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		conn := t.conn
		t.mu.Unlock()

		if t.cancel != nil {
			t.cancel()
		}
		if conn != nil {
			_ = conn.Close()
		}
		if t.agent != nil {
			retErr = t.agent.Close()
		}
		t.wg.Wait()
		close(t.events)
	})
	return retErr
}

func (t *Transport) emit(ev transport.TransportEvent) {
	select {
	case t.events <- ev:
	default:
		// 事件缓冲满：丢弃。传输层不能因此阻塞（见 transport 契约），
		// 但记录日志以便排查。
		t.cfg.logf("ice: event buffer full, dropped %T", ev)
	}
}

func toPionNetworks(ns []NetworkType) []pionice.NetworkType {
	if len(ns) == 0 {
		return []pionice.NetworkType{pionice.NetworkTypeUDP4, pionice.NetworkTypeUDP6}
	}
	out := make([]pionice.NetworkType, 0, len(ns))
	for _, n := range ns {
		switch n {
		case NetworkUDP4:
			out = append(out, pionice.NetworkTypeUDP4)
		case NetworkUDP6:
			out = append(out, pionice.NetworkTypeUDP6)
		case NetworkTCP4:
			out = append(out, pionice.NetworkTypeTCP4)
		case NetworkTCP6:
			out = append(out, pionice.NetworkTypeTCP6)
		}
	}
	return out
}

func roleWord(controlling bool) string {
	if controlling {
		return "dial"
	}
	return "accept"
}

func ptrDur(d time.Duration) *time.Duration { return &d }

// 断言 stun 包被使用（allURLs 依赖它），避免误删 import。
var _ = stun.ParseURI
