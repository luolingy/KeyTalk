package core

import (
	"context"
	"fmt"
	"time"

	"github.com/exeliang/keytalk/internal/session"
	"github.com/exeliang/keytalk/internal/transport"
)

// commandKind 是内部命令类型。
type commandKind int

const (
	cmdSendText commandKind = iota
	cmdStartChat
	cmdPeerFound
	cmdPeerLost
	cmdSessionReady
	cmdSessionFailed
)

// command 是一条投递给事件循环的命令。
//
// 所有状态变更都必须经由命令进入 run()，从而保证：
//   - 状态只被一个 goroutine 修改，无数据竞争；
//   - 处理的先后顺序与到达顺序一致（channel 保证 FIFO）。
type command struct {
	kind        commandKind
	peer        string
	text        string
	transportID transport.PeerID
	err         error
}

// run 是 core 的事件循环：唯一修改状态的地方。
func (a *App) run() {
	defer a.wg.Done()

	for {
		select {
		case <-a.closed:
			return
		case c := <-a.cmds:
			a.handle(c)
		}
	}
}

func (a *App) handle(c command) {
	switch c.kind {
	case cmdSendText:
		a.handleSendText(c)

	case cmdStartChat:
		a.handleStartChat(c)

	case cmdPeerFound:
		a.handlePeerFound(c)

	case cmdPeerLost:
		a.handlePeerLost(c)

	case cmdSessionReady:
		a.handleSessionReady(c)

	case cmdSessionFailed:
		a.handleSessionFailed(c)
	}
}

// handleSendText 处理发送命令。
func (a *App) handleSendText(c command) {
	// 状态可能在排队期间变化（例如会话断开），因此这里**重新检查**。
	// 只在 SendText 入口检查是不够的：那之间存在一个窗口。
	a.mu.RLock()
	cs, ok := a.contacts[c.peer]
	var status ContactStatus
	if ok {
		status = cs.status
	}
	a.mu.RUnlock()

	if !ok {
		a.emit(MessageFailed{PeerID: c.peer, Text: c.text,
			Err: fmt.Errorf("%w: %s", ErrUnknownContact, c.peer)})
		return
	}
	if status != StatusSecure {
		a.emit(MessageFailed{PeerID: c.peer, Text: c.text,
			Err: fmt.Errorf("%w: %s", ErrNoSession, c.peer)})
		return
	}

	msg := a.recordMessage(c.peer, c.text, true)

	// 真正发送。session.Manager 内部也是投递到它自己的事件循环，
	// 因此这里不会长时间阻塞。
	if err := a.mgr.SendText(session.PeerID(c.peer), c.text); err != nil {
		a.markMessageFailed(msg.ID)
		a.emit(MessageFailed{PeerID: c.peer, Text: c.text, Err: err})
		return
	}

	// 标记为已发出（清除 Pending）。
	a.markMessageSent(msg.ID)
	msg.Pending = false
	a.emit(MessageSent{Message: msg})
}

// handleStartChat 处理主动发起会话。
func (a *App) handleStartChat(c command) {
	a.mu.RLock()
	cs, ok := a.contacts[c.peer]
	a.mu.RUnlock()
	if !ok {
		a.emit(LogEvent{Level: LogWarn, Message: "无法发起会话：未知联系人 " + c.peer})
		return
	}

	if a.mgr.HasSession(session.PeerID(c.peer)) {
		a.setStatus(c.peer, StatusSecure, "")
		return
	}

	// 确保会话层知道"这个身份对应哪条传输连接"。
	//
	// 正常情况下这一步由 handlePeerFound 完成（收到发现事件时绑定）。
	// 但用户可能在**发现事件到达之前**就点击联系人发起聊天，
	// 或者传输层实现根本不产生发现事件（例如测试里直接注入地址、
	// 或未来用 ICE 由信令直接给出候选地址）。
	// 那种情况下若不在这里补绑，StartHandshake 会因为
	// "unknown peer" 直接失败——用户看到的是"点了没反应"。
	//
	// 绑定是幂等的，且传输层 ID 在本项目里就等于身份指纹
	// （见 transport/lan：peerID = 完整指纹），因此可以安全地补绑。
	a.mgr.SetTransportPeer(session.PeerID(c.peer), transport.PeerID(c.peer))

	// ⚠️ 主动发起也必须遵守**同一条角色规则**。
	//
	// 这里曾经绕过角色判断，导致一个真实可复现的竞态：
	// 用户点击联系人的时机可能早于发现事件到达，
	// 于是 StartChat 无条件发起，而随后 handlePeerFound 又按
	// 角色规则决定"本方不该发起"。两侧都发了 KEM_INIT →
	// 对方作为 responder 完成握手，而本方的 initiator 分支
	// 因为 pending 被顶掉而永远等不到 ACK，最终超时。
	//
	// 角色规则本身是对的，问题在于有两处入口、只在一处执行了它。
	// 现在两处都执行，且规则来自同一个函数，不会再分叉。
	if !a.shouldInitiate(c.peer) {
		// 本方是指纹较小的一方：不主动拨号。
		//
		// 但仍然把状态标记为"在线"——用户点了联系人之后
		// 应当看到"等待对方发起"，而不是"什么都没发生"。
		a.setStatus(c.peer, StatusOnline, "")
		a.emit(LogEvent{
			Level:   LogInfo,
			Message: fmt.Sprintf("等待 %s 发起加密握手…", cs.cfg.Name),
		})
		return
	}

	if err := a.mgr.StartHandshake(session.PeerID(c.peer)); err != nil {
		// "握手已在进行中"不是错误——可能是 mDNS 地址更新触发的重复调用。
		if isHandshakeInProgress(err) {
			a.logf("core: handshake with %s already in progress", cs.cfg.Name)
			return
		}
		a.setStatus(c.peer, StatusFailed, err.Error())
		a.emit(SessionStateChanged{PeerID: c.peer, Status: StatusFailed, Err: err})
		a.emit(LogEvent{
			Level:   LogError,
			Message: fmt.Sprintf("与 %s 握手失败：%v", cs.cfg.Name, err),
		})
		return
	}

	a.emit(LogEvent{
		Level:   LogInfo,
		Message: fmt.Sprintf("正在与 %s 握手…", cs.cfg.Name),
	})
}

// handlePeerFound 处理传输层发现。
//
// ⚠️ 只处理**联系人表里**的对端。
//
// 局域网里任何人都能广播 mDNS 记录（包括伪造指纹），
// 因此发现事件只是"有个自称是 X 的人出现"，**不是身份证明**。
// 身份在这里仅用于匹配本地联系人表；真正的验证发生在握手之后。
func (a *App) handlePeerFound(c command) {
	a.mu.Lock()
	var cs *contactState
	for _, s := range a.contacts {
		// 传输层键可能等于完整指纹；也允许前缀匹配（见 transport/lan）。
		if string(c.transportID) == s.fp.String() {
			cs = s
			break
		}
	}
	if cs == nil {
		a.mu.Unlock()
		// 传输层也会把"入站连接"以其临时 ID（inbound:<地址>）列入 Peers，
		// 那不是身份、也不该匹配任何联系人。这类条目在握手完成后会被
		// AdoptConnection 改名为真实指纹，因此这里只记录、不告警。
		a.logf("core: discovered peer %s is not a known contact (ignored)", c.transportID)
		return
	}

	alreadyOnline := cs.status == StatusOnline || cs.status == StatusSecure
	cs.transportID = c.transportID
	if !alreadyOnline {
		cs.status = StatusOnline
		cs.err = ""
	}
	id := cs.fp.String()
	name := cs.cfg.Name
	status := cs.status
	a.mu.Unlock()

	// 把传输层 ID 关联到会话层，使后续路由能找到对端。
	a.mgr.SetTransportPeer(session.PeerID(id), c.transportID)

	if !alreadyOnline {
		a.logf("core: %s is online", name)
		a.emit(ContactsChanged{})
		a.emit(SessionStateChanged{PeerID: id, Status: status})
	}

	// 已有会话则不必再握手。
	if a.mgr.HasSession(session.PeerID(id)) {
		a.setStatus(id, StatusSecure, "")
		return
	}

	// 分角色发起握手，避免双方同时拨号（见 docs/implementation-notes.md §4.6）。
	//
	// 规则与传输层、会话层保持一致：指纹较大的一方主动连接。
	if !a.shouldInitiate(id) {
		a.logf("core: waiting for %s to initiate (we have the smaller fingerprint: own=%s peer=%s)",
			name, a.cfg.Identity.Fingerprint().String()[:8], id[:8])
		return
	}
	a.logf("core: we initiate (larger fingerprint: own=%s peer=%s)",
		a.cfg.Identity.Fingerprint().String()[:8], id[:8])
	a.post(command{kind: cmdStartChat, peer: id})
}

// handlePeerLost 处理对端离线。
func (a *App) handlePeerLost(c command) {
	a.mu.Lock()
	var cs *contactState
	for _, s := range a.contacts {
		if string(c.transportID) == s.fp.String() {
			cs = s
			break
		}
	}
	if cs == nil {
		a.mu.Unlock()
		return
	}
	id := cs.fp.String()
	name := cs.cfg.Name
	changed := cs.status != StatusOffline
	// 离线只影响"可否直接连接"的展示。
	// 已有会话不在这里销毁——会话的生命周期由会话层管理，
	// 传输层短暂抖动不应让用户看到"会话断了"。
	if changed {
		cs.status = StatusOffline
	}
	a.mu.Unlock()

	if changed {
		a.logf("core: %s went offline", name)
		a.emit(ContactsChanged{})
		a.emit(SessionStateChanged{PeerID: id, Status: StatusOffline})
	}
}

// handleSessionReady 处理握手成功。
func (a *App) handleSessionReady(c command) {
	a.setStatus(c.peer, StatusSecure, "")

	a.mu.RLock()
	cs, ok := a.contacts[c.peer]
	a.mu.RUnlock()
	if !ok {
		return
	}

	a.emit(LogEvent{
		Level:   LogInfo,
		Message: fmt.Sprintf("与 %s 的端到端加密会话已建立（身份已校验）", cs.cfg.Name),
	})
}

// handleSessionFailed 处理握手失败。
func (a *App) handleSessionFailed(c command) {
	errStr := ""
	if c.err != nil {
		errStr = c.err.Error()
	}
	a.setStatus(c.peer, StatusFailed, errStr)

	a.mu.RLock()
	cs, ok := a.contacts[c.peer]
	a.mu.RUnlock()

	name := c.peer
	if ok {
		name = cs.cfg.Name
	}

	a.emit(LogEvent{
		Level:   LogError,
		Message: fmt.Sprintf("与 %s 的会话失败：%v", name, c.err),
	})
}

// setStatus 更新联系人状态并广播变化。
func (a *App) setStatus(peerID string, status ContactStatus, errStr string) {
	a.mu.Lock()
	cs, ok := a.contacts[peerID]
	if !ok {
		a.mu.Unlock()
		if a.cfg.Logf != nil {
			a.cfg.Logf("core: setStatus(%q, %v) ignored: not a known contact", peerID, status)
		}
		return
	}
	changed := cs.status != status || cs.err != errStr
	cs.status = status
	cs.err = errStr
	a.mu.Unlock()

	if changed {
		a.emit(ContactsChanged{})
		a.emit(SessionStateChanged{PeerID: peerID, Status: status})
	}
}

// shouldInitiate 决定本机是否应主动向该对端发起握手。
//
// 与会话层的 glare 规则、传输层的拨号规则保持**同一方向**：
// 指纹较大的一方主动。三层用同一种比较，避免出现
// "传输层认为该连、会话层认为该让"的错位死锁。
func (a *App) shouldInitiate(peerID string) bool {
	own := a.cfg.Identity.Fingerprint().String()
	return own > peerID
}

// recordMessage 记录一条消息，返回其快照。
func (a *App) recordMessage(peerID, text string, outgoing bool) Message {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.seq++
	msg := Message{
		ID:       fmt.Sprintf("m%d", a.seq),
		PeerID:   peerID,
		Outgoing: outgoing,
		Text:     text,
		SentAt:   time.Now(),
		Pending:  outgoing,
	}
	a.messages[peerID] = append(a.messages[peerID], msg)
	return msg
}

// markMessageSent 清除消息的 Pending 标记。
func (a *App) markMessageSent(id string) { a.updatePending(id, false) }

// markMessageFailed 保留消息但标记为不再重试。
//
// 不删除：用户需要看到"这条没发出去"，静默丢弃是最糟的选择。
func (a *App) markMessageFailed(id string) { a.updatePending(id, false) }

func (a *App) updatePending(id string, pending bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, list := range a.messages {
		for i := range list {
			if list[i].ID == id {
				list[i].Pending = pending
				return
			}
		}
	}
}

// consumeSessionEvents 把会话层事件转成 core 命令/事件。
func (a *App) consumeSessionEvents() {
	defer a.wg.Done()

	evs := a.mgr.Events()
	for {
		select {
		case <-a.closed:
			return
		case ev, ok := <-evs:
			if !ok {
				return
			}
			switch e := ev.(type) {
			case session.HandshakeDone:
				a.post(command{kind: cmdSessionReady, peer: string(e.Peer)})

			case session.HandshakeFailed:
				a.post(command{kind: cmdSessionFailed, peer: string(e.Peer), err: e.Err})

			case session.StateChanged:
				a.post(command{kind: cmdSessionReady, peer: string(e.Peer)})

			case session.Message:
				msg := a.recordMessage(string(e.Peer), e.Plaintext.Text, false)
				a.emit(MessageReceived{Message: msg})
			}
		}
	}
}

// watchPeers 轮询传输层的对端快照，推导"谁在线"。
//
// ⚠️ 本函数**故意不**去读 transport.Events()。
//
// 为什么：Events() 的 channel 不做扇出，每个事件只会被某一个
// goroutine 读到。`session.Manager` 已经持有它来驱动协议状态机；
// 如果 core 再起一个 goroutine 去读同一个 channel，两者会**随机瓜分**
// 事件，各拿到大约一半。症状极难定位——传输层日志明明写着
// "已读取 192 字节"，会话层却什么都没收到，看起来就像底层丢包。
//
// 这个错误在本项目中出现过**两次**（先是 cmd/keytalk，后来是我在
// core 里又写了一遍）。因此这里不再读事件流，而是改用 Peers() 快照：
// 它不消费任何事件，可以与 Events() 的持有者安全并存。
//
// 代价是发现延迟最多一个 tick（500ms）。对于"对端出现在局域网上"
// 这类状态，这个延迟完全不可感知；而它换来的是协议层再也不会被偷帧。
func (a *App) watchPeers(ctx context.Context) {
	defer a.wg.Done()

	const tick = 500 * time.Millisecond
	// 记录上一次上报的在线集合，只在变化时投递命令，
	// 避免每 500ms 就给事件循环塞一批无意义的命令。
	prev := map[string]bool{}

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-a.closed:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := a.cfg.Transport.Peers()

			cur := make(map[string]bool, len(snap))
			for _, p := range snap {
				// 传输层 ID 在本项目中就是指纹，但也可能是
				// "inbound:<地址>" 这样的临时值——后者不可作为身份，
				// 只在握手完成后由 AdoptConnection 改名。
				cur[string(p.ID)] = true
			}

			for id := range cur {
				if !prev[id] {
					a.post(command{kind: cmdPeerFound, transportID: transport.PeerID(id)})
				}
			}
			for id := range prev {
				if !cur[id] {
					a.post(command{kind: cmdPeerLost, transportID: transport.PeerID(id)})
				}
			}
			prev = cur
		}
	}
}

// isHandshakeInProgress 判断错误是否为"握手已在进行中"。
//
// 单独抽出来是为了让这个判断只写一次：它出现在多个调用点，
// 而"该错误应被静默接受"这一语义容易被误改。
func isHandshakeInProgress(err error) bool {
	return err != nil && err.Error() != "" &&
		containsAny(err.Error(), "handshake in progress", "already in progress")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) <= len(s) && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
