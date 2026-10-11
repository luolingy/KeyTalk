package core

import (
	"context"
	"fmt"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/sas"
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
	// cmdSessionLost 表示会话从"已建立"回落到"未加密"
	// （对端断开、或重新开始握手）。
	//
	// 与 cmdSessionFailed 的区别很重要：失败要显示红色错误，
	// 而"正在握手/刚断开"只是状态回退，不该让用户以为出了问题。
	cmdSessionLost
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

	// sas 是握手记录哈希，用于派生 emoji 二次确认的展示值。
	sas []byte
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

	case cmdSessionLost:
		a.handleSessionLost(c)
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

	// ⚠️ 但对端离线必须**清除**已核对状态与 emoji。
	//
	// 这两者都是"某一次具体会话"的属性。对端已经走了，
	// 下一次连接必然是**新会话**：新密钥、新握手哈希、新 emoji。
	// 若把旧的已核对状态留着，用户曾核对过的"那个人"
	// 会被自动套用到一条全新的链路上——攻击者只要等一次
	// 正常的断线重连，就能继承用户此前给出过的信任。
	//
	// 界面也依赖这一点：不清除的话，一个已经离线甚至已经
	// 换成别人的对端，标签仍会显示"已核实"。
	verificationDropped := cs.verified || cs.emoji != nil
	cs.verified = false
	cs.emoji = nil
	a.mu.Unlock()

	if verificationDropped {
		a.emit(LogEvent{
			Level: LogWarn,
			Message: fmt.Sprintf(
				"%s 已离线；先前的 emoji 核对结果已失效，下次连接需重新核对", name),
		})
	}
	if verificationDropped {
		a.emit(ContactsChanged{})
	}

	if changed {
		a.logf("core: %s went offline", name)
		a.emit(ContactsChanged{})
		a.emit(SessionStateChanged{PeerID: id, Status: StatusOffline})
	}
}

// handleSessionReady 处理握手成功。
func (a *App) handleSessionReady(c command) {
	a.mu.RLock()
	cs, ok := a.contacts[c.peer]
	a.mu.RUnlock()
	if !ok {
		return
	}

	// 派生出本次会话的 emoji 二次确认值。
	//
	// 派生失败**不阻断**会话：加密本身已经可用，emoji 只是
	// 帮助用户确认"公钥属于谁"。但必须明确告知用户
	// 无法核对，而不是悄悄跳过这一步。
	var emojis []sas.Emoji
	if len(c.sas) > 0 {
		var err error
		emojis, err = sas.FromHandshakeHash(c.sas)
		if err != nil {
			a.logf("core: derive SAS for %s failed: %v", c.peer, err)
			a.emit(LogEvent{
				Level: LogWarn,
				Message: fmt.Sprintf(
					"无法为与 %s 的会话生成核对用 emoji：%v；请改用指纹手动核对",
					cs.cfg.Name, err),
			})
		}
	}

	a.setEmoji(c.peer, emojis)
	a.setStatus(c.peer, StatusSecure, "")

	// ⚠️ 这里**刻意**不把 Verified 置为 true。
	//
	// 密码学校验（验签）已经自动完成，但"对方就是你朋友"
	// 这件事只能由人确认。自动置真等于把 TOFU 的结果
	// 伪装成"已核实"，用户会以为自己核对过。
	a.emit(LogEvent{
		Level: LogInfo,
		Message: fmt.Sprintf(
			"与 %s 的加密会话已建立。请与对方核对下方 emoji 后再开始通信。",
			cs.cfg.Name),
	})
}

// handleSessionFailed 处理握手失败。
// handleSessionLost 处理会话回落（断开或重新握手）。
//
// 与 handleSessionFailed 的关键区别：这**不是错误**。
// 对端离线、网络抖动、或双方重新协商都会走到这里。
// 若按失败处理，用户会看到红字错误——但那只是一次正常的状态变化，
// 徒增恐慌。因此这里回到 Online（仍可重连）而不是 Failed。
func (a *App) handleSessionLost(c command) {
	a.mu.RLock()
	cs, ok := a.contacts[c.peer]
	a.mu.RUnlock()
	if !ok {
		return
	}

	// 只有在**曾经**是 Secure 时才需要提示，避免正常握手过程中的
	// Init/SentInit 抖动刷出多余的日志。
	wasSecure := cs.status == StatusSecure

	// 会话没了，之前那份"用户已核对 emoji"的确认也随之失效。
	// 这很重要：不能让一次旧确认把**新的**会话自动标成已验证——
	// 新会话有新密钥，用户必须重新核对。
	a.setVerified(c.peer, false, "")

	a.setStatus(c.peer, StatusOnline, "")

	if wasSecure {
		a.emit(LogEvent{
			Level:   LogWarn,
			Message: fmt.Sprintf("与 %s 的加密会话已结束（连接断开或正在重新握手）", cs.cfg.Name),
		})
	}
}

// stateHint 把会话状态翻译成一句给用户看的话。
func stateHint(s crypto.State) string {
	switch s {
	case crypto.StateInit:
		return "等待握手"
	case crypto.StateSentInit:
		return "正在握手"
	case crypto.StateClosed:
		return "连接已断开"
	default:
		return ""
	}
}

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
// setVerified 清除"用户已核对 emoji"标记。
//
// 用于会话重建：新会话有新密钥、新 emoji，
// 旧的确认不能顺延到新链路上。
func (a *App) setVerified(peerID string, verified bool, _ string) {
	a.mu.Lock()
	cs, ok := a.contacts[peerID]
	if !ok {
		a.mu.Unlock()
		return
	}
	changed := cs.verified != verified
	cs.verified = verified
	if !verified && cs.emoji != nil {
		// 会话没了：清掉 emoji，避免界面上残留一组
		// 已经无效的核对值。
		cs.emoji = nil
		changed = true
	}
	a.mu.Unlock()

	if changed {
		a.emit(ContactsChanged{})
	}
}

// setEmoji 记录本次会话的 SAS 展示值，并**清除**旧的核对状态。
//
// ⚠️ 必须清除：每次会话建立都会产生新的握手哈希，
// 于是 emoji 也会变。若沿用旧确认，用户核对过的那组符号
// 会被自动套用到一条全新的链路上——那正是攻击者想要的结果。
func (a *App) setEmoji(peerID string, emojis []sas.Emoji) {
	a.mu.Lock()
	cs, ok := a.contacts[peerID]
	if !ok {
		a.mu.Unlock()
		return
	}
	wasVerified := cs.verified
	cs.emoji = emojis
	cs.verified = false
	a.mu.Unlock()

	if wasVerified {
		a.emit(LogEvent{
			Level:   LogWarn,
			Message: "会话已重建，先前的 emoji 核对结果已失效，请重新核对",
		})
	}
	a.emit(ContactsChanged{})
}

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
				// 把握手记录哈希带过去，由事件循环派生出
				// emoji 二次确认的展示值。
				a.post(command{
					kind: cmdSessionReady,
					peer: string(e.Peer),
					sas:  e.SAS,
				})

			case session.HandshakeFailed:
				a.post(command{kind: cmdSessionFailed, peer: string(e.Peer), err: e.Err})

			case session.StateChanged:
				// ⚠️ 这里**必须**按状态分派，不能一律当作"已就绪"。
				//
				// StateChanged 会带着多种状态发出：StateInit、
				// StateSentInit、StateEstablished、StateClosed。
				// 早期版本把它们全部映射成 cmdSessionReady，
				// 于是：
				//   · 等待握手的 Init 被显示成"已加密"；
				//   · 更糟的是 StateClosed（连接已断开、会话已销毁）
				//     也被显示成"已加密"。
				// 结果就是用户看到的"一边显示已连接、另一边还在握手"
				// 以及"明明断了却还显示加密"。
				switch e.State {
				case crypto.StateEstablished:
					a.post(command{kind: cmdSessionReady, peer: string(e.Peer)})
				case crypto.StateClosed, crypto.StateInit, crypto.StateSentInit:
					// 回到"在线但未加密"。注意 StateInit 与
					// StateSentInit 表示**正在**握手，不是失败，
					// 因此走 Online 而不是 Failed —— 否则一次正常的
					// 重连会闪出红色错误。
					a.post(command{
						kind: cmdSessionLost,
						peer: string(e.Peer),
						text: stateHint(e.State),
					})
				}

			case session.Message:
				msg := a.recordMessage(string(e.Peer), e.Plaintext.Text, false)
				a.emit(MessageReceived{Message: msg})
			}
		}
	}
}

// isSelfPeer 报告一个传输层对端是否就是本机。
//
// 为什么需要这个判断：mDNS 的广播会回到本机（尤其在启用了
// loopback 发现、或机器只有一块网卡时），于是每个实例都会
// "发现"自己。若不排除，用户会在日志里看到一条
// "discovered peer <自己的指纹> is not a known contact"，
// 既困惑又像是安全问题（有陌生设备在连我？）。
//
// 判定依据是指纹——这是**身份**，与 IP 无关。刻意不用 IP：
// 同一台机器可以有多个地址，而"自己"是由密钥定义的。
func (a *App) isSelfPeer(id transport.PeerID) bool {
	own := a.cfg.Identity.Fingerprint().String()
	if string(id) == own {
		return true
	}
	// 传输层 ID 在握手前可能是 "inbound:<地址>" 这类临时值；
	// 那些不是身份，不在这里判断（也无法判断）。
	return false
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
				//
				// ⚠️ 必须过滤掉**自己**。
				// mDNS 会把本机的广播也投递回来（loopback 或
				// 同一网卡的回环），于是每个实例都会发现"自己"
				// 并报告为陌生联系人。虽然随后会被忽略（不是已知
				// 联系人），但那两条日志是纯粹的噪声，也会让用户
				// 以为有陌生设备在连接。
				if a.isSelfPeer(transport.PeerID(p.ID)) {
					continue
				}
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
