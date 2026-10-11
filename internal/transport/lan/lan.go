package lan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/exeliang/keytalk/internal/transport"
)

// 编译期断言：lan.Transport 必须满足 transport.Transport 接口。
var _ transport.Transport = (*Transport)(nil)

// compile-time 守护：传输层帧上限不得超过 wire 的 1 MiB 契约。
//
// 这里用常量表达式而非 import wire，以维持解耦约束；
// 若哪天两个常量不一致，测试会失败（见 TestMaxFrameSizeContract）。
const _ = uint(transport.MaxFrameSize - (1 << 20))

// Config 是 LAN 传输层的配置。
type Config struct {
	// Fingerprint 是本机的完整 OpenPGP 指纹（十六进制大写）。
	//
	// ⚠️ 它会被广播到局域网，**任何人**都能看到。
	// 这是可接受的权衡（见 docs/threat-model.md §4.2）：
	// 局域网上"谁在用 KeyTalk"本来就可被观察；
	// 而指纹本身不是秘密——它不是密钥，只是公钥的摘要。
	// 但它确实是**元数据**，用户应知情。
	Fingerprint string

	// DisplayName 是广播的显示名（用户自定义）。
	DisplayName string

	// ListenPort 是 TCP 监听端口。0 表示由系统分配。
	//
	// 注意：mDNS 广播的是**实际**端口，因此用 0 也没问题。
	ListenPort int

	// ProtocolVersion 是广播的协议版本，用于未来兼容性判断。
	ProtocolVersion string

	// AnnounceInterval 是周期宣告间隔。0 表示用默认值。
	AnnounceInterval time.Duration

	// IncludeLoopback 决定是否在 loopback 接口上也进行发现。
	//
	// 默认 false（生产环境）。设 true 供**本机多实例测试**使用——
	// 这正是本方案 B（命令行双实例）所依赖的开关。
	IncludeLoopback bool

	// Logf 是可选的日志回调。nil 表示不记录。
	//
	// 传输层不直接依赖日志库，由调用方注入，
	// 这样测试可以捕获日志、UI 可以显示连接状态。
	Logf func(format string, args ...any)
}

func (c *Config) announceInterval() time.Duration {
	if c.AnnounceInterval > 0 {
		return c.AnnounceInterval
	}
	return 30 * time.Second
}

func (c *Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Transport 是 LAN 传输层实现（mDNS 发现 + TCP）。
// peerEmitInterval 是同一对端地址更新时上报 PeerFound 的最小间隔。
//
// 存在的理由：无节流的地址更新会引发连接风暴（见 handleRecord）。
// 500ms 足以把一次宣告在所有接口上的到达合并起来，
// 又快到用户察觉不到延迟。
const peerEmitInterval = 500 * time.Millisecond

type Transport struct {
	cfg Config

	ln     net.Listener
	mdns   *mdnsConn
	events chan transport.TransportEvent

	mu        sync.RWMutex
	peers     map[transport.PeerID]*transport.PeerInfo
	conns     map[transport.PeerID]*conn
	byAddr    map[string]transport.PeerID // "ip:port" -> peerID
	selfAddrs map[string]bool             // 本机地址，用于过滤自身

	startOnce sync.Once
	started   bool

	// lastPeerEmit 记录每个对端上次上报 PeerFound 的时间，用于限流。
	// 见 handleRecord 中的说明：不限流会导致连接风暴。
	lastPeerEmit map[transport.PeerID]time.Time

	// discoveryActive 记录 mDNS 是否真的启用了。
	// 供上层如实显示状态——绝不能报告一个并未运行的功能。
	discoveryActive bool
	discoveryErr    error
	closeOnce       sync.Once
	closed          chan struct{}
	wg              sync.WaitGroup

	// ctx 用于停止发现循环。
	ctx    context.Context
	cancel context.CancelFunc
}

// New 创建一个 LAN 传输层。
func New(cfg Config) *Transport {
	if cfg.Fingerprint == "" {
		// 没有指纹就无法构造有意义的服务名。
		// 与其静默生成一个假指纹，不如明确报错——
		// 上层必须提供真实身份，否则发现出来的对端无法校验。
		panic("lan: Config.Fingerprint is required")
	}
	if cfg.ProtocolVersion == "" {
		cfg.ProtocolVersion = "1"
	}
	return &Transport{
		cfg:          cfg,
		events:       make(chan transport.TransportEvent, 256),
		peers:        map[transport.PeerID]*transport.PeerInfo{},
		lastPeerEmit: map[transport.PeerID]time.Time{},
		conns:        map[transport.PeerID]*conn{},
		byAddr:       map[string]transport.PeerID{},
		selfAddrs:    map[string]bool{},
		closed:       make(chan struct{}),
	}
}

// Start 启动 TCP 监听与 mDNS 发现。
func (t *Transport) Start(ctx context.Context) error {
	var startErr error
	t.startOnce.Do(func() {
		startErr = t.start(ctx)
	})
	if startErr != nil {
		return startErr
	}
	if !t.started {
		return transport.ErrAlreadyStarted
	}
	return nil
}

func (t *Transport) start(ctx context.Context) error {
	t.ctx, t.cancel = context.WithCancel(ctx)

	// 1. TCP 监听
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", t.cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("lan: listen: %w", err)
	}
	t.ln = ln

	port := t.port()
	t.cfg.logf("lan: listening on TCP %s", ln.Addr())

	// 记录本机地址，用于过滤自己的组播（否则会把自己当成对端）。
	t.collectSelfAddrs()

	// 2. mDNS
	mc, err := openMDNS()
	if err != nil {
		// 发现失败不应导致整个传输层不可用：
		// 用户仍可通过手动指定地址连接（未来功能），
		// 且监听端口已经打开。故记录警告后继续。
		t.discoveryErr = err
		t.cfg.logf("lan: mDNS unavailable (%v); discovery disabled, listening still active", err)
	} else {
		t.mdns = mc
		t.discoveryActive = true
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.discoveryLoop(ctx, port)
		}()
	}

	// 3. 接受入站连接
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.acceptLoop()
	}()

	t.started = true
	return nil
}

// port 返回实际监听端口。
func (t *Transport) port() uint16 {
	if t.ln == nil {
		return 0
	}
	if a, ok := t.ln.Addr().(*net.TCPAddr); ok {
		return uint16(a.Port)
	}
	return 0
}

// collectSelfAddrs 记录本机所有地址，用于过滤自己发出的组播。
func (t *Transport) collectSelfAddrs() {
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				t.selfAddrs[ipn.IP.String()] = true
			}
		}
	}
}

// discoveryLoop 周期宣告自己并监听他人。
func (t *Transport) discoveryLoop(ctx context.Context, port uint16) {
	service := makeServiceName(t.cfg.Fingerprint)
	host := makeHostName(t.cfg.Fingerprint)
	txt := map[string]string{
		txtKeyFingerprint: t.cfg.Fingerprint,
		txtKeyVersion:     t.cfg.ProtocolVersion,
		txtKeyName:        t.cfg.DisplayName,
	}

	t.mu.Lock()
	t.peers[transport.PeerID(t.cfg.Fingerprint)] = &transport.PeerInfo{
		ID:          transport.PeerID(t.cfg.Fingerprint),
		Fingerprint: t.cfg.Fingerprint,
		Metadata:    txt,
		LastSeen:    time.Now(),
	}
	t.mu.Unlock()

	// 接收报文。
	//
	// ⚠️ 这里**不按来源 IP 过滤自己**。
	//
	// 早期版本用 isSelf(srcIP) 丢弃本机发出的组播，看似合理，
	// 但会连带屏蔽同一台机器上的**另一个 KeyTalk 实例**——
	// 而那是一个完全合法的场景（同机多用户，或本机双实例联调），
	// 也正是本项目"方案 B"端到端验证所依赖的。
	//
	// 正确的过滤依据是**指纹**：报文里的 fp 字段若等于自己的指纹，
	// 那才是自己（见 handleRecord）。指纹是报文内容，IP 只是信封。
	go t.mdns.readLoop(ctx, func(pkt []byte, srcIP net.IP) {
		recs, err := parseMDNS(pkt, srcIP)
		if err != nil || len(recs) == 0 {
			return
		}
		for _, r := range recs {
			t.handleRecord(r)
		}
	})

	announce := func(ttl uint32) {
		pkt, err := announcement(service, host, port, txt, ttl)
		if err != nil {
			t.cfg.logf("lan: build announcement: %v", err)
			return
		}
		if err := t.mdns.writeToAll(pkt); err != nil {
			t.cfg.logf("lan: send announcement: %v", err)
		}
	}

	// 启动时立即宣告 + 主动查询。
	// 主动查询让"后启动的节点"立刻发现已存在的节点，
	// 而不必等下一次周期宣告（最多 30s 的空窗）。
	announce(mdnsTTL)
	if q, err := queryPacket(); err == nil {
		_ = t.mdns.writeToAll(q)
	}

	tick := time.NewTicker(t.cfg.announceInterval())
	defer tick.Stop()

	// 更频繁的初期宣告：RFC 6762 §8.3 建议启动后短时间内重复几次，
	// 以应对丢包。
	burst := time.NewTicker(2 * time.Second)
	defer burst.Stop()
	bursts := 0

	for {
		select {
		case <-ctx.Done():
			// 发送 goodbye，让对端立即移除我们（而非等 TTL 过期）。
			announce(mdnsGoodbyeTTL)
			return
		case <-burst.C:
			if bursts >= 3 {
				burst.Stop()
				continue
			}
			bursts++
			announce(mdnsTTL)
		case <-tick.C:
			announce(mdnsTTL)
			if q, err := queryPacket(); err == nil {
				_ = t.mdns.writeToAll(q)
			}
		case <-t.closed:
			return
		}
	}
}

// handleRecord 处理一条解析出的 mDNS 记录。
func (t *Transport) handleRecord(r parsedRecord) {
	fp := r.TXT[txtKeyFingerprint]
	if fp == "" {
		return
	}
	// 过滤自己。
	if fp == t.cfg.Fingerprint {
		return
	}
	if r.SourceIP == nil || r.Port == 0 {
		return
	}

	addr := &net.TCPAddr{IP: r.SourceIP, Port: int(r.Port)}
	peerID := transport.PeerID(fp)
	key := addr.String()

	t.mu.Lock()
	existing, existed := t.peers[peerID]
	lastAddrCount := 0
	if existed {
		lastAddrCount = len(existing.Addrs)
	}
	if existed {
		existing.LastSeen = time.Now()
		existing.Metadata = r.TXT
		// **累积**地址而不是替换。
		//
		// 多网卡机器上，同一次宣告会从每个接口各到达一次，
		// 来源 IP 各不相同（本机就有 WLAN/VMware/WSL/VPN 等多个）。
		// 早先的实现只保留"最后到达的那个"，很可能选中
		// 不可路由的虚拟网卡地址（如 172.x 的 WSL 网络），
		// 于是连接必然失败。
		//
		// 保留全部候选，由 connFor 逐个尝试——这正是
		// docs/nat-traversal.md §10.3 所说"Addrs 支持多地址"的用意。
		if !hasAddr(existing.Addrs, addr) {
			existing.Addrs = append(existing.Addrs, addr)
		}
	} else {
		t.peers[peerID] = &transport.PeerInfo{
			ID:          peerID,
			Fingerprint: fp,
			Addrs:       []net.Addr{addr},
			Metadata:    r.TXT,
			LastSeen:    time.Now(),
		}
	}
	t.byAddr[key] = peerID
	info := *t.peers[peerID]
	addrCount := len(info.Addrs)
	t.mu.Unlock()

	// 上报策略：首次发现必须上报；地址增加时可以上报（让上层拿到
	// 更可用的地址），但**必须限流**。
	//
	// ⚠️ 无节流会引发连接风暴——这是实测踩到的坑：
	// 同一次宣告会从每个接口各到达一次，本机有十余个接口，
	// 于是几秒内地址数从 1 涨到 12，每次都触发一次 PeerFound。
	// 上层（cmd/keytalk）收到 PeerFound 就调 StartHandshake，
	// 而 StartHandshake 会走 connFor 建立**新**连接——
	// 结果：握手进行到一半，连接被后续的 PeerFound 替换掉，
	// 双方各自超时。表现为"随机握手失败"（8 次里失败 3 次）。
	//
	// 限流后，地址更新依然能传达（有 500ms 合并窗口），
	// 但不会把上层的握手流程冲垮。
	shouldEmit := false
	switch {
	case !existed:
		shouldEmit = true
	case addrCount != lastAddrCount:
		now := time.Now()
		if now.Sub(t.lastPeerEmit[peerID]) >= peerEmitInterval {
			shouldEmit = true
			t.lastPeerEmit[peerID] = now
		}
	}

	if shouldEmit {
		t.cfg.logf("lan: discovered peer %s (%d address(es))", short(fp), addrCount)
		t.emit(transport.PeerFound{ID: peerID, Info: info})
	}
}

// emit 发送事件，尊重关闭状态。
//
// 非阻塞：事件 channel 满时丢弃并记录。
// 丢弃而非阻塞的理由——阻塞会让整个读循环停摆，
// 进而导致连接超时被误判为断开。
func (t *Transport) emit(ev transport.TransportEvent) {
	select {
	case <-t.closed:
		return
	default:
	}
	select {
	case t.events <- ev:
	default:
		t.cfg.logf("lan: event channel full, dropping %T", ev)
	}
}

// acceptLoop 接受入站连接。
func (t *Transport) acceptLoop() {
	for {
		nc, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			t.cfg.logf("lan: accept: %v", err)
			continue
		}
		go t.handleInbound(nc)
	}
}

// handleInbound 处理一条入站连接。
//
// ⚠️ 关键设计点：入站连接的**身份尚不可知**。
//
// TCP 层只知道对端 IP，而这既可能是真实对端，也可能是攻击者。
// 因此这里**不**尝试绑定 peerID，而是等到应用层的握手完成后
// 由上层告知"这条连接属于谁"。
//
// 首期实现的简化：入站连接先挂起，等应用层发来第一帧（KEM_INIT）
// 后再由 core 通过 BindConn 建立关联。这避免了在传输层做任何
// 身份推断——那正是我们明确要避免的耦合。
//
// ⚠️ 安全要点：**绝不**用来源 IP 去匹配已建立的连接。
//
// 早期版本曾按 IP 匹配来"识别"入站对端，这引入了一个真实的漏洞：
//   - 同一台主机上的任意进程（或同一 NAT 后的任意设备）
//     与已知对端共享同一个来源 IP；
//   - 于是一个恶意连接会被误认为"就是那个对端"，
//     并**顶替掉**真实对端的连接；
//   - 恶意连接随后关闭，连带摧毁了真实对端的会话。
//
// 也就是说，攻击者无需任何密码学能力，仅凭"在同一 IP 上发起连接"
// 就能实施拒绝服务。
//
// 正确做法：入站连接一律视为**未知来源**，分配独立的临时 ID；
// 只有应用层完成密码学握手后才能确立身份（见 session.identifySender）。
func (t *Transport) handleInbound(nc net.Conn) {
	addr := nc.RemoteAddr().String()

	// ⚠️ 必须去掉 IPv6 的 zone 标识（"%eth0"）。
	//
	// 坑：Windows 上链路本地 IPv6 的 RemoteAddr 会带上**接口名**作 zone，
	// 形如 "169.254.201.140%VMware Network Adapter VMnet8:62733"——
	// 里面含空格和中文。这个字符串会被当作 peerID 使用，
	// 而 peerID 是事件路由的键，任何解析/比较/日志都可能被它搞坏
	// （实测表现为帧收到了却无法路由到会话层，握手静默超时）。
	//
	// zone 对**本机**有意义（决定从哪张网卡出去），
	// 但对"这条连接是谁"没有意义，因此在这里剥掉。
	addr = stripZone(addr)

	// 独立的临时标识。绝不与已建立的连接 ID 冲突。
	peerID := transport.PeerID("inbound:" + addr)

	// 注意：即使 addr 恰好等于某个已知对端广播的地址，
	// 也**不**做匹配——那正是上面描述的漏洞。
	t.cfg.logf("lan: inbound from %s (identity pending handshake)", addr)

	t.registerConn(peerID, nc)
}

// AdoptConnection 把一条入站连接的临时 ID 替换为已认证的会话 ID。
//
// 由应用层在握手完成后调用：此时身份已经过密码学校验
// （验签 + 指纹比对），可以安全地与传输层标识关联。
//
// 这是"传输层不做身份推断"这一约束的落地点：
// 身份由上层确定，传输层只负责按给定的 ID 路由。
func (t *Transport) AdoptConnection(tempID, realID transport.PeerID) {
	if tempID == realID {
		return
	}

	t.mu.Lock()
	c, ok := t.conns[tempID]
	if !ok {
		t.mu.Unlock()
		return
	}
	delete(t.conns, tempID)

	// 若已有同 ID 的旧连接，关闭它——
	// 但这次是**基于已验证身份**的替换，与按 IP 猜测有本质区别。
	if old, exists := t.conns[realID]; exists {
		_ = old.Close()
	}
	t.conns[realID] = c
	// 更新连接自身的 ID，使其后续事件上报正确的身份。
	c.setPeerID(realID)
	t.mu.Unlock()

	t.cfg.logf("lan: adopted inbound connection %s as %s", tempID, short(string(realID)))
}

// registerConn 注册一条连接并启动读写循环。
func (t *Transport) registerConn(peerID transport.PeerID, nc net.Conn) *conn {
	c := newConn(peerID, nc)

	t.mu.Lock()
	if old, ok := t.conns[peerID]; ok {
		// 已有连接：关闭旧的，用新的（后连接的更可能是最新的网络状态）。
		t.mu.Unlock()
		_ = old.Close()
		t.mu.Lock()
	}
	t.conns[peerID] = c
	t.mu.Unlock()

	t.emit(transport.ConnOpened{ID: peerID})

	// ⚠️ 事件中的 ID 必须**动态**读取连接当前的 peerID，
	// 而不能捕获注册时的值。
	//
	// 原因：入站连接在握手完成前是临时 ID（"inbound:<地址>"），
	// 握手后由 AdoptConnection 改名为已认证的指纹。
	// 若闭包捕获了旧值，收编之后所有事件仍会带着临时 ID，
	// 导致会话层查不到对应会话——表现为
	// "received secure frame before handshake completed"。
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		c.readLoop(
			func(frame []byte) {
				t.emit(transport.FrameReceived{ID: c.currentPeerID(), Frame: frame})
			},
			func(err error) {
				t.unregister(c.currentPeerID(), c, err)
			},
		)
	}()

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		c.writeLoop(func(err error) {
			t.unregister(c.currentPeerID(), c, err)
		})
	}()

	return c
}

// unregister 移除连接并上报关闭事件。
func (t *Transport) unregister(peerID transport.PeerID, c *conn, err error) {
	t.mu.Lock()
	if cur, ok := t.conns[peerID]; ok && cur == c {
		delete(t.conns, peerID)
	} else {
		// 已被更新的连接替换：不上报关闭，避免上层误判。
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()

	_ = c.Close()
	t.emit(transport.ConnClosed{ID: peerID, Err: err})
}

// Send 向对端发送帧。
//
// 若尚无连接，会尝试用已发现的地址建立连接（这是"电话先拨号"的一方）。
// 这样上层无需显式管理连接生命周期——Send 即可用。
func (t *Transport) Send(peerID transport.PeerID, frame []byte) error {
	if len(frame) > transport.MaxFrameSize {
		return fmt.Errorf("%w: %d > %d", transport.ErrFrameTooLarge, len(frame), transport.MaxFrameSize)
	}

	select {
	case <-t.closed:
		return transport.ErrClosed
	default:
	}

	c, err := t.connFor(peerID)
	if err != nil {
		return err
	}
	return c.enqueue(frame)
}

// connFor 返回（必要时建立）到对端的连接。
func (t *Transport) connFor(peerID transport.PeerID) (*conn, error) {
	t.mu.RLock()
	c, ok := t.conns[peerID]
	info, found := t.peers[peerID]
	t.mu.RUnlock()

	if ok && !c.isClosed() {
		// 复用现有连接。
		//
		// 这一点比看起来重要：若这里改成"每次发现新地址就重连"，
		// 进行中的握手会因为连接被替换而失败。
		// 复用是默认路径，重连只发生在连接确实已断时。
		return c, nil
	}
	if !found || len(info.Addrs) == 0 {
		return nil, fmt.Errorf("%w: %s", transport.ErrPeerUnknown, peerID)
	}

	// 按可用性排序后逐个尝试。
	//
	// ⚠️ 顺序很关键。
	//
	// mDNS 宣告里的 SRV 记录给的是主机名，解析后可能得到
	// IPv6 链路本地地址（fe80::...）。这类地址有两个问题：
	//
	//   1. 需要 scope/zone 才能路由，而跨机器时 zone 名可能不匹配
	//      （实测出现过 "fe80::a564:7fb4:89cf:2a9%vEthernet (Default Switch)"
	//      这种把接口名当 zone 传来的情况）；
	//   2. 即使连上了，对端看到的入站是**另一条** TCP 连接
	//      （IPv4 那条），于是对端把 ACK 发到 IPv4 连接上，
	//      而发起方在 IPv6 连接上等——双方各等各的，握手超时。
	//
	// 因此优先选 IPv4：在局域网里它最可靠，且能保证
	// 双方对"这是哪条连接"的理解一致。
	// IPv6 仅在完全没有 IPv4 候选时才用（纯 IPv6 网络）。
	addrs := make([]net.Addr, 0, len(info.Addrs))
	for _, a := range info.Addrs {
		if isIPv6Addr(a) {
			continue
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		addrs = info.Addrs // 纯 IPv6 环境：没有选择余地
	}

	var lastErr error
	for _, addr := range addrs {
		nc, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		t.cfg.logf("lan: connected to %s at %s", short(string(peerID)), addr)
		return t.registerConn(peerID, nc), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable address")
	}
	return nil, fmt.Errorf("%w: %s: %v", transport.ErrNotConnected, peerID, lastErr)
}

// Events 返回事件流。
func (t *Transport) Events() <-chan transport.TransportEvent { return t.events }

// Peers 返回当前已知的对端快照（按 peerID）。
//
// 这是对本接口的扩展（transport.Transport 未定义），
// 供 core 在启动时拉取初始状态——否则在 Events 订阅之前
// 已经发现的对端会被漏掉。
func (t *Transport) Peers() map[transport.PeerID]transport.PeerInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[transport.PeerID]transport.PeerInfo, len(t.peers))
	for k, v := range t.peers {
		out[k] = *v
	}
	return out
}

// DiscoveryActive 报告 mDNS 发现是否真的启用了。
//
// 上层必须据此如实显示状态：若发现不可用（例如端口被占用），
// 界面不能宣称"正在搜索附近的人"——那是在骗用户。
func (t *Transport) DiscoveryActive() bool { return t.discoveryActive }

// DiscoveryError 返回发现功能不可用的原因（若可用则为 nil）。
func (t *Transport) DiscoveryError() error { return t.discoveryErr }

// LocalAddr 返回 TCP 监听地址。
func (t *Transport) LocalAddr() net.Addr {
	if t.ln == nil {
		return nil
	}
	return t.ln.Addr()
}

// SetPeerForTest 注入一个对端及其地址，绕过 mDNS。
//
// ⚠️ 仅供测试使用。生产代码绝不应调用它——
// 真实场景下对端信息必须来自发现协议，而非外部注入。
//
// 存在理由：mDNS 依赖真实网络环境（组播可达性、防火墙），
// 在 CI 与某些容器里不可靠。会话层与加密层的测试不该因
// 环境限制而无法运行，故提供一个明确的测试注入点。
// mDNS 自身的正确性由 transport/lan 的单元测试覆盖。
func (t *Transport) SetPeerForTest(id transport.PeerID, addr net.Addr, fingerprint string) {
	if addr == nil {
		return
	}
	t.mu.Lock()
	t.peers[id] = &transport.PeerInfo{
		ID:          id,
		Fingerprint: fingerprint,
		Addrs:       []net.Addr{addr},
		LastSeen:    time.Now(),
	}
	t.byAddr[addr.String()] = id
	t.mu.Unlock()
}

// Close 关闭传输层。幂等。
func (t *Transport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.closed)
		if t.cancel != nil {
			t.cancel()
		}

		if t.ln != nil {
			err = t.ln.Close()
		}
		if t.mdns != nil {
			_ = t.mdns.close()
		}

		t.mu.Lock()
		for _, c := range t.conns {
			_ = c.Close()
		}
		t.conns = map[transport.PeerID]*conn{}
		t.mu.Unlock()

		// 等待所有 goroutine 退出，避免 Close 返回后还有事件写入。
		// 用带超时的等待：某条连接可能卡在系统调用上，
		// 无限等待会让 Shutdown 挂死。
		done := make(chan struct{})
		go func() {
			t.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.cfg.logf("lan: close timed out waiting for goroutines")
		}

		close(t.events)
	})
	return err
}

// stripZone 去掉地址里的 IPv6 zone 标识。
//
// 例："[fe80::1%eth0]:80" -> "[fe80::1]:80"
//
//	"169.254.1.1%Ethernet 2:80" -> "169.254.1.1:80"
//
// 注意 zone 可能含空格（Windows 接口名如 "VMware Network Adapter VMnet8"），
// 所以不能按空白切分，只能在"直到冒号之前的最后一个 %"处截断。
func stripZone(addr string) string {
	i := strings.LastIndexByte(addr, '%')
	if i < 0 {
		return addr
	}

	// 从 % 之后找 zone 的结束位置：要么是右方括号（IPv6 带括号形式
	// "[fe80::1%eth0]:5353"），要么是冒号（裸地址形式 "fe80::1%eth0:80"）。
	// 只在冒号**先于**右方括号出现时才按冒号切——否则会把
	// IPv6 地址的收尾括号一并吃掉。
	rest := addr[i:]
	jBracket := strings.IndexByte(rest, ']')
	jColon := strings.IndexByte(rest, ':')

	switch {
	case jBracket >= 0 && (jColon < 0 || jBracket < jColon):
		// 括号形式：保留 "]" 及其后的端口。
		return addr[:i] + rest[jBracket:]
	case jColon >= 0:
		// 裸地址带端口。
		return addr[:i] + rest[jColon:]
	default:
		// 只有地址 + zone，没有端口。
		return addr[:i]
	}
}

// isIPv6Addr 判断地址是否为 IPv6（含链路本地）。
func isIPv6Addr(a net.Addr) bool {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		host = a.String()
	}
	// 去掉可能的 zone（fe80::1%eth0）。
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

// hasAddr 判断地址是否已在列表中。
func hasAddr(addrs []net.Addr, a net.Addr) bool {
	for _, x := range addrs {
		if x.String() == a.String() {
			return true
		}
	}
	return false
}

// short 返回指纹的短形式，用于日志。
func short(fp string) string {
	if len(fp) > 8 {
		return fp[:8]
	}
	return fp
}
