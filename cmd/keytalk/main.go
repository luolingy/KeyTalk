// Command keytalk 是一个命令行版的局域网加密聊天工具（方案 B）。
//
// 用途：在**没有 UI** 的情况下验证完整的端到端加密链路——
// 发现 → 握手 → 加密通信。这是 Gio 界面之前的可运行中间产物，
// 也是排查"到底是加密错了还是 UI 错了"的最短路径。
//
// 用法：
//
//	# 终端 1
//	keytalk -name alice -id ./data/alice
//
//	# 终端 2
//	keytalk -name bob -id ./data/bob
//
// 首次运行时每个实例生成自己的 OpenPGP 身份并打印指纹。
// 要互相通信，双方需交换公钥文件并把对方加入联系人
// （见 README 中的使用说明）。
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/sas"
	"github.com/exeliang/keytalk/internal/session"
	"github.com/exeliang/keytalk/internal/transport"
	"github.com/exeliang/keytalk/internal/transport/lan"
)

func main() {
	// ⚠️ 必须在任何输出之前：双击启动时 Windows 会先新建一个
	// 控制台窗口，我们要在它被看到之前藏起来。
	// 从终端启动时不会隐藏——那个窗口是用户的终端。
	hideOwnConsole(len(os.Args) <= 1)

	if err := run(); err != nil {
		reportFatal(err)
		os.Exit(1)
	}
}

// reportFatal 把致命错误送到用户**真能看到**的地方。
//
// 图形模式下控制台是隐藏的，往 stderr 写等于什么也没说，
// 程序表现为"闪一下就没了"。那种情况必须弹窗——否则用户
// 只知道它坏了，不知道坏在哪。
func reportFatal(err error) {
	if consoleHidden {
		messageBox("KeyTalk 启动失败", err.Error())
		return
	}
	fmt.Fprintf(os.Stderr, "\n错误: %v\n", err)
}

// options 是命令行参数。
type options struct {
	name        string
	dataDir     string
	listenPort  int
	contactFile string
	verbose     bool

	// setupOnly 表示只做身份生成与联系人导入，然后立即退出。
	//
	// 存在理由：无此开关时，任何调用都会进入交互循环并阻塞 stdin，
	// 使"生成身份/导入联系人"这类一次性操作无法在脚本中使用。
	setupOnly bool

	// gui 为 true 时使用 Gio 图形界面而非命令行 REPL。
	//
	// 两者共用同一套 core（下面的 runGUI 会新建一个 core.App），
	// 因此加密与网络行为完全一致，只有呈现方式不同。
	gui bool
}

func run() error {
	var opt options
	flag.StringVar(&opt.name, "name", "", "显示名（默认用系统用户名）")
	// 默认留空，稍后按"显式指定 > 已有 ./keytalk-data > 系统配置目录"
	// 解析（见 resolveDataDir）。
	flag.StringVar(&opt.dataDir, "id", "", "身份与数据目录（默认放到系统用户配置目录）")
	flag.IntVar(&opt.listenPort, "port", 0, "TCP 监听端口（0 = 自动分配）")
	flag.StringVar(&opt.contactFile, "contact", "", "导入联系人公钥文件（可重复用逗号分隔）")
	flag.BoolVar(&opt.verbose, "v", false, "输出详细日志")
	flag.BoolVar(&opt.setupOnly, "setup", false, "仅生成身份并导入联系人，然后退出（不进入聊天）")
	flag.BoolVar(&opt.gui, "gui", false, "使用图形界面（默认使用命令行界面）")
	flag.Parse()

	// 无参数的裸启动 = 双击启动。
	//
	// 此时用户期望的是"打开程序"，而不是面对一个需要输入命令的
	// 提示符。传了参数就维持命令行行为——e2e.ps1 等脚本全都依赖
	// 这一点，因此不能把图形界面变成无条件默认。
	if len(os.Args) <= 1 {
		opt.gui = true
	}

	if opt.dataDir == "" {
		opt.dataDir = resolveDataDir("")
	}

	if opt.name == "" {
		if u := os.Getenv("USERNAME"); u != "" {
			opt.name = u
		} else if u := os.Getenv("USER"); u != "" {
			opt.name = u
		} else {
			opt.name = "keytalk-user"
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 日志有三个出口：终端详细输出（-v）、图形模式的日志文件，
	// 以及由 core 转发到界面状态栏的事件。
	var logFile *os.File

	logf := func(format string, args ...any) {
		if opt.verbose {
			fmt.Printf("  · "+format+"\n", args...)
		}
		if logFile != nil {
			fmt.Fprintf(logFile, format+"\n", args...)
		}
	}

	// --- 1. 身份 ---
	fmt.Println("KeyTalk — 局域网端到端加密聊天")
	fmt.Println(strings.Repeat("=", 60))

	if err := os.MkdirAll(opt.dataDir, 0o700); err != nil {
		return fmt.Errorf("创建数据目录 %s: %w", opt.dataDir, err)
	}

	// 图形模式下控制台可能是隐藏的（双击启动），出了问题用户
	// 手上不会有任何可排查的信息。因此把日志同时写进数据目录。
	//
	// 命令行模式不写文件：脚本靠 stdout，多一个日志文件
	// 只会让人困惑到底该看哪个。
	if opt.gui {
		if f, ferr := os.OpenFile(filepath.Join(opt.dataDir, "keytalk.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); ferr == nil {
			logFile = f
			defer f.Close()
			logf("--- keytalk gui start ---")
		}
	}

	identity, created, err := loadOrCreateIdentity(opt.dataDir, opt.name, logf)
	if err != nil {
		return fmt.Errorf("身份: %w", err)
	}
	defer identity.Close()

	fp := identity.Fingerprint()
	if created {
		fmt.Printf("\n✓ 已生成新身份（首次运行）\n")
	} else {
		fmt.Printf("\n✓ 已载入身份\n")
	}
	fmt.Printf("  显示名: %s\n", opt.name)
	fmt.Printf("  指纹:   %s\n", fp.Display())
	// 数据目录必须明说：用户的身份私钥和公钥都在这里，
	// 而他多半不会想到去 %AppData% 下面找。
	fmt.Printf("  数据目录: %s\n", opt.dataDir)

	// --- 2. 联系人 ---
	contacts, err := loadContacts(opt.dataDir, logf)
	if err != nil {
		return fmt.Errorf("载入联系人: %w", err)
	}

	if opt.contactFile != "" {
		added, err := importContacts(opt.dataDir, contacts, opt.contactFile, logf)
		if err != nil {
			return fmt.Errorf("导入联系人: %w", err)
		}
		for _, c := range added {
			fmt.Printf("✓ 已添加联系人: %s (%s)\n", c.name, c.fp.Display())
		}
	}

	if opt.setupOnly {
		fmt.Printf("\nSETUP_DONE %s\n", fp.String())
		if len(contacts) > 0 {
			for _, c := range contacts {
				fmt.Printf("CONTACT %s %s\n", c.name, c.fp.String())
			}
		}
		return nil
	}

	// --- 图形界面 ---
	//
	// 刻意放在创建命令行传输链路**之前**。
	//
	// 旧写法是先建 lan 传输 + session.Manager，再由 gui 分支把它们
	// 整个丢弃、重新建一套。那样会短暂占用一个监听端口和一个 mDNS
	// 名字——虽然能跑通，但等于凭空多出一个只在几百毫秒内存在的
	// 监听者，排障时极易误判成"有两个实例"。
	if opt.gui {
		return runGUI(ctx, opt, identity, contacts, logf)
	}

	if len(contacts) == 0 {
		fmt.Println("\n⚠ 联系人列表为空。")
		fmt.Printf("  请让对方运行本程序，然后把他的公钥文件交给你：\n")
		fmt.Printf("    %s/public.key\n", opt.dataDir)
		fmt.Printf("  用以下命令导入：\n")
		fmt.Printf("    keytalk -id %s -contact <对方公钥文件>\n", opt.dataDir)
		fmt.Println("\n  本程序**不会**自动信任陌生连接——这是有意的设计。")
	}

	// --- 3. 传输层 ---
	tr := lan.New(lan.Config{
		Fingerprint:     fp.String(),
		DisplayName:     opt.name,
		ListenPort:      opt.listenPort,
		ProtocolVersion: "1",
		Logf:            logf,
	})
	if err := tr.Start(ctx); err != nil {
		return fmt.Errorf("启动网络: %w", err)
	}
	defer func() { _ = tr.Close() }()

	fmt.Printf("✓ 正在监听: %s\n", tr.LocalAddr())

	// 如实报告发现状态。绝不宣称一个并未运行的功能——
	// 若端口被占用（同机还有别的 mDNS 服务），发现会是关闭的，
	// 用户必须知道这一点，否则会一直等一个永远不来的连接。
	if tr.DiscoveryActive() {
		fmt.Printf("✓ 正在通过 mDNS 广播与搜索服务 %s\n", lan.ServiceType)
	} else {
		fmt.Printf("✗ mDNS 发现不可用: %v\n", tr.DiscoveryError())
		fmt.Println("  影响: 无法自动发现对端。TCP 监听仍然有效，")
		fmt.Println("        但需要对方先主动连接，或手动指定地址。")
	}

	// --- 4. 会话层 ---
	mgr := session.New(session.Config{
		Identity:  identity,
		Importer:  &crypto.PGPImporter{},
		Transport: tr,
		Logf:      logf,
	})

	// 注册联系人，使入站握手能被识别。
	for _, c := range contacts {
		id := session.PeerID(c.fp.String())
		mgr.AddPeer(id, session.PeerConfig{
			Fingerprint: c.fp,
			PublicKey:   c.pub,
		})
		mgr.SetTransportPeer(id, transport.PeerID(id))
	}

	mgr.Start(ctx)
	defer mgr.Close()

	// --- 5. 交互循环 ---
	app := &app{
		opt:      opt,
		tr:       tr,
		mgr:      mgr,
		contacts: contacts,
		logf:     logf,
		peers:    map[session.PeerID]peerState{},
	}
	// ⚠️ 只能有**一个**消费者读取 transport.Events()。
	//
	// 会话层（session.Manager）已经独占消费该通道。若这里再起一个
	// goroutine 读同一个通道，两者会**竞争**：谁先拿到事件是随机的，
	// 于是大约一半的帧被 CLI 这个"旁观者"吃掉，会话永远收不到，
	// 表现为**随机**握手超时（实测 10 次里失败 6~10 次）。
	//
	// 教训：事件通道是**单消费者**资源。想同时观察，
	// 必须由持有者转发（fan-out），而不是各自去读。
	//
	// 因此这里不再单独消费传输层事件；在线状态通过会话层事件
	// 以及 /who 时主动查询 Peers() 获得。
	go app.consumeSession(ctx)
	go app.watchPeers(ctx)

	fmt.Println(strings.Repeat("=", 60))
	app.printHelp()

	go app.repl(ctx)

	select {
	case <-ctx.Done():
		fmt.Println("\n正在退出…")
	}

	// 给 goodbye 包一点时间发出去，让对端立即把我们移除。
	time.Sleep(300 * time.Millisecond)
	return nil
}

// peerState 是一个对端的运行时状态。
type peerState struct {
	name      string
	online    bool
	sessionOn bool
	transport transport.PeerID
}

// app 持有交互状态。
type app struct {
	opt      options
	tr       *lan.Transport
	mgr      *session.Manager
	contacts []contact
	logf     func(string, ...any)

	mu     sync.Mutex
	peers  map[session.PeerID]peerState
	active session.PeerID // 当前对话对象
}

func (a *app) printHelp() {
	fmt.Println(`
可用命令：
  /who               列出联系人及其在线/会话状态
  /talk <名字或序号>  选择对话对象（会自动发起握手）
  /keys              显示本机指纹（发给对方以交换公钥）
  /help              显示本帮助
  /quit              退出

直接输入文字即发送给当前对话对象。
如果还没有选定对话对象，用 /talk 选择。`)
	fmt.Println()
}

// repl 读取标准输入并处理命令。
func (a *app) repl(ctx context.Context) {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !sc.Scan() {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "/") {
			a.handleCommand(ctx, line)
			continue
		}

		// 普通消息。
		a.mu.Lock()
		target := a.active
		a.mu.Unlock()

		if target == "" {
			fmt.Println("⚠ 尚未选择对话对象。用 /who 查看联系人，用 /talk <名字> 选择。")
			continue
		}
		if !a.mgr.HasSession(target) {
			fmt.Printf("⚠ 与 %s 的会话尚未建立（可能对方不在线，或公钥不匹配）。\n",
				a.displayName(target))
			continue
		}
		if err := a.mgr.SendText(target, line); err != nil {
			fmt.Printf("✗ 发送失败: %v\n", err)
			continue
		}
	}
}

func (a *app) handleCommand(ctx context.Context, line string) {
	parts := strings.Fields(line)
	switch parts[0] {
	case "/help", "/h", "/?":
		a.printHelp()

	case "/keys", "/fp":
		fmt.Printf("本机指纹: %s\n", a.mgr.Fingerprint())
		fmt.Printf("公钥文件: %s\n", filepath.Join(a.opt.dataDir, "public.key"))

	case "/who", "/w":
		a.printPeers()

	case "/talk", "/t":
		if len(parts) < 2 {
			fmt.Println("用法: /talk <名字或序号>")
			a.printPeers()
			return
		}
		a.selectPeer(parts[1])

	case "/quit", "/q", "/exit":
		fmt.Println("再见。")
		os.Exit(0)

	default:
		fmt.Printf("未知命令: %s（用 /help 查看帮助）\n", parts[0])
	}
}

func (a *app) printPeers() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.contacts) == 0 {
		fmt.Println("联系人列表为空。")
		return
	}

	fmt.Println("联系人：")
	for i, c := range a.contacts {
		id := session.PeerID(c.fp.String())
		st := a.peers[id]
		status := "离线"
		if st.online {
			status = "在线"
		}
		sess := ""
		if st.sessionOn {
			sess = " · 会话已建立（加密就绪）"
		}
		marker := " "
		if a.active == id {
			marker = "*"
		}
		fmt.Printf("  %s [%d] %-12s %s%s\n", marker, i+1, c.name, status, sess)
	}
}

func (a *app) selectPeer(arg string) {
	// 支持序号或名字前缀。
	var chosen *contact
	if n, err := parseIndex(arg); err == nil && n >= 1 && n <= len(a.contacts) {
		chosen = &a.contacts[n-1]
	} else {
		var matches []*contact
		for i := range a.contacts {
			if strings.HasPrefix(strings.ToLower(a.contacts[i].name), strings.ToLower(arg)) {
				matches = append(matches, &a.contacts[i])
			}
		}
		if len(matches) == 1 {
			chosen = matches[0]
		} else if len(matches) > 1 {
			fmt.Printf("「%s」匹配到多个联系人，请更具体：\n", arg)
			for _, m := range matches {
				fmt.Printf("  %s\n", m.name)
			}
			return
		}
	}

	if chosen == nil {
		fmt.Printf("找不到联系人「%s」。用 /who 查看列表。\n", arg)
		return
	}

	id := session.PeerID(chosen.fp.String())
	a.mu.Lock()
	a.active = id
	st := a.peers[id]
	st.name = chosen.name
	a.peers[id] = st
	a.mu.Unlock()

	fmt.Printf("✓ 当前对话对象: %s\n", chosen.name)
	fmt.Printf("  指纹: %s\n", chosen.fp.Display())

	if a.mgr.HasSession(id) {
		fmt.Println("  会话已建立，可以直接发送消息。")
		return
	}

	// 自动发起握手。
	if err := a.mgr.StartHandshake(id); err != nil {
		if errors.Is(err, session.ErrHandshakeInProgress) {
			fmt.Println("  握手正在进行中…")
		} else {
			fmt.Printf("  ⚠ 发起握手失败: %v\n", err)
		}
		return
	}
	fmt.Println("  正在握手（若对方不在线，约 20 秒后超时）…")
}

func (a *app) displayName(id session.PeerID) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if st, ok := a.peers[id]; ok && st.name != "" {
		return st.name
	}
	for _, c := range a.contacts {
		if session.PeerID(c.fp.String()) == id {
			return c.name
		}
	}
	s := string(id)
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// watchPeers 定期把传输层的对端快照同步到本地的在线状态。
//
// 为什么要轮询而不是订阅：transport.Events() 已被会话层独占
// （见 run() 中的说明），CLI 不能再读同一个通道。快照接口 Peers()
// 是只读的，可以安全并发调用，适合这种低频的展示需求。
//
// 间隔 1 秒：只影响"谁在线"的显示，不影响任何协议行为。
func (a *app) watchPeers(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	announced := map[session.PeerID]bool{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			snap := a.tr.Peers()
			// 索引化，便于按指纹查找（Peers 返回有序切片）。
			online := make(map[transport.PeerID]bool, len(snap))
			for _, p := range snap {
				online[p.ID] = true
			}
			a.mu.Lock()
			for _, c := range a.contacts {
				id := session.PeerID(c.fp.String())
				st := a.peers[id]
				st.name = c.name

				_, present := online[transport.PeerID(id)]
				wasOnline := st.online
				st.online = present
				if present {
					st.transport = transport.PeerID(id)
				}
				a.peers[id] = st

				// 首次上线时提示一次，避免每秒刷屏。
				if present && !wasOnline && !announced[id] {
					announced[id] = true
					fmt.Printf("\n📡 %s 上线了\n", c.name)
					fmt.Printf("PEER_ONLINE %s\n", c.fp.String())
				}
				if !present {
					announced[id] = false
				}
			}
			a.mu.Unlock()

			// 对端出现后按角色决定是否发起握手。
			for _, c := range a.contacts {
				id := session.PeerID(c.fp.String())
				if !a.isOnline(id) {
					continue
				}
				if a.mgr.HasSession(id) {
					continue
				}
				if !a.shouldDial(id) {
					continue
				}
				if err := a.mgr.StartHandshake(id); err != nil &&
					!errors.Is(err, session.ErrHandshakeInProgress) {
					a.logf("向 %s 发起握手失败: %v", c.name, err)
				}
			}
		}
	}
}

// isOnline 报告某个联系人当前是否在线。
func (a *app) isOnline(id session.PeerID) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peers[id].online
}

func (a *app) shouldDial(peer session.PeerID) bool {
	own := a.mgr.Fingerprint().String()
	theirs := string(peer)
	return own > theirs
}

// consumeSession 处理会话层事件。
func (a *app) consumeSession(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.mgr.Events():
			if !ok {
				return
			}
			switch e := ev.(type) {
			case session.HandshakeDone:
				a.mu.Lock()
				st := a.peers[e.Peer]
				st.sessionOn = true
				a.peers[e.Peer] = st
				a.mu.Unlock()
				fmt.Printf("\n🔒 与 %s 的端到端加密会话已建立\n",
					a.displayName(e.Peer))
				// 稳定的 ASCII 标记，供脚本/测试断言。
				fmt.Printf("session established IDENTITY_VERIFIED %s\n", e.Peer)

				// emoji 二次确认（SAS）。
				//
				// 握手只能证明"对端持有联系人表里那把公钥的私钥"，
				// 不能证明"那把公钥真的属于你朋友"。因此这里必须
				// 把核对用的 emoji 摊给用户，并且**不**声称身份已确认。
				if emojis, err := sas.FromHandshakeHash(e.SAS); err == nil {
					fmt.Println()
					fmt.Println("  ⚠ 请与对方核对以下 emoji，一致才能确认没有被中间人：")
					fmt.Printf("\n      %s\n\n", sas.Format(emojis))
					fmt.Printf("      （念给对方听：%s）\n", sas.FormatNames(emojis))
					fmt.Println("  一致 = 通信可信；不一致 = 可能有人在冒充，请立即停止。")
					fmt.Printf("  EMOJI_SAS %s\n", sas.Format(emojis))
				} else {
					fmt.Printf("  (无法生成核对用 emoji: %v；请改用指纹手动核对)\n", err)
				}

			case session.HandshakeFailed:
				a.mu.Lock()
				st := a.peers[e.Peer]
				st.sessionOn = false
				a.peers[e.Peer] = st
				a.mu.Unlock()
				fmt.Printf("\n✗ 与 %s 握手失败: %v\n",
					a.displayName(e.Peer), e.Err)

			case session.Message:
				a.printMessage(e)

			case session.StateChanged:
				a.mu.Lock()
				st := a.peers[e.Peer]
				st.sessionOn = e.State == crypto.StateEstablished
				a.peers[e.Peer] = st
				a.mu.Unlock()
			}
		}
	}
}

func (a *app) printMessage(e session.Message) {
	name := a.displayName(e.Peer)
	ts := time.UnixMilli(e.Plaintext.SentAt).Format("15:04:05")

	switch e.Plaintext.Kind {
	case 0x01: // KindText
		fmt.Printf("\n[%s] %s: %s\n> ", ts, name, e.Plaintext.Text)
	default:
		fmt.Printf("\n[%s] %s: <未处理的类型 0x%02x>\n> ",
			ts, name, byte(e.Plaintext.Kind))
	}
}

func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}
