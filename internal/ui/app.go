package ui

import (
	"fmt"
	"image"
	"image/color"
	"log"
	"os"
	"strings"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/exeliang/keytalk/internal/core"
)

// Options 是启动界面所需的一切。
//
// ⚠️ 界面**只**通过 core 与外界交互（见 architecture.md §1.1）。
// 这里不出现 transport/crypto/wire 的任何类型——
// 那正是"低耦合"的检验方式：把 core 换成别的实现，ui 不需要改。
type Options struct {
	// App 是应用状态机（必填）。
	App *core.App

	// Logf 是界面的日志出口。
	Logf func(string, ...any)

	// Setup 是配置阶段（可选）。
	//
	// 提供时，界面先渲染"创建 / 导入 / 解锁身份"向导，
	// 身份就绪后自动组装 App 并切换到主界面。
	// 此时 App 应为 nil——两者互斥：有 App 就说明身份已就绪，
	// 那就没有什么可配置的了。
	Setup *core.Setup

	// NetInfoFunc 返回网络层状态（可选）。
	//
	// 用函数而不是值：传输层是在配置阶段结束、App 组装时才
	// 创建的，runGUI 拿到界面选项时还不知道端口号。
	NetInfoFunc func() NetInfo

	// Title 是窗口标题。
	Title string
}

// NetInfo 是网络层的展示信息。
//
// 放在 ui 而不是 core：这些是**诊断信息**，不是协议状态。
// 让 core 去暴露监听端口会迫使 transport.Transport 接口
// 新增方法（并波及所有实现与测试），而界面只是想把它们显示出来。
// 由 cmd 填进来最省事，也不破坏分层——cmd 本来就知道具体传输实现。
type NetInfo struct {
	// ListenAddr 是实际监听的地址（端口为 0 时是内核分配的端口）。
	ListenAddr string
	// DiscoveryActive 表示局域网自动发现是否可用。
	DiscoveryActive bool
	// DiscoveryError 在发现不可用时说明原因。
	DiscoveryError string
}

// Run 创建窗口并进入事件循环，**阻塞**到窗口关闭。
//
// 调用方（main）必须让 app.Main() 在自身 goroutine 上运行，
// 因此本函数应当在单独的 goroutine 里调用，或者由 Run 负责启动
// app.Main()（当前采用后者，见下）。
func Run(opts Options) error {
	if opts.App == nil && opts.Setup == nil {
		return fmt.Errorf("ui: Options.App or Options.Setup is required")
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}

	a := newState(opts)
	return a.run()
}

// app 是界面的全部可变状态。
//
// ⚠️ 这里的字段**只允许被 UI goroutine 访问**。
//
// Gio 是单线程 immediate mode：所有 Layout 调用都发生在同一个
// goroutine 上。core 的事件是通过 channel 送进来的，
// 因此在 UI goroutine 里消费 channel 是安全的；
// 但**绝不能**在 Layout 里阻塞地等 channel——
// 那会直接冻结界面。做法见 drainEvents。
type uiState struct {
	opts    Options
	theme   *material.Theme
	shaper  *text.Shaper
	win     *app.Window
	fontMsg string

	// 界面状态（仅 UI goroutine 访问）。
	selected    string // 当前会话的对端 ID
	composer    widget.Editor
	composerOK  bool
	contactList widget.List
	msgList     widget.List

	// 最近一次操作错误，显示在顶部。
	banner    string
	bannerErr bool

	// 收到新消息时把列表滚到底部。
	scrollToEnd bool

	// sendBtn 是发送按钮的点击状态。
	//
	// ⚠️ 必须是**持久**字段，不能每帧 new 一个。
	// Gio 的 Clickable 需要跨帧保持状态才能识别点击；
	// 每帧新建会让按钮永远收不到点击（表现为"点了没反应"）。
	sendBtn widget.Clickable

	// rowClicks 是联系人列表每一行的点击状态。
	//
	// ⚠️ 同样必须持久，且**按行索引**保存。
	// 早期版本在 contactRow 里 `click := &widget.Clickable{}`，
	// 导致整个联系人列表都点不动、右侧聊天区永远不出现。
	rowClicks []widget.Clickable

	// emojiAck 是"我确认这组 emoji 与对方一致"按钮。
	emojiAck widget.Clickable

	// verifying 是当前正在做 emoji 二次确认的对端 ID。
	verifying string

	// showEmojiDetail 控制是否展开完整的 12 字节 SAS 十六进制。
	showEmojiDetail bool

	// su 是配置向导的可变状态（创建 / 导入 / 解锁）。
	su setupState

	// appStartErr 记录组装 App 失败的原因（端口占用、mDNS 起不来）。
	//
	// 与 su.errMsg 分开：那是"用户输入有问题"，
	// 这是"环境有问题"，处置方式不同。
	appStartErr string

	// showInfo 控制配置信息面板。
	showInfo bool

	// showAddContact 控制"添加联系人"面板。
	showAddContact bool

	// ac 是添加联系人面板的状态。
	ac addContactState

	// infoScroll 让配置信息面板可以滚动。
	infoScroll widget.List

	// 面板入口按钮（必须跨帧持久，见 setupState 的注释）。
	btnAddContact widget.Clickable
	btnInfo       widget.Clickable
	panelClose    widget.Clickable

	// info 是配置信息面板的状态。
	info infoState
}

func newState(opts Options) *uiState {
	coll, fontPath, fontErrs := loadFonts()
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(coll))

	fontMsg := "中文字体: 未加载，中文可能显示为方块"
	if fontPath != "" {
		fontMsg = "中文字体: " + base(fontPath)
	}
	if len(fontErrs) > 0 {
		opts.Logf("ui: font parse errors: %s", strings.Join(fontErrs, "; "))
	}
	// 字体缺失必须**说出来**：否则用户只会看到满屏方块，
	// 不会想到是缺字体。
	if fontPath == "" {
		opts.Logf("ui: WARNING no CJK font found; Chinese text will render as tofu boxes")
	} else {
		opts.Logf("ui: %s", fontMsg)
	}

	a := &uiState{
		opts:    opts,
		theme:   th,
		shaper:  th.Shaper,
		fontMsg: fontMsg,
	}
	a.composer.SingleLine = false
	a.composer.Submit = true
	a.contactList.Axis = layout.Vertical
	a.msgList.Axis = layout.Vertical
	a.infoScroll.Axis = layout.Vertical
	return a
}

func (a *uiState) run() error {
	a.win = new(app.Window)
	a.win.Option(
		app.Title(a.opts.Title),
		app.Size(unit.Dp(1000), unit.Dp(680)),
		app.MinSize(unit.Dp(560), unit.Dp(420)),
	)

	go func() {
		if err := a.loop(); err != nil {
			a.opts.Logf("ui: loop failed: %v", err)
			os.Exit(1)
		}
		// 窗口关闭即退出进程。core 的清理在 main 里通过 defer 完成，
		// 但这里必须先让事件循环结束。
		os.Exit(0)
	}()

	app.Main()
	return nil
}

func (a *uiState) loop() error {
	var ops op.Ops
	for {
		switch e := a.win.Event().(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			// 配置阶段先行：它可能在后台生成密钥、
			// 并在就绪后组装 App。
			a.pumpSetup()
			// 先排空 core 事件，再绘制——顺序很重要：
			// 若先绘制再排空，界面会永远比状态慢一帧，
			// 表现为"刚发的消息要碰一下窗口才出现"。
			a.drainEvents()
			a.layout(gtx)
			e.Frame(gtx.Ops)

			// 后台操作进行中时必须主动请求下一帧，
			// 否则界面停在"正在生成密钥…"，等用户动鼠标才更新。
			if a.su.busy {
				a.win.Invalidate()
			}
		}
	}
}

// drainEvents 非阻塞地消费 core 事件。
//
// 必须**非阻塞**：core.Events() 是带缓冲的 channel，
// 若这里用 for range 或阻塞 receive，界面会在无事件时卡死。
func (a *uiState) drainEvents() {
	if a.opts.App == nil {
		return
	}
	for {
		select {
		case ev, ok := <-a.opts.App.Events():
			if !ok {
				return
			}
			a.handleEvent(ev)
		default:
			return
		}
	}
}

func (a *uiState) handleEvent(ev core.Event) {
	switch e := ev.(type) {
	case core.MessageReceived:
		if a.selected == "" {
			// 收到消息但还没选中会话：自动切过去，
			// 免得用户"听到提示音却找不到消息在哪"。
			a.selected = e.Message.PeerID
		}
		a.scrollToEnd = true

	case core.MessageSent:
		a.scrollToEnd = true

	case core.MessageFailed:
		a.banner = "发送失败: " + e.Err.Error()
		a.bannerErr = true

	case core.SessionStateChanged:
		if e.Status == core.StatusFailed && e.Err != nil {
			a.banner = "会话失败: " + e.Err.Error()
			a.bannerErr = true
		}

	case core.LogEvent:
		if e.Level >= core.LogWarn {
			a.banner = e.Message
			a.bannerErr = e.Level == core.LogError
		}
		a.opts.Logf("core: %s", e.Message)

	case core.ContactsChanged:
		// 快照是即时读取的，这里无需缓存，只需重绘。
	}
}

// layout 绘制一帧。
//
// 结构（方案 C）：
//
//	┌──────────────────────────────────────────┐
//	│ 常驻信任条（色带 + 状态 + 本机指纹）        │  ← 不可折叠
//	├────────────┬─────────────────────────────┤
//	│ 联系人列表  │ 会话（标题药丸 / 核对面板 /   │
//	│            │       消息流 / 输入框）       │
//	├────────────┴─────────────────────────────┤
//	│ 状态栏（字体状态 / 最近错误）              │
//	└──────────────────────────────────────────┘
func (a *uiState) layout(gtx layout.Context) {
	// 身份尚未就绪：整体让位给配置向导。
	if a.opts.App == nil {
		a.layoutSetup(gtx)
		return
	}

	fillRect(gtx, colorBackground, gtx.Constraints.Max)

	contacts := a.opts.App.Snapshot()

	layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.trustBar(gtx, contacts)
		}),
		layout.Rigid(vLineH),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return a.body(gtx, contacts)
		}),
		layout.Rigid(vLineH),
		layout.Rigid(a.statusBar),
	)

	// 浮层最后画，压在主体之上。
	a.overlay(gtx)
}

// body 是主体：左栏联系人，右栏会话。
func (a *uiState) body(gtx layout.Context, contacts []core.Contact) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			w := gtx.Dp(unit.Dp(sidebarWidthDp))
			gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
			return a.sidebar(gtx, contacts)
		}),
		layout.Rigid(vLineV),
		layout.Flexed(1, a.conversation),
	)
}

// sidebar 是联系人列表。
func (a *uiState) sidebar(gtx layout.Context, contacts []core.Contact) layout.Dimensions {
	fillRect(gtx, colorSurface, gtx.Constraints.Max)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// 分组标题。用大写字母 + 字距做出"页眉"感，
			// 与可点的联系人行区分开（页眉不可点）。
			inset := layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(6), Left: unit.Dp(16), Right: unit.Dp(16)}
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						lbl := material.Caption(a.theme, "联系人")
						lbl.Color = colorFaint
						return lbl.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						lbl := material.Caption(a.theme, fmt.Sprintf("%d", len(contacts)))
						lbl.Color = colorFaint
						return lbl.Layout(gtx)
					}),
				)
			})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			if len(contacts) == 0 {
				return a.emptyContacts(gtx)
			}
			return a.contactRows(gtx, contacts)
		}),
	)
}

// emptyContacts 是"没有联系人"时的空状态。
//
// 必须告诉用户**下一步做什么**，而不是只写"暂无数据"：
// 本工具没有服务器、没有账号体系，用户不主动与对方交换公钥，
// 就永远不会出现联系人——这与其他聊天软件的心智模型完全不同。
func (a *uiState) emptyContacts(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(16), Left: unit.Dp(16), Right: unit.Dp(16)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(a.theme, emptyContactsText())
				lbl.Color = colorMuted
				return lbl.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.emptySteps(gtx)
			}),
		)
	})
}

// emptySteps 给出具体的三步操作指引。
//
// 只写"交换公钥"用户不知道**怎么**交换。这里直接给命令，
// 因为目标用户就是愿意用命令行的人。
func (a *uiState) emptySteps(gtx layout.Context) layout.Dimensions {
	steps := []string{
		"1. 让对方运行 keytalk -setup",
		"2. 把他的 public.key 发给你",
		"3. keytalk -contact <公钥文件>",
	}
	children := make([]layout.FlexChild, 0, len(steps)*2)
	for i, st := range steps {
		if i > 0 {
			children = append(children, layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout))
		}
		text := st
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Caption(a.theme, text)
			lbl.Color = colorAccent
			lbl.Font.Typeface = "monospace"
			return lbl.Layout(gtx)
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// emptyContactsText 是"没有联系人"时的说明文案。
//
// 抽成函数是为了能被单测直接断言（见 fonts_test.go）。
// 这段文案必须回答"我下一步该做什么"——本工具没有服务器、
// 没有账号体系，用户不主动交换公钥就永远不会有联系人，
// 这与其他聊天软件的心智模型完全不同。
func emptyContactsText() string {
	return "还没有联系人。\n\n" +
		"本工具没有中心服务器，也没有账号。\n" +
		"需要与对方当面（或通过可信渠道）\n" +
		"交换公钥、核对指纹之后才能通信。\n\n" +
		"这样做是为了让「对方是谁」这件事\n" +
		"由你们两人确认，而不是由服务器断言。"
}

// contactRows 绘制联系人列表。
func (a *uiState) contactRows(gtx layout.Context, contacts []core.Contact) layout.Dimensions {
	// 联系人行数变化时同步行点击状态。
	//
	// ⚠️ Clickable **必须**跨帧持久（见 docs/ui-gio.md §5.3.1）：
	// 每帧 new 一个会让它永远收不到点击，表现为"点联系人没反应、
	// 右侧聊天区永远不出现"。这正是本文件早期版本的真实缺陷。
	if len(a.rowClicks) != len(contacts) {
		if len(a.rowClicks) < len(contacts) {
			grown := make([]widget.Clickable, len(contacts))
			copy(grown, a.rowClicks)
			a.rowClicks = grown
		} else {
			a.rowClicks = a.rowClicks[:len(contacts)]
		}
	}

	return material.List(a.theme, &a.contactList).Layout(gtx, len(contacts),
		func(gtx layout.Context, i int) layout.Dimensions {
			c := contacts[i]
			return a.contactRow(gtx, c, &a.rowClicks[i])
		})
}

func (a *uiState) contactRow(gtx layout.Context, c core.Contact, click *widget.Clickable) layout.Dimensions {
	selected := c.ID == a.selected

	// 整行可点：点击区域覆盖整行，而不是只有文字。
	// 那是最基本的可用性要求——聊天软件里点不到行会让人烦躁。
	if click.Clicked(gtx) {
		a.selected = c.ID
		// 主动尝试建立会话。core 会按角色规则决定是否真的发起，
		// 因此这里重复调用是安全的。
		if err := a.opts.App.StartChat(c.ID); err != nil {
			a.banner = "无法开始会话: " + err.Error()
			a.bannerErr = true
		}
	}

	level := trustOf(c)

	bg := colorSurface
	if selected {
		bg = colorRaised
	}

	return click.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		h := gtx.Dp(unit.Dp(56))
		fillRect(gtx, bg, image.Pt(gtx.Constraints.Max.X, h))

		// 选中行左侧加一条强调色竖条，代替边框。
		// 边框会让列表显得拥挤，竖条更轻。
		if selected {
			fillRect(gtx, colorAccent, image.Pt(gtx.Dp(unit.Dp(2)), h))
		}

		inset := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(14), Right: unit.Dp(14)}
		return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Right: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return a.trustDot(gtx, level)
					})
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body1(a.theme, c.Name)
							lbl.Color = colorText
							return lbl.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							// 显示**信任**标签而不是连接标签。
							// 用户更关心"我能不能信这个人"，
							// 而不是"TCP 连上没有"。
							lbl := material.Caption(a.theme, trustPhraseShort(level))
							lbl.Color = trustColor(level)
							return lbl.Layout(gtx)
						}),
					)
				}),
			)
		})
	})
}

// trustDot 画一个信任状态圆点。
//
// 已核实用实心 + 双环（"盖章"的观感），未核实用空心环。
// 实心/空心的差别在没有颜色的情况下也成立——
// 色觉障碍用户同样能分辨。
func (a *uiState) trustDot(gtx layout.Context, level TrustLevel) layout.Dimensions {
	d := gtx.Dp(unit.Dp(10))
	col := trustColor(level)

	if level == TrustVerified {
		paint.FillShape(gtx.Ops, col, clip.Ellipse{
			Min: image.Pt(0, 0), Max: image.Pt(d, d),
		}.Op(gtx.Ops))
		return layout.Dimensions{Size: image.Pt(d, d)}
	}

	// 空心环：画外圆，再挖内圆。
	const ringPx = 2
	paint.FillShape(gtx.Ops, col, clip.Ellipse{
		Min: image.Pt(0, 0), Max: image.Pt(d, d),
	}.Op(gtx.Ops))
	paint.FillShape(gtx.Ops, colorSurface, clip.Ellipse{
		Min: image.Pt(ringPx, ringPx), Max: image.Pt(d-ringPx, d-ringPx),
	}.Op(gtx.Ops))
	return layout.Dimensions{Size: image.Pt(d, d)}
}

// trustPhraseShort 是联系人行下方的短表述。
func trustPhraseShort(l TrustLevel) string {
	switch l {
	case TrustVerified:
		return "已核实身份"
	case TrustUnverified:
		return "未核实身份"
	case TrustFailed:
		return "连接失败"
	default:
		return "离线"
	}
}

// conversation 是右侧会话区。
func (a *uiState) conversation(gtx layout.Context) layout.Dimensions {
	// 没有任何联系人时，整个右侧显示引导页而不是"请选择联系人"。
	// 后者在联系人列表为空时是一句没有意义的话：
	// 用户根本无从选择，需要的是"怎么才能有联系人"。
	if len(a.opts.App.Snapshot()) == 0 {
		return a.onboarding(gtx)
	}

	if a.selected == "" {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body1(a.theme, "从左侧选择一位联系人开始对话")
			lbl.Color = colorFaint
			return lbl.Layout(gtx)
		})
	}

	c, ok := a.opts.App.Contact(a.selected)
	if !ok {
		a.selected = ""
		return layout.Dimensions{}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.convHeader(gtx, c) }),
		layout.Rigid(vLineH),
		// emoji 二次确认面板：会话已建立但用户尚未核对时显示在最上方。
		// 放在消息流**之上**而不是折叠起来——核对的可见性
		// 直接决定它会不会真的发生。
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if c.Status != core.StatusSecure {
				return layout.Dimensions{}
			}
			return a.verifyPanel(gtx, c)
		}),
		layout.Rigid(vLineH),
		layout.Flexed(1, a.messageList),
		layout.Rigid(vLineH),
		layout.Rigid(a.composerArea),
	)
}

func (a *uiState) convHeader(gtx layout.Context, c core.Contact) layout.Dimensions {
	level := trustOf(c)

	inset := layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(20), Right: unit.Dp(20)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fillRect(gtx, colorSurface, gtx.Constraints.Max)
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						lbl := material.Body1(a.theme, c.Name)
						lbl.Color = colorText
						return lbl.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// 指纹直接显示在会话标题下。用户核对指纹时
						// 不必再去翻设置——那一步越省事，越可能真的被做。
						lbl := material.Caption(a.theme, c.Fingerprint.Display())
						lbl.Color = colorFaint
						lbl.Font.Typeface = "monospace"
						lbl.TextSize = unit.Sp(10)
						return lbl.Layout(gtx)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.trustPill(gtx, level)
			}),
		)
	})
}

func (a *uiState) messageList(gtx layout.Context) layout.Dimensions {
	msgs := a.opts.App.Messages(a.selected)
	if len(msgs) == 0 {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			msg := "还没有消息。"
			if c, ok := a.opts.App.Contact(a.selected); ok && c.Status != core.StatusSecure {
				msg = "会话尚未建立。\n双方都在线时会自动完成加密握手。"
			}
			lbl := material.Body2(a.theme, msg)
			lbl.Color = colorMuted
			return lbl.Layout(gtx)
		})
	}

	return material.List(a.theme, &a.msgList).Layout(gtx, len(msgs),
		func(gtx layout.Context, i int) layout.Dimensions {
			return a.bubble(gtx, msgs[i])
		})
}

// bubble 绘制一条消息气泡。
//
// 方案 C 的第二条硬规则：**未核实身份时每条消息都带可见标记**。
//
// 理由：把信任状态只放在顶部会被忽略——用户读消息时不看顶部。
// 把一条 3px 的色带贴在气泡边缘，用户在阅读内容时无法避开它。
// 这比任何弹出提示都更有效，因为它不打断操作，也就不会被关掉。
func (a *uiState) bubble(gtx layout.Context, m core.Message) layout.Dimensions {
	level := a.trustFor(m.PeerID)

	inset := layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4), Left: unit.Dp(16), Right: unit.Dp(16)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		align := layout.Start
		if m.Outgoing {
			align = layout.End
		}

		return layout.Flex{Axis: layout.Vertical, Alignment: align}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				maxW := gtx.Dp(unit.Dp(maxBubbleWidthDp))
				if gtx.Constraints.Max.X > maxW {
					gtx.Constraints.Max.X = maxW
				}
				return a.bubbleCard(gtx, m, level)
			}),
		)
	})
}

// trustFor 返回某个会话当前的信任等级（未知会话按"未知"处理）。
func (a *uiState) trustFor(peerID string) TrustLevel {
	c, ok := a.opts.App.Contact(peerID)
	if !ok {
		return TrustUnknown
	}
	return trustOf(c)
}

func (a *uiState) bubbleCard(gtx layout.Context, m core.Message, level TrustLevel) layout.Dimensions {
	bg := colorRaised
	fg := colorText
	if m.Outgoing {
		// 自己的消息用强调色的深色变体，而不是高饱和的强调色本身：
		// 满屏青色气泡会盖过信任色带，而那条色带才是重点。
		bg = color.NRGBA{R: 0x14, G: 0x3D, B: 0x39, A: 0xFF}
		fg = colorText
	}
	if m.Pending {
		// 待发送的消息降低不透明度——用户应当能看出
		// "这条还没真正发出去"，而不是以为已经送达。
		bg.A = 0x88
	}

	radius := gtx.Dp(unit.Dp(radiusCard))

	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fillRounded(gtx, bg, gtx.Constraints.Min, radius)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				// 信任色带：只在"未核实"和"失败"时出现。
				// 已核实不加标记——满屏绿线会让绿色变成噪音，
				// 反而削弱它在顶部信任条里的分量。
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if level == TrustVerified || level == TrustUnknown {
						return layout.Dimensions{}
					}
					return a.stripe(gtx, level)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					inset := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(14)}
					return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body1(a.theme, m.Text)
								lbl.Color = fg
								return lbl.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if level == TrustVerified || level == TrustUnknown {
									return layout.Dimensions{}
								}
								// 逐条标注"未核实"，而不是只在第一条上标。
								// 用户可能从中间开始翻阅，任何一条都应当
								// 自带这个信息。
								lbl := material.Caption(a.theme, trustLabel(level)+"身份")
								lbl.Color = trustColor(level)
								return lbl.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if m.State != core.MessageStateFailed {
									return layout.Dimensions{}
								}
								// 发送失败必须**逐条**标出来。
								//
								// 重启之后这些消息看起来与已发送的
								// 一模一样，不标就等于告诉用户
								// "对方收到了"——而这正是事实的反面。
								lbl := material.Caption(a.theme, "未发送（发送失败）")
								lbl.Color = colorErr
								return lbl.Layout(gtx)
							}),
						)
					})
				}),
			)
		},
	)
}

// stripe 画消息左侧的信任色带。
//
// 单独一个 layout 维度，宽度固定 3dp —— 用固定值与消息高度解耦，
// 避免内部布局返回的高度影响色带的观感。
func (a *uiState) stripe(gtx layout.Context, level TrustLevel) layout.Dimensions {
	w := gtx.Dp(unit.Dp(3))
	// 让色带至少有一个可见高度；父容器会把它拉伸到与内容同高。
	h := gtx.Constraints.Min.Y
	if h <= 0 {
		h = gtx.Dp(unit.Dp(20))
	}
	paint.FillShape(gtx.Ops, trustColor(level), clip.Rect{Max: image.Pt(w, h)}.Op())
	return layout.Dimensions{Size: image.Pt(w, h)}
}

// composerArea 是底部输入区。
//
// 输入框做成圆角"胶囊"，与圆角气泡保持同一套形状语言。
// 直接裸露一个矩形 Editor 会显得未完成。
func (a *uiState) composerArea(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(20), Right: unit.Dp(20)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fillRect(gtx, colorSurface, gtx.Constraints.Max)
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Background{}.Layout(gtx,
					func(gtx layout.Context) layout.Dimensions {
						m := op.Record(gtx.Ops)
						dims := a.editorContent(gtx)
						op.Defer(gtx.Ops, m.Stop())
						fillRounded(gtx, colorRaised, dims.Size, gtx.Dp(unit.Dp(radiusCard)))
						return dims
					},
					a.editorContent,
				)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.sendButton(gtx) }),
		)
	})
}

// editorContent 是输入框的内容层（带内边距）。
func (a *uiState) editorContent(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(9), Left: unit.Dp(14), Right: unit.Dp(14)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(20))
		ed := material.Editor(a.theme, &a.composer, "输入消息，回车发送")
		ed.Color = colorText
		ed.HintColor = colorFaint
		return ed.Layout(gtx)
	})
}

func (a *uiState) sendButton(gtx layout.Context) layout.Dimensions {
	c, ok := a.opts.App.Contact(a.selected)
	canSend := ok && c.Status == core.StatusSecure
	// 未核对 emoji 时**允许**发送，但按钮显示为警示状态。
	//
	// 为什么不直接禁用：本工具第一次通信时双方还没法核对，
	// 硬性阻断会让用户完全无法开始。产品上选择"允许但持续提醒"，
	// 并且状态栏诚实显示"未核实身份"。
	// 但同样是这个原因，界面**绝不能**在未核实时显示"已核实"。
	needsVerify := canSend && !c.Verified

	btn := &a.sendBtn
	sent := btn.Clicked(gtx) || a.composer.Submit

	if sent && canSend {
		text := a.composer.Text()
		a.composer.SetText("")
		if err := a.opts.App.SendText(a.selected, text); err != nil {
			a.banner = "发送失败: " + err.Error()
			a.bannerErr = true
		} else {
			a.scrollToEnd = true
		}
	}

	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		bc := colorAccent
		btnFg := color.NRGBA{R: 0x06, G: 0x1A, B: 0x17, A: 0xFF}
		label := "发送"
		if !canSend {
			// 会话未建立时**禁用**按钮并说明原因。
			// 允许点击然后报错，不如直接不让点——但必须
			// 让用户知道为什么不能点。
			bc = colorRaised
			btnFg = colorMuted
			label = "未连接"
		} else if needsVerify {
			bc = colorWarn
			// 深色字压在黄底上：黄底配白字几乎看不清。
			btnFg = color.NRGBA{R: 0x1F, G: 0x18, B: 0x0A, A: 0xFF}
			label = "发送（未核实）"
		}
		// 先量出内容尺寸，再用圆角底衬包裹。
		// 不能先画背景：Gio 里背景必须先知道尺寸，
		// 而尺寸由内容决定。
		inset := layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(9), Left: unit.Dp(18), Right: unit.Dp(18)}
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				// 背景层需要与内容同尺寸：借道一个宏来测量。
				m := op.Record(gtx.Ops)
				dims := inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(a.theme, label)
					lbl.Color = btnFg
					return lbl.Layout(gtx)
				})
				op.Defer(gtx.Ops, m.Stop())
				fillRounded(gtx, bc, dims.Size, gtx.Dp(unit.Dp(radiusCard)))
				return dims
			},
			func(gtx layout.Context) layout.Dimensions {
				return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(a.theme, label)
					lbl.Color = btnFg
					return lbl.Layout(gtx)
				})
			},
		)
	})
}

// statusBar 是底部状态栏：显示字体状态与最近的错误。
// statusBar 是底部状态栏。
//
// 显示两类信息，优先级：最近的错误 > 字体状态。
//
// 字体状态值得常驻：中文字体缺失会让整个界面变成方块，
// 而用户不会想到"是缺字体"。把这一条一直摆在底部，
// 出问题时用户能立刻看到原因，而不是以为程序坏了。
func (a *uiState) statusBar(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(20), Right: unit.Dp(20)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fillRect(gtx, colorSurface, gtx.Constraints.Max)

		text := a.fontMsg
		col := colorFaint
		if a.banner != "" {
			text = a.banner
			if a.bannerErr {
				col = colorErr
			} else {
				col = colorWarn
			}
		}

		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(a.theme, text)
				lbl.Color = col
				return lbl.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				// 持续提示"检查对方身份"这一动作的存在。
				// 放在状态栏而不是弹窗：弹窗会被关掉，
				// 而这件事需要反复被看到。
				lbl := material.Caption(a.theme, "核对 emoji = 确认对方身份")
				lbl.Color = colorFaint
				return lbl.Layout(gtx)
			}),
		)
	})
}

// ---- 绘制辅助 ----

// vLineV 画竖直分隔线。
func vLineV(gtx layout.Context) layout.Dimensions {
	h := gtx.Constraints.Max.Y
	if h <= 0 {
		h = gtx.Dp(unit.Dp(1))
	}
	w := gtx.Dp(unit.Dp(1))
	// 高度必须由父容器给出；若为 0（尚未确定），至少要占 1dp，
	// 否则这条线会消失。
	paint.FillShape(gtx.Ops, colorLine, clip.Rect{Max: image.Pt(w, h)}.Op())
	return layout.Dimensions{Size: image.Pt(w, h)}
}

// vLineH 画水平分隔线。
func vLineH(gtx layout.Context) layout.Dimensions {
	w := gtx.Constraints.Max.X
	if w <= 0 {
		w = gtx.Dp(unit.Dp(1))
	}
	h := gtx.Dp(unit.Dp(1))
	paint.FillShape(gtx.Ops, colorLine, clip.Rect{Max: image.Pt(w, h)}.Op())
	return layout.Dimensions{Size: image.Pt(w, h)}
}

func base(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}
