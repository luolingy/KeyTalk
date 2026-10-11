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

// Palette 是界面配色。
//
// 深色为主：聊天工具长时间停留在屏幕上，浅色更刺眼；
// 且深色更容易让人一眼看出"这是通信工具"而非文档编辑器。
// 这里避免纯黑（#000）与纯白文字——高对比在低质量面板上会发糊。
var (
	colorBackground = color.NRGBA{R: 0x12, G: 0x14, B: 0x19, A: 0xFF}
	colorSurface    = color.NRGBA{R: 0x1B, G: 0x1E, B: 0x25, A: 0xFF}
	colorSurfaceAlt = color.NRGBA{R: 0x22, G: 0x26, B: 0x2E, A: 0xFF}
	colorLine       = color.NRGBA{R: 0x2A, G: 0x2F, B: 0x3A, A: 0xFF}
	colorPrimary    = color.NRGBA{R: 0x4C, G: 0x8B, B: 0xF5, A: 0xFF}
	colorText       = color.NRGBA{R: 0xE6, G: 0xE8, B: 0xEC, A: 0xFF}
	colorMuted      = color.NRGBA{R: 0x8B, G: 0x92, B: 0xA1, A: 0xFF}
	colorOK         = color.NRGBA{R: 0x4A, G: 0xD9, B: 0x91, A: 0xFF}
	colorWarn       = color.NRGBA{R: 0xF5, G: 0xB8, B: 0x4C, A: 0xFF}
	colorErr        = color.NRGBA{R: 0xF0, G: 0x6A, B: 0x6A, A: 0xFF}
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

	// Title 是窗口标题。
	Title string
}

// Run 创建窗口并进入事件循环，**阻塞**到窗口关闭。
//
// 调用方（main）必须让 app.Main() 在自身 goroutine 上运行，
// 因此本函数应当在单独的 goroutine 里调用，或者由 Run 负责启动
// app.Main()（当前采用后者，见下）。
func Run(opts Options) error {
	if opts.App == nil {
		return fmt.Errorf("ui: Options.App is required")
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
			// 先排空 core 事件，再绘制——顺序很重要：
			// 若先绘制再排空，界面会永远比状态慢一帧，
			// 表现为"刚发的消息要碰一下窗口才出现"。
			a.drainEvents()
			a.layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

// drainEvents 非阻塞地消费 core 事件。
//
// 必须**非阻塞**：core.Events() 是带缓冲的 channel，
// 若这里用 for range 或阻塞 receive，界面会在无事件时卡死。
func (a *uiState) drainEvents() {
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
func (a *uiState) layout(gtx layout.Context) {
	fill(gtx, colorBackground)

	layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(a.header),
		layout.Rigid(vLineH),
		layout.Flexed(1, a.body),
		layout.Rigid(vLineH),
		layout.Rigid(a.statusBar),
	)
}

// header 是顶部栏：应用名 + 本机指纹。
//
// 指纹放在**显眼位置**而不是设置页里：带外核对指纹是防中间人的
// 唯一手段，藏起来等于鼓励用户跳过它。
func (a *uiState) header(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(16), Right: unit.Dp(16)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fill(gtx, colorSurface)
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.H6(a.theme, "KeyTalk")
				lbl.Color = colorPrimary
				return lbl.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(14)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(a.theme, "本机指纹 "+a.opts.App.Fingerprint().Display())
				lbl.Color = colorMuted
				lbl.Font.Typeface = "monospace"
				return lbl.Layout(gtx)
			}),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Dimensions{}
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(a.theme, "端到端加密 · 局域网直连")
				lbl.Color = colorMuted
				return lbl.Layout(gtx)
			}),
		)
	})
}

// body 是主体：左栏联系人，右栏会话。
func (a *uiState) body(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			w := gtx.Dp(unit.Dp(260))
			gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
			return a.sidebar(gtx)
		}),
		layout.Rigid(vLineV),
		layout.Flexed(1, a.conversation),
	)
}

// sidebar 是联系人列表。
func (a *uiState) sidebar(gtx layout.Context) layout.Dimensions {
	fill(gtx, colorSurface)
	contacts := a.opts.App.Snapshot()

	inset := layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(10), Right: unit.Dp(10)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(a.theme, fmt.Sprintf("联系人 (%d)", len(contacts)))
				lbl.Color = colorMuted
				return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, lbl.Layout)
			}),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				if len(contacts) == 0 {
					return a.emptyContacts(gtx)
				}
				return a.contactRows(gtx, contacts)
			}),
		)
	})
}

// emptyContacts 是"没有联系人"时的空状态。
//
// 必须告诉用户**下一步做什么**，而不是只写"暂无数据"：
// 本工具没有服务器、没有账号体系，用户不主动与对方交换公钥，
// 就永远不会出现联系人——这与其他聊天软件的心智模型完全不同。
func (a *uiState) emptyContacts(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		lbl := material.Body2(a.theme, emptyContactsText())
		lbl.Color = colorMuted
		return lbl.Layout(gtx)
	})
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
	return material.List(a.theme, &a.contactList).Layout(gtx, len(contacts),
		func(gtx layout.Context, i int) layout.Dimensions {
			c := contacts[i]
			return a.contactRow(gtx, c)
		})
}

func (a *uiState) contactRow(gtx layout.Context, c core.Contact) layout.Dimensions {
	selected := c.ID == a.selected

	// 整行可点：点击区域覆盖整行，而不是只有文字。
	// 那是最基本的可用性要求——聊天软件里点不到行会让人烦躁。
	click := &widget.Clickable{}
	if click.Clicked(gtx) {
		a.selected = c.ID
		// 主动尝试建立会话。core 会按角色规则决定是否真的发起，
		// 因此这里重复调用是安全的。
		if err := a.opts.App.StartChat(c.ID); err != nil {
			a.banner = "无法开始会话: " + err.Error()
			a.bannerErr = true
		}
	}

	bg := colorSurface
	if selected {
		bg = colorSurfaceAlt
	}

	return click.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fill(gtx, bg)
		inset := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(8), Right: unit.Dp(8)}
		return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return a.statusDot(gtx, c.Status)
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
							lbl := material.Caption(a.theme, statusLabel(c.Status))
							lbl.Color = statusColor(c.Status)
							return lbl.Layout(gtx)
						}),
					)
				}),
			)
		})
	})
}

// statusDot 画一个状态圆点。
func (a *uiState) statusDot(gtx layout.Context, st core.ContactStatus) layout.Dimensions {
	d := gtx.Dp(unit.Dp(9))
	paint.FillShape(gtx.Ops, statusColor(st), clip.Ellipse{
		Min: image.Pt(0, 0), Max: image.Pt(d, d),
	}.Op(gtx.Ops))
	return layout.Dimensions{Size: image.Pt(d, d)}
}

func statusColor(st core.ContactStatus) color.NRGBA {
	switch st {
	case core.StatusSecure:
		return colorOK
	case core.StatusOnline:
		return colorPrimary
	case core.StatusFailed:
		return colorErr
	default:
		return colorMuted
	}
}

func statusLabel(st core.ContactStatus) string {
	switch st {
	case core.StatusSecure:
		return "已加密"
	case core.StatusOnline:
		return "在线 · 握手中"
	case core.StatusFailed:
		return "失败"
	default:
		return "离线"
	}
}

// conversation 是右侧会话区。
func (a *uiState) conversation(gtx layout.Context) layout.Dimensions {
	if a.selected == "" {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body1(a.theme, "从左侧选择一位联系人开始对话")
			lbl.Color = colorMuted
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
		layout.Flexed(1, a.messageList),
		layout.Rigid(vLineH),
		layout.Rigid(a.composerArea),
	)
}

func (a *uiState) convHeader(gtx layout.Context, c core.Contact) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(16), Right: unit.Dp(16)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fill(gtx, colorSurface)
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body1(a.theme, c.Name)
				lbl.Color = colorText
				return lbl.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				// 指纹直接显示在会话标题下。用户核对指纹时
				// 不必再去翻设置——那一步越省事，越可能真的被做。
				lbl := material.Caption(a.theme, c.Fingerprint.Display()+"  ·  "+statusLabel(c.Status))
				lbl.Color = colorMuted
				lbl.Font.Typeface = "monospace"
				return lbl.Layout(gtx)
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
func (a *uiState) bubble(gtx layout.Context, m core.Message) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(5), Bottom: unit.Dp(5), Left: unit.Dp(16), Right: unit.Dp(16)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		align := layout.Start
		if m.Outgoing {
			align = layout.End
		}

		return layout.Flex{Axis: layout.Vertical, Alignment: align}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				// 限制气泡最大宽度：占满整行会让长消息难以阅读，
				// 也让人分不清谁说的。
				maxW := gtx.Dp(unit.Dp(560))
				if gtx.Constraints.Max.X > maxW {
					gtx.Constraints.Max.X = maxW
				}
				return a.bubbleCard(gtx, m)
			}),
		)
	})
}

func (a *uiState) bubbleCard(gtx layout.Context, m core.Message) layout.Dimensions {
	bg := colorSurfaceAlt
	fg := colorText
	if m.Outgoing {
		bg = colorPrimary
		fg = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	}
	if m.Pending {
		// 待发送的消息降低不透明度——用户应当能看出
		// "这条还没真正发出去"，而不是以为已经送达。
		bg.A = 0x99
	}

	return layout.Background{}.Layout(gtx,
		// 背景层：只画底色，不产生尺寸。
		func(gtx layout.Context) layout.Dimensions {
			fill(gtx, bg)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		// 内容层。
		func(gtx layout.Context) layout.Dimensions {
			inset := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body1(a.theme, m.Text)
				lbl.Color = fg
				return lbl.Layout(gtx)
			})
		},
	)
}

// composerArea 是底部输入区。
func (a *uiState) composerArea(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(16), Right: unit.Dp(16)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fill(gtx, colorSurface)
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(38))
				ed := material.Editor(a.theme, &a.composer, "输入消息，回车发送")
				ed.Color = colorText
				ed.HintColor = colorMuted
				return ed.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.sendButton(gtx) }),
		)
	})
}

func (a *uiState) sendButton(gtx layout.Context) layout.Dimensions {
	c, ok := a.opts.App.Contact(a.selected)
	canSend := ok && c.Status == core.StatusSecure

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
		bc := colorPrimary
		label := "发送"
		if !canSend {
			// 会话未建立时**禁用**按钮并说明原因。
			// 允许点击然后报错，不如直接不让点——但必须
			// 让用户知道为什么不能点。
			bc = colorSurfaceAlt
			label = "未连接"
		}
		fill(gtx, bc)
		inset := layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(9), Left: unit.Dp(18), Right: unit.Dp(18)}
		dims := inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body2(a.theme, label)
			if canSend {
				lbl.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
			} else {
				lbl.Color = colorMuted
			}
			return lbl.Layout(gtx)
		})
		return dims
	})
}

// statusBar 是底部状态栏：显示字体状态与最近的错误。
func (a *uiState) statusBar(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(5), Bottom: unit.Dp(5), Left: unit.Dp(16), Right: unit.Dp(16)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fill(gtx, colorSurface)
		text := a.fontMsg
		col := colorMuted
		if a.banner != "" {
			text = a.banner
			if a.bannerErr {
				col = colorErr
			} else {
				col = colorWarn
			}
		}
		lbl := material.Caption(a.theme, text)
		lbl.Color = col
		return lbl.Layout(gtx)
	})
}

// ---- 绘制辅助 ----

// fill 用纯色填满当前约束区域。
//
// Gio 没有"填充背景"原语：惯用做法是画一个与可用空间等大的矩形。
// 必须用 Max 而非 Min——Min 在 Flexed 布局里可能是 0。
func fill(gtx layout.Context, c color.NRGBA) {
	sz := gtx.Constraints.Max
	if sz.X <= 0 || sz.Y <= 0 {
		return
	}
	paint.FillShape(gtx.Ops, c, clip.Rect{Max: sz}.Op())
}

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
