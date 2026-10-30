package ui

import (
	"errors"
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/exeliang/keytalk/internal/core"
	"github.com/exeliang/keytalk/internal/crypto"
)

// setupState 是首次配置界面的可变状态。
//
// ⚠️ 所有输入框与按钮都**必须跨帧持久**。
// 每帧新建 widget.Editor / widget.Clickable 会让输入与点击
// 全部失效——本项目在联系人列表上已经踩过一次这个坑
// （见 docs/ui-gio.md §5.3.1）。
type setupState struct {
	// tab: 0 = 创建新身份，1 = 导入已有身份。
	tab int

	nameEd   widget.Editor // 创建：显示名
	passEd   widget.Editor // 创建/导入/解锁：口令
	pass2Ed  widget.Editor // 创建：确认口令
	keyEd    widget.Editor // 导入：粘贴私钥
	inNameEd widget.Editor // 导入：显示名（可留空）

	tabCreate widget.Clickable
	tabImport widget.Clickable
	createBtn widget.Clickable
	importBtn widget.Clickable
	unlockBtn widget.Clickable
	retryBtn  widget.Clickable
	copyBtn   widget.Clickable

	busy   bool
	errMsg string
	okMsg  string

	// result 是后台操作的完成信号。
	// 生成 RSA 2048 要几百毫秒，必须放在 goroutine 里，
	// 否则界面会卡住一整帧（表现为"点了没反应"）。
	result chan error
}

// pendingAppErr 记录组装 App 失败的原因。
//
// 与 setupState.errMsg 分开：那是"用户输入有问题"，
// 这是"环境有问题"（端口被占、mDNS 起不来），
// 两者的处置方式不同。
type appStartError struct {
	msg string
}

func (a *uiState) layoutSetup(gtx layout.Context) {
	fillRect(gtx, colorBackground, gtx.Constraints.Max)

	layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(a.setupTopBar),
		layout.Rigid(vLineH),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.setupCard(gtx)
			})
		}),
		layout.Rigid(vLineH),
		layout.Rigid(a.statusBar),
	)
}

// setupTopBar 说明"为什么先看到这一页"。
func (a *uiState) setupTopBar(gtx layout.Context) layout.Dimensions {
	height := gtx.Dp(unit.Dp(trustBarHeightDp))
	fillRect(gtx, colorSurface, image.Pt(gtx.Constraints.Max.X, height))

	stage := a.setupStage()
	col := colorTrustUnverified
	text := "首次使用 —— 需要先建立一个身份"
	if stage == core.StageNeedsUnlock {
		text = "身份已加密 —— 需要口令解锁"
	}

	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			fillRect(gtx, col, image.Pt(gtx.Dp(unit.Dp(4)), height))
			return layout.Dimensions{Size: image.Pt(gtx.Dp(unit.Dp(4)), height)}
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body2(a.theme, text)
			lbl.Color = colorText
			return lbl.Layout(gtx)
		}),
	)
}

func (a *uiState) setupStage() core.SetupStage {
	if a.opts.Setup == nil {
		return core.StageReady
	}
	return a.opts.Setup.Stage()
}

// setupCard 是居中的表单卡片。
func (a *uiState) setupCard(gtx layout.Context) layout.Dimensions {
	maxW := gtx.Dp(unit.Dp(520))
	if gtx.Constraints.Max.X > maxW {
		gtx.Constraints.Max.X = maxW
	}
	// 允许纵向滚动：窄窗口下表单会超出可见区域。
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			m := op.Record(gtx.Ops)
			dims := a.setupCardContent(gtx)
			m.Stop() // 仅用于测量尺寸；不要 Defer——那会重放内容
			fillRounded(gtx, colorSurface, dims.Size, gtx.Dp(unit.Dp(radiusCard)))
			return dims
		},
		a.setupCardContent,
	)
}

func (a *uiState) setupCardContent(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(24), Bottom: unit.Dp(24), Left: unit.Dp(28), Right: unit.Dp(28)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		if a.opts.Setup == nil {
			return a.setupHint(gtx, "界面未提供配置阶段，请用命令行创建身份。")
		}

		// 组装 App 失败：只显示错误与重试，不再显示表单——
		// 否则用户会以为要重新输入一遍。
		if a.appStartErr != "" {
			return a.setupAppError(gtx)
		}

		switch a.setupStage() {
		case core.StageNeedsUnlock:
			return a.unlockForm(gtx)
		default:
			return a.identityForm(gtx)
		}
	})
}

// --- 创建 / 导入 ---

func (a *uiState) identityForm(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.H6(a.theme, "你的身份")
			lbl.Color = colorText
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "身份就是本机生成的这对密钥。没有服务器，也没有账号——"+
				"指纹就是你在别人眼里的唯一标识。")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.setupTabs(gtx) }),
		layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if a.su.tab == 0 {
				return a.createForm(gtx)
			}
			return a.importForm(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.setupMessages(gtx) }),
	)
}

func (a *uiState) setupTabs(gtx layout.Context) layout.Dimensions {
	tab := func(click *widget.Clickable, label string, idx int) layout.FlexChild {
		return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			active := a.su.tab == idx
			if click.Clicked(gtx) {
				a.su.tab = idx
				a.su.errMsg = ""
				a.su.okMsg = ""
			}
			bg := colorRaised
			fg := colorMuted
			if active {
				bg = color.NRGBA{R: 0x14, G: 0x3D, B: 0x39, A: 0xFF}
				fg = colorAccent
			}
			return a.button(gtx, click, bg, fg, label, false,
				layout.Inset{Top: unit.Dp(7), Bottom: unit.Dp(7), Left: unit.Dp(14), Right: unit.Dp(14)})
		})
	}
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		tab(&a.su.tabCreate, "创建新身份", 0),
		layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
		tab(&a.su.tabImport, "导入已有身份", 1),
	)
}

func (a *uiState) createForm(gtx layout.Context) layout.Dimensions {
	busy := a.su.busy

	submit := a.su.createBtn.Clicked(gtx)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &a.su.nameEd, "显示名", "例如 alice", 0, false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &a.su.passEd, "口令", "至少 12 个字符", '•', false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &a.su.pass2Ed, "确认口令", "再输一遍", '•', false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "口令用于加密磁盘上的私钥。"+
				"它只在这里使用，不会被发送，也无法找回——忘记了就只能重新生成身份。")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			label := "生成身份"
			if busy {
				label = "正在生成密钥…"
			}
			return a.button(gtx, &a.su.createBtn, colorAccent, color.NRGBA{R: 0x06, G: 0x1A, B: 0x17, A: 0xFF},
				label, !busy,
				layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(24), Right: unit.Dp(24)})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if submit && !busy {
				a.submitCreate()
			}
			return layout.Dimensions{}
		}),
	)
}

func (a *uiState) importForm(gtx layout.Context) layout.Dimensions {
	busy := a.su.busy
	submit := a.su.importBtn.Clicked(gtx)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "把备份的私钥内容（-----BEGIN PGP PRIVATE KEY BLOCK----- 开头）"+
				"整段粘贴到下面。换机器、重装系统后用它恢复同一个指纹。")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &a.su.keyEd, "私钥内容", "粘贴 armored 私钥", 0, true)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &a.su.inNameEd, "显示名（可留空）", "留空则从密钥里读取", 0, false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &a.su.passEd, "新口令", "用于加密导入后的私钥", '•', false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			label := "导入身份"
			if busy {
				label = "正在导入…"
			}
			return a.button(gtx, &a.su.importBtn, colorAccent, color.NRGBA{R: 0x06, G: 0x1A, B: 0x17, A: 0xFF},
				label, !busy,
				layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(24), Right: unit.Dp(24)})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if submit && !busy {
				a.submitImport()
			}
			return layout.Dimensions{}
		}),
	)
}

// --- 解锁 ---

func (a *uiState) unlockForm(gtx layout.Context) layout.Dimensions {
	busy := a.su.busy
	submit := a.su.unlockBtn.Clicked(gtx)

	meta := a.opts.Setup.Meta()

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.H6(a.theme, "解锁身份")
			lbl.Color = colorText
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if meta == nil {
				return layout.Dimensions{}
			}
			// 显示"正在解锁哪一个身份"：用户可能有多份备份，
			// 看不到指纹就无法判断打开的是不是对的那份。
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(a.theme, meta.Name)
					lbl.Color = colorText
					return lbl.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Caption(a.theme, meta.Fingerprint.Display())
					lbl.Color = colorFaint
					lbl.Font.Typeface = "monospace"
					return lbl.Layout(gtx)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &a.su.passEd, "口令", "解锁私钥", '•', false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			label := "解锁"
			if busy {
				label = "正在解锁…"
			}
			return a.button(gtx, &a.su.unlockBtn, colorAccent, color.NRGBA{R: 0x06, G: 0x1A, B: 0x17, A: 0xFF},
				label, !busy,
				layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(24), Right: unit.Dp(24)})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if submit && !busy {
				a.submitUnlock()
			}
			return layout.Dimensions{}
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.setupMessages(gtx) }),
	)
}

// --- 组装 App 失败 ---

func (a *uiState) setupAppError(gtx layout.Context) layout.Dimensions {
	retry := a.su.retryBtn.Clicked(gtx)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.H6(a.theme, "启动失败")
			lbl.Color = colorErr
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body2(a.theme, a.appStartErr)
			lbl.Color = colorMuted
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "身份本身没有问题，已经保存在数据目录里。"+
				"修好网络问题后重试即可，不需要重新生成。")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.button(gtx, &a.su.retryBtn, colorAccent, color.NRGBA{R: 0x06, G: 0x1A, B: 0x17, A: 0xFF},
				"重试", true,
				layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(24), Right: unit.Dp(24)})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if retry {
				a.appStartErr = ""
			}
			return layout.Dimensions{}
		}),
	)
}

// --- 小部件 ---

func (a *uiState) setupHint(gtx layout.Context, text string) layout.Dimensions {
	lbl := material.Caption(a.theme, text)
	lbl.Color = colorFaint
	return lbl.Layout(gtx)
}

// setupMessages 显示错误或成功提示。
func (a *uiState) setupMessages(gtx layout.Context) layout.Dimensions {
	if a.su.errMsg == "" && a.su.okMsg == "" {
		return layout.Dimensions{}
	}
	col := colorErr
	text := a.su.errMsg
	if a.su.errMsg == "" {
		col = colorTrustVerified
		text = a.su.okMsg
	}
	return layout.Inset{Top: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		lbl := material.Body2(a.theme, text)
		lbl.Color = col
		return lbl.Layout(gtx)
	})
}

// field 画一个带标签的输入框。
//
// mask 为 0 表示明文显示；口令字段传 '•'。
// multi 为 true 时允许多行（粘贴私钥/公钥用）。
func field(gtx layout.Context, th *material.Theme, ed *widget.Editor, label, hint string, mask rune, multi bool) layout.Dimensions {
	// Mask 与 SingleLine 都是 Editor 的公开字段，每帧设置是幂等的。
	ed.Mask = mask
	ed.SingleLine = !multi

	inset := layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(9), Left: unit.Dp(12), Right: unit.Dp(12)}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Caption(th, label)
			lbl.Color = colorMuted
			return layout.Inset{Bottom: unit.Dp(5)}.Layout(gtx, lbl.Layout)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Background{}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					m := op.Record(gtx.Ops)
					dims := inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(20))
						e := material.Editor(th, ed, hint)
						e.Color = colorText
						e.HintColor = colorFaint
						return e.Layout(gtx)
					})
					m.Stop() // 仅用于测量尺寸；不要 Defer——那会重放内容
					fillRounded(gtx, colorRaised, dims.Size, gtx.Dp(unit.Dp(radiusSmall)))
					return dims
				},
				func(gtx layout.Context) layout.Dimensions {
					return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(20))
						e := material.Editor(th, ed, hint)
						e.Color = colorText
						e.HintColor = colorFaint
						return e.Layout(gtx)
					})
				},
			)
		}),
	)
}

// button 画一个圆角按钮。
//
// enabled 为 false 时只改配色、仍然接收点击——调用方负责
// 在禁用状态下忽略 Clicked。刻意不做"真的禁用"：
// Gio 里让 Clickable 忽略点击需要额外状态，
// 而这里所有禁用场景都有 busy 标志兜底。
func (a *uiState) button(gtx layout.Context, click *widget.Clickable, bg, fg color.NRGBA,
	label string, enabled bool, inset layout.Inset) layout.Dimensions {

	if !enabled {
		bg = colorRaised
		fg = colorFaint
	}

	content := func(gtx layout.Context) layout.Dimensions {
		lbl := material.Body2(a.theme, label)
		lbl.Color = fg
		return lbl.Layout(gtx)
	}

	return click.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				m := op.Record(gtx.Ops)
				dims := inset.Layout(gtx, content)
				m.Stop() // 仅用于测量尺寸；不要 Defer——那会重放内容
				fillRounded(gtx, bg, dims.Size, gtx.Dp(unit.Dp(radiusCard)))
				return dims
			},
			func(gtx layout.Context) layout.Dimensions {
				return inset.Layout(gtx, content)
			},
		)
	})
}

// --- 后台操作 ---

// startOp 在后台执行一次可能耗时的配置操作。
//
// 为什么不直接同步执行：生成 RSA 2048 要几百毫秒，
// argon2id 也要几百毫秒。同步做会让界面在点击后整帧不动，
// 用户看到的是"点了没反应"，然后重复点击。
func (a *uiState) startOp(fn func() error) {
	if a.su.busy {
		return
	}
	a.su.busy = true
	a.su.errMsg = ""
	a.su.okMsg = ""

	ch := make(chan error, 1)
	a.su.result = ch
	go func() { ch <- fn() }()
}

// pollOp 非阻塞地收取后台操作结果。
func (a *uiState) pollOp() {
	if a.su.result == nil {
		return
	}
	select {
	case err := <-a.su.result:
		a.su.result = nil
		a.su.busy = false
		if err != nil {
			a.su.errMsg = setupErrText(err)
		}
	default:
	}
}

func (a *uiState) submitCreate() {
	name := a.su.nameEd.Text()
	pass := a.su.passEd.Text()
	if pass != a.su.pass2Ed.Text() {
		a.su.errMsg = "两次输入的口令不一致"
		return
	}
	setup := a.opts.Setup
	a.startOp(func() error { return setup.CreateIdentity(name, pass) })
}

func (a *uiState) submitImport() {
	key := a.su.keyEd.Text()
	pass := a.su.passEd.Text()
	name := a.su.inNameEd.Text()
	setup := a.opts.Setup
	a.startOp(func() error { return setup.ImportIdentity(key, pass, name) })
}

func (a *uiState) submitUnlock() {
	pass := a.su.passEd.Text()
	setup := a.opts.Setup
	a.startOp(func() error {
		if err := setup.Unlock(pass); err != nil {
			return err
		}
		// 解锁成功后立刻清掉输入框里的口令：
		// 界面上不该长时间留着一串明文口令。
		a.su.passEd.SetText("")
		return nil
	})
}

// setupErrText 把底层错误翻译成用户能懂的话。
//
// 底层错误里有 "crypto: wrong passphrase or corrupted keystore"
// 这种句子。直接显示等于没说——用户既不知道哪部分错了，
// 也不知道下一步该做什么。
func setupErrText(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, crypto.ErrWrongPassphrase):
		return "口令不正确（或者身份文件已被改动）。"
	case errors.Is(err, crypto.ErrKeystoreFormat), errors.Is(err, crypto.ErrKeystoreVersion):
		return "身份文件已损坏或被修改，无法读取。请用备份重新导入。"
	}
	return err.Error()
}

// pumpSetup 推进配置阶段，并在就绪后组装 App。
//
// 每帧调用一次。它做三件事：
//  1. 收取后台操作结果；
//  2. 若身份已就绪且 App 尚未组装，组装它；
//  3. 出错时记下原因供界面显示。
func (a *uiState) pumpSetup() {
	a.pollOp()

	if a.opts.App != nil || a.opts.Setup == nil || a.appStartErr != "" {
		return
	}
	if !a.opts.Setup.Ready() {
		return
	}

	app, err := a.opts.Setup.App()
	if err != nil {
		a.appStartErr = err.Error()
		a.opts.Logf("ui: building the app failed: %v", err)
		return
	}
	a.opts.App = app
}
