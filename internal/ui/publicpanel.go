package ui

import (
	"context"
	"strings"
	"time"

	"image/color"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// publicChoiceState 是公网连接面板的可变状态。
type publicChoiceState struct {
	// offerEd 显示本端信令（只读，供用户复制）。
	offerEd widget.Editor
	// peerEd 让用户粘贴对方信令。
	peerEd widget.Editor

	genBtn     widget.Clickable
	connectBtn widget.Clickable
	backBtn    widget.Clickable

	// busy 表示正在生成/连接（后台 goroutine 进行中）。
	busy bool
	// busyLabel 是 busy 时显示的文案。
	busyLabel string
	// offer 是已生成的本地信令（空表示还没生成）。
	offer string
	// status 是最近一次操作得到的连接状况。
	status NatSummary
	// errMsg 是本面板内的错误。
	errMsg string
	// okMsg 是本面板内的成功提示。
	okMsg string

	// ch 用于把后台操作结果送回界面 goroutine。
	result chan publicResult
}

// publicResult 是后台生成/连接的结果。
type publicResult struct {
	offer  string
	status NatSummary
	err    error
	// done 表示连接成功、可以进入主界面了。
	done bool
}

// isChoiceScreen 报告是否应显示"连接方式/公网连接"界面。
//
// 条件：有公网能力、身份已就绪、App 尚未组装、且刚刚进入选择阶段。
func (a *uiState) isChoiceScreen() bool {
	return a.connecting && a.opts.App == nil && a.opts.PublicNet != nil
}

// choiceScreen 是身份就绪后的连接方式界面（局域网 / 公网）。
func (a *uiState) choiceScreen(gtx layout.Context) layout.Dimensions {
	if a.chooseMode == 2 {
		return a.publicPanel(gtx)
	}
	return a.transportChooser(gtx)
}

// transportChooser 让用户选局域网还是公网。
func (a *uiState) transportChooser(gtx layout.Context) layout.Dimensions {
	lanBtn := &a.choiceLANBtn
	pubBtn := &a.choicePubBtn

	if lanBtn.Clicked(gtx) {
		// 局域网：标记已选，pumpSetup 随后会组装 App。
		a.transportChosen = true
		a.connecting = false
	}
	if pubBtn.Clicked(gtx) {
		a.chooseMode = 2
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.H6(a.theme, "选择连接方式")
			lbl.Color = colorText
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "同一局域网内，选「局域网」即可自动发现对方。"+
				"两台设备不在同一网络时，选「公网连接」——它会生成一段连接信令，你发给对方、对方再回传一段即可。")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.modeCard(gtx, lanBtn, "局域网（自动发现）",
				"同一 WiFi / 有线网络。零配置，最快。",
				"选择局域网", false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.modeCard(gtx, pubBtn, "公网连接（手动信令）",
				"不同网络之间。需要双方手动交换一段信令文本。",
				"选择公网连接", true)
		}),
	)
}

// modeCard 绘制一张可点击的"连接方式"卡片。
//
// 整张卡片就是一个按钮：点卡片任意处即选中。
// 早期版本在卡片里再套一个 button，导致点击被两层 Clickable
// 各自消费一次，行为不可预期。这里只保留一层。
func (a *uiState) modeCard(gtx layout.Context, btn *widget.Clickable,
	title, desc, action string, accent bool) layout.Dimensions {

	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		bg := colorRaised
		edge := colorMuted
		if accent {
			bg = color.NRGBA{R: 0x14, G: 0x3D, B: 0x39, A: 0xFF}
			edge = colorAccent
		}
		radius := gtx.Dp(unit.Dp(radiusCard))
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				fillRounded(gtx, bg, gtx.Constraints.Min, radius)
				return layout.Dimensions{Size: gtx.Constraints.Min}
			},
			func(gtx layout.Context) layout.Dimensions {
				inset := layout.Inset{Top: unit.Dp(16), Bottom: unit.Dp(16), Left: unit.Dp(18), Right: unit.Dp(18)}
				return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body1(a.theme, title)
							lbl.Color = colorText
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Caption(a.theme, desc)
							lbl.Color = colorMuted
							return lbl.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Caption(a.theme, action+" →")
							lbl.Color = edge
							return lbl.Layout(gtx)
						}),
					)
				})
			},
		)
	})
}

// publicPanel 是公网连接面板：生成/粘贴信令、显示状态。
func (a *uiState) publicPanel(gtx layout.Context) layout.Dimensions {
	p := &a.pub
	pn := a.opts.PublicNet

	genClicked := p.genBtn.Clicked(gtx)
	connectClicked := p.connectBtn.Clicked(gtx)
	backClicked := p.backBtn.Clicked(gtx)

	if backClicked && !p.busy {
		a.chooseMode = 0
	}

	if genClicked && !p.busy {
		a.startPublicOp("正在收集本端候选…", func(ctx context.Context) publicResult {
			offer, err := pn.GenerateOffer(ctx)
			return publicResult{offer: offer, err: err}
		})
	}
	if connectClicked && !p.busy {
		sig := strings.TrimSpace(p.peerEd.Text())
		if sig == "" {
			p.errMsg = "请先粘贴对方的连接信令。"
		} else {
			// 允许整行 "keytalk -ice-answer ..." 粘贴。
			if i := strings.Index(sig, "KTICE1:"); i > 0 {
				sig = sig[i:]
			}
			a.startPublicOp("正在建立公网连接…", func(ctx context.Context) publicResult {
				st, err := pn.Connect(ctx, sig)
				return publicResult{status: st, err: err, done: err == nil}
			})
		}
	}

	if p.busy {
		a.win.Invalidate()
	}

	// 结果收集（非阻塞）。
	if p.result != nil {
		select {
		case r := <-p.result:
			p.busy = false
			p.result = nil
			if r.err != nil {
				p.errMsg = r.err.Error()
			} else {
				p.errMsg = ""
				if r.offer != "" {
					p.offer = r.offer
					p.offerEd.SetText(r.offer)
					p.okMsg = "已生成信令。把它发给对方（对方用同一面板的「连接」栏粘贴）。"
				}
				if r.done {
					p.status = r.status
					// 连接成功：标记已选并把控制权交回，pumpSetup 会组装 App。
					a.transportChosen = true
					a.connecting = false
				}
			}
		default:
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.H6(a.theme, "公网连接")
			lbl.Color = colorText
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "双方任一方先「生成信令」并发给对方；对方把它粘贴到下面的「对方信令」框，"+
				"点「建立连接」。谁点了「建立连接」，谁是发起方。")
		}),

		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.sectionLabel(gtx, "① 我的连接信令")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(84))
			p.offerEd.Mask = 0
			p.offerEd.SingleLine = false
			if p.offer == "" {
				ph := "点下方按钮生成；生成后这里会出现一段 KTICE1: 开头的文本"
				return a.boxedEditor(gtx, &p.offerEd, ph)
			}
			return a.boxedEditor(gtx, &p.offerEd, "")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			label := "生成我的信令"
			if p.busy {
				label = p.busyLabel
			}
			return a.button(gtx, &p.genBtn, colorRaised, colorText, label, !p.busy,
				layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(16), Right: unit.Dp(16)})
		}),

		layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.sectionLabel(gtx, "② 粘贴对方的连接信令")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(64))
			p.peerEd.Mask = 0
			p.peerEd.SingleLine = false
			return a.boxedEditor(gtx, &p.peerEd, "粘贴对方发来的 KTICE1: 开头的文本")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			label := "建立连接"
			if p.busy {
				label = p.busyLabel
			}
			return a.button(gtx, &p.connectBtn, colorAccent, color.NRGBA{R: 0x06, G: 0x1A, B: 0x17, A: 0xFF},
				label, !p.busy,
				layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(9), Left: unit.Dp(20), Right: unit.Dp(20)})
		}),

		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.publicStatusRow(gtx, p.status)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.panelMessages(gtx, p.errMsg, p.okMsg)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.button(gtx, &p.backBtn, colorRaised, colorMuted, "← 返回", !p.busy,
				layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(12), Right: unit.Dp(12)})
		}),
	)
}

// publicStatusRow 显示公网连接的状态（已连接时含直连/中继）。
func (a *uiState) publicStatusRow(gtx layout.Context, st NatSummary) layout.Dimensions {
	if st.Detail == "" && st.PublicAddr == "" && !st.Connected {
		// 还没操作过：显示 PublicNet 的当前快照（可能是上一轮遗留）。
		if a.opts.PublicNet != nil {
			st = a.opts.PublicNet.Status()
		}
	}
	if st.Detail == "" && st.PublicAddr == "" && st.Path == "" {
		return layout.Dimensions{}
	}

	lines := []string{}
	if st.Path != "" {
		lines = append(lines, "当前路径："+st.Path)
	}
	if st.PublicAddr != "" {
		lines = append(lines, "公网映射："+st.PublicAddr)
	}
	if st.Detail != "" {
		lines = append(lines, st.Detail)
	}
	text := strings.Join(lines, "\n")

	return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		col := colorMuted
		if st.Connected {
			col = colorAccent
		}
		lbl := material.Caption(a.theme, text)
		lbl.Color = col
		return lbl.Layout(gtx)
	})
}

// startPublicOp 在后台跑一次公网操作，结果通过 pub.result 送回。
func (a *uiState) startPublicOp(label string, fn func(context.Context) publicResult) {
	p := &a.pub
	p.busy = true
	p.busyLabel = label
	p.errMsg = ""
	p.okMsg = ""
	if p.result == nil {
		p.result = make(chan publicResult, 1)
	}
	ch := p.result
	pn := a.opts.PublicNet
	go func() {
		// 给 ICE 收集/连通一个合理上限，避免无限转圈。
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		_ = pn
		ch <- fn(ctx)
	}()
}

// sectionLabel 是面板里的小节标题。
func (a *uiState) sectionLabel(gtx layout.Context, text string) layout.Dimensions {
	lbl := material.Caption(a.theme, text)
	lbl.Color = colorMuted
	return lbl.Layout(gtx)
}

// scrollContent 用 widget.List 把可变高度的内容做成可滚动。
//
// 公网面板内容较多，窄窗口下必须能滚，否则底部"建立连接"
// 按钮会被裁掉、根本点不到。
func (a *uiState) scrollContent(gtx layout.Context, list *widget.List, content layout.Widget) layout.Dimensions {
	list.Axis = layout.Vertical
	return material.List(a.theme, list).Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
		return content(gtx)
	})
}
