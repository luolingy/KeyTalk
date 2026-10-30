package ui

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"github.com/exeliang/keytalk/internal/core"
	"github.com/exeliang/keytalk/internal/sas"
)

// verifyPanel 是"emoji 二次确认"面板。
//
// 这是本工具**最重要的一个界面**：其他所有密码学保证
// （前向保密、验签、指纹比对）都只能证明"对端持有某把私钥"，
// 唯独这一步能确认"那把私钥属于你朋友"。
//
// 因此设计上刻意：
//   - 未核对时用琥珀色块托底，在一片深灰里跳出来，但不刺眼；
//   - emoji 用大字号 + 卡片，让人一眼能比对；
//   - 明说"对不上"意味着什么——那是攻击迹象，不是故障；
//   - 给出英文名序列，供打电话核对的场景使用。
func (a *uiState) verifyPanel(gtx layout.Context, c core.Contact) layout.Dimensions {
	level := trustOf(c)

	bg := colorRaised
	if !c.Verified {
		// 极低透明度的琥珀：足以让面板"浮"出来，
		// 又不至于像错误提示那样抢走全部注意力。
		bg = colorTrustUnverified
		bg.A = 0x14
	}

	inset := layout.Inset{Top: unit.Dp(14), Bottom: unit.Dp(14), Left: unit.Dp(20), Right: unit.Dp(20)}

	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fillRect(gtx, bg, gtx.Constraints.Max)
			return layout.Dimensions{Size: gtx.Constraints.Max}
		},
		func(gtx layout.Context) layout.Dimensions {
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.verifyTitle(gtx, level)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.emojiRow(gtx, c)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.verifyActions(gtx, c)
					}),
				)
			})
		},
	)
}

func (a *uiState) verifyTitle(gtx layout.Context, level TrustLevel) layout.Dimensions {
	col := trustColor(level)
	title := "请与对方核对下面 7 个 emoji"
	detail := "一致 → 确认对方身份；不一致 → 可能有人冒充，请立即停止"

	if level == TrustVerified {
		title = "已确认：emoji 与对方一致"
		detail = "此后的通信已排除中间人（会话重建后需重新核对）"
	}

	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.trustGlyph(gtx, level, col)
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body1(a.theme, title)
					lbl.Color = colorText
					return lbl.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Caption(a.theme, detail)
					lbl.Color = col
					return lbl.Layout(gtx)
				}),
			)
		}),
	)
}

// emojiRow 用大字号显示 7 个 emoji。
//
// 字号刻意放大：核对能否真的发生，取决于它有多容易做。
// 小字号会让人"扫一眼就点确认"，那样安全属性就名存实亡。
func (a *uiState) emojiRow(gtx layout.Context, c core.Contact) layout.Dimensions {
	if len(c.Emoji) == 0 {
		lbl := material.Body2(a.theme, "（本次会话没有可用的核对值，请改用指纹手动核对）")
		lbl.Color = colorMuted
		return lbl.Layout(gtx)
	}

	children := make([]layout.FlexChild, 0, len(c.Emoji)*2)
	for i, e := range c.Emoji {
		if i > 0 {
			children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout))
		}
		em := e
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.emojiCell(gtx, em)
		}))
	}
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
}

// emojiCell 是单个 emoji 的方形卡片。
//
// 卡片形式（而不是裸字符）让每个符号的边界清晰，
// 避免用户把相邻两个 emoji 看成一个组合符号而数错数量。
func (a *uiState) emojiCell(gtx layout.Context, e sas.Emoji) layout.Dimensions {
	side := gtx.Dp(unit.Dp(emojiCellDp))
	gtx.Constraints.Min = image.Pt(side, side)
	gtx.Constraints.Max = image.Pt(side, side)

	fillRounded(gtx, colorBackground, image.Pt(side, side), gtx.Dp(unit.Dp(radiusCard)))

	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		lbl := material.H4(a.theme, e.Char)
		lbl.Color = colorText
		return lbl.Layout(gtx)
	})
}

// verifyActions 是英文名序列与确认按钮。
func (a *uiState) verifyActions(gtx layout.Context, c core.Contact) layout.Dimensions {
	children := []layout.FlexChild{
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			if len(c.Emoji) == 0 {
				return layout.Dimensions{}
			}
			// 名称序列：用于"念给对方听"的场景（打电话核对时）。
			// 对于不熟悉这些英文名的用户，这是唯一的语音核对途径。
			lbl := material.Caption(a.theme, "念给对方听: "+sas.FormatNames(c.Emoji))
			lbl.Color = colorFaint
			return lbl.Layout(gtx)
		}),
	}

	if !c.Verified {
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.verifyButton(gtx, c)
		}))
	}

	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
}

func (a *uiState) verifyButton(gtx layout.Context, c core.Contact) layout.Dimensions {
	btn := &a.emojiAck
	if btn.Clicked(gtx) {
		if err := a.opts.App.VerifyEmoji(c.ID); err != nil {
			a.banner = err.Error()
			a.bannerErr = true
		} else {
			a.banner = ""
			a.bannerErr = false
		}
	}

	// 绿底配近黑字：白字压在亮绿上对比度不足，看不清。
	fg := color.NRGBA{R: 0x04, G: 0x1F, B: 0x0D, A: 0xFF}

	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				m := op.Record(gtx.Ops)
				dims := a.verifyButtonContent(gtx, fg)
				m.Stop() // 仅用于测量尺寸；不要 Defer——那会重放内容
				fillRounded(gtx, colorTrustVerified, dims.Size, gtx.Dp(unit.Dp(radiusCard)))
				return dims
			},
			func(gtx layout.Context) layout.Dimensions { return a.verifyButtonContent(gtx, fg) },
		)
	})
}

func (a *uiState) verifyButtonContent(gtx layout.Context, fg color.NRGBA) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(9), Left: unit.Dp(18), Right: unit.Dp(18)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		lbl := material.Body2(a.theme, "一致，确认可信")
		lbl.Color = fg
		return lbl.Layout(gtx)
	})
}

// emojiSummary 返回一行用于日志/终端的核对摘要。
func emojiSummary(c core.Contact) string {
	if len(c.Emoji) == 0 {
		return "(no emoji)"
	}
	state := "UNVERIFIED"
	if c.Verified {
		state = "VERIFIED"
	}
	return sas.Format(c.Emoji) + " [" + state + "]"
}
