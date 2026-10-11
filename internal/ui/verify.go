package ui

import (
	"fmt"
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/exeliang/keytalk/internal/core"
	"github.com/exeliang/keytalk/internal/sas"
)

// 核对相关的配色。
var (
	colorVerifyBg   = color.NRGBA{R: 0x1F, G: 0x2A, B: 0x1F, A: 0xFF}
	colorVerifyWarn = color.NRGBA{R: 0x2E, G: 0x24, B: 0x18, A: 0xFF}
)

// verifyPanel 是"emoji 二次确认"面板。
//
// 这是本工具**最重要的一个界面**：其他所有密码学保证
// （前向保密、验签、指纹比对）都只能证明"对端持有某把私钥"，
// 唯独这一步能确认"那把私钥属于你朋友"。
//
// 因此设计上刻意：
//   - 未核对时用醒目提示，而不是一个不起眼的小图标；
//   - emoji 用大字号，让人一眼能比对；
//   - 明说"如果对不上该怎么办"（那是攻击迹象）。
func (a *uiState) verifyPanel(gtx layout.Context, c core.Contact) layout.Dimensions {
	verified := c.Verified
	bg := colorVerifyWarn
	if verified {
		bg = colorVerifyBg
	}

	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fill(gtx, bg)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			inset := layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(16), Right: unit.Dp(16)}
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.verifyTitle(gtx, c, verified)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.emojiRow(gtx, c)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return a.verifyActions(gtx, c, verified)
					}),
				)
			})
		},
	)
}

func (a *uiState) verifyTitle(gtx layout.Context, c core.Contact, verified bool) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			icon := "⚠"
			col := colorWarn
			if verified {
				icon = "✓"
				col = colorOK
			}
			lbl := material.H6(a.theme, icon)
			lbl.Color = col
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			text := "请与对方核对下面 7 个 emoji，一致才能确认身份"
			if verified {
				text = "已核对：emoji 与对方一致，通信已排除中间人"
			}
			lbl := material.Body1(a.theme, text)
			if verified {
				lbl.Color = colorOK
			} else {
				lbl.Color = colorText
			}
			return lbl.Layout(gtx)
		}),
	)
}

// emojiRow 用大字号显示 7 个 emoji。
//
// 字号刻意放大：核对能否真的发生，取决于它有多容易做。
// 小字号会让人"扫一眼就点确认"，那样安全属性就名存实亡了。
func (a *uiState) emojiRow(gtx layout.Context, c core.Contact) layout.Dimensions {
	if len(c.Emoji) == 0 {
		lbl := material.Body2(a.theme, "（本次会话没有可用的核对值，请改用指纹手动核对）")
		lbl.Color = colorMuted
		return lbl.Layout(gtx)
	}

	children := make([]layout.FlexChild, 0, len(c.Emoji)*2)
	for i, e := range c.Emoji {
		if i > 0 {
			children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout))
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
	side := gtx.Dp(unit.Dp(52))
	gtx.Constraints.Min = image.Pt(side, side)
	gtx.Constraints.Max = image.Pt(side, side)

	paint.FillShape(gtx.Ops, colorSurface, clip.Rect{Max: image.Pt(side, side)}.Op())

	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		lbl := material.H4(a.theme, e.Char)
		lbl.Color = colorText
		return lbl.Layout(gtx)
	})
}

// verifyActions 是确认/取消按钮。
func (a *uiState) verifyActions(gtx layout.Context, c core.Contact, verified bool) layout.Dimensions {
	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// 名称序列：用于"念给对方听"的场景（打电话核对时）。
			lbl := material.Caption(a.theme, sas.FormatNames(c.Emoji))
			lbl.Color = colorMuted
			return lbl.Layout(gtx)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Dimensions{}
		}),
	}

	if !verified {
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.verifyButton(gtx, c)
			}),
		)
	} else {
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(a.theme, "会话重建后需要重新核对")
				lbl.Color = colorMuted
				return lbl.Layout(gtx)
			}),
		)
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

	return btn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		fill(gtx, colorOK)
		inset := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(16), Right: unit.Dp(16)}
		return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			lbl := material.Body2(a.theme, "一致，确认可信")
			lbl.Color = color.NRGBA{R: 0x0A, G: 0x1A, B: 0x12, A: 0xFF}
			return lbl.Layout(gtx)
		})
	})
}

// trustBadge 是会话标题处的可信状态标记。
//
// 分三档而不是两档：把"加密了但没核实"与"已核实"分开显示，
// 是最关键的诚实之处——否则用户会把"加密"误当成"确认了对方是谁"。
func (a *uiState) trustBadge(gtx layout.Context, c core.Contact) layout.Dimensions {
	text := "未核实"
	col := colorWarn
	if c.Status != core.StatusSecure {
		text = "未加密"
		col = colorMuted
	} else if c.Verified {
		text = "已核实"
		col = colorOK
	} else {
		text = "已加密 · 未核实身份"
	}

	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fill(gtx, color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x00})
			return layout.Dimensions{Size: gtx.Constraints.Min}
		},
		func(gtx layout.Context) layout.Dimensions {
			inset := layout.Inset{Top: unit.Dp(2), Bottom: unit.Dp(2), Left: unit.Dp(8), Right: unit.Dp(8)}
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(a.theme, text)
				lbl.Color = col
				return lbl.Layout(gtx)
			})
		},
	)
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
	return fmt.Sprintf("%s [%s]", sas.Format(c.Emoji), state)
}

var _ = widget.Clickable{}
