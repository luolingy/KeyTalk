package ui

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"github.com/exeliang/keytalk/internal/core"
)

// trustBar 是常驻顶部的信任状态条。
//
// 这是方案 C 的核心：它**不可折叠、不可关闭、永远在顶部**。
//
// 为什么值得占用永久空间：
// 本项目的信任状态是"默认不安全、需要用户主动动作才能变好"。
// 若把提示做成可关闭的横幅，用户第一次就会关掉它，
// 此后永远看不到——而那正是提示最需要出现的时候。
//
// 颜色是唯一编码：灰=未知、黄=未核实、绿=已核实、红=失败。
func (a *uiState) trustBar(gtx layout.Context, contacts []core.Contact) layout.Dimensions {
	level := worstTrust(contacts)
	col := trustColor(level)

	// 没有任何会话时，条带退化为"关于本机身份"的信息条，
	// 而不是显示一个永远红色的告警——那会让用户对告警脱敏。
	if len(contacts) == 0 {
		return a.identityBar(gtx)
	}

	height := gtx.Dp(unit.Dp(trustBarHeightDp))

	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fillRect(gtx, colorSurface, image.Pt(gtx.Constraints.Max.X, height))
			return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, height)}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				// 左侧色带：整个条带的主色，一眼可辨。
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					fillRect(gtx, col, image.Pt(gtx.Dp(unit.Dp(4)), height))
					return layout.Dimensions{Size: image.Pt(gtx.Dp(unit.Dp(4)), height)}
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
				// 状态图标。
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.trustGlyph(gtx, level, col)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Body2(a.theme, trustPhrase(level))
							lbl.Color = colorText
							return lbl.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							d := trustDetail(level)
							if d == "" {
								return layout.Dimensions{}
							}
							lbl := material.Caption(a.theme, d)
							lbl.Color = col
							return lbl.Layout(gtx)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
				// 面板入口。放在这里而不是设置菜单里：
				// "添加联系人"是本应用最常用的动作，
				// 藏起来会让第一步就卡住。
				layout.Rigid(a.panelButtons),
				// 右侧本机指纹：常驻可见，不需要点开设置。
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.localFingerprint(gtx)
				}),
			)
		},
	)
}

// identityBar 是没有会话时的顶部条：展示本机身份与"下一步做什么"。
func (a *uiState) identityBar(gtx layout.Context) layout.Dimensions {
	height := gtx.Dp(unit.Dp(trustBarHeightDp))
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			fillRect(gtx, colorSurface, image.Pt(gtx.Constraints.Max.X, height))
			return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, height)}
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					fillRect(gtx, colorTrustUnknown, image.Pt(gtx.Dp(unit.Dp(4)), height))
					return layout.Dimensions{Size: image.Pt(gtx.Dp(unit.Dp(4)), height)}
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(a.theme, "尚无联系人 —— 请与对方当面交换公钥")
					lbl.Color = colorMuted
					return lbl.Layout(gtx)
				}),
				layout.Rigid(a.panelButtons),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.localFingerprint(gtx)
				}),
			)
		},
	)
}

// localFingerprint 显示本机指纹。
//
// 等宽小字 + 较低对比度：它是"需要时才读"的信息，
// 不该和信任状态抢注意力。但必须在**第一屏**可见——
// 藏进设置页会让交换指纹这一步被跳过。
func (a *uiState) localFingerprint(gtx layout.Context) layout.Dimensions {
	fp := a.opts.App.Fingerprint().Display()
	return layout.Flex{Axis: layout.Vertical, Alignment: layout.End}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Caption(a.theme, "本机指纹")
			lbl.Color = colorFaint
			return lbl.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Caption(a.theme, fp)
			lbl.Color = colorMuted
			lbl.Font.Typeface = "monospace"
			lbl.TextSize = unit.Sp(10)
			return lbl.Layout(gtx)
		}),
	)
}

// trustGlyph 画状态图标。
//
// 用字符而不是矢量图：无需引入图像资源，
// 且这几个符号（● ◐ ○ ✕）在任何字体下都能渲染。
func (a *uiState) trustGlyph(gtx layout.Context, level TrustLevel, col color.NRGBA) layout.Dimensions {
	glyph := "○"
	switch level {
	case TrustVerified:
		glyph = "●"
	case TrustUnverified:
		// 半实心：既不是"完成"也不是"缺失"，
		// 视觉上正好对应"进行中、需要你确认"。
		glyph = "◐"
	case TrustFailed:
		glyph = "✕"
	}
	lbl := material.H6(a.theme, glyph)
	lbl.Color = col
	return lbl.Layout(gtx)
}

// trustPill 是用于会话标题的小药丸标签。
func (a *uiState) trustPill(gtx layout.Context, level TrustLevel) layout.Dimensions {
	col := trustColor(level)
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			h := gtx.Dp(unit.Dp(20))
			w := gtx.Constraints.Min.X
			if w <= 0 {
				w = gtx.Dp(unit.Dp(64))
			}
			// 半透明底 + 同色文字，形成"标签"而非"按钮"的观感。
			bg := col
			bg.A = 0x26
			fillRect(gtx, bg, image.Pt(w, h))
			return layout.Dimensions{Size: image.Pt(w, h)}
		},
		func(gtx layout.Context) layout.Dimensions {
			inset := layout.Inset{Top: unit.Dp(3), Bottom: unit.Dp(3), Left: unit.Dp(8), Right: unit.Dp(8)}
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(a.theme, trustLabel(level))
				lbl.Color = col
				return lbl.Layout(gtx)
			})
		},
	)
}

// unverifiedStripe 是未核实消息旁的警示条。
//
// 方案 C 的第二条硬规则：未核实身份时，
// 发出的**每一条消息**都带可见标记。
//
// 理由：信任状态放在顶部会被忽略（用户看消息时不看顶部）。
// 把标记贴在消息本身，用户无法在阅读内容时避开它。
func unverifiedStripe(gtx layout.Context, h int, l TrustLevel) {
	col := trustColor(l)
	fillRect(gtx, col, image.Pt(gtx.Dp(unit.Dp(3)), h))
}

// fillRect 用纯色填满给定尺寸。
//
// Gio 没有"填充"原语，惯用做法是画一个矩形。
func fillRect(gtx layout.Context, c color.NRGBA, size image.Point) {
	if size.X <= 0 || size.Y <= 0 {
		return
	}
	paint.FillShape(gtx.Ops, c, clip.Rect{Max: size}.Op())
}

// fillRounded 画圆角矩形。
func fillRounded(gtx layout.Context, c color.NRGBA, size image.Point, radius int) {
	if size.X <= 0 || size.Y <= 0 {
		return
	}
	r := clip.RRect{Rect: image.Rectangle{Max: size}, NE: radius, NW: radius, SE: radius, SW: radius}
	paint.FillShape(gtx.Ops, c, r.Op(gtx.Ops))
}
