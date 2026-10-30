package ui

import (
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// onboarding 是首次使用（没有任何联系人）时的引导页。
//
// 方案 C 的第三条：本工具与其他聊天软件的心智模型**完全不同**，
// 必须显式说明，否则用户会一直等一个永远不会出现的"注册"按钮。
//
// 为什么值得单独做一页而不是塞进侧栏的空状态：
// 这段说明需要讲清"为什么没有账号"——那是一个设计选择，
// 不是功能缺失。放在侧栏角落会被当成"暂时没有数据"，
// 于是用户会去别处找注册入口。
func (a *uiState) onboarding(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(28), Bottom: unit.Dp(28), Left: unit.Dp(40), Right: unit.Dp(40)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.H5(a.theme, "没有服务器，也没有账号")
				lbl.Color = colorText
				return lbl.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(a.theme,
					"KeyTalk 不连接任何服务器。消息在两台机器之间直接传输，"+
						"密钥始终留在本地。因此没有地方可以注册——"+
						"你的身份就是本机生成的这对密钥。")
				lbl.Color = colorMuted
				return lbl.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body1(a.theme, "开始使用")
				lbl.Color = colorText
				return lbl.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.onboardingStep(gtx, "1", "交换公钥",
					"把你的 public.key 交给对方，也拿到对方的那份。")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.onboardingStep(gtx, "2", "连接后核对 emoji",
					"双方都上线后会显示同一组 7 个 emoji。"+
						"通过电话或当面念一遍，一致才说明没有中间人。")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.onboardingStep(gtx, "3", "开始通信",
					"核对通过后，顶端信任条会变绿。")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(26)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.onboardingWhy(gtx)
			}),
		)
	})
}

// onboardingStep 是带序号的一步指引。
func (a *uiState) onboardingStep(gtx layout.Context, num, title, detail string) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			w := gtx.Dp(unit.Dp(26))
			gtx.Constraints.Min.X, gtx.Constraints.Max.X = w, w
			lbl := material.Body2(a.theme, num)
			lbl.Color = colorAccent
			return lbl.Layout(gtx)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(a.theme, title)
					lbl.Color = colorText
					return lbl.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					lbl := material.Caption(a.theme, detail)
					lbl.Color = colorFaint
					return lbl.Layout(gtx)
				}),
			)
		}),
	)
}

// onboardingWhy 解释"为什么要这么麻烦"。
//
// 这一段是整个界面上最重要的文字。用户会问
// "别的软件扫个码就行了，为什么你要我念 emoji"。
// 不回答，用户就会把核对当成可跳过的仪式，
// 于是安全属性名存实亡。
func (a *uiState) onboardingWhy(gtx layout.Context) layout.Dimensions {
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			m := op.Record(gtx.Ops)
			dims := a.onboardingWhyContent(gtx)
			m.Stop() // 仅用于测量尺寸；不要 Defer——那会重放内容
			fillRounded(gtx, colorRaised, dims.Size, gtx.Dp(unit.Dp(radiusCard)))
			return dims
		},
		a.onboardingWhyContent,
	)
}

func (a *uiState) onboardingWhyContent(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(14), Bottom: unit.Dp(14), Left: unit.Dp(16), Right: unit.Dp(16)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Body2(a.theme, "为什么需要核对 emoji？")
				lbl.Color = colorTrustUnverified
				return lbl.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(a.theme,
					"加密能保证「没有人在偷听」，但不能保证「对面是你想找的那个人」。\n"+
						"如果有人在最开始就冒充你的联系人，此后每一次握手都会「验证通过」——"+
						"因为验的是冒充者的密钥。\n"+
						"只有你们两人亲自对一下那组 emoji，才能排除这种情况。")
				lbl.Color = colorMuted
				return lbl.Layout(gtx)
			}),
		)
	})
}
