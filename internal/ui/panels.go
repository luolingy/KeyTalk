package ui

import (
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/exeliang/keytalk/internal/core"
)

// addContactState 是"添加联系人"面板的可变状态。
type addContactState struct {
	nameEd widget.Editor
	keyEd  widget.Editor

	// confirmed 是"我已通过其他渠道核对过下面的指纹"勾选框。
	//
	// ⚠️ 这不是装饰。core.AddContact 要求 fingerprintConfirmed=true，
	// 本项目的产品决策是**绝不静默信任未核对的身份**：
	// 粘贴一个公钥就等于把通信对象交给提供这个公钥的人，
	// 中间人只要换掉公钥就能全程解密。
	confirmed widget.Bool

	parseBtn widget.Clickable
	addBtn   widget.Clickable

	// parsedFP 是解析成功后的指纹（空表示尚未解析）。
	parsedFP string
	errMsg   string
	okMsg    string
}

// infoState 是配置信息面板的可变状态。
type infoState struct {
	pubKeyEd widget.Editor
	backupEd widget.Editor

	// passEd 用于导出私钥备份前的二次确认。
	passEd widget.Editor

	toggleBackupBtn widget.Clickable
	exportBtn       widget.Clickable

	showBackup bool
	backup     string
	errMsg     string
}

// --- 触发按钮 ---

// panelButtons 是顶部条右侧的两个入口。
func (a *uiState) panelButtons(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(5), Bottom: unit.Dp(5), Left: unit.Dp(12), Right: unit.Dp(12)}
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if a.btnAddContact.Clicked(gtx) {
				a.showAddContact = true
			}
			return a.button(gtx, &a.btnAddContact, colorRaised, colorText,
				"＋ 添加联系人", true, inset)
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if a.btnInfo.Clicked(gtx) {
				a.showInfo = true
			}
			return a.button(gtx, &a.btnInfo, colorRaised, colorText, "配置信息", true, inset)
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
	)
}

// --- 浮层 ---

// overlay 在主体 UI 之上绘制当前打开的面板。
func (a *uiState) overlay(gtx layout.Context) {
	if !a.showAddContact && !a.showInfo {
		return
	}

	// 半透明遮罩：既压暗背景以突出面板，
	// 也明确表示"下面那层现在不能点"。
	fillRect(gtx, color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xB0}, gtx.Constraints.Max)

	layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		maxW := gtx.Dp(unit.Dp(560))
		maxH := gtx.Constraints.Max.Y - gtx.Dp(unit.Dp(48))
		if gtx.Constraints.Max.X > maxW {
			gtx.Constraints.Max.X = maxW
		}
		if maxH > 0 && gtx.Constraints.Max.Y > maxH {
			gtx.Constraints.Max.Y = maxH
		}
		return layout.Background{}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				m := op.Record(gtx.Ops)
				dims := a.panelContent(gtx)
				op.Defer(gtx.Ops, m.Stop())
				fillRounded(gtx, colorSurface, dims.Size, gtx.Dp(unit.Dp(radiusCard)))
				return dims
			},
			a.panelContent,
		)
	})
}

func (a *uiState) panelContent(gtx layout.Context) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(20), Bottom: unit.Dp(20), Left: unit.Dp(24), Right: unit.Dp(24)}
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		if a.showAddContact {
			return a.addContactPanel(gtx)
		}
		return a.infoPanel(gtx)
	})
}

// --- 添加联系人 ---

func (a *uiState) addContactPanel(gtx layout.Context) layout.Dimensions {
	ac := &a.ac

	parseClicked := ac.parseBtn.Clicked(gtx)
	addClicked := ac.addBtn.Clicked(gtx)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.panelHeader(gtx, "添加联系人", func() { a.showAddContact = false })
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &ac.nameEd, "名字", "例如 bob", 0, false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Caption(a.theme, "对方公钥")
			lbl.Color = colorMuted
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(110))
			ac.keyEd.Mask = 0
			ac.keyEd.SingleLine = false
			return a.boxedEditor(gtx, &ac.keyEd, "粘贴 armored 公钥，或从对方给的 public.key 文件里复制")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.filePathHint(gtx, &ac.keyEd)
		}),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if parseClicked {
				a.parseContactKey()
			}
			return a.button(gtx, &ac.parseBtn, colorRaised, colorText, "解析并核对指纹", true,
				layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(16), Right: unit.Dp(16)})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),

		// 指纹核对区：只有解析成功后才出现。
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if ac.parsedFP == "" {
				return layout.Dimensions{}
			}
			return a.fingerprintConfirm(gtx)
		}),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.panelMessages(gtx, ac.errMsg, ac.okMsg)
		}),

		layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			enabled := ac.parsedFP != "" && ac.confirmed.Value
			return a.button(gtx, &ac.addBtn, colorAccent,
				color.NRGBA{R: 0x06, G: 0x1A, B: 0x17, A: 0xFF},
				"添加联系人", enabled,
				layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(24), Right: unit.Dp(24)})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if addClicked {
				a.addContact()
			}
			return layout.Dimensions{}
		}),
	)
}

// filePathHint 提示可以直接从文件读取公钥。
//
// 用一个显式路径输入框而不是系统的文件选择对话框：
// Gio 没有跨平台的文件对话框，自己实现一个文件浏览器
// 需要大量与核心功能无关的代码。这里的折中是
// "粘贴文本" + "粘贴文件路径"，两者都是复制粘贴，
// 对手工交换公钥的场景已经够用（见 docs/ui-design.md §7）。
func (a *uiState) filePathHint(gtx layout.Context, target *widget.Editor) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "也可以把 public.key 的完整路径粘到上面的框里，点“解析并核对指纹”时会自动读取。")
		}),
	)
}

// fingerprintConfirm 是带外核对区。
func (a *uiState) fingerprintConfirm(gtx layout.Context) layout.Dimensions {
	ac := &a.ac
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Background{}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					m := op.Record(gtx.Ops)
					dims := layout.Inset{
						Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(14), Right: unit.Dp(14),
					}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Caption(a.theme, "解析出的指纹")
								lbl.Color = colorMuted
								return lbl.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body2(a.theme, core.GroupFingerprint(ac.parsedFP))
								lbl.Color = colorText
								lbl.Font.Typeface = "monospace"
								return lbl.Layout(gtx)
							}),
						)
					})
					op.Defer(gtx.Ops, m.Stop())
					fillRounded(gtx, colorRaised, dims.Size, gtx.Dp(unit.Dp(radiusSmall)))
					return dims
				},
				func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{
						Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(14), Right: unit.Dp(14),
					}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Caption(a.theme, "解析出的指纹")
								lbl.Color = colorMuted
								return lbl.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body2(a.theme, core.GroupFingerprint(ac.parsedFP))
								lbl.Color = colorText
								lbl.Font.Typeface = "monospace"
								return lbl.Layout(gtx)
							}),
						)
					})
				},
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return material.CheckBox(a.theme, &ac.confirmed,
				"我已通过其他渠道（当面、电话、另一条已信任的通道）核对过这个指纹").Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "没核对指纹就等于把通信交给提供这把公钥的人。"+
				"若有人中途替换了公钥，他能读到你们全部的消息，而双方界面不会有任何异常。")
		}),
	)
}

// parseContactKey 解析输入的公钥或文件路径，取出指纹供核对。
func (a *uiState) parseContactKey() {
	ac := &a.ac
	ac.errMsg = ""
	ac.okMsg = ""
	ac.parsedFP = ""
	ac.confirmed.Value = false

	text := strings.TrimSpace(ac.keyEd.Text())
	if text == "" {
		ac.errMsg = "请先粘贴对方的公钥，或 public.key 文件的路径。"
		return
	}

	// 若输入看起来是一个存在的文件路径，就读进来。
	// 允许用户直接把路径粘进来，省掉"打开文件、全选、复制"。
	if !strings.Contains(text, "-----BEGIN") {
		if data, err := readIfFile(text); err == nil {
			ac.keyEd.SetText(strings.TrimSpace(string(data)))
			text = strings.TrimSpace(string(data))
		} else {
			ac.errMsg = "这既不像 armored 公钥（缺少 -----BEGIN 行），也不是一个能读取的文件路径。"
			return
		}
	}

	fp, err := core.ParsePublicKey([]byte(text))
	if err != nil {
		ac.errMsg = err.Error()
		return
	}
	ac.parsedFP = fp
}

func (a *uiState) addContact() {
	ac := &a.ac
	if ac.parsedFP == "" {
		ac.errMsg = "请先解析并核对指纹。"
		return
	}
	if !ac.confirmed.Value {
		// 理论上按钮已经置灰，这里是第二道防线：
		// 置灰只改配色，按钮仍然会收到点击。
		ac.errMsg = "请先勾选确认已核对指纹。"
		return
	}

	name := ac.nameEd.Text()
	key := ac.keyEd.Text()

	_, err := a.opts.App.AddContact(name, []byte(key), true)
	if err != nil {
		ac.errMsg = err.Error()
		return
	}

	ac.okMsg = "已添加 " + strings.TrimSpace(name) + "。"
	ac.errMsg = ""
	ac.parsedFP = ""
	ac.confirmed.Value = false
	ac.nameEd.SetText("")
	ac.keyEd.SetText("")
}

// --- 配置信息 ---

func (a *uiState) infoPanel(gtx layout.Context) layout.Dimensions {
	info := &a.info
	a.syncPublicKeyEditor()

	backupClicked := info.toggleBackupBtn.Clicked(gtx)

	var body layout.FlexChild
	if info.showBackup {
		body = layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.backupSection(gtx)
		})
	} else {
		body = layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Dimensions{}
		})
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.panelHeader(gtx, "配置信息", func() {
				a.showInfo = false
				info.showBackup = false
				info.backup = ""
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "显示名", a.identityName())
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "本机指纹", a.opts.App.Fingerprint().Display())
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "数据目录", a.dataDir())
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "身份文件", filepath.Join(a.dataDir(), "identity.json"))
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "私钥保护", a.keyProtectionText())
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "监听地址", a.netListenAddr())
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "局域网发现", a.netDiscovery())
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "联系人", fmt.Sprintf("%d 个", len(a.opts.App.Snapshot())))
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "消息存储", a.messageStorageText())
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.infoRow(gtx, "中文字体", a.fontMsg)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),

		layout.Rigid(vLineH),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Caption(a.theme, "你的公钥（发给对方，让对方添加你）")
			lbl.Color = colorMuted
			return layout.Inset{Top: unit.Dp(14)}.Layout(gtx, lbl.Layout)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(120))
			return a.boxedEditor(gtx, &info.pubKeyEd, "")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.setupHint(gtx, "可以全选复制，也可以直接把文件发给对方："+
				filepath.Join(a.dataDir(), "public.key"))
		}),

		layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),

		body,

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if backupClicked {
				info.showBackup = !info.showBackup
				info.errMsg = ""
			}
			label := "导出私钥备份…"
			if info.showBackup {
				label = "收起"
			}
			return a.button(gtx, &info.toggleBackupBtn, colorRaised, colorText, label, true,
				layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(16), Right: unit.Dp(16)})
		}),
	)
}

// backupSection 是导出私钥备份的表单。
func (a *uiState) backupSection(gtx layout.Context) layout.Dimensions {
	info := &a.info
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return field(gtx, a.theme, &info.passEd, "口令", "再次输入口令以确认", '•', false)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if info.exportBtn.Clicked(gtx) {
				a.doExportBackup()
			}
			return a.button(gtx, &info.exportBtn, colorRaised, colorText, "确认导出", true,
				layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(16), Right: unit.Dp(16)})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.panelMessages(gtx, info.errMsg, "")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if info.backup == "" {
				return layout.Dimensions{}
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(120))
					return a.boxedEditor(gtx, &info.backupEd, "")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return a.setupHint(gtx, "把这段内容存到安全的地方。任何拿到它的人都能冒充你，"+
						"因此不要放进聊天记录、云笔记或邮件。")
				}),
			)
		}),
	)
}

func (a *uiState) doExportBackup() {
	info := &a.info
	info.errMsg = ""
	pass := info.passEd.Text()
	if pass == "" {
		info.errMsg = "请输入口令。"
		return
	}
	if a.opts.Setup == nil {
		info.errMsg = "当前会话没有配置阶段，无法导出。"
		return
	}

	key, err := a.opts.Setup.ExportPrivateKey(pass)
	if err != nil {
		info.errMsg = setupErrText(err)
		return
	}
	info.backup = key
	info.backupEd.SetText(key)
	info.passEd.SetText("")
}

// syncPublicKeyEditor 把公钥填进只读输入框。
//
// 用只读 Editor 而不是自绘文本：这样用户可以直接用键盘
// 全选复制（Ctrl+A / Ctrl+C）。Gio 里让自绘文本可选要另写代码，
// 而"能复制"正是这个面板存在的意义。
func (a *uiState) syncPublicKeyEditor() {
	info := &a.info
	info.pubKeyEd.ReadOnly = true
	info.pubKeyEd.SingleLine = false
	info.backupEd.ReadOnly = true
	info.backupEd.SingleLine = false

	if info.pubKeyEd.Text() != "" || a.opts.Setup == nil {
		return
	}
	if pub, err := a.opts.Setup.ExportPublicKey(); err == nil {
		info.pubKeyEd.SetText(pub)
	}
}

func (a *uiState) identityName() string {
	if a.opts.Setup != nil {
		if n := a.opts.Setup.IdentityName(); n != "" {
			return n
		}
	}
	return "（未命名）"
}

func (a *uiState) dataDir() string {
	if a.opts.Setup != nil {
		return a.opts.Setup.DataDir()
	}
	return ""
}

// keyProtectionText 说明私钥在磁盘上受什么保护。
//
// 这一行必须是实话。若身份是 v1 明文格式，这里会明说
// "未加密"——用户有权知道自己的私钥正以明文躺在磁盘上。
func (a *uiState) keyProtectionText() string {
	if a.opts.Setup == nil {
		return "未知"
	}
	meta := a.opts.Setup.Meta()
	if meta == nil {
		return "未知"
	}
	if meta.LegacyPlaintext {
		return "⚠️ 未加密（早期版本格式，私钥以明文存放）"
	}
	if meta.Encrypted {
		return "已用口令加密（argon2id + ChaCha20-Poly1305）"
	}
	return "未知"
}

// messageStorageText 说明消息是否落盘。
//
// 明文身份没有主密钥，因此**没有**消息历史。这件事必须说出来：
// 用户会以为聊天记录和别的程序一样自动保存，
// 关掉窗口才发现什么都没有。
func (a *uiState) messageStorageText() string {
	if a.opts.Setup == nil {
		return "未知"
	}
	if a.opts.Setup.HasMessageStore() {
		return "已启用（正文用口令派生的主密钥加密）"
	}
	return "⚠️ 未启用 —— 身份没有口令，无法加密落盘；消息不会保存"
}

// netInfo 读取网络层状态。
func (a *uiState) netInfo() NetInfo {
	if a.opts.NetInfoFunc == nil {
		return NetInfo{}
	}
	return a.opts.NetInfoFunc()
}

func (a *uiState) netListenAddr() string {
	if v := a.netInfo().ListenAddr; v != "" {
		return v
	}
	return "未知"
}

// netDiscovery 如实报告发现状态。
//
// 不可用时必须显示原因：局域网里"找不到对方"最常见的原因
// 就是 mDNS 被防火墙或网卡挡住，用户看到"已启用"会白找半天。
func (a *uiState) netDiscovery() string {
	n := a.netInfo()
	if n.DiscoveryActive {
		return "已启用（mDNS）"
	}
	if n.DiscoveryError != "" {
		return "不可用：" + n.DiscoveryError
	}
	return "不可用"
}

// infoRow 是一行"标签：值"。
func (a *uiState) infoRow(gtx layout.Context, label, value string) layout.Dimensions {
	return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Dp(unit.Dp(96))
				lbl := material.Caption(a.theme, label)
				lbl.Color = colorMuted
				return lbl.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				lbl := material.Caption(a.theme, value)
				lbl.Color = colorText
				return lbl.Layout(gtx)
			}),
		)
	})
}

// --- 公共小部件 ---

func (a *uiState) panelHeader(gtx layout.Context, title string, onClose func()) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			lbl := material.H6(a.theme, title)
			lbl.Color = colorText
			return lbl.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if a.panelClose.Clicked(gtx) {
				onClose()
			}
			return a.button(gtx, &a.panelClose, colorRaised, colorMuted, "关闭", true,
				layout.Inset{Top: unit.Dp(5), Bottom: unit.Dp(5), Left: unit.Dp(12), Right: unit.Dp(12)})
		}),
	)
}

func (a *uiState) panelMessages(gtx layout.Context, errMsg, okMsg string) layout.Dimensions {
	if errMsg == "" && okMsg == "" {
		return layout.Dimensions{}
	}
	col := colorErr
	text := errMsg
	if errMsg == "" {
		col = colorTrustVerified
		text = okMsg
	}
	return layout.Inset{Top: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		lbl := material.Body2(a.theme, text)
		lbl.Color = col
		return lbl.Layout(gtx)
	})
}

// readIfFile 在 path 指向一个可读的普通文件时返回其内容。
//
// 限制 1 MiB：用户可能误把某个大文件的路径粘进来，
// 我们不希望界面因此卡住。
func readIfFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if fi.Size() > 1<<20 {
		return nil, fmt.Errorf("file too large")
	}
	return os.ReadFile(path)
}

// boxedEditor 画一个带背景框的多行输入/只读文本区。
func (a *uiState) boxedEditor(gtx layout.Context, ed *widget.Editor, hint string) layout.Dimensions {
	inset := layout.Inset{Top: unit.Dp(10), Bottom: unit.Dp(10), Left: unit.Dp(12), Right: unit.Dp(12)}
	content := func(gtx layout.Context) layout.Dimensions {
		e := material.Editor(a.theme, ed, hint)
		e.Color = colorText
		e.HintColor = colorFaint
		e.TextSize = unit.Sp(11)
		return e.Layout(gtx)
	}
	return layout.Background{}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			m := op.Record(gtx.Ops)
			dims := inset.Layout(gtx, content)
			op.Defer(gtx.Ops, m.Stop())
			fillRounded(gtx, colorRaised, dims.Size, gtx.Dp(unit.Dp(radiusSmall)))
			return dims
		},
		func(gtx layout.Context) layout.Dimensions { return inset.Layout(gtx, content) },
	)
}
