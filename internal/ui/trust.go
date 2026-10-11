package ui

import (
	"image/color"

	"github.com/exeliang/keytalk/internal/core"
)

// TrustLevel 是"我们对这个对端知道多少"的三档抽象。
//
// ⚠️ 刻意分成三档而不是两档（安全/不安全）。
//
// 把"已加密但没核实"与"已核实身份"合并显示成"安全"，
// 是这类工具最常见也最有害的偷懒：用户会把
// "内容没有被窃听"读成"我知道对面是谁"。
// 这是两件完全不同的事，必须分开呈现：
//
//   - 加密解决"有没有人在听"；
//   - emoji 核对解决"对面是不是那个人"。
//
// 握手能自动保证前者，**只有人能保证后者**。
type TrustLevel int

const (
	// TrustUnknown：没有会话。灰。
	TrustUnknown TrustLevel = iota

	// TrustUnverified：加密已建立，但用户尚未核对 emoji。**黄**。
	//
	// 这是初始状态。所有新会话都从这里开始——
	// 绝不允许握手把它直接推进到 TrustVerified。
	TrustUnverified

	// TrustVerified：用户比对过 emoji 且一致。绿。
	TrustVerified

	// TrustFailed：握手失败或指纹不匹配。红。
	TrustFailed
)

// trustOf 从联系人状态推导信任等级。
//
// 这是**唯一**的推导入口：顶部信任条、侧栏圆点、消息边缘标记
// 全部调用它。任何一处自行判断都会产生不一致——
// 而"界面各处对信任的表述不一致"本身就是安全缺陷：
// 用户会相信最乐观的那一处。
func trustOf(c core.Contact) TrustLevel {
	switch {
	case c.Status == core.StatusFailed:
		return TrustFailed
	case c.Status != core.StatusSecure:
		// 离线、在线（握手中）都归入"未知"：
		// 还没有可核对的东西，谈不上信任。
		return TrustUnknown
	case c.Verified:
		return TrustVerified
	default:
		return TrustUnverified
	}
}

// trustColor 返回信任等级对应的颜色。
func trustColor(l TrustLevel) color.NRGBA {
	switch l {
	case TrustVerified:
		return colorTrustVerified
	case TrustUnverified:
		return colorTrustUnverified
	case TrustFailed:
		return colorTrustFailed
	default:
		return colorTrustUnknown
	}
}

// trustLabel 是信任等级的**短**标签，用于空间受限处（圆点提示、状态栏）。
func trustLabel(l TrustLevel) string {
	switch l {
	case TrustVerified:
		return "已核实"
	case TrustUnverified:
		return "未核实"
	case TrustFailed:
		return "失败"
	default:
		return "未连接"
	}
}

// trustPhrase 是信任等级的**完整**表述，用于顶部信任条。
//
// 必须把"加密"和"身份"两件事都说清楚。
// 只说"未核实"用户不知道核实什么；
// 只说"已加密"用户会以为已经安全了。
func trustPhrase(l TrustLevel) string {
	switch l {
	case TrustVerified:
		return "已核实身份 · 已加密"
	case TrustUnverified:
		return "已加密，但尚未核实对方身份"
	case TrustFailed:
		return "连接失败"
	default:
		return "未建立加密会话"
	}
}

// trustDetail 是一句行动指引，回答"我该做什么"。
//
// 空字符串表示无需行动。
func trustDetail(l TrustLevel) string {
	switch l {
	case TrustUnverified:
		return "请与对方核对下方 emoji；一致才能确认没有被中间人"
	case TrustFailed:
		return "请确认联系人公钥是否正确，或稍后重试"
	default:
		return ""
	}
}

// worstTrust 汇总多个联系人的信任等级，用于全局状态。
//
// 取**最差**的一档：全局指示器存在的意义是
// "有没有任何一件事需要我注意"。取最乐观的一档会让
// 一个未核实的会话被另一个已核实的会话掩盖掉。
func worstTrust(contacts []core.Contact) TrustLevel {
	if len(contacts) == 0 {
		return TrustUnknown
	}
	worst := TrustVerified
	for _, c := range contacts {
		l := trustOf(c)
		// Failed 比 Unverified 更需要注意，Unknown 次之。
		if trustRank(l) < trustRank(worst) {
			worst = l
		}
	}
	return worst
}

// trustRank 给各等级排序，数值越小越"需要注意"。
func trustRank(l TrustLevel) int {
	switch l {
	case TrustFailed:
		return 0
	case TrustUnverified:
		return 1
	case TrustUnknown:
		return 2
	default:
		return 3
	}
}
