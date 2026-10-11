// Package ui 的视觉设计系统（方案 C「安全优先」）。
//
// # 设计原则
//
// 本项目的核心难点**不是**功能，而是让用户看到真相：
// 已经发生过的三个真实缺陷（点了没反应、状态与实际不符、
// 死对端仍显示已连接）全都是"界面显示了不真实的状态"。
//
// 因此视觉设计的第一目标不是好看，而是**信任状态不可能被忽略**。
// 具体体现为三条硬规则：
//
//  1. 顶部常驻信任条，颜色编码当前会话的信任等级；
//  2. 未核实身份时，发出的**每一条消息**都带可见标记；
//  3. 指纹与 emoji 常驻可见，不藏在设置页里。
//
// 颜色只承担一种语义：**灰=未知、黄=未核实、绿=已核实、红=失败**。
// 强调色刻意只用青色一种，避免"五颜六色"稀释掉这三个状态的分量。
package ui

import "image/color"

// 配色。
//
// 近黑而非纯黑（#000）：纯黑配纯白在多数 LCD 上会发糊，
// 长时间阅读更累。层级用极小的明度差拉开，而不是靠边框。
var (
	// 背景层次（由深到浅）。
	colorBackground = color.NRGBA{R: 0x0A, G: 0x0A, B: 0x0B, A: 0xFF}
	colorSurface    = color.NRGBA{R: 0x13, G: 0x14, B: 0x16, A: 0xFF}
	colorRaised     = color.NRGBA{R: 0x1C, G: 0x1E, B: 0x21, A: 0xFF}
	colorLine       = color.NRGBA{R: 0x25, G: 0x28, B: 0x2C, A: 0xFF}

	// 唯一强调色：青。比蓝色更"工具"，且与常见聊天软件的
	// 蓝色区分开——用户不应当把本工具误认成即时通讯产品。
	colorAccent = color.NRGBA{R: 0x2D, G: 0xD4, B: 0xBF, A: 0xFF}

	// 文字层次。
	colorText  = color.NRGBA{R: 0xE8, G: 0xEA, B: 0xED, A: 0xFF}
	colorMuted = color.NRGBA{R: 0x87, G: 0x8E, B: 0x99, A: 0xFF}
	colorFaint = color.NRGBA{R: 0x5A, G: 0x60, B: 0x6A, A: 0xFF}
)

// 信任等级配色。
//
// ⚠️ 这组颜色是**唯一的**信任语义来源，不要在别处另起一套。
// 同一个"已核实"在顶部信任条、联系人圆点、消息边缘
// 必须是同一个绿——否则用户要重新学习，编码就失效了。
var (
	// colorTrustUnknown 灰：未连接，谈不上信任。
	colorTrustUnknown = color.NRGBA{R: 0x6B, G: 0x72, B: 0x7D, A: 0xFF}

	// colorTrustUnverified 黄：加密已建立，但**没人确认过对方是谁**。
	//
	// 这是本工具最重要的一档。使用琥珀色而不是橙色/红色：
	// 它不是错误，只是一种"还没完成"的状态。
	// 用红色会让用户以为自己被攻击了。
	colorTrustUnverified = color.NRGBA{R: 0xE8, G: 0xB3, B: 0x39, A: 0xFF}

	// colorTrustVerified 绿：用户比对过 emoji，确认一致。
	colorTrustVerified = color.NRGBA{R: 0x3F, G: 0xB9, B: 0x50, A: 0xFF}

	// colorTrustFailed 红：握手失败/指纹不匹配。
	// 这是真正的告警，必须与"未核实"明显区分。
	colorTrustFailed = color.NRGBA{R: 0xE5, G: 0x53, B: 0x4B, A: 0xFF}
)

// 语义别名，让调用点读起来是"意图"而不是"颜色"。
var (
	colorOK   = colorTrustVerified
	colorWarn = colorTrustUnverified
	colorErr  = colorTrustFailed
)

// 尺寸与间距。
//
// 统一在一处，避免各处魔数导致界面"看着不齐"——
// 那种不齐很难定位，但一眼就能感觉到。
const (
	// 信任条高度：必须足够高以承载文字，且**不可折叠**。
	trustBarHeightDp = 44

	// 侧栏宽度。
	sidebarWidthDp = 280

	// 消息气泡最大宽度。占满整行会让长消息难读，
	// 也让人分不清哪句是谁说的。
	maxBubbleWidthDp = 560

	// emoji 核对格尺寸。刻意大——核对会不会真的发生，
	// 取决于它有多容易做。
	emojiCellDp = 64
)

// 圆角半径。
const (
	radiusSmall = 4
	radiusCard  = 10
	radiusPill  = 999
)
