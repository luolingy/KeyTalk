# Gio 界面设计

## 1. Gio 基础与约束

Gio 是**立即模式（immediate mode）** GUI：

- 每帧重新执行整个 `Layout` 函数来"画"界面，而不是持有控件对象树；
- 所有 `Layout` 在同一 goroutine 上串行执行；
- 需要重绘时调用 `w.Invalidate()`；
- 标准启动模式：

```go
func main() {
    go func() {
        w := app.NewWindow(app.Title("KeyTalk"))
        if err := run(w); err != nil {
            log.Fatal(err)
        }
        os.Exit(0)
    }()
    app.Main()   // 必须在主线程阻塞
}
```

### 1.1 硬约束

| 约束 | 后果 |
|---|---|
| `Layout` 内不可阻塞 | 界面冻结；`select` 读 channel 必须带 `default` |
| 不可在 `Layout` 内做网络/加密 | 每帧执行，开销 ×60/s |
| 状态变更后需 `w.Invalidate()` | 否则界面不刷新（易漏） |
| 主线程必须留给 `app.Main()` | 否则平台集成（尤其 macOS/Android）异常 |

---

## 2. 事件桥接（UI ↔ core）

```go
// core → UI
type UIEvent interface{ isUIEvent() }

type EvIncoming   struct{ Contact string; Body string; At time.Time }
type EvMessageAck struct{ Contact string; LocalID int64; At time.Time }
type EvConnState  struct{ Contact string; State ConnState }
type EvPresence   struct{ Contact string; Online bool }
type EvDiscovered struct{ Device DiscoveredDevice }   // mDNS 发现的新设备
type EvSecurity   struct{ Contact string; Kind SecurityEvent }
type EvError      struct{ Text string }

// UI → core（全部非阻塞）
func (a *App) SendText(contact string, text string) int64
func (a *App) AddContactFromKey(armored []byte) (Contact, error)
func (a *App) SetTrust(contact string, t TrustLevel)
func (a *App) Connect(contact string) error
```

### 2.1 UI 侧事件泵

在根 `Layout` 开头排空事件队列：

```go
func (v *View) drain(app *core.App) {
    for {
        select {
        case ev := <-app.Events():
            v.apply(ev)          // 只改内存中的视图状态
        default:
            return               // 关键：非阻塞
        }
    }
}
```

**要点**：

- `app.Events()` 返回有界 channel（建议容量 1024）。若 UI 跟不上，core 侧**不得阻塞**——应丢弃"可丢弃事件"（如 `EvPresence` 重复项）并合并，但**不得丢弃** `EvIncoming`（消息）与 `EvError`。
- 丢弃无关键事件的策略需在 core 中显式实现，不能靠 channel 满时静默丢弃（那会丢消息）。

### 2.2 重绘触发

core 无法直接调用 `w.Invalidate()`（会跨 goroutine）。做法：

```go
// UI 侧持有窗口引用，通过 channel 被唤醒
go func() {
    for range core.NeedsRedraw() {
        w.Invalidate()
    }
}()
```

或更简单：在 UI 的 `Layout` 中检测到"本次 drain 处理了事件"时返回一个标志，由外层循环调用 `w.Invalidate()`。**推荐前者**，因为后者依赖每帧都执行到 drain，而在无事件、无输入时 Gio 可能不触发重绘——形成"没事件就没帧，没帧就看不到事件"的死锁。这是 Gio 中非常典型的坑。

> **务必实现前者**：一个常驻 goroutine 监听 core 的"有新事件"信号并调用 `w.Invalidate()`。

---

## 3. 视图结构

```
RootView
├── LockView        身份未解锁（口令输入）
├── MainView        已解锁
│   ├── Sidebar     联系人列表 + 发现的设备 + 设置入口     （桌面：常驻；移动：抽屉）
│   ├── ChatView    当前会话的消息流 + 输入框
│   └── SettingsView 身份信息、指纹、密钥导入导出
└── Dialogs
    ├── AddContactDialog    粘贴公钥 / 输入邀请
    ├── VerifyFingerprintDialog  指纹比对确认
    └── SafetyNumberDialog       安全码展示
```

### 3.1 锁定态

- 若设置了口令，启动时先显示 `LockView`。
- 解锁失败要有**退避**（连续失败延迟递增），防止暴力破解口令。
- 提供"重置身份"入口，但需**明确警告**：重置后无法解密历史消息，且联系人需重新验证。

### 3.2 布局适配

| 平台 | 布局 |
|---|---|
| 桌面（宽） | 左侧联系人栏 + 右侧会话，双栏 |
| 移动（窄） | 单栏栈式导航：列表 → 会话；返回键/手势回列表 |

判断方式：用 `gtx.Constraints.Max.X` 与阈值（如 `unit.Dp(600)`) 比较，而非查询平台。这样窗口缩放也能正确切换。

---

## 4. 关键控件

### 4.1 消息列表

用 `layout.List`（只渲染可见项，天然适合长列表）：

```go
&layout.List{
    Axis:      layout.Vertical,
    Alignment: layout.End,      // 从底部开始，聊天语义
    ScrollToEnd: true,
}
```

**要点**：

- `Alignment: layout.End` 让内容贴底，符合聊天习惯。
- 新消息到达时若用户已在底部 → 自动滚动到底；若用户**上翻查看历史** → **不要**强制滚动（否则会打断阅读）。需记录"是否在底部"状态。
- 每项渲染：气泡（`layout.Stack` + `clip.RRect` 圆角 + `paint.Fill`）、正文、时间戳、状态图标。
- **文本测量开销**：`text.Shaper` 会缓存，但超长消息仍可能慢。对超长文本需限制每帧测量范围或分块。

### 4.2 输入框

```go
var editor widget.Editor
editor.SingleLine = false        // 支持多行
editor.Submit = true             // 回车提交
```

- 回车发送，Shift+回车换行（桌面）；移动端由软键盘"发送"键触发 `Submit`。
- **输入框内容属于敏感数据**，不应写入日志。
- 移动端：点击输入框需请求焦点并唤起软键盘（Gio 处理 IME，但中文输入法的组合态需要实测）。

### 4.3 在线状态与发送按钮

- 对方离线时**禁用发送**，并显示"对方离线，消息无法送达"。
- 理由见 [transport-lan.md](transport-lan.md) §7.1：纯 P2P 无法离线投递，做"能发但丢失"的假象比直接禁用更糟。

### 4.4 安全状态展示（重要）

安全状态的 UI 是**功能的一部分**，不是装饰。必须做到：

| 状态 | 展示 | 颜色/图标 |
|---|---|---|
| `TOFU` | "未验证"——首次使用信任，存在中间人风险 | 黄色警告 |
| `VERIFIED` | "已验证"——指纹已带外比对 | 绿色 |
| `BLOCKED` | "已阻止"——比对失败或用户拉黑 | 红色 |
| 会话密钥刚完成 ratchet | 显示"密钥已更新"（短暂提示） | 中性 |

**必须避免的反模式**：

- ❌ 显示一个笼统的"🔒 已加密"并让用户以为一切安全。E2EE 只保证"内容没被中间人改"，**不保证对方是谁**。
- ❌ 把"加密中"与"已验证身份"混为一谈。
- ✅ 对未验证联系人，在会话标题处**持续**显示"未验证"，直到用户完成比对。不能只在添加时提示一次。

### 4.5 指纹展示与验证

- 指纹以 `ABCD 1234 5678 ...` 四位分组展示，便于口头比对。
- 提供**二维码**（编码全量指纹）供扫码比对（移动端尤其实用）。
- 提供"安全码"（如 Signal 的做法：双方公钥的哈希派生的可读数字/词组），提高人工比对准确率。
- 确认对话框必须要求用户**主动确认已比对**，不得默认勾选。

---

## 5. 字体与国际化（易踩的坑）

### 5.1 中文缺字问题

**Gio 默认的 `gofont` 字体不包含 CJK 字形。** 如果不处理，中文会显示为豆腐块/空白。必须显式提供中文字体：

```go
// 思路（API 随 Gio 版本略有差异，实现时以所用版本为准）
// 1. 用 embed 或运行时读取，拿到字体文件字节
// 2. opentype.Parse 得到 font.Face
// 3. 构造 text.Shaper 的字体集合，并在 material.Theme 中使用
th := material.NewTheme()
th.Shaper = text.NewShaper(text.WithCollection(cjkCollection))
```

**字体文件体积问题**：

| 方案 | 体积 | 说明 |
|---|---|---|
| 完整 Noto Sans CJK SC | 10–20 MB | 显著增大二进制/APK |
| 字体子集（常用汉字） | 1–4 MB | 需构建期裁剪；生僻字会缺 |
| 运行时加载系统字体 | 0 | 各平台路径不同，Gio 不直接提供系统字体枚举，需自行探测 |

**建议**：桌面端可在构建期嵌入子集字体；移动端若体积敏感，运行时尝试常见系统字体路径，失败则回退到嵌入子集。**这需要实测各平台路径**，属待定项。

#### 5.1.1 实现结果（已验证）

已按"运行时加载系统字体"实现，`internal/ui/fonts.go`：

- 候选列表覆盖 Windows / macOS / Linux 常见路径，命中即用；
- `opentype.ParseCollection` 解析（`.ttc` 是集合，会返回多个 face）；
- **解析失败会记录告警并继续尝试下一个候选**，不静默放弃；
- 全部失败时通过 `cjkFontStatus()` 在状态栏明确显示
  "中文字体: 未找到（中文可能显示为方块）"。

实测（Windows 10）：

```
CJK font loaded from C:\Windows\Fonts\msyh.ttc
font collection has 14 face(s)     # gofont 的若干 face + 微软雅黑
```

**关键实现细节**：字体只解析**一次**（`sync.Once`）。
`.ttc` 有十几 MB，每帧解析会立刻把 immediate-mode 的帧率拖垮。

**测试**：`TestCJKFontIsLoaded` 在找不到字体时 **Skip 而非 Fail**——
那是环境限制（精简 Linux 容器确实可能没有中文字体），
不是代码缺陷。但**运行时必须告警**，绝不静默降级：
用户看到满屏方块时应当能立刻知道原因。

---

## 5.3 其它实测到的 API 细节

以下几处与设计文档的设想不同，记录以免重复踩坑：

| 事项 | 实际情况 |
|---|---|
| `layout.Background` | `Layout(gtx, 背景, 内容)` **两个** widget，不是委托式单参数 |
| `widget.Clickable` | 必须**跨帧持久**（结构体字段）。每帧 `new` 一个会让按钮永远收不到点击 |
| `widget.Clickable.Cursor` | 不存在；光标形状需经 `pointer.Cursor` 的 op 栈 |
| 填充背景 | 无 `fill` 原语，用 `paint.FillShape(ctx.Ops, c, clip.Rect{Max: sz}.Op())`；**用 Max 而非 Min**（Flexed 布局里 Min 可能是 0） |
| 状态圆点 | `clip.Ellipse{Min, Max}.Op(gtx.Ops)` |

### 5.3.1 一个隐蔽的"点了没反应"

`widget.Clickable` 是**有状态**的：它需要在帧之间保留上一次的
点击区域与按下状态。若写成

```go
btn := new(widget.Clickable)   // ❌ 每帧新建
if btn.Clicked(gtx) { ... }
```

按钮**永远**不会触发。不会有编译错误，也不会有运行时错误——
只是点下去毫无反应。本项目发送按钮因此把 `sendBtn` 作为
`uiState` 的字段持久保存。

---

## 5.4 无窗口环境下的验证方式

Gio 没有截图或内省接口，因此"界面画对了吗"无法直接断言。
本项目的做法是**分层验证**：

| 验证项 | 方式 |
|---|---|
| 窗口能否创建 | `cmd/uitest -d Ns`：开窗渲染 N 秒后自动退出 |
| 中文字体是否加载 | `TestCJKFontIsLoaded`（可直接断言字体路径与 face 数） |
| 文案是否面向用户 | `statusLabel` / `emptyContactsText` 的单测 |
| 交互逻辑 | 抽成纯函数后单测（如 `statusColor` 不重复） |

`cmd/uitest` 用"存活满 N 秒且无错误输出"作为通过标准——
窗口创建失败或字体加载失败都会**立即**报错或崩溃，
因此这是对那两个高风险假设的有效证据。

它**不是**产品的一部分，存在的意义就是在投入完整界面之前
把风险先验证掉。这类 spike 用完即应删除或明确标记。

---

- 首期只需从左到右的纯文本 + emoji。
- Emoji 需要额外的彩色字体支持，Gio 的支持程度需实测；若不支持，emoji 会显示为单色或缺失。
- **不做** Markdown/富文本渲染，避免范围膨胀。

---

## 6. 跨平台差异

| 项 | 桌面 | Android | iOS |
|---|---|---|---|
| 入口 | `app.Main()` | Gradle 工程 + `app.Main()` | Xcode 工程 + `app.Main()` |
| 配置目录 | `os.UserConfigDir()` | 应用私有目录 | 沙盒路径 |
| 软键盘 | 无 | 需处理遮挡与收起 | 同左，另有安全区 |
| 返回键/手势 | 无 | 需响应系统返回 | 边缘手势 |
| 后台 | 常驻 | 可前台服务保活 | **不可后台长连** |
| 权限 | 防火墙 | MulticastLock 等 | 本地网络 + Bonjour |
| 通知 | 系统托盘可选 | 通知渠道 | 需权限 |

**移动端额外 UI 考量**：

- 安全区（刘海/灵动岛/手势条）内边距。
- 软键盘弹起时的布局重排（消息区收缩，输入框上移）。
- 移动端不做系统托盘；离线状态由应用内提示。

---

## 7. 性能注意

| 问题 | 应对 |
|---|---|
| 每帧重建整个列表 | 用 `layout.List` 虚拟化；不要手写 `for` 遍历全部消息 |
| 每帧重复计算文本布局 | 依赖 `text.Shaper` 缓存；避免每帧构造新的样式对象 |
| 大量 `op.Save`/`op.Restore` | 复用 `clip` 路径，减少栈操作 |
| 频繁 `Invalidate` | 只在状态真正变化时触发；避免"每帧都 invalidate" |
| 消息很多时的滚动卡顿 | 分页加载（每次加载最近 N 条，上滚再取） |

**建议**：消息列表采用**分页窗口**（如内存中最多保留 500 条 + 视口附近），历史从 SQLite 按需加载，避免全量驻留内存。

---

## 8. 无障碍与可用性

- 关键操作提供键盘快捷键（桌面）：`Ctrl+F` 搜索、`Esc` 关闭对话框、`Ctrl+N` 新会话。
- 颜色不是唯一的状态载体（色盲友好）：信任状态同时用文字与图标，不只靠颜色。
- 对比度：警告/危险色需满足可读性。

---

## 9. 测试要点

| 场景 | 验证 |
|---|---|
| 中文、emoji、超长单行、超长多行 | 正确渲染不溢出 |
| 窗口缩放跨越 600dp 阈值 | 布局在双栏/单栏间正确切换 |
| 收到消息时用户正在上翻历史 | 不强制滚动 |
| 收到消息时用户在底部 | 自动滚动到底 |
| 输入框中文输入法组合态 | 不丢字、不重复提交 |
| 移动端软键盘弹起 | 输入框不被遮挡 |
| 未验证联系人 | 持续显示"未验证"警告 |
| 对方离线 | 发送按钮禁用 + 明确提示 |
| 解锁口令连续失败 | 退避生效 |
| 移动端旋转屏幕 | 布局正确重排 |

---

## 10. 待定问题

| 问题 | 影响 | 建议 |
|---|---|---|
| 中文字体分发策略 | 体积 vs 覆盖 | 实现前实测系统字体路径 |
| Emoji 渲染支持程度 | 体验 | 实测；不支持则明确不承诺 |
| Gio 版本与 API 稳定性 | 迁移成本 | 锁定版本，升级需回归 |
| 是否需要消息搜索 | 工作量 | 首期不做 |
| 移动端是否需要通知 | 体验 | 首期仅应用内提示 |
