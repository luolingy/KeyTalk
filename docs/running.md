# 运行指南

本文档说明**如何实际运行**当前代码。项目处于 S5 阶段：加密链路已完全打通，
但**还没有图形界面**——目前的入口是命令行工具。

---

## 1. 当前能做什么

| 能力 | 状态 |
|---|---|
| 生成 OpenPGP 身份 | ✅ |
| 局域网自动发现（mDNS） | ✅ |
| 端到端加密握手（M2 / 有前向保密） | ✅ |
| 双向加密文本消息 | ✅ |
| 大小写、Unicode 消息 | ✅ |
| 拒绝陌生身份接入 | ✅ |
| **图形界面** | ❌ 尚未实现（S7） |
| **附件传输** | ❌ 尚未实现（S10） |
| **公网穿透** | ❌ 尚未实现（S11） |
| **私钥加密存储** | ❌ 尚未接入（见下方警告） |

---

## 2. 快速开始

### 2.0 环境准备

```powershell
cd F:\exeliang\KeyTalk
$env:GOCACHE="F:\exeliang\KeyTalk\.gocache"   # 必须：默认缓存在沙箱外
$env:GOTELEMETRY="off"                        # 可选：压掉无害的遥测警告
```

> `GOCACHE` 不是可选项。默认缓存在工作区之外，不设置会直接报
> `Access is denied` 且构建失败。

### 2.1 一键构建（推荐）

```powershell
.\build.ps1              # 产出 dist\keytalk.exe，并做一次冒烟自检
.\build.ps1 -Run         # 构建后立即启动
.\build.ps1 -Clean       # 先清空 dist\
.\build.ps1 -GuiOnly     # 完全不出现控制台窗口（代价：不能再当命令行用）
```

脚本会自动设置 `GOMODCACHE` / `GOCACHE`，并保证产物**真的能跑**：
它会在临时目录里执行一次 `-setup`，确认身份文件和公钥都被写出。
只"链接成功"不算数。

也可以手工编译：

```powershell
go build -o keytalk.exe ./cmd/keytalk
```

### 2.2 生成两个身份（模拟两台机器）

```powershell
.\keytalk.exe -name alice -id .\demo\alice -setup
.\keytalk.exe -name bob   -id .\demo\bob   -setup
```

每个身份会产出：

- `identity.json` — 私钥（**明文**，见 §5 警告）
- `public.key` — 公钥，可以安全地发给对方

### 2.3 交换公钥

这一步必须**带外**完成（当面对指纹、通过其他可信渠道），
这正是端到端加密的意义所在——首次信任无法由协议本身建立。

```powershell
# Alice 导入 Bob 的公钥
.\keytalk.exe -id .\demo\alice -contact .\demo\bob\public.key

# Bob 导入 Alice 的公钥
.\keytalk.exe -id .\demo\bob -contact .\demo\alice\public.key
```

导入后程序会**继续进入聊天界面**。若只想导入后退出，加 `-setup`：

```powershell
.\keytalk.exe -id .\demo\alice -contact .\demo\bob\public.key -setup
```

### 2.4 开始聊天

**图形界面（双击即用）**：

```powershell
.\keytalk.exe                                       # 数据目录自动决定
.\keytalk.exe -gui -id .\demo\alice                 # 指定数据目录
```

首次运行会**自动生成身份**，不需要任何参数或配置。
数据落在 `%AppData%\KeyTalk`（可用 `-id` 覆盖）。

**命令行界面**：

打开**两个**终端窗口：

```powershell
# 终端 1
.\keytalk.exe -name alice -id .\demo\alice

# 终端 2
.\keytalk.exe -name bob -id .\demo\bob
```

两个实例会自动通过 mDNS 发现对方并完成握手。握手成功后会打印
一组 **7 个 emoji**：

```
🔒 与 bob 的端到端加密会话已建立。请与对方核对下方 emoji，一致才能确认没有中间人：

    🐕 🌙 🚲 🍓 🐧 👍 🐰

    （念给对方听：Dog, Moon, Bicycle, Strawberry, Penguin, Thumbs Up, Rabbit）
一致 = 通信可信；不一致 = 可能有人在冒充，请立即停止。
```

**双方打印的必须完全相同。** 通过电话或当面念一遍——
这一步才真正排除中间人；握手本身只能证明"对方持有某把私钥"，
不能证明"那把私钥属于你朋友"。

然后直接输入文字即可发送。可用命令：

| 命令 | 作用 |
|---|---|
| `/who` | 列出联系人及在线/会话状态 |
| `/talk <名字或序号>` | 选择对话对象（会自动发起握手） |
| `/keys` | 显示本机指纹 |
| `/help` | 帮助 |
| `/quit` | 退出 |

### 2.5 启动方式与数据目录

同一个可执行文件有两种用法，靠**有没有参数**区分：

| 启动方式 | 行为 |
|---|---|
| 无参数 / 双击 | 图形界面，首次运行自动生成身份 |
| 带任何参数 | 命令行，行为与以往完全一致 |

数据目录按以下顺序决定（`resolveDataDir`）：

1. 显式 `-id <路径>` → 无条件使用；
2. 当前目录已存在 `./keytalk-data` → 继续用它；
3. 否则用 `%AppData%\KeyTalk`。

第 2 条是为了**不弄丢老用户的身份**：私钥就在那个目录里，
默认值一改，程序会看不到 `identity.json` 而静默生成新密钥，
指纹随之改变，所有已交换公钥的联系人全部握手失败。

第 3 条是为了双击场景：那时的工作目录是 exe 所在位置，
可能是 `Program Files` 或只读介质，写不进去。

图形界面会把日志同时写入 `<数据目录>/keytalk.log`——
双击启动时控制台是隐藏的，没有这个文件就没有任何可排查的线索。

---

## 3. 一键验证

不需要手动操作，直接跑端到端验证脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\e2e.ps1
```

它会：生成身份 → 交换公钥 → 启动两个真实进程 → 等待自动发现与握手 →
检查双方是否都报告"身份已校验"，最后清理。

预期结尾：

```
  [OK] mDNS discovery observed
  [OK] bidirectional handshake completed
  [OK] both sides confirmed cryptographic identity verification
*** END-TO-END ENCRYPTED LINK VERIFIED ***
```

> 脚本刻意使用**纯 ASCII**。Windows PowerShell 5.1 会按 ANSI 代码页读取
> `.ps1` 文件，中文字面量会被解析成乱码导致语法错误。

---

## 4. 跑测试

```powershell
go test ./... -count=1
```

各包覆盖范围：

| 包 | 覆盖内容 |
|---|---|
| `internal/crypto` | AEAD、重放窗口、握手（含前向保密）、篡改、密钥清零 |
| `internal/wire` | 帧编解码、fuzz、AAD 布局 |
| `internal/transport/lan` | mDNS 报文编解码、帧切分、畸形输入、背压 |
| `internal/session` | 握手编排、加密消息、身份不匹配拒绝、恶意帧 |
| `internal/e2e` | **四层串起来跑**：真实 TCP + 30 条消息保序 + 攻击者注入被拒 |

---

## 5. ⚠️ 使用前必读的安全限制

这几条是**真实存在**的限制，不是谦辞。

### 5.1 私钥当前以明文存储

`identity.json` 里的私钥**没有加密**。程序启动时会明确打印警告。

设计中的方案（`passphrase → argon2id → KEK → MK → 加密私钥`）已在
`internal/crypto/keystore.go` 实现，但**尚未接通**——那需要一个口令输入
界面，属于 UI 阶段（S7）的工作。

**因此：目前不要用真实身份。** 仅用于功能验证。

> ⚠️ 一键构建后这一点的影响面变大了：默认数据目录是
> `%AppData%\KeyTalk`，路径固定且可预测，而备份软件会把它
> 连同明文私钥一起同步到云端。用真实身份之前请先做加密。

### 5.2 加密实现是参考级，不是生产级

`internal/crypto/pgp_provider.go` 基于已废弃的 `golang.org/x/crypto/openpgp`：

- 上游已标记废弃，官方建议迁移；
- **仅支持 RSA**，无法使用 Ed25519；
- 保留它只是为了让整个包在没有外部依赖时也能完整单测。

生产构建应替换为 `github.com/ProtonMail/go-crypto/openpgp`。
替换只需实现 `IdentityProvider` 接口，其余模块不受影响
（详见 [crypto-protocol.md](crypto-protocol.md) §10.4.1）。

### 5.3 元数据没有加密

局域网广播包含**你的指纹**，任何在同一网段的人都能看到
"有人在用 KeyTalk，指纹是 X"。指纹不是密钥，但确实是元数据。

协议层的字段（`Epoch`、`Seq`、帧类型、长度）也都是明文——这是
AEAD 设计的必然要求，接收方必须先看到这些才能选密钥解密。
本项目的做法是**承认它**，而不是假装元数据也被保护
（见 [threat-model.md](threat-model.md)）。

### 5.4 没有离线消息

纯 P2P 架构下，对方不在线就发不出去。这不是 bug，是设计取舍
（见 [transport-lan.md](transport-lan.md) §7）。

### 5.5 加密强度受限于握手

M2 方案提供**前向保密**（临时密钥用完即毁），但**不是** Signal 那样的
持续 ratchet：泄露长期私钥仍可影响当前会话。具体边界见
[crypto-protocol.md](crypto-protocol.md) §5。

---

## 6. 排错

### 看不到对方（发现失败）

程序启动时会如实报告 mDNS 状态：

```
✓ 正在通过 mDNS 广播与搜索服务 _keytalk._tcp.local.
```

若显示 `✗ mDNS 发现不可用`，常见原因：

| 现象 | 原因 | 处理 |
|---|---|---|
| 端口 5353 被占用 | 同机有其他 mDNS 服务 | 现代码已用 `SO_REUSEADDR` 共存；若仍失败请查看错误详情 |
| 防火墙拦截 | 系统防火墙阻止入站 UDP 5353 / TCP | 放行 KeyTalk |
| 虚拟网卡干扰 | 多网卡机器（WSL/VMware/VPN） | 代码会尝试**所有**接口与所有候选地址，一般可自愈 |
| 跨网段 | 两个设备不在同一广播域 | 局域网发现无法跨网段（这是 mDNS 的固有限制） |

### 一直显示"正在握手"

20 秒后会明确超时报错，而不是无限等待。若超时：

- 确认对方**也**导入了你的公钥；
- 确认双方导入的是**对方的**公钥（不能导错、不能导成自己的）；
- 指纹不匹配是最常见的原因——用 `/keys` 核对。

### 反复出现"随机"失败

如果有时成功、有时超时，用 `-v` 跑一次并看日志。两个实例应各自
在日志里出现 `connected to` / `inbound from`。

历史上这类间歇性失败有明确原因（均已修复），但如果再次出现，
优先怀疑这几处：

| 日志线索 | 含义 |
|---|---|
| 一侧 `read N bytes` 但会话层毫无动静 | 有人**抢走了**传输层事件通道（见实现笔记 §4.5） |
| 双方都 `connected to` 且地址不同网段 | 多网卡各自拨号，应分角色（§4.6） |
| peerID 里出现 `%网卡名` | IPv6 zone 未剥离（§4.7） |

> 判断稳定性不能只看跑一次。请用 `e2e.ps1` **连续跑 8~12 次**，
> 全绿才说明这条链路在当前网络环境下是稳的。
> 本项目多个 bug 只在第 4 次之后才复现。

### 握手失败：身份不在联系人表

这是**有意的**拒绝。程序不会自动信任陌生连接。要通信必须先交换公钥。

---

## 7. 接下来

下一阶段是 **S7（Gio 图形界面）**，把命令行流程搬到真正的聊天窗口。

在此之前建议先做 **S0 spike**：验证 Gio 在 Android 上的 mDNS
（`MulticastLock`）与中文字体。这是移动端最大的未知数，
万一不通，移动端架构需要调整——早发现比晚发现便宜得多。

完整路线见 [roadmap.md](roadmap.md)。
