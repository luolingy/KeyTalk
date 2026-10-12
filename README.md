# KeyTalk

基于 [Gio](https://gioui.org/)（Go 跨平台 GUI）+ OpenPGP/GPG 的 **P2P 端到端加密聊天工具**。

- **P2P**：优先直连；公网打洞失败时经中继转发（**中继只看到密文**）。
- **E2EE**：消息在应用层加密，网络中间节点（含中继）看不到明文。
- **身份 = GPG 密钥指纹**：复用 OpenPGP 生态的公钥/私钥与信任习惯。

> 当前阶段：**局域网加密聊天已经能跑**（命令行）。状态见下节。

---

## 设计决策速览

| 决策点 | 选择 | 理由 |
|---|---|---|
| 加密模式 | **KEM + AEAD**（OpenPGP 封装临时公钥，X25519 ECDH 派生会话密钥，ChaCha20-Poly1305 加密数据） | 逐条非对称加密性能差、密文膨胀大、无法分块；ECDH 派生是获得前向保密的前提 |
| OpenPGP 实现 | `github.com/ProtonMail/go-crypto/openpgp` | `golang.org/x/crypto/openpgp` 已废弃；该 fork 维护中并支持 ECC/cv25519 |
| 调用方式 | Go 库优先，`gpg` CLI 仅用于硬件密钥后端 | 库无进程启动开销、无临时文件、跨平台行为一致 |
| 首期网络 | 局域网 mDNS + TCP | 零外部基础设施，最快跑通端到端闭环 |
| 公网穿透 | **ICE（pion/webrtc）+ 自建 TURN 兜底**；**STUN 自建为主、公共兜底** | ICE 是解决 NAT 穿透的标准（RFC 8445）；STUN 流量极小可免费公共使用，TURN 承载数据必须自建 |
| 附件传输 | **64 KiB 分块 AEAD + 两级优先队列** | 分块解决重排/截断/重放；优先级调度让大文件不阻塞聊天 |
| 本地密钥 | **口令 → KEK → MK（主密钥）→ 数据** | 改口令时只需重新封装 MK，不必重新加密任何消息或附件 |
| GUI | Gio（immediate mode） | 单份代码覆盖 Windows/Linux/macOS/Android/iOS，纯 Go 无 cgo 依赖 |
| 存储 | SQLite（`modernc.org/sqlite`，纯 Go） | 免 cgo，交叉编译简单 |

---

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 分层架构、模块职责、并发模型、目录结构 |
| [docs/crypto-protocol.md](docs/crypto-protocol.md) | **核心**：密钥体系、握手、KEM、AEAD、密钥轮换、重放防护、密钥存储 |
| [docs/wire-protocol.md](docs/wire-protocol.md) | 线上帧格式、Epoch 语义、状态机、错误码 |
| [docs/transport-lan.md](docs/transport-lan.md) | mDNS 服务发现、TCP 连接管理、移动端权限与保活 |
| [docs/nat-traversal.md](docs/nat-traversal.md) | **公网穿透**：NAT 行为分类、ICE/STUN/TURN、信令安全、中继成本控制 |
| [docs/attachments.md](docs/attachments.md) | **附件传输**：分块 AEAD、优先级调度、断点续传、主密钥分层 |
| [docs/ui-gio.md](docs/ui-gio.md) | Gio 界面架构、事件桥接、跨平台差异 |
| [docs/threat-model.md](docs/threat-model.md) | 威胁模型、防护边界、**明确不防什么** |
| [docs/roadmap.md](docs/roadmap.md) | 分阶段实施路线与验收标准 |
| [docs/running.md](docs/running.md) | **怎么跑起来**：命令行用法、一键验证、排错 |
| [docs/ui-design.md](docs/ui-design.md) | 界面设计系统：信任编码规则、配色、必须持久化的状态 |
| [docs/implementation-notes.md](docs/implementation-notes.md) | **实现笔记**：踩过的坑、为什么代码长这样、安全决策理由 |

---

## 必读：五个容易误解的点

这四条是本项目最容易产生错误预期的地方，实现前务必先读 [docs/threat-model.md](docs/threat-model.md)。

1. **"基于 GPG 的 E2EE" ≠ Signal 级安全。**
   本设计没有 Double Ratchet。会话密钥由一次性 ECDH 派生，**确实提供前向保密**，但入侵后恢复（PCS）迟钝——密钥泄露的影响窗口是**一整轮**（默认 ≤1000 条 / ≤60 分钟）。
   详见 [docs/crypto-protocol.md](docs/crypto-protocol.md) §9.4。

2. **若有人把方案简化成"用 GPG 公钥直接加密会话密钥"（文档中的 M1 变体），那就没有前向保密。**
   那样的密钥链可被长期私钥完整回溯。**M1 下不得在任何 UI 或宣传材料中出现"前向保密"字样。** 详见 §9.3。

3. **纯 P2P 无法离线投递消息。**
   双方必须同时在线。要支持离线消息就必须引入存储转发节点——那本质上是服务器。首期明确不做，见 [docs/transport-lan.md](docs/transport-lan.md) §7。

4. **纯 P2P 在公网上也不成立。**
   对称 NAT 与 CGNAT 下打洞**在原理上无法成功**，必须有 TURN/中继兜底；而中继要付**双向带宽成本**。正确目标不是"零服务器"，而是**最大化直连比例**。见 [docs/nat-traversal.md](docs/nat-traversal.md)。

5. **公共 STUN 能省掉一台 STUN 服务器，但省不掉会合服务器，也省不掉 TURN。**
   公共 STUN 只负责"告诉你自己的公网地址"，它**不会**把你的地址告诉对端，也**不会**在打洞失败时转发数据。见 [docs/nat-traversal.md](docs/nat-traversal.md) §4.2。

---

## 项目状态

**可运行的加密闭环已打通**（S3/S4/S5/S7 完成）。

一键构建出双击即用的可执行文件：

```powershell
.\build.ps1              # 产出 dist\keytalk.exe（含冒烟自检）
.\build.ps1 -Run         # 构建后立即启动
```

双击 `dist\keytalk.exe` 即开界面，数据自动落在
`%AppData%\KeyTalk`。同一个文件传参数就是命令行工具，
脚本与排错不受影响。

```powershell
powershell -ExecutionPolicy Bypass -File .\e2e.ps1   # 一键端到端验证
```

实测已验证：双向加密消息字节一致、30 条消息严格保序、陌生身份被拒绝、
攻击尝试不影响合法流量。详见 [docs/running.md](docs/running.md)。

已实现（`go test ./...` 全绿，且 `-race` 全绿）：

| 包 | 内容 |
|---|---|
| `internal/crypto` | 身份、KEM+AEAD 握手、前向保密、重放防护、密钥存储 |
| `internal/wire` | 帧格式、明文消息编解码（含 fuzz 测试） |
| `internal/transport/lan` | mDNS 发现、TCP 连接管理、背压 |
| `internal/session` | 握手编排、事件循环、身份校验、glare 收敛 |
| `internal/core` | 应用状态机：联系人、会话生命周期、命令/事件接口 |
| `internal/ui` | Gio 图形界面（侧栏 / 消息流 / 输入框 / 状态栏） |
| `internal/e2e` | 四层串联的真实 TCP 回归测试 |
| `cmd/keytalk` | 聊天工具：双击启动图形界面，带参数则是命令行工具 |

尚未实现：`internal/storage`、`internal/files`。

```powershell
.\build.ps1                                        # 一键构建（推荐）
# 或手工构建：
go build -o keytalk.exe ./cmd/keytalk

.\keytalk.exe                                       # 双击等价：图形界面 + 自动生成身份
.\keytalk.exe -setup -name alice -id .\alice        # 生成身份与公钥
.\keytalk.exe -gui -id .\alice                      # 指定数据目录的图形界面
.\keytalk.exe -id .\alice -contact .\bob\public.key # 命令行界面
```

`internal/core` 是 UI 与协议层之间**唯一**的组装点：
上层只通过「非阻塞命令 + 事件 channel + 只读快照」与它交互，
不得直接调用 `transport` / `crypto`（见 [docs/architecture.md](docs/architecture.md) §1.1）。
界面实现（S7）只依赖 `core`，因此可以独立更换。

**下一阶段是 S7（Gio 界面）**，把命令行流程搬到真正的聊天窗口。
在此之前建议先做 **S0 spike** 验证 Android mDNS（`MulticastLock`）——
这是唯一可能推翻当前移动端架构的风险点。

计划见 [docs/roadmap.md](docs/roadmap.md)。

---

## ⚠️ 当前不可用于真实通信

三条硬限制，详见 [docs/running.md](docs/running.md) §5：

1. **私钥以明文存储**——口令加密方案（`keystore.go`）已实现但尚未接通，
   因为那需要口令输入界面。**目前不要使用真实身份。**
2. **加密后端是参考级**——基于已废弃的 `golang.org/x/crypto/openpgp`，
   仅支持 RSA。生产构建应换 `ProtonMail/go-crypto`
   （替换只需实现 `IdentityProvider` 接口，其余模块不受影响）。
3. **元数据未加密**——局域网广播暴露你的指纹与"正在使用 KeyTalk"这一事实。

---

## 环境

- Go 1.25+（开发机已验证 `go1.25.5 windows/amd64`）
- 桌面端：Windows / Linux / macOS
- 移动端：Android（需 Android SDK/NDK）、iOS（需 macOS + Xcode）

> 注：受限环境下 `go` 命令可能因无法写入 `%APPDATA%\go\telemetry` 而打印
> `error acquiring upload token`。这是遥测写入失败，**不影响编译**；
> 可通过 `set GOTELEMETRY=off` 消除该提示。
