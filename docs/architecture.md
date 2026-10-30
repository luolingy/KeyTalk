# 架构设计

## 1. 分层

```
┌──────────────────────────────────────────────────────────┐
│  ui/            Gio 界面（单线程 immediate mode）          │
│                 联系人 / 会话 / 指纹验证 / 连接状态         │
├──────────────────────────────────────────────────────────┤
│  core/          应用状态机（业务编排）                      │
│                 消息路由、事件汇聚与分发、在线状态           │
├──────────────────────────────────────────────────────────┤
│  files/         附件传输（分块 AEAD、优先级调度、续传）〔二期〕│
│  session/       会话管理                                   │
│                 会话生命周期、密钥协商编排、轮换触发         │
│  sig/           信令/会合客户端（签名验证）〔二期〕          │
├──────────────────────────────────────────────────────────┤
│  crypto/        密码学原语（纯函数，无 IO，无网络）          │
│                 OpenPGP 身份与 KEM / AEAD / HKDF / 重放窗口 │
│  wire/          帧编解码（纯函数）                          │
├──────────────────────────────────────────────────────────┤
│  transport/     传输抽象 + 实现                             │
│                 ├─ iface.go    接口（为公网扩展预留）        │
│                 ├─ lan/        mDNS 发现 + TCP 直连（首期）  │
│                 └─ ice/        ICE/DTLS/DataChannel（二期）  │
├──────────────────────────────────────────────────────────┤
│  storage/       SQLite 持久化 + 附件密文文件                │
└──────────────────────────────────────────────────────────┘
        ▲ 依赖方向自上而下，下层不得反向依赖上层
```

### 1.1 依赖方向（硬约束）

```
ui ──▶ core ──┬──▶ files ────┐
              ├──▶ session ──┼──▶ crypto   （纯原语，被多包复用）
              ├──▶ sig ──────┘
              ├──▶ transport          （不得依赖 crypto）
              └──▶ storage ──▶ crypto （本地加密用 MK）
```

- `crypto` **不得** import 任何内部包，保证可独立单测。
- `wire` 只做字节 ↔ 结构的转换，无状态，**不得** import 其他内部包。
- `transport` **不得** import `crypto`。传输层对明文帧一无所知——E2EE 是应用层的事，两者必须解耦（插入中继时不希望传输层能接触密钥材料）。
- `files` 依赖 `crypto`（分块 AEAD）与 `wire`（Kind 定义），**不得**依赖 `transport`（附件的收发经 core 调度）。
- `ui` **不得**直接调用 `transport` / `crypto` / `files`，一律经 `core`。

---

## 2. 并发模型

Gio 是**单线程 immediate mode**：所有 `Layout` 调用发生在同一个 UI goroutine 上。任何阻塞操作都会冻结界面。

```
┌────────────────────────┐
│ UI goroutine           │  app.Main() / window.Event()
│  - 消费 core.Events()  │  收到事件 → 改视图状态 → w.Invalidate()
│  - 不阻塞、不做 IO      │
└───────────┬────────────┘
            │ channel (缓冲)
┌───────────▼────────────┐
│ core goroutine         │  事件汇聚：网络事件 + UI 命令
│  - 单一事件循环 select │  串行化状态变更，避免锁竞争
└───────────┬────────────┘
            │
   ┌────────┴────────┬──────────────┐
   ▼                 ▼              ▼
per-peer reader   per-peer writer  discovery
goroutine         (+ 发送队列)      goroutine
   │                                  │
   └──────── transport.Events() ──────┘
```

### 2.1 规则

1. **UI 线程零阻塞**。`Layout` 中读取 `core.Events()` 使用非阻塞 `select` + `default` 排空，绝不 `<-ch` 等待。
2. **状态串行化**。跨 goroutine 的共享状态（会话表、联系人表）由 `core` 的事件循环独占持有，其他 goroutine 只通过 channel 提交变更请求，不做内存共享加锁。
   - 例外：`crypto.Session` 内部有 `mutex`（seq 递增、重放窗口），因为一个会话可能被 reader/writer 同时访问，且该结构足够小，锁竞争可忽略。
3. **每 peer 一对 goroutine**：一个 reader（阻塞读分帧）、一个 writer（消费发送队列）。写队列满时**向 core 报背压**，不允许无限缓冲导致内存膨胀。
4. **禁止在 UI goroutine 启动 goroutine 做网络 IO**——必须经 `core` 的命令 channel 转发，否则会绕过状态串行化。

---

## 3. 模块职责

### 3.1 `crypto/`

| 文件 | 职责 |
|---|---|
| `identity.go` | 身份密钥生成/导入/导出；指纹计算与格式化；keyring 目录管理 |
| `pgp.go` | KEM 封装（公钥加密会话密钥）/ 解封（私钥解密）；硬件后端可插拔 |
| `session.go` | 会话结构；密钥派生；AEAD 封包/解包；seq 与重放窗口 |
| `aead.go` | ChaCha20-Poly1305 封装；HKDF 派生辅助 |
| `keystore.go` | 私钥落盘、口令加密（argon2id）、OS 密钥库集成（可选） |

**关键约束**：`crypto` 不感知网络。传入字节、传出字节。

### 3.2 `wire/`

帧编解码。定义所有消息类型的结构体与其二进制表示。纯函数：

```go
func EncodeFrame(w io.Writer, m Message) error
func DecodeFrame(r io.Reader, maxLen int) (Message, error)
```

必须强制 `maxLen`（防长度字段导致的 OOM 攻击）。

### 3.3 `transport/`

```go
// transport/iface.go
type PeerID string   // 传输层标识：局域网场景 = "<fp-prefix>@<ip:port>"，仅为路由用途

type TransportEvent interface{ isTransportEvent() }

type PeerFound    struct{ ID PeerID; Info PeerInfo }  // 发现
type PeerLost     struct{ ID PeerID }
type ConnOpened   struct{ ID PeerID }
type ConnClosed   struct{ ID PeerID; Err error }
type FrameReceived struct{ ID PeerID; Frame []byte }

type PeerInfo struct {
    ID       PeerID
    Addrs    []net.Addr
    Metadata map[string]string // mDNS TXT：指纹、协议版本等
}

type Transport interface {
    Start(ctx context.Context) error
    Send(peerID PeerID, frame []byte) error
    Events() <-chan TransportEvent
    Close() error
}
```

- 首期唯一实现：`transport/lan`（mDNS + TCP）。
- 未来公网实现（libp2p / WebRTC）只需满足同一接口，`core` 无感。
- **传输层不持有任何密钥**。

### 3.4 `core/`

应用状态机。持有：联系人表、会话表、消息仓储句柄、附件传输表、当前连接状态。对外两个面：

```go
// 命令（UI → core），全部非阻塞
func (a *App) SendText(peerID string, text string) error
func (a *App) AddContact(armoredPubKey string) (Contact, error)
func (a *App) VerifyFingerprint(peerID string, confirmed bool) error
func (a *App) SendFile(peerID string, path string) (fileID string, err error)  // 二期
func (a *App) AcceptFile(fileID string) error                                  // 二期
func (a *App) CancelFile(fileID string) error                                  // 二期
func (a *App) Shutdown()

// 事件（core → UI）
func (a *App) Events() <-chan UIEvent
```

**发送调度**：core 维护**两级优先队列**（见 [attachments.md](attachments.md) §6.2）——文本消息与控制帧为高优先级，附件块为低优先级。`transport.Send` 是唯一出口，两者走同一通道，从而避免为大文件另开会话。

### 3.5 `files/`

附件传输编排（见 [attachments.md](attachments.md)）。职责：

| 职责 | 说明 |
|---|---|
| 分块加密/解密 | 64 KiB 块，`index` 进 nonce/AAD，末块带 `is_final` 标志 |
| 整体哈希 | 流式 SHA-256，**不缓存整个文件** |
| 优先级标注 | 产出块并标注优先级，由 core 调度 |
| 限速 | 令牌桶，给聊天留出带宽 |
| 位图管理 | 已收/已发块记录（续传用，二期） |
| 磁盘配额 | 接受前检查可用空间 |

**关键约束**：`files` **不持有网络连接**，附件块经 `core` 走与文本消息相同的发送路径。

### 3.6 `storage/`

**自研的嵌入式加密数据库**（`internal/db`），单文件 `<dataDir>/chat.db`。

这一节曾经写的是 SQLite + 附件密文文件，也曾经退而用追加式 JSONL 日志。现在两者都不是：构建环境取不到纯 Go 的 SQLite 驱动（模块缓存没有、代理不可达），而"聊天记录放在一个可检索的加密数据库里"是核心需求，于是实现了一个只解决本场景问题的迷你引擎。

- **页式**：每页 4 KiB，**每页独立加密**（`PurposePage`），AAD 绑定"文件盐 ‖ 页号"。因此页被搬到别的偏移、搬到别的库、或被改一个字节，都会**解密失败**而不是安静地返回错误内容。整个文件只有 64 字节明文头（magic、版本、页大小、盐、密钥校验值 KCV）。
- **表与索引**：`messages` / `contacts` / `attachments` 三张表，各有页链；`messages` 有按 ID 的索引页链，使"按 ID 覆盖"是 O(1)。
- **事务**：写入先进脏页集，`Commit` 依次写数据页 → 元数据页 → fsync；`Rollback` 丢弃并**还原元数据快照**（不还原的话 NextPage 会指向没写过的页，下次打开直接报"页被截断"）。
- **打开即全校验**：`Open` 检查文件长度并逐页 AEAD 验签，坏库在门口就被拦住，而不是聊到一半才炸。
- **口令**：口令 → argon2id → KEK → 解包 MK。MK 同时用于数据库与附件；口令错由 KCV 在第一毫秒判定为 `ErrWrongKey`。

**没有主密钥就不落盘**：明文身份（v1）没有 keystore，因此没有 MK，`OpenDBStore` 返回 nil，结果是**没有历史**而不是**明文历史**，不存在静默降级路径。

**附件**由 `internal/files` 按 64 KiB 分块加密（`PurposeAttachmentBlob`，AAD 绑定 blobID ‖ 块号），落盘 `<dataDir>/blobs/<blobID>.bin`。分块使内存占用与附件大小无关；块号绑定使块不能互换、截断会被发现；读取时校验明文 SHA-256。

**旧数据迁移**：首次以新库启动时，若存在旧版 `<dataDir>/messages/*.jsonl`，会被一次性导入，原目录改名 `messages.migrated/` **保留**（可回退）。迁移复用 `internal/storage` 的读取实现，不重写解密逻辑。

**备份**：`internal/backup` 导出单个 `.ktbackup` 文件，内容是 `identity.json` 原始字节 + 通讯录，用**导出专用口令**（建议异于登录口令）加密。恢复时仍需要登录口令解锁——备份携带的是身份文件，不是解密它的能力。

#### 与 SQLite 方案的偏离（诚实记录）

本节原先规定"SQLite + 附件密文文件"，表结构见 §5。实现改成了追加式日志，原因：

1. 需要的纯 Go SQLite 驱动（`modernc.org/sqlite`）在本项目的构建环境里取不到：模块缓存里没有，代理也不可达。而"消息能活过重启"这个用户可见的价值不应该被一个依赖卡住。
2. 追加式日志在这个场景下有两个正合适的性质：
   - **崩溃安全**——一次 `write` 写一整行，崩溃最多留下半行，读取时跳过，不影响其余记录；
   - **状态变更即追加**——"待发送 → 已发送"用同一个 ID 再写一行，读取时"最后一次生效"，不需要原地改写文件。
3. 聊天记录几乎没有需要 SQL 的查询：读某个会话的历史就是顺序读一个文件。

**代价**（这些是真实的，不是理论上的）：

- 没有索引，按关键词检索只能全量扫；历史很大时启动会变慢；
- 没有跨会话的复杂查询能力和 `attachments` 那张关系表，[attachments.md](attachments.md) 的设计仍然需要它；
- 日志只增不减：一次状态变更留下一行冗余，尚未实现压实（compaction）。

若将来能引入 SQLite，迁移路径是明确的：`.jsonl` 是纯文本行格式，逐行解密后 `INSERT` 即可，`id` 与 `sent_at` 可直接复用。

---

## 4. 目录结构

```
keytalk/
├── cmd/
│   └── keytalk/
│       └── main.go              # 入口：app.Main() 或移动端入口
├── internal/
│   ├── ui/
│   │   ├── app.go               # 窗口、主循环、事件泵
│   │   ├── chatview.go          # 会话视图（消息列表 + 输入框）
│   │   ├── contacts.go          # 联系人列表 / 添加 / 指纹验证
│   │   ├── settings.go          # 身份信息、密钥导入导出
│   │   ├── state.go             # 视图状态
│   │   └── theme.go
│   ├── core/
│   │   ├── app.go               # 状态机与事件循环
│   │   ├── event.go             # UIEvent 定义
│   │   ├── contacts.go          # 联系人 CRUD
│   │   └── router.go            # 入站帧 → 会话/消息分发
│   ├── session/
│   │   ├── manager.go           # 会话表、生命周期
│   │   ├── handshake.go         # 握手编排（生成/校验 KEM 帧）
│   │   └── rekey.go             # 轮换策略与触发
│   ├── crypto/
│   │   ├── identity.go
│   │   ├── pgp.go
│   │   ├── session.go
│   │   ├── aead.go
│   │   └── keystore.go
│   ├── wire/
│   │   ├── frame.go
│   │   ├── message.go
│   │   └── file.go              # 附件相关 Kind（二期）
│   ├── files/                   # 附件传输（二期）
│   │   ├── chunk.go             # 分块 AEAD（STREAM 构造）
│   │   ├── send.go              # 发送编排、位图、限速
│   │   ├── recv.go              # 接收编排、落盘、校验
│   │   └── store.go             # 附件密文文件管理
│   ├── sig/                     # 信令/会合客户端（二期）
│   │   ├── client.go            # WebSocket 连接与重连
│   │   └── msg.go               # 信令消息签名/验证
│   ├── transport/
│   │   ├── iface.go
│   │   ├── lan/
│   │   │   ├── discovery.go     # mDNS 服务注册与浏览
│   │   │   ├── listener.go      # TCP 监听与连接接受
│   │   │   ├── conn.go          # 单连接读写、心跳、重连
│   │   │   └── manager.go       # peer 连接池
│   │   └── ice/                 # 二期
│   │       ├── agent.go         # ICE / DTLS / DataChannel
│   │       ├── stun.go          # 地址发现与 NAT 行为探测
│   │       └── turn.go          # 中继回退与成本控制
│   └── storage/
│       ├── db.go
│       ├── migrations.go
│       └── models.go
├── platform/                    # 平台特定代码
│   ├── android/                 # Gradle 宿主、MulticastLock 桥接
│   └── ios/                     # Xcode 宿主、Info.plist
├── docs/
└── go.mod
```

---

## 5. 数据模型

> ⚠️ **本节是 SQLite 目标模型，当前实现不是 SQLite。** 消息持久化用 §3.6 的自研加密数据库；
> 下面的 `messages` 表结构仍然是理解字段意图的参考：
> 日志里的 `id` / `out` / `st` / `sent_at` 与它一一对应。
> `identity` / `contacts` 两张表同样没有实现——那两项现在
> 是 `identity.json` 与 `contacts.json`。


```sql
-- 本机身份
CREATE TABLE identity (
    id          INTEGER PRIMARY KEY CHECK (id = 1),  -- 单行
    fingerprint TEXT NOT NULL,        -- 全量指纹（hex）
    armored_pub TEXT NOT NULL,        -- 导出的公钥
    created_at  INTEGER NOT NULL
);

-- 联系人
CREATE TABLE contacts (
    fingerprint   TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    armored_pub   TEXT NOT NULL,
    trust         INTEGER NOT NULL DEFAULT 0,  -- 0=TOFU未验证 1=已带外验证 2=已拉黑
    last_seen_at  INTEGER,
    created_at    INTEGER NOT NULL
);

-- 会话（当前活跃的密钥上下文）
CREATE TABLE sessions (
    id            BLOB PRIMARY KEY,   -- 8 字节 session_id
    peer_fp       TEXT NOT NULL REFERENCES contacts(fingerprint),
    created_at    INTEGER NOT NULL,
    rekey_count   INTEGER NOT NULL DEFAULT 0,
    msg_count     INTEGER NOT NULL DEFAULT 0,
    closed_at     INTEGER,
    -- 注意：会话密钥不落库，见 crypto-protocol.md §10
    FOREIGN KEY (peer_fp) REFERENCES contacts(fingerprint)
);

-- 消息（正文密文存储）
CREATE TABLE messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_fp     TEXT NOT NULL,
    direction   INTEGER NOT NULL,      -- 0=in 1=out
    body_ct     BLOB NOT NULL,         -- 静态加密后的正文
    body_nonce  BLOB NOT NULL,         -- 12 字节
    sent_at     INTEGER NOT NULL,
    state       INTEGER NOT NULL,      -- 0=pending 1=ack 2=failed
    seq         INTEGER                -- 会话内序号（可空）
);
CREATE INDEX idx_messages_peer ON messages(peer_fp, sent_at);

-- 附件（二期）；正文以密文文件存盘，见 attachments.md §10
CREATE TABLE attachments (
    file_id        BLOB PRIMARY KEY,    -- 16B
    message_id     INTEGER REFERENCES messages(id),
    peer_fp        TEXT NOT NULL REFERENCES contacts(fingerprint),
    direction      INTEGER NOT NULL,    -- 0=in 1=out
    name_ct        BLOB NOT NULL,       -- 文件名，MK 加密
    name_nonce     BLOB NOT NULL,
    mime_ct        BLOB,
    size           INTEGER NOT NULL,
    chunk_size     INTEGER NOT NULL,
    total_chunks   INTEGER NOT NULL,
    file_hash      BLOB NOT NULL,
    file_key_ct    BLOB NOT NULL,       -- file_key，MK 加密
    file_key_nonce BLOB NOT NULL,
    state          INTEGER NOT NULL,    -- 0=offering 1=transferring 2=complete 3=failed 4=cancelled
    received       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_attachments_msg ON attachments(message_id);
```

### 5.1 存储加密的诚实说明

`messages.body_ct`、附件文件名与 `file_key` 使用**主密钥 MK** 加密（MK 由口令经 KEK 封装，见 [crypto-protocol.md](crypto-protocol.md) §10.2；与传输会话密钥无关）。目的是防止"设备被翻看数据库文件"这一场景，**不是**防止本机上的恶意进程——恶意进程可以读内存和口令。见 [threat-model.md](threat-model.md)。

附件正文存盘的是**传输时的密文**（用 `file_key` 加密），因此不做二次加密；只要 `file_key` 仍被 MK 保护，附件就是安全的。详见 [attachments.md](attachments.md) §10.2。

---

## 6. 启动流程

```
1. 解析配置目录（桌面 os.UserConfigDir()/keytalk；移动端沙盒）
2. 打开 SQLite，执行 migration
3. 加载 identity
   ├─ 不存在 → 引导生成身份（提示口令，保护私钥落盘）
   └─ 存在   → 请求口令解锁私钥（或走 OS 密钥库）
4. 派生存取仅本地存储所需的本地存储密钥
5. transport.Start(ctx)：注册 mDNS 服务 + 启动 TCP 监听
6. 启动 core 事件循环 goroutine
7. app.Main() 进入 UI 主循环
```

**注意**：第 3 步口令提示需要一个"解锁界面"，它先于主界面出现。UI 需支持"锁定态"与"解锁态"两种根视图。

---

## 7. 关闭与错误处理

- 收到 `SIGINT` / 窗口关闭：先发 `BYE`，关 transport，flush 写队列，关 DB。
- 单连接错误（`ConnClosed`）不终止应用，由 `manager` 退避重连。
- **不可恢复错误**（DB 损坏、身份无法解密）必须显式呈现给用户，不静默降级。
- 任何"解密失败"都不允许静默丢弃：必须记录并在 UI 提示（可能是攻击，也可能是 bug）。
