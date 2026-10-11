# 线上协议（Wire Protocol）

> 与 [crypto-protocol.md](crypto-protocol.md) 配套。本文定义字节级格式与状态机，两者必须同步修改。

## 1. 帧格式

TCP 是字节流，必须自行分帧。统一使用 **length-prefixed** 帧：

```
┌──────────────┬──────────┬─────────────────────────────┐
│ Length (4B)  │ Type(1B) │ Body (Length-1 字节)        │
│ big-endian   │          │                             │
└──────────────┴──────────┴─────────────────────────────┘
```

- `Length` **包含** `Type` 字段，因此合法取值 `1 ≤ Length ≤ MAX_FRAME`。
- `MAX_FRAME = 1 << 20`（1 MiB）。首期无文件传输，1 MiB 足够；未来传文件需改为分块 + 独立流。
- `Length = 0`、`Length > MAX_FRAME` 一律**立即断开连接**，不尝试恢复。

**为什么必须先查 Length 再分配内存**：否则一个 `Length = 0xFFFFFFFF` 的恶意头就会导致 4 GiB 分配（OOM DoS）。解码时使用 `io.LimitReader` 并限制缓冲增长。

### 1.1 读超时

每次读取帧头与帧体都设置超时（建议 30s）。超时视为连接异常，不做无限等待。

---

## 2. 帧类型

**只有四种帧类型**，会话内的所有消息靠正文中的 `Kind` 区分，不增加传输层分支。

| Type | 名称 | 允许的状态 | Body 保护 |
|---|---|---|---|
| `0x01` | `KEM_INIT` | IDLE | OpenPGP Encrypt+Sign（自身受保护） |
| `0x02` | `KEM_ACK` | IDLE / RECV_INIT | AEAD（`key_r2i`），`Epoch=0, Seq=0` |
| `0x03` | `SECURE` | ESTABLISHED / RATCHETING | AEAD（当前方向密钥） |
| `0x04` | `ERROR` | 任意 | 会话建立前明文；建立后 AEAD |

- `0x05`–`0xFF` 保留给未来扩展。
- **不引入 `PING`/`BYE`/`DATA` 等独立 Type**：它们都是 `SECURE` 帧的不同 `Kind`。理由：Type 数量越多，状态机分支越多，越容易出现"某类型在某状态下未处理"的漏洞；统一为 `SECURE` 后，只需在解密后做 `Kind` 分发。

### 2.1 为什么会话内一切都加密

会话建立后的**所有**帧（含心跳、告别）一律 AEAD 加密：

- 明文控制帧可被伪造以实施 DoS（伪造 `BYE` 直接断连）；
- 局域网带宽充裕，每帧 AEAD 开销仅约 16 字节 tag；
- 统一处理路径减少分支，降低出错概率。

---

## 3. AEAD 帧的统一帧头

`KEM_ACK`（Type `0x02`）与 `SECURE`（Type `0x03`）共用同一帧头：

```
┌──────────────┬──────────┬─────────────┬───────────┬──────────┬──────────────┐
│ Length (4B)  │ Type(1B) │ SessionID   │ Epoch(8B) │ Seq(8B)  │ Ciphertext   │
│              │          │ (8B)        │           │          │ (变长)       │
└──────────────┴──────────┴─────────────┴───────────┴──────────┴──────────────┘
```

### 3.1 为什么帧头必须包含 `Epoch`

密钥轮换（ratchet）后，发送方用新密钥加密、`Seq` 归零，而网络上**仍可能在途传播用旧密钥加密的帧**（见本文件 §5.2）。

接收方必须先知道"这一帧属于哪一代密钥"，才能选择正确的密钥与重放窗口去解密。若帧头没有 `Epoch`，接收方只能靠"尝试所有密钥"来解密——这既低效，又会给攻击者提供区分性的失败时序。

因此 `Epoch` 是**必需字段**，不是可选优化。

### 3.2 为什么 `SessionID` / `Epoch` / `Seq` 是明文

接收方需要它们来**定位会话、选择密钥、重建 nonce**，之后才能解密。这是"自描述帧头"的必然代价。

- 三者都参与 **AAD**（见 §3.4），因此篡改会导致解密失败，机密性之外的完整性有保障。
- 代价是泄露"会话标识、密钥代次、消息计数"。会话标识是随机 8 字节，不直接暴露身份。若需隐藏消息条数，需要恒定长度填充与独立于计数的 nonce 方案（牺牲可观性能），**首期不做**，见 [threat-model.md](threat-model.md) §4.3。

### 3.3 nonce 构造

```
nonce = Seq(8B, big-endian) ‖ 0x00000000(4B)
```

`nonce` **不传输**，由接收方用帧头的 `Seq` 重建。

**唯一性论证**：

- 每个 `(SessionID, Epoch)` 组合唯一对应一对方向密钥；
- 在该组合内，`Seq` 严格单调递增且不回绕；
- 因此 `(key, nonce)` 组合永不重复。

**这把"密钥变更"与"Seq 归零"绑定成了不变式**：
> 任何 `Seq` 归零都必须伴随 `Epoch` 递增（即密钥变更）；任何密钥变更都必须伴随 `Seq` 归零。

实现时这条不变式**必须有断言或测试保障**（[threat-model.md](threat-model.md) §6 第 7 条）。nonce 重用是 AEAD 下最严重的错误之一，一旦发生，机密性与完整性同时崩塌。

### 3.4 AAD

```
AAD = Ver(1B) ‖ Type(1B) ‖ SessionID(8B) ‖ Epoch(8B) ‖ Seq(8B)
```

其中 `Ver` 是会话内明文头部的版本号（见 §4.1）。把帧头整体纳入认证范围，防止攻击者篡改 `SessionID` / `Epoch` / `Seq` 而密文仍校验通过。

> **已知的小瑕疵**：`Ver` 位于密文内部（§4.1），却参与 AAD，而 AAD 必须在解密**前**构造。这意味着实现上 `Ver` 需要**约定为常量 0x01**，协商升级需通过 §9 的明文版本交换完成，而不是靠密文内的 `Ver`。本文保留该字段以标记格式版本，但**解密前不得依赖其值**——请把 `Ver` 在 AAD 中视为常量。

---

## 4. `SECURE` 帧正文结构

`Ciphertext` 解密后的明文：

```
CommonHeader = {
  Ver:    1B     // 0x01（常量，见 §3.4 注）
  Kind:   1B
  SentAt: 8B     // unix ms, big-endian
}
```

| Kind | 名称 | 后续字段 | 说明 |
|---|---|---|---|
| `0x01` | `TEXT` | `BodyLen(4B)‖Body(UTF-8)` | 聊天文本 |
| `0x02` | `RECEIPT` | `RefSeq(8B)‖RefEpoch(8B)` | 送达确认 |
| `0x03` | `TYPING` | `State(1B)` | 0 停止 / 1 正在输入 |
| `0x04` | `REKEY` | `EphPub(32B)‖TS(8B)` | 发起轮换（见 §5） |
| `0x05` | `REKEY_ACK` | `EphPub(32B)‖TS(8B)` | 响应轮换 |
| `0x06` | `PING` | — | 心跳 |
| `0x07` | `PONG` | — | 心跳响应 |
| `0x08` | `BYE` | `Reason(1B)` | 主动关闭 |
| `0x09` | `HANDSHAKE_CONFIRM` | `HandshakeHash(32B)` | 握手收尾确认（§6.3） |
| `0x10`–`0x17` | `FILE_*` | 见 [attachments.md](attachments.md) §7 | 附件传输（二期） |

`Kind` 的值域独立于 `Type`，`0x0A`–`0x0F` 与 `0x18`–`0xFF` 保留。

> **注意**：附件相关 `Kind` 的字段定义与安全要求（分块 AEAD、`index` 进 AAD、末块 `is_final` 标志）见 [attachments.md](attachments.md)——本文件只登记编号，不重复其设计。修改附件格式时以该文件为准。

### 4.1 长度校验

- `BodyLen` 必须等于实际剩余字节数，否则判定为 `BAD_FRAME`。
- `SentAt` 仅用于 UI 展示与调试，**不得**用于安全判定（时间由发送方自填，不可信）。

---

## 5. `REKEY` 与 `REKEY_ACK`

**核心规则（本文档对该字段的唯一权威定义）**：

> 帧头的 `Epoch` 字段**始终等于解密本帧所用的密钥代次**。

`Kind = REKEY` 本身就是"下一帧将换密钥"的信号，因此 `REKEY` 帧仍携带**旧** epoch。

```
发起方 A（当前 epoch = n）:
  1. 生成新的 EK_A' (X25519 keypair)
  2. kind = REKEY, payload = { EphPub_A', TS }
  3. 用当前 key_i2r (epoch n) 加密，帧头 Epoch = n，Seq = ++sendSeq
  4. 发送，进入 RATCHETING（暂不切换密钥）

接收方 B:
  5. 帧头 Epoch = n → 用 epoch n 的 key_i2r 解密
  6. 生成 EK_B'，SK' = HKDF(ECDH(EK_B', EphPub_A'))
  7. 派生新 key_i2r' / key_r2i'，新 epoch = n+1
  8. 用 key_r2i' 加密 REKEY_ACK{ EphPub_B', TS }，帧头 Epoch = n+1，Seq = 0
  9. 发送，并立即完成自身密钥切换（epoch = n+1，sendSeq 归零）

发起方 A:
 10. 帧头 Epoch = n+1 → 用 key_r2i' 解密
 11. 校验通过 → 完成切换：epoch = n+1，sendSeq 与 recvWin 归零
 12. 退出 RATCHETING，进入 ESTABLISHED
```

### 5.1 为什么 `REKEY` 的 `Epoch` 不能填新值

一个容易被误设计的方案是：`REKEY` 帧的帧头 `Epoch` 直接填 `n+1`，表示"这是新会话的第一帧"。这**不可行**：

- 接收方看到 `Epoch = n+1` 会尝试用 `key_i2r'` 解密，而该密钥**尚未派生**（它需要先拿到 `EphPub_A'` 才能算出）；
- 于是陷入死锁：要先解密才能派生密钥，要先有密钥才能解密。

因此 `REKEY` 帧必须携带**旧** epoch。**只有 `REKEY_ACK` 及其后的帧携带新 epoch**，因为它们确实用新密钥加密。

这条规则推广到全部帧，即得 §3.1 的不变式：`Epoch` = 解密本帧所用密钥代次。

### 5.2 切换期间的在途消息

切换密钥后，网络上可能仍有使用**旧密钥**加密的在途帧。处理：

- 保留旧 key 与旧重放窗口一段时间（建议 30s，或直到收到第一个新 epoch 的合法帧）；
- 一旦收到新 epoch 的合法帧，**立即销毁**旧 key 与旧窗口；
- 收到任何 epoch 的帧时，先按帧头 `Epoch` 选择对应密钥，**不要**假设"帧头 epoch 必须等于当前 epoch"。
- 若帧头 `Epoch` 既不是当前也不是上一代 → 回 `ERROR(BAD_EPOCH)` 并计数。

> **简化选项**：若不愿处理在途消息，可在 ratchet 时直接丢弃旧密钥，接受"恰好在途的消息丢失"。局域网 RTT 极低，丢包概率很小。**但必须在文档与 UI 中声明这是有意取舍**，不能悄悄丢失。

### 5.3 Ratchet 超时

发起方进入 `RATCHETING` 后若 **10s** 内未收到合法 `REKEY_ACK`：回滚到旧密钥，回到 `ESTABLISHED`，计数告警。**不得**留在 `RATCHETING` 状态导致会话僵死。

---

## 6. 握手帧格式

### 6.1 `KEM_INIT`（Type `0x01`）

```
Body = OpenPGP_Encrypt_and_Sign(
    to   = IK_enc_peer,
    sign = IK_sign_self,
    data = KEMPlaintext
)

KEMPlaintext = {
  Ver:            1B
  SessionID:      8B      // 随机，全局唯一
  SenderFP:       2B len ‖ bytes
  RecipientFP:    2B len ‖ bytes
  Timestamp:      8B      // unix ms
  EphPub:         32B     // initiator 的 X25519 公钥
  Flags:          1B      // bit0: 请求 ratchet；其余保留为 0
}
```

- 使用 OpenPGP **二进制 packet** 格式，不使用 ASCII Armor（省去 Base64 膨胀）。
- `EphPub` 为 X25519 公钥的原始 32 字节。
- `SenderFP` 必须与签名者一致，`RecipientFP` 必须与本机指纹一致，否则拒绝。
- `KEM_INIT` 的 `SessionID` 在 OpenPGP 载荷内（此时尚无会话，帧头不含 `SessionID`）。

### 6.2 `KEM_ACK`（Type `0x02`）

```
帧头: Length ‖ Type(0x02) ‖ SessionID(8B) ‖ Epoch=0(8B) ‖ Seq=0(8B) ‖ Ciphertext

Ciphertext = AEAD(key_r2i, nonce=0, plaintext, aad)

plaintext = {
  Ver:           1B
  ResponderFP:   2B len ‖ bytes
  Timestamp:     8B
  EphPub:        32B
  HandshakeHash: 32B
}
```

- `nonce = 0`：这是 `key_r2i` 下发送的第 0 帧，符合 §3.3 的构造规则，不构成重用（每个 `key_r2i` 仅用于一轮）。
- `HandshakeHash = SHA-256("keytalk/v1/handshake" ‖ KEMPlaintext ‖ ACKPlaintext)`：双向确认双方对同一份握手记录达成一致，防参数降级。

### 6.3 `HANDSHAKE_CONFIRM`

initiator 收到 `KEM_ACK` 并成功解密后，发送第一条 `SECURE` 帧（`Kind = 0x09`），`Payload` 为自身计算的 `HandshakeHash`。

responder 校验一致后，双方进入稳定的 `ESTABLISHED`。

> **不一致时必须终止会话并上报**，不得继续。这通常意味着协议实现不匹配或主动攻击（参数降级）。

### 6.4 responder 的状态推进

responder 在发出 `KEM_ACK` 时密钥已派生完毕，可进入 `ESTABLISHED`。但在收到 `HANDSHAKE_CONFIRM` 之前，它**不得**向 UI 报告"安全会话已建立"，且此时收到的 `TEXT` 应缓冲而非直接展示。

理由：`HandshakeHash` 校验失败意味着双方对握手参数的理解不一致，此时展示消息可能误导用户。

---

## 7. 状态机

```
                    ┌──────────┐
                    │   IDLE   │
                    └────┬─────┘
        发送 KEM_INIT     │      收到 KEM_INIT
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
  ┌───────────┐                       ┌───────────┐
  │ SENT_INIT │                       │ RECV_INIT │
  └─────┬─────┘                       └─────┬─────┘
        │ 收到并验证 KEM_ACK                │ 发出 KEM_ACK
        │ 发出 HANDSHAKE_CONFIRM            │
        └──────────────┬────────────────────┘
                       ▼
                ┌──────────────┐
                │ ESTABLISHED  │◀──────────────┐
                └──────┬───────┘               │
                       │ 本地触发 rekey        │ REKEY_ACK 验证通过
                       ▼                       │ 完成密钥切换
                ┌──────────────┐               │
                │ RATCHETING   │───────────────┘
                └──────┬───────┘
                       │ 超时(10s) → 回滚至 ESTABLISHED
                       │
    任意状态 ──────────┴──────────▶ ┌──────────┐
                                     │  CLOSED  │
    （收到 BYE / 解密连续失败 / 对端关闭）└──────────┘
```

### 7.1 状态转移表

| 状态 | 收到 | 动作 | 新状态 |
|---|---|---|---|
| IDLE | 本地发起 | 生成 EK、发 `KEM_INIT` | SENT_INIT |
| IDLE | `KEM_INIT` | 校验 → 生成 EK → 发 `KEM_ACK` | ESTABLISHED* |
| SENT_INIT | `KEM_ACK` | 派生密钥、校验 Hash、发 `HANDSHAKE_CONFIRM` | ESTABLISHED |
| SENT_INIT | `KEM_INIT` | 冲突，见 §8 | — |
| ESTABLISHED | `SECURE` | 按 `Epoch` 选密钥 → 重放检查 → 解密 → 按 `Kind` 分发 | ESTABLISHED |
| ESTABLISHED | `SECURE`(`Kind=REKEY`) | 处理轮换，安装新密钥，回 `REKEY_ACK` | ESTABLISHED |
| ESTABLISHED | 本地触发 rekey | 发 `REKEY` | RATCHETING |
| RATCHETING | `SECURE`(`Kind=REKEY_ACK`) | 切换密钥、`Epoch+1`、`Seq` 归零 | ESTABLISHED |
| RATCHETING | 超时 10s | 回滚旧密钥、计数告警 | ESTABLISHED |
| ESTABLISHED | `SECURE`(`Kind=BYE`) | 关闭会话（**保留联系人**） | CLOSED |
| 任意 | 解密连续失败 ≥ 阈值 | 断开 | CLOSED |
| 任意 | 收到 `ERROR` | 记录；致命错误则断开 | 视错误码 |

\* 见 §6.4：进入 ESTABLISHED 但尚未向 UI 确认。

### 7.2 解密失败的阈值

- 单次解密失败：计数 + 上报，**不断开**（可能是网络乱序导致的过期帧）。
- 连续失败 ≥ 10 次，或 60s 内失败率 > 50%：判定为异常，断开并告警。
- **任何解密失败都不得静默丢弃**。

---

## 8. 连接与握手冲突

### 8.1 谁发起握手

双方通过 mDNS 互相发现后**都可能**主动发起连接，导致两条 TCP 连接、双方同时发 `KEM_INIT`。

### 8.2 解决规则（确定性，无需协商）

**规则 1（连接去重）**：同一对 peer 只保留一条连接。检测到重复连接时：

```
比较双方指纹（hex 字符串，字典序）
  保留「本机指纹 < 对端指纹」时由本机发起的连接
  即：指纹小的一方发起的连接胜出，另一方主动关闭自己的连接
```

**规则 2（握手发起方）**：**指纹较小的一方作为 initiator**，只发 `KEM_INIT`。

**规则 3（冲突兜底）**：若在 `SENT_INIT` 状态收到 `KEM_INIT`（不应发生，但网络异常时可能）：

```
比较指纹：
  本机较小 → 忽略对端的 KEM_INIT（我方是 initiator，以我方为准）
  本机较大 → 放弃自己的握手，转 RECV_INIT 处理对端
```

指纹字典序是全序，因此双方必然得出**一致且互斥**的结论。

**规则 4**：指纹相同的两个身份视为同一身份（重复导入公钥），不允许自连。若检测到自身指纹的连接请求，直接拒绝。

### 8.3 为什么不用会话 ID 比较

若用 `sid` 大小决定胜者，双方在收到对方 `sid` 前都已发出 `KEM_INIT`，产生无谓开销；指纹在发现阶段（mDNS TXT）就已获知，可在建立连接前确定角色，避免浪费。

---

## 9. 版本演进

- 首期只支持 `Ver = 0x01`。
- `KEM_INIT` 的载荷由 OpenPGP 保护，**无法在不解密的情况下读取版本号**，因此无法做优雅协商。
- **建议增加明文版本前缀**：在 TCP 连接建立后、`KEM_INIT` 之前，发送固定 8 字节明文握手：

```
magic(4B) = "KTlk"      // 0x4B 0x54 0x6C 0x6B
ver_major(2B)
ver_minor(2B)
```

- 该明文前缀**仅用于选择解析路径**，不参与任何安全判定，也**不替代** `KEM_INIT` 内的 `Ver`。
- 若 magic 不匹配 → 立即断开（避免与其他协议误连）。
- 若版本不受支持 → 回 `ERROR(UNSUPPORTED_VER)` 后断开。

> **待定**：是否采用该前缀需在实现前确认。若不加，则跨版本通信只能整体升级，无渐进余地。

---

## 10. 错误处理

### 10.1 错误码

`ERROR` 帧的 Body：

```
会话建立前（明文）:  Code(1B) ‖ MsgLen(2B) ‖ Msg(UTF-8)
会话建立后（AEAD）: Kind=ERROR 的 SECURE 帧，同样携带 Code ‖ MsgLen ‖ Msg
```

| Code | 名称 | 含义 |
|---|---|---|
| `0x01` | `BAD_FRAME` | 帧格式非法（长度、类型、字段） |
| `0x02` | `UNSUPPORTED_VER` | 协议版本不支持 |
| `0x03` | `AUTH_FAILED` | 签名/指纹校验失败 |
| `0x04` | `DECRYPT_FAILED` | AEAD 解封失败 |
| `0x05` | `REPLAY_DETECTED` | 重放检测 |
| `0x06` | `SESSION_CONFLICT` | 会话冲突 / 未知 sid |
| `0x07` | `BAD_EPOCH` | 未知的密钥代次 |
| `0x08` | `RATE_LIMITED` | 触发限流 |
| `0x09` | `INTERNAL` | 内部错误 |
| `0x0A` | `TRUST_REJECTED` | 对方被标记为 BLOCKED |

### 10.2 处理原则

1. **收到格式错误帧 → 发 `ERROR(BAD_FRAME)` → 关闭连接**。不尝试猜测或修复。
2. **解密失败不静默**（见 §7.2）。累计计数并上报 core；UI 需可见。
3. **不在错误消息中泄露敏感信息**。`Msg` 只放通用描述，不得包含密钥、明文或对方指纹的额外信息。
4. **`TRUST_REJECTED`**：若对端指纹处于 `BLOCKED`，拒绝握手并回该错误，随后断开。
5. **限流**：短时间内大量非法帧（如 >100/s）视为攻击，断开并临时拉黑该地址（建议 5 分钟）。
6. **不反射攻击**：`ERROR` 帧不得作为对 `ERROR` 帧的响应无限往返。收到 `ERROR` 后只记录，最多回一次。

---

## 11. 编解码实现要求

```go
// wire/frame.go
const (
    MaxFrame       = 1 << 20
    FrameHeaderLen = 5   // 4B length + 1B type
    SecureHeaderLen = 5 + 8 + 8 + 8  // + SessionID + Epoch + Seq
)

type Type byte
type Kind byte

type Frame struct {
    Type      Type
    SessionID [8]byte
    Epoch     uint64
    Seq       uint64
    Body      []byte   // KEM_INIT: OpenPGP blob；KEM_ACK/SECURE: 密文
}

func WriteFrame(w io.Writer, f Frame) error
func ReadFrame(r io.Reader) (Frame, error)   // 强制 MaxFrame 与超时
```

**必须做到**：

1. 所有长度字段在分配内存前校验上界。
2. 使用 `encoding/binary.BigEndian`，统一字节序，不依赖平台。
3. 解析变长字段（如指纹）时，校验"声明长度 ≤ 剩余字节数"。
4. 编解码函数是**纯函数**，不做 IO、不加锁、不访问全局状态，便于 fuzz 测试。

### 11.1 测试要点

| 用例 | 期望 |
|---|---|
| 空输入 | 返回 EOF，不 panic |
| `Length = 0` | `BAD_FRAME` |
| `Length = MaxFrame+1` | `BAD_FRAME`，且**未分配大内存** |
| 声明变长字段长度 > 剩余 | `BAD_FRAME` |
| `SessionID`/`Epoch`/`Seq` 缺失（SECURE 帧体过短） | `BAD_FRAME` |
| 分多次写入的帧（TCP 粘包/拆包） | 正确重组 |
| 单次写入多个帧 | 逐帧正确切分 |
| `Epoch` 既非当前也非上一代 | `BAD_EPOCH` |
| fuzz 随机字节 | 无 panic、无超大分配 |
| 固定向量（nonce/AAD 构造） | 与预期字节完全一致 |

---

## 12. 待定问题

| 问题 | 影响 | 建议 |
|---|---|---|
| 是否增加明文版本前缀（§9） | 未来兼容性 | 建议加，成本低 |
| Ratchet 期间旧密钥保留时长 | 丢消息 vs 密钥驻留 | 30s 起步，可配置 |
| 是否处理在途旧 epoch 消息（§5.2） | 完整性 vs 复杂度 | 建议保留 30s |
| 最大帧 1 MiB 是否合适 | 未来文件传输 | 首期够用，文件传输另起流 |
| 是否需要 `TYPING` | 体验 vs 元数据泄露 | 可选；会额外泄露"正在输入"元数据 |
