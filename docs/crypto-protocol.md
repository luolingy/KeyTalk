# 加密协议设计

> 本文档是本项目的安全核心。实现前请完整阅读，特别是 §9（前向保密的真实边界）与 §12（已知局限）。

## 1. 术语

| 缩写 | 含义 |
|---|---|
| IK | Identity Key，长期 OpenPGP 身份密钥（Ed25519 签名 + cv25519 加密） |
| EK | Ephemeral Key，一次性 X25519 密钥，用完即弃 |
| SK | Session Key，会话对称密钥（32 字节） |
| KEM | Key Encapsulation Mechanism，密钥封装 |
| AEAD | Authenticated Encryption with Associated Data |
| FP | Fingerprint，OpenPGP 公钥指纹 |
| AAD | Additional Authenticated Data |
| PFS | Perfect Forward Secrecy，完美前向保密 |
| PCS | Post-Compromise Security，入侵后恢复安全 |

---

## 2. 设计目标与原则

**目标**

1. 消息机密性：网络上的任何中间节点（含未来中继）无法读取明文。
2. 消息完整性：篡改、截断、注入均可检测。
3. 双向身份认证：双方都能确认对端持有其声称身份对应的私钥。
4. 抗重放：重复投递的密文不能导致重复处理。
5. 可接受性能：消息加解密在微秒级，不引入每消息非对称运算。
6. 前向保密：**参见 §9，需选择 M2 方案才成立。**

**原则**

- **GPG 承担身份与认证层，不承担数据加密层。**
  非对称加密只用于握手（低频）；数据通道完全是对称 AEAD。这是现代 E2EE 的标准分层，也避免了逐条 GPG 加密的性能与膨胀问题。
- 不自行发明密码学原语。仅组合成熟的 OpenPGP、X25519、HKDF、ChaCha20-Poly1305。
- 任何解密失败都必须显式上报，**禁止静默丢弃**。
- 密钥材料用 `[]byte` 承载并主动清零，避免 `string`（不可控）。

---

## 3. 密钥体系

| 密钥 | 算法 | 生成 | 生命周期 | 用途 |
|---|---|---|---|---|
| IK_sign | Ed25519 | 一次性（用户可能已持有） | 长期 | 签名认证、证明身份 |
| IK_enc | cv25519 (ECDH) | 同上 | 长期 | 保护初始握手中的临时公钥 |
| EK_i | X25519 | 每次握手 / 每次 ratchet | 单轮，立即销毁 | 提供 PFS 的 DH 主体 |
| SK | 32 随机字节 | 由 ECDH 派生，非随机生成 | 单轮 | 派生 AEAD key |
| AEAD key | HKDF-SHA256 输出 32B | 派生 | 单轮 | 消息加解密 |
| KEK | argon2id(口令) 输出 32B | 每次解锁 | 会话（内存） | **仅**用于封装/解封 MK |
| MK | 随机 32B（`crypto/rand`） | 首次创建身份时 | **永久不变** | 加密所有本地敏感数据 |

**身份标识** = IK 的 OpenPGP 指纹（v4: 40 hex，v5: 64 hex）。全量指纹用于所有内部标识与信任判定；**短 ID 仅用于 UI 展示，不得用于任何安全判定**。

---

## 4. 信任模型

```
① 密码学绑定
   IK 私钥 ──持有──▶ 唯一主体
   └─ 由 KEM + 签名隐式证明（§6.4）

② 身份绑定（密码学无法自动完成）
   指纹 "ABCD 1234 ..." ──确实属于──▶ 真人 Alice
   └─ 必须带外验证（扫码 / 当面比对 / 可信渠道）
   └─ 未验证前，状态为 TOFU，UI 必须显著提示
```

**这两层必须分开理解。** 密码学能证明"对方持有指纹 ABCD 对应的私钥"，但**不能**证明"ABCD 就是你以为的那个人"。中间人攻击正是在第②层发生的。UI 设计必须让未验证状态显眼，见 [ui-gio.md](ui-gio.md)。

信任状态机：

```
UNKNOWN ──收到公钥(TOFU)──▶ TOFU ──带外比对通过──▶ VERIFIED
                              │
                              └──比对失败──▶ BLOCKED（拒绝通信并告警）
```

---

## 5. 会话建立总览

采用**方案 M2（推荐）**：GPG 用于**保护并认证临时公钥**，会话密钥由 X25519 ECDH 派生。M1 作为可降级的简化变体在 §5.3 说明。

```
A (initiator)                                  B (responder)

 1. 生成 EK_A (X25519 keypair)
 2. 构造 KEM 载荷 P = {
      ver, sid, sender_fp, recipient_fp, ts,
      eph_pub_A,       // 一次性公钥
      flags
    }
 3. blob = OpenPGP.Encrypt_and_Sign(
      to   = IK_enc_B,
      sign = IK_sign_A,
      data = P )

 ────────────── KEM_INIT{ blob } ──────────────────────▶
                                        4. OpenPGP.Decrypt_and_Verify(
                                             priv = IK_B, from = IK_A_pub)
                                           ├─ 校验 recipient_fp == B.fp
                                           ├─ 校验签名者 == sender_fp
                                           └─ 校验 ts 在容忍窗口内
                                        5. 生成 EK_B (X25519 keypair)
                                        6. SK = HKDF(ECDH(EK_B_priv, eph_pub_A))
                                                   ↑ 加盐与上下文绑定
                                        7. 派生 key_r2i / key_i2r
                                        8. ack = AEAD(key_r2i, ack_data)
                                           ack_data = {ver, responder_fp, ts, eph_pub_B, handshake_hash}
                                           （帧格式详见 [wire-protocol.md](wire-protocol.md) §6.2）

 ◀───────────── KEM_ACK{ ack } ───────────────────────
 9. SK = HKDF(ECDH(EK_A_priv, eph_pub_B))
10. 派生同 key_i2r / key_r2i
11. 验证 ack 解封成功 → 隐式确认对端持有 IK_B 私钥
12. 发送 HANDSHAKE_CONFIRM（第一条 SECURE 帧，含握手记录哈希）
    ──────────────────────────────────────────────▶
                                         13. 校验记录哈希 → 握手完成
14. 双方清零 EK 私钥，进入会话态
```

### 5.1 关键校验（缺一不可）

| 校验 | 防的是什么 |
|---|---|
| `recipient_fp == 本机指纹` | KEM blob 被转发给第三方后仍有效 |
| 签名者 == 载荷中的 `sender_fp` | 攻击者用自己的密钥签名并冒名 |
| `ts` 在 ±300s 窗口内 | 整个握手交互被录制后重放 |
| `sid` 全局唯一（本地无重复记录） | 会话 ID 碰撞/复用 |
| ACK 能正确解封 | 对端未持有 IK_B 私钥（隐式认证失败） |
| 握手记录哈希一致 | 双方对同一份握手记录达成一致（防参数降级） |

### 5.2 为什么 ACK 不要求用 GPG 加密

`KEM_ACK` 用 `key_r2i`（由 ECDH 派生的对称密钥）加密即可，不需要 GPG：

- 只有持有 `IK_B` 私钥的一方能解出 `eph_pub_A`，进而算出 SK；
- 因此能产生正确 `key_r2i` 密文这一事实**本身就是**对 `IK_B` 持有权的证明（隐式认证）；
- 若此时仍走 GPG，会让后续每轮 rekey 也必须走 GPG，导致必须频繁使用硬件密钥。

### 5.3 方案 M1（简化变体，可降级）

若希望最快跑通，可先实现 M1：

```
KEM 载荷 P = { ver, sid, sender_fp, recipient_fp, ts, sk(32B随机), salt(16B) }
blob = OpenPGP.Encrypt_and_Sign(IK_enc_B, IK_sign_A, P)
B 解密后直接用 P.sk，派生 AEAD key（HKDF(salt, sk, info)）
```

**M1 与 M2 的唯一差别**：SK 是"发送方随机生成后封装"还是"双方 ECDH 协商"。

**M1 不提供前向保密**（因为 SK 是被长期私钥直接加密的对称密钥，泄漏 IK_enc_B 即可解出 SK 及全部后续轮换密钥）。详见 §9。

> **建议**：不要为了省事选 M1。M2 相比 M1 只多引入一个 X25519 密钥对与一次 ECDH（约 50 行代码 + `golang.org/x/crypto/curve25519`），却让"E2EE"名副其实。

---

## 6. 会话密钥派生

```
输入:
  shared  = X25519(own_EK_priv, peer_EK_pub)      // 32 字节
  salt    = HKDF-Salt
  context = 绑定的上下文信息

prk      = HKDF-Extract(salt, shared)
key_i2r  = HKDF-Expand(prk, "keytalk/v1/i2r" || context, 32)
key_r2i  = HKDF-Expand(prk, "keytalk/v1/r2i" || context, 32)
```

### 6.1 上下文绑定（防未知密钥共享 UKS）

`context` 必须包含双方身份与全部握手参数，使派生密钥与"谁和谁、用什么参数"强绑定：

```
context = H( ver || sid || FP_A || FP_B || eph_pub_A || eph_pub_B )
```

若不绑定，可能出现攻击者诱导双方进入参数不一致的会话（unknown key share）。

### 6.2 方向独立的密钥

`key_i2r` 与 `key_r2i` 必须不同，否则双向流量共享密钥会导致 **nonce 重用**——这是 AEAD 下的灾难性错误。

### 6.3 salt 的来源

- 初始握手：`salt = 32 字节随机数`，由 initiator 生成，随 KEM 载荷在 GPG 保护下传递。
- Ratchet：`salt = H(上一轮 SK)` —— 链式，保证每轮 salt 不同且不可预测。

### 6.4 隐式认证的推理链

```
B 能正确解封 KEM_INIT
  ⟺ B 持有 IK_enc_B 私钥
A 能正确解封 KEM_ACK（含 eph_pub_B）
  ⟺ 对端持有 IK_B 私钥 且 持有 EK_B 私钥
  ⟹ A 确认对端身份为 FP_B
```

注意最后一步依赖"A 持有的 `FP_B` 公钥确实属于 B"。这正是 §4 第②层——**必须由用户带外验证补上**。

---

## 7. 数据消息加密

### 7.1 明文结构

```
DATA_PLAINTEXT = {
  ver:     1B
  kind:    1B        // 0x01 text, 0x02 file-meta, 0x03 receipt, 0x04 typing
  sent_at: 8B        // unix ms, big-endian
  body_len:4B
  body:    body_len 字节（UTF-8）
}
```

### 7.2 nonce 构造

```
nonce = seq(8B, big-endian) ‖ 0x00000000(4B)
```

**唯一性依据**：一个 AEAD key 唯一对应一组 `(SessionID, Epoch)`，而 `seq` 在该组内严格单调递增且不重复，因此 `(key, nonce)` 组合永不重复。

**必须保证**：
- `seq` 单调递增**且不允许回绕**。若达到 `2^64-1`，必须立即触发 ratchet 或强制结束该会话（**不得回绕**）。
- ratchet 后 `seq` 重置为 0 —— 安全，因为 key 已更换、`epoch` 已递增。
- **绝不允许**在 key 未更换的情况下重置 `seq`。

> 这条不变式（`seq` 归零 ⟺ `epoch` 递增 ⟺ 密钥变更）是 AEAD 安全的根基，
> 必须有断言或测试保障。见 [wire-protocol.md](wire-protocol.md) §3.3。

### 7.3 AAD（附加认证数据）

```
AAD = ver ‖ frame_type ‖ sid ‖ epoch ‖ seq
```

把帧头（含 `epoch`）纳入认证范围，防止攻击者篡改 `sid` / `epoch` / `seq` 而密文仍校验通过。虽然 nonce 已含 `seq`（改动会导致解密失败），但显式绑定可避免"头部与密文错配"这类混淆，成本为零。

> **注**：`ver` 位于密文内部却参与 AAD，而 AAD 必须在解密前构造。
> 实现上必须把 AAD 中的 `ver` 视为**常量 0x01**，不得依赖密文内的值。详见 [wire-protocol.md](wire-protocol.md) §3.4。

### 7.4 发送流程

```
1. seq   = ++s.sendSeq                  // 原子递增
2. epoch = s.epoch                      // 当前密钥代次
3. nonce = buildNonce(seq)
4. aad   = buildAAD(ver=0x01, type, sid, epoch, seq)
5. ct = ChaCha20Poly1305.Seal(key, nonce, plaintext, aad)
6. 组装 SECURE 帧：{ sid, epoch, seq, ct }   // nonce 可由 seq 重建，不必传输
7. transport.Send(peer, frame)
8. 入队等待 RECEIPT；超时则标记 failed（不自动重发，见 §7.6）
```

### 7.5 接收流程

```
1. 解析帧头，取 sid / epoch / seq
2. 按 (sid, epoch) 选择密钥与对应重放窗口
   ├─ 未知 epoch（既非当前也非上一代）→ 回 ERROR(BAD_EPOCH) 并计数
   └─ 命中 → 继续
3. 重放窗口检查（§8）——不通过则丢弃并计数告警
4. nonce = buildNonce(seq)
5. aad   = buildAAD(ver=0x01, type, sid, epoch, seq)
6. pt, err = AEAD.Open(key, nonce, ct, aad)
   ├─ err ≠ nil → 解密失败：记录 + 上报，绝不静默丢弃
   └─ ok → 解析明文结构
7. 校验 ver / kind 合法、body_len 与内容一致
8. 更新重放窗口
9. 投递到 core
```

**顺序要点**：**先按 epoch 选密钥、再做重放检查、最后才解密**。这样重放包不会消耗解密算力，也避免通过解密耗时差异做侧信道探测。

### 7.6 关于自动重发

**不实现自动重发**。理由：P2P 场景下连接断开是常态，盲目重发会与重放防护冲突、并可能放大网络问题。正确做法是：
- 连接重建后由**应用层**提供"未送达列表"，重发时使用**新的 seq**；
- UI 明确显示消息状态（pending / ack / failed），让用户知情。

---

## 8. 重放防护

### 8.1 滑动窗口

**每个 `(SessionID, Epoch)` 维护一个独立窗口**——因为 `seq` 在每个 epoch 内独立计数：

```go
type replayWindow struct {
    highest uint64     // 已见最大 seq
    seen    [1024]bool // 位图：highest-1023 .. highest
    init    bool
}

// 会话持有当前与上一代 epoch 的状态
type epochState struct {
    epoch   uint64
    sendKey []byte        // 32B
    recvKey []byte        // 32B
    sendSeq uint64
    recvWin replayWindow
}
```

- **当前 epoch**：正常收发。
- **上一代 epoch**：仅用于接收 ratchet 切换瞬间的在途帧（寿命 ≤30s，见 [wire-protocol.md](wire-protocol.md) §5.2）。
- 一旦收到新 epoch 的合法帧，**立即销毁**旧 epoch 的密钥与窗口。

若帧头 `epoch` 既非当前也非上一代 → `ERROR(BAD_EPOCH)` 并计数。

判定规则：

| 情形 | 处理 |
|---|---|
| `seq > highest` | 接受；窗口右移，将新位置位 |
| `highest-1023 ≤ seq ≤ highest` | 查位图：未置位 → 接受并置位；已置位 → **拒绝（重放）** |
| `seq < highest-1023` | **拒绝（过旧）**，但**不得**据此判定为攻击（可能是网络乱序延迟过大） |

窗口大小 1024 是"容忍乱序深度"与"内存/位图开销"的折中。局域网场景 RTT 极低，实际乱序很浅；若未来走公网可调大。

### 8.2 握手层重放

- `ts` ±300s 窗口：拒绝陈旧的 KEM_INIT / KEM_ACK。
- `sid` 去重：本地维护最近 N 个（建议 1024）已用 sid 的集合，拒绝复用。
- 若收到合法签名但 `sid` 已存在的 KEM_INIT（可能是重放，也可能是对端重连后未清理），**必须重新走一轮全新握手**，不能复用旧 SK。

### 8.3 异常计数

拒绝次数需计数并在 UI 暴露（"检测到 N 个异常数据包"）。持续异常上升可能是主动攻击的信号，不应只在日志里沉默。

---

## 9. 密钥轮换与前向保密的真实边界

> **本节是全文最重要的部分。请勿在 UI 或宣传材料中作出超出本文的承诺。**

### 9.1 轮换触发

| 条件 | 阈值（可配置） |
|---|---|
| 消息条数 | 每 1000 条 |
| 会话存活时间 | 每 60 分钟 |
| 检测到异常 | 立即 |
| 手动 | 用户点击"重新协商密钥" |

### 9.2 M2 的 Ratchet 流程（提供 PFS）

```
发起方 A:
 1. 生成新的 EK_A' (X25519)
 2. payload = { ver, epoch+1, eph_pub_A', ts }
 3. mac = HMAC(key_i2r_mac, "keytalk/v1/ratchet" || payload)   ← 链式认证
 4. ct  = AEAD(key_i2r, payload)                              ← 用当前密钥加密
 5. 发送 REKEY{ epoch+1, eph_pub_A', ct, mac }

接收方 B:
 6. 用当前 key_i2r 解封 → 得 eph_pub_A'
 7. 生成 EK_B'，SK' = HKDF(ECDH(EK_B', eph_pub_A'))
 8. 回 REKEY_ACK 带 eph_pub_B'
 9. 双方派生新 key，epoch 递增，seq 归零，销毁旧 EK 私钥与旧 SK
```

**为什么 ratchet 用链式 MAC 而不是 GPG 签名**：会话已被认证，后续轮换用 MAC 足以防止伪造；若每轮都要求 GPG 私钥签名，使用硬件密钥（YubiKey）的用户将被迫频繁插卡，导致方案不可用。

### 9.3 【关键】M1 不提供前向保密

M1 的密钥链是：

```
IK_enc_B 私钥 ──解密──▶ sk₀ ──加密──▶ sk₁ ──加密──▶ sk₂ ──▶ ...
```

攻击者一旦获得 `IK_enc_B` 私钥（设备失窃、备份泄露、口令被爆破），即可解出 `sk₀`，然后**沿链依次解出所有历史 SK，解密全部历史消息**。

**M1 的"密钥轮换"只是换钥匙，不是前向保密。** 任何"轻量前向保密""部分 PFS"的说法都是错误的。

### 9.4 M2 提供的 PFS 及其边界

M2 中每轮 SK 来自**一次性 ECDH**：

```
sk₀ = HKDF(ECDH(EK_A, EK_B))        EK_* 用完立即清零
sk₁ = HKDF(ECDH(EK_A', EK_B'))
IK_B 私钥 ──▶ 只能解出 eph_pub_A（公开值），得不到 EK 私钥
因此: IK_B 私钥泄露 ✗⇒ 重建历史 sk_i
```

**M2 确实提供前向保密**：长期密钥泄露无法回溯历史会话，因为重建 SK 所需的临时私钥已被销毁。

**但 M2 仍不是 Signal Protocol**，边界如下：

| 能力 | M2 | Signal（Double Ratchet） |
|---|---|---|
| 长期密钥泄露后历史消息安全 | ✅ | ✅ |
| 密钥泄露后**未来**消息自愈（PCS） | ⚠️ 部分：需等下一轮 ratchet 才恢复 | ✅ 快得多（每消息/每往返 ratchet） |
| 单条消息泄露的影响范围 | 整轮（≤1000 条） | 单条 |
| 抗密钥泄漏后的主动攻击 | 弱（攻击者可在 ratchet 前持续解密） | 强 |
| 实现复杂度 | 中 | 高 |

M2 的 PCS 是"迟钝"的：若攻击者持续在线并窃取当前 SK，在下一次 ratchet 之前它能解出整轮消息；ratchet 后才被踢出。要缩短这个窗口，**降低 §9.1 的阈值**（例如每 50 条 ratchet 一次），代价是更多 ECDH 运算——即便如此仍远低于逐条 GPG 加密。

### 9.5 若安全要求高于本设计

如果威胁模型包含"长期密钥可能泄露 + 需要强 PCS + 抗主动攻击"，那么正确的选择是使用 **Signal Protocol（libsignal）**，而不是继续加固 GPG 方案。届时"基于 GPG"这一前提需要放弃。这是产品决策，应由需求方明确拍板。

---

## 10. 本地密钥存储

### 10.1 目录

| 平台 | 路径 |
|---|---|
| Linux | `$XDG_CONFIG_HOME/keytalk`（默认 `~/.config/keytalk`） |
| macOS | `~/Library/Application Support/keytalk` |
| Windows | `%AppData%\keytalk` |
| Android | 应用私有目录（`filesDir`） |
| iOS | 应用沙盒 Documents / Library |

统一通过 `os.UserConfigDir()` 派生，移动端由 Gio/gomobile 提供沙盒路径。

### 10.2 密钥分层：KEK → MK → 数据

**不要用口令派生的密钥直接加密数据**。否则用户改口令时，所有历史数据（消息正文、附件密钥、文件名……）都会永久不可读。

必须引入一层**主密钥（MK）**：

```
口令 ──argon2id──▶ KEK ──加密──▶ MK（32B 随机，永不变）
                                    │
                                    ├──加密──▶ 身份私钥 (identity.key)
                                    ├──加密──▶ 消息正文 (messages.body_ct)
                                    ├──加密──▶ 附件密钥 (attachments.file_key_ct)
                                    └──加密──▶ 附件文件名等元数据
```

| 密钥 | 来源 | 生命周期 | 用途 |
|---|---|---|---|
| **KEK** | `argon2id(口令, salt, m=64MiB, t=3, p=1)` | 每次解锁（仅内存） | **仅**用于加解密 MK |
| **MK** | `crypto/rand` 32B，首次创建身份时生成 | **永久不变** | 加密所有本地敏感数据 |

**落盘文件**：

```
identity.key   ← 身份私钥，用 MK 加密
wrapped_mk     ← MK，用 KEK 加密（32B）
identity.pub   ← 公钥（明文，可导出/展示）
identity.meta  ← 指纹、argon2id 参数(salt,m,t,p)、创建时间
```

**解锁流程**：

```
口令 → argon2id(meta 中的参数) → KEK
KEK 解密 wrapped_mk → MK
MK 解密 identity.key → 私钥（驻留内存）
```

**改口令流程**（瞬时完成）：

```
用旧 KEK 解出 MK → 用新 KEK 重新加密 MK → 覆写 wrapped_mk
（其他数据完全不动，无需重新加密任何消息或附件）
```

**安全说明**：解锁期间 MK 与 KEK 同时驻留内存，因此引入 MK **不降低**对"本机恶意进程"的防护（见 §10.5 与 [threat-model.md](threat-model.md) §4.4）。它解决的是**密钥生命周期**问题，不是内存保护问题。

`argon2id` 参数存于 `identity.meta`，随硬件升级可调。解锁后 KEK 应尽快清零；MK 需保留至锁定。

### 10.3 OS 密钥库（可选增强）

平台密钥库（Windows DPAPI / macOS Keychain / Android Keystore / iOS Keychain）可用于免除每次输入口令。三种模式：

| 模式 | 做法 | 安全 |
|---|---|---|
| **口令** | 用户设口令 → 派生 KEK → 解 MK | 依赖口令强度 |
| **OS 密钥库** | 把 **MK 本身**存入密钥库（受系统用户凭据保护） | 依赖系统登录凭据 |
| **两者并用** | MK 既被 KEK 包裹，又要求密钥库解锁 | 最强，但体验最麻烦 |

**要点**：

- 存入密钥库的应是 **MK**，不是 KEK——存 KEK 等于直接绕过口令，语义混乱。
- **失败时必须回退到口令模式**，不因此阻断启动。
- 安全差异需在 UI 中向用户说明：OS 密钥库模式下，"能登录系统"即等于"能解密数据"。

### 10.4 硬件密钥后端

若用户私钥位于硬件（YubiKey / 智能卡），OpenPGP 解封与签名须经 `gpg` CLI 或 PC/SC：

```go
type Unwrapper interface {
    Unwrap(blob []byte) ([]byte, error)   // 默认：库内软件解密
    Sign(data []byte) ([]byte, error)
}
// 实现 1: go-crypto/openpgp（软件）
// 实现 2: gpg CLI / 智能卡（硬件，仅握手与 ratchet 认证需要）
```

硬件后端仅在**初始握手**（解密 + 签名）和需要长期密钥的场合调用，频次低，用户插卡成本可接受。

### 10.4.1 实现选型与已验证的坑（重要）

`internal/crypto` 通过 `IdentityProvider` 接口隔离 OpenPGP 实现，因此**切换实现不影响** KEM、会话、传输与 UI。当前仓库内提供的是基于 `golang.org/x/crypto/openpgp` 的参考实现。

**关于实现选型（决策）**：

| 项 | x/crypto/openpgp | ProtonMail/go-crypto |
|---|---|---|
| 维护状态 | 已废弃（frozen） | 活跃 |
| 密钥算法 | **仅 RSA**（`NewEntity`） | Ed25519 + cv25519 |
| 生产适用 | 否（仅用于参考/测试） | 是 |

`golang.org/x/crypto/openpgp` 已被上游标记为废弃，官方建议迁移到 `github.com/ProtonMail/go-crypto/openpgp`。仓库内保留 x/crypto 实现的原因是**在无外部依赖时也能完整单测**；生产构建应替换为 ProtonMail 实现 —— 只需实现 `IdentityProvider` 接口并在装配处替换。

**已验证的三个坑**（均由实际测试暴露，非推测）：

#### 坑 1：`NewEntity` 的 `PreferredHash` 不会随公钥分发

`openpgp.NewEntity` 在 `keys.go` 中先调用 `SignUserId()` 完成签名，**之后**才赋值 `SelfSignature.PreferredHash`。而 `PreferredHash` 属于签名包内的子包（RFC 4880 §5.2.3.8），必须在**签名之前**设置才会被序列化。

后果：内存中 `PreferredHash = [8]`（SHA256），但经一次 `Serialize → ReadEntity`（即"把公钥发给对端"的正常流程）后变成 `[]`。

对端拿到空偏好后，openpgp 回退到 `defaultHashes`，其**唯一元素是 RIPEMD160**（`write.go`: `defaultHashes := candidateHashes[len-1:]`）。Go 标准库默认不编译 RIPEMD160，于是加密直接失败：

```
cannot encrypt because no candidate hash functions are compiled in. (Wanted RIPEMD160 in this case.)
```

**解法**：生成密钥后重新签署身份自签名 —— 先构造 `packet.Signature` 并设置 `PreferredHash` / `PreferredSymmetric` / `PreferredCompression`，**再**调用 `SignUserId()`，最后替换实体中的 `SelfSignature`。见 `pgp_provider.go` 的 `resignWithPreferredHashes`。

注意：修复必须在**签名前**设置字段。仅修改内存字段（不重签）是无效的，因为该字段不会进入被签名的字节流。

#### 坑 2：`ReadMessage` 的 keyring 必须同时含签名者公钥

`openpgp.ReadMessage` 的文档契约是：

> The given KeyRing should contain **both** public keys (for signature verification) and, possibly encrypted, private keys for decrypting.

只传接收方私钥时，签名在密码学上可验证，但库**无法解析出签名者身份**，`md.SignedBy` 为 `nil`，表现为 `no verified signer`。

**解法**：解密前显式注册对端公钥（`PGPProvider.AddPeerKey`）。

⚠️ **安全要点**：必须注册**调用方通过带外渠道确认过的**公钥，**绝不可**信任消息自带的公钥。否则攻击者可生成一对新密钥、用它签名并随消息附带自己的公钥，从而冒充任意身份。

#### 坑 3：响应方临时公钥的"鸡生蛋"问题

initiator 必须用 `(自己的临时私钥, 响应方的临时公钥)` 做 ECDH 才能派生会话密钥，而 KEM_ACK 恰恰是用该会话密钥加密的 —— 两者互相依赖。

**解法**：KEM_ACK 采用如下线上结构，把响应方临时公钥放在**密文之外**：

```
ephPub(32, 明文) ‖ ciphertext
```

这**不是**安全弱点，理由有三：

1. 它本来就是公开信息（ECDH 公钥无需保密）；
2. 它参与 AAD，攻击者替换它会导致 ACK 解密失败；
3. 它参与派生 initiator 的密钥，而 ACK 中的握手哈希会被 initiator 覆核 —— 攻破它需要同时伪造一致的哈希。

真正需要保密的是响应方的临时**私**钥，它从未离开响应方内存。

对应实现：`KEMACK.Encode` / `DecodeKEMACK`，以及 `CompleteInitiate` 中"先派生密钥、再解密 ACK"的顺序。

### 10.4.2 AAD 必须与方向无关（已验证）

同一帧在发送方与接收方必须产生**逐字节相同**的 AAD，否则接收方解密必然失败（AAD 参与认证）。

方向隔离已经由**密钥**保证（`i2r` / `r2i` 是两条独立密钥），因此 AAD 中**不能**再掺入方向标签（如 `"i2r"` / `"r2i"`）。那不是"额外防护"，而是会让双方算出不同 AAD 的 bug —— 这一点由 `TestHandshakeEndToEnd` 实际捕获。

### 10.5 密钥清零的现实边界

Go 无法保证内存清零：

- GC 可能在复制 `[]byte` 时留下未清零副本；
- 编译器可能优化掉写入全零的死代码；
- `string` 完全不可控。

可行做法：

```go
func zero(b []byte) {
    for i := range b { b[i] = 0 }
    runtime.KeepAlive(b)   // 抑制优化
}
```

**诚实结论**：这能减少密钥在内存中的驻留时间，但**不能**保证"密钥从不残留"。若威胁模型包含"本机内存取证"，Go 不是合适的技术选型。

---

## 11. 接口定义（草案）

```go
// crypto/identity.go
type Identity struct {
    fp       string
    pub      *openpgp.Entity
    priv     *openpgp.Entity   // 可能为 nil（仅公钥模式）
}

func GenerateIdentity(name, email string) (*Identity, error)
func LoadIdentity(dir string, passphrase []byte) (*Identity, error)
func ImportPublicKey(armored []byte) (*openpgp.Entity, error)
func (i *Identity) Fingerprint() string          // 全量 hex
func (i *Identity) EncryptAndSign(to *openpgp.Entity, data []byte) ([]byte, error)
func (i *Identity) DecryptAndVerify(from *openpgp.Entity, blob []byte) ([]byte, error)

// crypto/session.go
type Session struct {
    id       [8]byte
    epoch    uint64
    sendKey  []byte           // 32B，AEAD
    recvKey  []byte           // 32B，AEAD
    sendSeq  uint64           // 仅 writer goroutine 访问
    recvWin  replayWindow     // 仅 reader 访问；或加 mutex
    mu       sync.Mutex
}

type HandshakeState int
const (
    StInit HandshakeState = iota
    StSentInit
    StEstablished
    StRatcheting
    StClosed
)

func Initiate(my *Identity, peerPub *openpgp.Entity, peerFP string) (*Session, []byte /*KEM_INIT frame*/, error)
func Respond(my *Identity, peerPub *openpgp.Entity, kemInit []byte) (*Session, []byte /*KEM_ACK frame*/, error)
func (s *Session) Seal(plaintext []byte) (frame []byte, err error)
func (s *Session) Open(frame []byte) (plaintext []byte, err error)
func (s *Session) NeedsRekey() bool
func (s *Session) InitiateRekey() ([]byte, error)
func (s *Session) Close()                                  // 清零所有密钥材料
```

> **实现提示**：`Seal` 只应由 writer goroutine 调用，`Open` 只应由 reader goroutine 调用。二者对 `replayWindow` 的访问模式不同，若未来出现多 reader，需为窗口单独加锁。

---

## 12. 已知局限（必须体现在 UI 与文档中）

1. **M1 无前向保密**。若实现选 M1，UI 不得出现任何"前向保密"字样。
2. **M2 的 PCS 迟钝**：密钥泄露的影响窗口是一整轮（默认 ≤1000 条 / ≤60 分钟）。
3. **元数据不加密**：谁能看到流量特征？局域网内可见"某 IP 与某 IP 在通信"；未来中继可进一步看到时间/大小/频率。E2EE 不保护通信关系本身。
   - 流量分析（消息大小、发送时间）可推断内容类型甚至输入模式。首期不做消息填充；若需要，可加固定长度 padding，但会牺牲带宽。
4. **不抗本机恶意进程**：同机恶意软件可读内存、截键盘、注入 UI。超出 E2EE 范围。
5. **不抗端点妥协**：对端设备被入侵，任何 E2EE 方案都无能为力。
6. **Go 内存清零不彻底**（§10.5）。
7. **无群聊**：首期为 1:1。群聊需要 Sender Keys 或 MLS，是独立工作量。
8. **无离线消息**：见 [transport-lan.md](transport-lan.md) §7。
9. **初次使用依赖带外验证**：未验证前处于 TOFU 状态，存在被中间人利用的窗口。

---

## 13. 测试要点

### 13.1 单元测试（`crypto` 包，无需网络）

| 用例 | 期望 |
|---|---|
| 正常握手 → 双向加解密 | 明文一致 |
| 篡改 KEM blob 任意字节 | 解封失败 |
| 篡改 DATA 密文 / tag | 解密失败，且上报错误 |
| 篡改 AAD（sid / seq） | 解密失败 |
| 重放同一 DATA 帧 | 第二次被拒，计数 +1 |
| 乱序投递 seq（窗口内） | 全部接受 |
| 乱序投递 seq（窗口外、过旧） | 拒绝且不算攻击 |
| 用错误的私钥解封 | 失败 |
| `recipient_fp` 不匹配 | 拒绝 |
| 陈旧 `ts`（>300s） | 拒绝 |
| 复用 `sid` | 拒绝 |
| M2：泄漏 IK 私钥后尝试重建旧 SK | **重建失败**（PFS 验证） |
| M1：泄漏 IK 私钥后重建旧 SK | 重建成功（**记录该预期行为**，警示不要误用 M1） |
| ratchet 后旧 key 无法解密新消息 | 失败 |
| seq 达到上限 | 触发强制 ratchet 或拒绝 |
| 会话 Close 后密钥为全零 | 断言通过 |

### 13.2 属性测试

- 随机长度、随机内容的明文往返一致性。
- 随机比特翻转：任何单比特翻转都必须导致认证失败（AEAD 保证，但值得回归）。

### 13.3 互操作测试

- 生成的公钥能被 GnuPG 导入（`gpg --import`），确认未破坏 OpenPGP 规范。
- 能被 `gpg --list-packets` 正确解析 KEM blob 结构。

### 13.4 向量测试

对 HKDF、nonce 构造、AAD 构造、指纹格式化编写固定测试向量，防止后续重构悄悄改变线上格式。

---

## 14. 待定问题

| 问题 | 影响 | 建议 |
|---|---|---|
| M1 还是 M2 作为默认？ | 决定是否有 PFS | **M2**（本文推荐） |
| ratchet 阈值 | 安全 vs 性能 | 1000 条 / 60 分钟起步，可配置 |
| 是否做消息长度填充 | 抗流量分析 vs 带宽 | 首期不做，留扩展位 |
| 是否引入群聊 | 工作量 | 二期，考虑 Sender Keys |
| 是否支持多设备 | 密钥同步复杂度 | 二期，需慎重设计 |
| 硬件密钥是否首期支持 | 用户覆盖 vs 复杂度 | 接口预留，二期实现 |
