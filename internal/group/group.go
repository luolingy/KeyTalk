// Package group 实现群组的密钥管理与群消息状态机。
//
// # 已实现的范围
//
//   - 群组密钥（GK）的分发与收起：发起者生成 GK，按成员公钥逐份封装；
//   - 成员变更触发的换钥（epoch 递增）；
//   - 群消息的三态机：可读 / 等待密钥 / 校验失败；
//   - "密文先落库、拿到 GK 再解密"的决策逻辑。
//
// # 尚未实现（见 docs/group-design.md §8）
//
//   - 与 session 层的收发放帧挂接；
//   - 与 db 层的持久化；
//   - UI。
//
// 本包是纯粹的状态与决策逻辑，不碰网络、不碰磁盘，因此可以完整单测。
package group

import (
	"errors"
	"fmt"
	"sync"

	"github.com/exeliang/keytalk/internal/crypto"
)

// 群消息的可见状态。
type Visibility int

const (
	// VisibleReadable 表示已用正确 epoch 的 GK 解密成功。
	VisibleReadable Visibility = iota
	// Unreadable 表示有密文，但缺该 epoch 的 GK。
	//
	// 这不是错误，是正常的"还没拿到钥匙"。界面显示占位提示，
	// 绝不显示正文（也没有正文可显示）。
	Unreadable
	// Tampered 表示有 GK，但 AEAD 校验失败。
	//
	// 与 Unreadable 严格区分：前者是"可能被篡改"，是安全事件，
	// 必须显式告警；后者只是"暂时缺钥匙"，不是安全事件。
	Tampered
)

func (v Visibility) String() string {
	switch v {
	case VisibleReadable:
		return "readable"
	case Unreadable:
		return "unreadable"
	case Tampered:
		return "tampered"
	default:
		return "unknown"
	}
}

// errNoKey 表示缺该 epoch 的 GK。
var errNoKey = errors.New("group: no key for this epoch")

// Keyring 保存一个群组手上持有的各 epoch 的 GK。
//
// 只存**当前进程内存**里的 GK，绝不落盘明文。落盘的只有密文
// （见 docs/group-design.md §5.2）。
type Keyring struct {
	mu  sync.RWMutex
	gks map[uint64][]byte // epoch -> GK(32B)
}

// NewKeyring 创建空钥匙环。
func NewKeyring() *Keyring {
	return &Keyring{gks: make(map[uint64][]byte)}
}

// Put 存入某个 epoch 的 GK。
func (k *Keyring) Put(epoch uint64, gk []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	cp := make([]byte, len(gk))
	copy(cp, gk)
	k.gks[epoch] = cp
}

// Get 取出某个 epoch 的 GK（不存在返回 nil）。
func (k *Keyring) Get(epoch uint64) []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.gks[epoch]
}

// Has 报告是否有某个 epoch 的 GK。
func (k *Keyring) Has(epoch uint64) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.gks[epoch]
	return ok
}

// Wipe 清空所有 GK（退出群组 / 关闭应用时调用）。
func (k *Keyring) Wipe() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for e, gk := range k.gks {
		crypto.Zero(gk)
		delete(k.gks, e)
	}
}

// groupAAD 是群消息的 AAD：绑定 group_id 与 epoch。
//
// 绑定 epoch 是关键：用错误 epoch 的 GK 去解，AAD 不匹配 → AEAD 失败
// → 归为 Tampered 或 Unreadable，而不会解出垃圾明文冒充正文。
func groupAAD(groupID string, epoch uint64) []byte {
	out := make([]byte, 0, len(groupID)+9)
	out = append(out, []byte("keytalk/v1/group/")...)
	out = append(out, []byte(groupID)...)
	out = append(out, 0)
	out = append(out,
		byte(epoch>>56), byte(epoch>>48), byte(epoch>>40), byte(epoch>>32),
		byte(epoch>>24), byte(epoch>>16), byte(epoch>>8), byte(epoch))
	return out
}

// SealedGroupMessage 是一条落库的群消息（密文形态）。
//
// 这份结构就是"能写库、暂时看不了"的落地：它有密文但不要求 GK 才能构造。
type SealedGroupMessage struct {
	ID         string
	GroupID    string
	Epoch      uint64
	Sender     string // 发送者指纹
	Nonce      []byte
	Ciphertext []byte
}

// Classified 是解密尝试后的结果。
type Classified struct {
	// Visibility 是可见状态。
	Visibility Visibility
	// Plaintext 仅在 VisibleReadable 时非空。
	Plaintext []byte
	// Reason 是给用户看的说明（Unreadable / Tampered 时）。
	Reason string
}

// Classify 尝试用钥匙环里的 GK 解密一条群消息。
//
// 这是"信息能写库、暂时看不了"的核心决策函数。它从不返回错误——
// 失败被转成 Visibility 状态，因为"解不开"是一个正常的、需要展示的
// 状态，而不是一个需要中止流程的错误。
func Classify(ring *Keyring, m SealedGroupMessage) Classified {
	gk := ring.Get(m.Epoch)
	if gk == nil {
		return Classified{
			Visibility: Unreadable,
			Reason: fmt.Sprintf(
				"等待群组密钥（epoch %d）。拿到后会重新解密这条消息。", m.Epoch),
		}
	}

	aad := groupAAD(m.GroupID, m.Epoch)
	pt, err := crypto.Open(gk, m.Nonce, m.Ciphertext, aad)
	if err != nil {
		// 有钥匙却解不开：要么消息被篡改，要么 epoch 标注与密钥不符。
		// 两种情况都必须显式告警，不能当成"缺钥匙"糊弄过去。
		return Classified{
			Visibility: Tampered,
			Reason: fmt.Sprintf(
				"消息校验失败（epoch %d）。可能被篡改，已保留原始密文。", m.Epoch),
		}
	}
	return Classified{Visibility: VisibleReadable, Plaintext: pt}
}

// SealGroupMessage 用某 epoch 的 GK 加密一条群消息（发送侧用）。
func SealGroupMessage(ring *Keyring, groupID string, epoch uint64,
	id, sender string, plaintext []byte) (SealedGroupMessage, error) {

	gk := ring.Get(epoch)
	if gk == nil {
		return SealedGroupMessage{}, fmt.Errorf("group: cannot seal with unknown epoch %d", epoch)
	}
	nonce := make([]byte, crypto.NonceLen)
	// 用 crypto 包提供的随机源；此处直接走 Seal 的内部约定。
	// （crypto.Seal 需要调用方给 nonce，这里生成随机 nonce。）
	copy(nonce, crypto.RandomNonce())
	aad := groupAAD(groupID, epoch)
	ct, err := crypto.Seal(gk, nonce, plaintext, aad)
	if err != nil {
		return SealedGroupMessage{}, err
	}
	return SealedGroupMessage{
		ID: id, GroupID: groupID, Epoch: epoch, Sender: sender,
		Nonce: nonce, Ciphertext: ct,
	}, nil
}

// NewGroupKey 生成一把新的群组密钥（32 字节）。
//
// 只应由发起者在换钥时调用。
func NewGroupKey() []byte {
	return crypto.RandomBytes32()
}
