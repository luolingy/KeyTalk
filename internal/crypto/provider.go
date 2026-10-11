package crypto

import (
	"context"
	"errors"
)

// IdentityProvider 抽象"长期身份密钥"的操作。
//
// 这层抽象存在的理由（重要）：
//
//  1. **实现可替换**。OpenPGP 生态正在迁移——golang.org/x/crypto/openpgp 已废弃，
//     github.com/ProtonMail/go-crypto/openpgp 是继任者，但两者 API 与
//     支持的算法（ECC/cv25519）不同。把它隔离在一个接口后，切换实现
//     不影响 KEM、会话、传输与 UI。
//
//  2. **硬件密钥可插拔**。私钥位于 YubiKey / 智能卡时，"解封"必须走
//     gpg CLI 或 PC/SC。这是低频操作（每会话一次），适合经此接口分流。
//
//  3. **测试可注入**。单元测试无需真实密钥即可覆盖 KEM 与握手逻辑。
//
// 契约（实现者必须遵守）：
//
//   - Wrap 对**任意长度**的 data 返回可还原的 blob，且 blob 必须完整认证
//     （即篡改任意字节都必须导致 Unwrap 失败）。
//   - Unwrap 失败必须返回错误，**不得**返回部分明文。
//   - Unwrap 必须验证签名，签名者身份经 SenderFingerprint 返回。
//   - 实现不得依赖网络或文件系统。
type IdentityProvider interface {
	// Fingerprint 返回本身份的完整指纹。
	Fingerprint() Fingerprint

	// PublicKey 返回本身份公钥的可分发表示（实现自定义，通常为 armored 文本）。
	// 该表示由 ImportPublicKey 消费。
	PublicKey() []byte

	// Wrap 用 recipient 的公钥加密 data，并用本身份的私钥签名。
	//
	// recipient 由 ImportPublicKey 产出，与实现绑定。
	Wrap(recipient any, data []byte) ([]byte, error)

	// Unwrap 用本身份的私钥解密 blob，并验证其签名。
	//
	// 返回的 sender 是签名者指纹。调用方**必须**校验 sender 与预期一致
	// ——这是防止攻击者用自己密钥签名并冒名的关键。
	Unwrap(blob []byte) (data []byte, sender Fingerprint, err error)

	// Sign 用本身份私钥签名（用于信令消息签名等场景）。
	Sign(data []byte) ([]byte, error)

	// Close 释放敏感材料（尽力清零，见 crypto.go 中 zero 的说明）。
	Close() error
}

// PublicKeyImporter 从外部表示导入公钥。
type PublicKeyImporter interface {
	// ImportPublicKey 解析公钥表示，返回可用于 Wrap 的不透明值，
	// 以及该公钥的完整指纹。
	ImportPublicKey(encoded []byte) (entity any, fp Fingerprint, err error)
}

// Unwrapper 是 IdentityProvider 中"仅解密"子集的抽象，
// 供硬件后端等只实现部分能力的场景使用。
type Unwrapper interface {
	Unwrap(blob []byte) (data []byte, sender Fingerprint, err error)
}

// Signer 是"仅签名"子集的抽象。
type Signer interface {
	Sign(data []byte) ([]byte, error)
	Fingerprint() Fingerprint
}

// ErrProviderUnavailable 表示所选的 IdentityProvider 实现不可用
// （如依赖未引入、硬件未插入）。UI 应据此给出可操作的提示。
var ErrProviderUnavailable = errors.New("crypto: identity provider unavailable")

// Wipeable 由需要显式销毁的密钥材料实现。
type Wipeable interface {
	Wipe()
}

// ContextUnwrapper 是可取消的解封操作（硬件后端可能长时间等待用户触卡）。
type ContextUnwrapper interface {
	UnwrapContext(ctx context.Context, blob []byte) (data []byte, sender Fingerprint, err error)
}
