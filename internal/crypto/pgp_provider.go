package crypto

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// 本文件是 IdentityProvider 的一个具体实现，基于 golang.org/x/crypto/openpgp。
//
// ⚠️ 重要说明（见 docs/crypto-protocol.md §10.4 与 docs/threat-model.md §5）：
//
//	golang.org/x/crypto/openpgp 已被上游标记为废弃（frozen），
//	官方建议迁移至 github.com/ProtonMail/go-crypto/openpgp。
//
//	本实现存在的意义是让 crypto 包在无外部依赖时也能完整单测与运行。
//	**生产环境应改用 ProtonMail 实现**——它支持 Ed25519/cv25519，
//	而 x/crypto 版本的 NewEntity 仅能生成 RSA。
//
//	做到这一点只需实现 IdentityProvider 接口并在装配处替换，
//	KEM、会话、传输、UI 均无需改动。这正是该接口存在的理由。
//
// 另一个 x/crypto 特有的坑：openpgp 的默认哈希偏好列表里包含 RIPEMD160，
// 而 Go 标准库默认**不编译**该哈希（需 crypto/ripemd160 的注册）。
// 若不在 Config 中显式指定，Encrypt 会以
// "no candidate hash functions are compiled in" 失败。
// 因此下面统一通过 defaultPacketConfig() 强制使用 SHA-256。

// defaultPacketConfig 返回强制使用已编译哈希的 packet.Config。
func defaultPacketConfig() *packet.Config {
	return &packet.Config{
		DefaultHash: crypto.SHA256,
	}
}

// PGPProvider 是基于 x/crypto/openpgp 的 IdentityProvider 实现。
type PGPProvider struct {
	entity *openpgp.Entity
	fp     Fingerprint

	// peer 是对端公钥，用于 Unwrap 时验证签名者身份。
	// 见 AddPeerKey 的说明：必须显式注册，不可信任消息自带的公钥。
	peer *openpgp.Entity
}

// 编译期断言。
var _ IdentityProvider = (*PGPProvider)(nil)

// PGPConfig 控制密钥生成参数。
type PGPConfig struct {
	// Name 与 Email 写入密钥的 User ID。
	Name  string
	Email string

	// RSABits 是生成密钥的位数。仅在使用 x/crypto 实现时有效
	// （该实现只支持 RSA）。2048 是兼容性下限，4096 更安全但生成慢。
	RSABits int
}

// GeneratePGPIdentity 生成一个新的身份密钥。
//
// 生成后会重签自签名，把 PreferredHash 真正写进被签名的子包中。
// 详见 resignWithPreferredHashes 的说明——这是一个必须处理的
// x/crypto/openpgp 上游缺陷，否则对端在加密时会直接失败。
func GeneratePGPIdentity(cfg PGPConfig) (*PGPProvider, error) {
	if cfg.RSABits == 0 {
		cfg.RSABits = 3072
	}
	if cfg.Name == "" {
		cfg.Name = "KeyTalk User"
	}

	pc := defaultPacketConfig()
	pc.RSABits = cfg.RSABits

	entity, err := openpgp.NewEntity(cfg.Name, "", cfg.Email, pc)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate openpgp identity: %w", err)
	}
	if err := resignWithPreferredHashes(entity, pc); err != nil {
		return nil, err
	}

	return &PGPProvider{
		entity: entity,
		fp:     fingerprinOf(entity),
	}, nil
}

// 哈希算法编号（RFC 4880 §9.4）。硬编码为字面量：
// Go 标准库默认不编译 RIPEMD160，其常量在 crypto 包中不可用。
const (
	ripemd160HashID byte = 3
	hashIDSHA256    byte = 8
	hashIDSHA384    byte = 9
	hashIDSHA512    byte = 10
)

// preferredHashIDs 是我们要声明的哈希偏好（均为标准库已编译项）。
//
// 顺序即优先级，SHA-256 在前。
var preferredHashIDs = []uint8{hashIDSHA256, hashIDSHA384, hashIDSHA512}

// resignWithPreferredHashes 重新签署身份自签名，使哈希偏好真正生效。
//
// ⚠️ 这里绕过的是一处**上游缺陷**（golang.org/x/crypto/openpgp/keys.go）：
//
//	NewEntity 先在 L547 调用 SignUserId() 完成签名，
//	之后才在 L554 赋值 SelfSignature.PreferredHash = [SHA256]。
//
//	PreferredHash 属于签名包内的子包（RFC 4880 §5.2.3.8），必须在
//	**签名之前**设置才会被序列化进签名。L554 的赋值只改了内存字段，
//	既未被签名，也不会被序列化——实体一旦经由 Serialize/ReadEntity
//	往返（即"发给对端"的正常流程），该字段就变回空。
//
//	而对端拿到空偏好后，openpgp 会回退到 defaultHashes，其唯一元素是
//	RIPEMD160（write.go: defaultHashes := candidateHashes[len-1:]）。
//	Go 标准库默认不编译 RIPEMD160，于是加密直接失败：
//	    "cannot encrypt because no candidate hash functions are compiled in.
//	     (Wanted RIPEMD160 in this case.)"
//
// 实测证据：内存中 PreferredHash=[8]，经一次 Serialize→ReadEntity 后变成 []。
//
// 因此必须重新签署：构造一个带上 PreferredHash / PreferredSymmetric 的
// SelfSignature，先设置字段、再调用 SignUserId，最后替换实体中的自签名。
func resignWithPreferredHashes(e *openpgp.Entity, pc *packet.Config) error {
	for _, id := range e.Identities {
		old := id.SelfSignature
		if old == nil {
			continue
		}
		sig := &packet.Signature{
			CreationTime: old.CreationTime,
			SigType:      old.SigType,
			PubKeyAlgo:   old.PubKeyAlgo,
			Hash:         old.Hash,
			IsPrimaryId:  old.IsPrimaryId,
			FlagsValid:   old.FlagsValid,
			FlagSign:     old.FlagSign,
			FlagCertify:  old.FlagCertify,
			IssuerKeyId:  old.IssuerKeyId,
		}
		// 关键：在签名**之前**设置这些子包字段。
		sig.PreferredHash = append([]uint8(nil), preferredHashIDs...)
		sig.PreferredSymmetric = []uint8{
			uint8(packet.CipherAES256),
			uint8(packet.CipherAES128),
		}
		// 声明偏好压缩算法，避免对端回退到未编译的默认值。
		sig.PreferredCompression = []uint8{0, 1, 2} // none / ZIP / ZLIB

		if err := sig.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, pc); err != nil {
			return fmt.Errorf("crypto: re-sign user id %q: %w", id.Name, err)
		}
		id.SelfSignature = sig
	}
	return nil
}

// fingerprinOf 把 openpgp 的 [20]byte 指纹转换为本包类型。
func fingerprinOf(e *openpgp.Entity) Fingerprint {
	fp := e.PrimaryKey.Fingerprint
	return NewFingerprint(fp[:])
}

// Fingerprint 返回完整指纹。
func (p *PGPProvider) Fingerprint() Fingerprint { return p.fp }

// Name 返回身份里的用户名。
//
// 用途：从备份导入身份时预填显示名，省去用户手输。
//
// 注意 Identities 是 map，迭代顺序随机。本项目的密钥只有一个
// user id，因此结果确定；若将来支持多个，这里需要改为
// 选取主 user id（自签名指向的那个）。
func (p *PGPProvider) Name() string {
	for _, id := range p.entity.Identities {
		if id != nil && id.UserId != nil && id.UserId.Name != "" {
			return id.UserId.Name
		}
	}
	return ""
}

// PublicKey 返回 armored 公钥文本（可安全分发给对端）。
func (p *PGPProvider) PublicKey() []byte {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		// armor.Encode 只在写入头失败时出错，内存 buffer 不会失败。
		panic(fmt.Sprintf("crypto: armor encode: %v", err))
	}
	if err := p.entity.Serialize(w); err != nil {
		panic(fmt.Sprintf("crypto: serialize public key: %v", err))
	}
	if err := w.Close(); err != nil {
		panic(fmt.Sprintf("crypto: close armor: %v", err))
	}
	return buf.Bytes()
}

// Wrap 用 recipient 公钥加密 data 并用本身份签名。
//
// 加密+签名同时进行，使接收方能验证"确实是这个身份发来的"。
// 这是 KEM 载荷的关键防护：仅有加密而无签名时，攻击者无需解密即可
// 用自己的密钥重新签名，冒充他人。
func (p *PGPProvider) Wrap(recipient any, data []byte) ([]byte, error) {
	// 接受 *openpgp.Entity 或 []byte（armored/二进制公钥）。
	var rec *openpgp.Entity
	switch v := recipient.(type) {
	case *openpgp.Entity:
		rec = v
	case []byte:
		var err error
		rec, _, err = ImportPGPPublicKey(v)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("crypto: wrap: unsupported recipient type %T", recipient)
	}

	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, []*openpgp.Entity{rec}, p.entity, nil, defaultPacketConfig())
	if err != nil {
		return nil, fmt.Errorf("crypto: encrypt: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("crypto: write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("crypto: close encrypted writer: %w", err)
	}
	return buf.Bytes(), nil
}

// Unwrap 解密并验签。
//
// 返回签名者指纹——调用方**必须**校验它与预期一致。
//
// 实现要点：ReadMessage 的 keyring 参数必须能提供**签名者的公钥**，
// 否则 md.SignedBy 为 nil，报 "no verified signer"。
// （openpgp.ReadMessage 的文档明确要求："The given KeyRing should contain
// both public keys (for signature verification) and, possibly encrypted,
// private keys for decrypting."）
//
// 这里的关键技巧：签名者的公钥通常**随消息一起传输**（OpenPGP 的
// 内联签名会带上签发者 KeyId，而公钥则在需要时随消息附带）。
// 若不附带，就必须由调用方预先在 keyring 中放入对端公钥。
//
// 我们采用**显式注入**的方式：Unwrap 前由调用方通过 AddPeerKey 注册
// 对端公钥。这样既满足 ReadMessage 的契约，又不必信任消息自带的公钥——
// 后者会让攻击者用自己生成的密钥签名并自带公钥，从而冒充任意身份。
func (p *PGPProvider) Unwrap(blob []byte) ([]byte, Fingerprint, error) {
	ring := openpgp.EntityList{p.entity}
	if p.peer != nil {
		ring = append(ring, p.peer)
	}

	md, err := openpgp.ReadMessage(bytes.NewReader(blob), ring, nil, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%w: read message: %v", ErrDecrypt, err)
	}
	if !md.IsEncrypted {
		return nil, "", fmt.Errorf("%w: message is not encrypted", ErrAuthFailed)
	}
	// 必须要求签名：无签名的载荷无法证明发送者身份。
	if !md.IsSigned {
		return nil, "", fmt.Errorf("%w: message is not signed", ErrAuthFailed)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(md.UnverifiedBody); err != nil {
		return nil, "", fmt.Errorf("%w: read body: %v", ErrDecrypt, err)
	}
	// 签名在读取完整 body 之后才被校验，因此必须在 ReadFrom 之后检查。
	if md.SignatureError != nil {
		return nil, "", fmt.Errorf("%w: signature: %v", ErrAuthFailed, md.SignatureError)
	}
	if md.SignedBy == nil || md.SignedBy.Entity == nil {
		// 签名密码学上有效，但我们不持有签名者公钥，无法确认其身份。
		return nil, "", fmt.Errorf("%w: signer public key not registered (call AddPeerKey)", ErrAuthFailed)
	}

	fp := fingerprinOf(md.SignedBy.Entity)
	return buf.Bytes(), fp, nil
}

// AddPeerKey 注册对端公钥，供 Unwrap 验证签名者身份。
//
// 必须显式注册而非信任消息自带的公钥——否则攻击者可以生成一对新密钥，
// 用它签名并随消息附带自己的公钥，从而冒充任意身份。
// 只有调用方通过带外渠道确认过的公钥才应被注册。
func (p *PGPProvider) AddPeerKey(encoded []byte) (Fingerprint, error) {
	ent, fp, err := ImportPGPPublicKey(encoded)
	if err != nil {
		return "", err
	}
	p.peer = ent
	return fp, nil
}

// Sign 用本身份签名（detached-style，嵌入二进制签名包）。
func (p *PGPProvider) Sign(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := openpgp.DetachSign(&buf, p.entity, bytes.NewReader(data), defaultPacketConfig()); err != nil {
		return nil, fmt.Errorf("crypto: sign: %w", err)
	}
	return buf.Bytes(), nil
}

// VerifyPGP 用给定公钥验证分离签名。
func VerifyPGP(publicKey, data, sig []byte) error {
	entity, _, err := ImportPGPPublicKey(publicKey)
	if err != nil {
		return err
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{entity},
		bytes.NewReader(data), bytes.NewReader(sig)); err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}
	return nil
}

// Close 释放内存中的私钥材料。
//
// x/crypto/openpgp 的 PrivateKey 内部持有 big.Int / rsa 结构，
// Go 无法可靠清零（见 crypto.go 中 zero 的说明）。
// 此处尽力切断引用（含明文 User ID），其余交给 GC。
func (p *PGPProvider) Close() error {
	if p.entity == nil {
		return nil
	}
	for _, id := range p.entity.Identities {
		id.SelfSignature = nil
		id.UserId = nil
		id.Name = ""
	}
	for _, sub := range p.entity.Subkeys {
		sub.Sig = nil
	}
	p.entity = nil
	p.peer = nil
	return nil
}

// --- 公钥导入 ---

// PGPImporter 实现 PublicKeyImporter。
type PGPImporter struct{}

var _ PublicKeyImporter = PGPImporter{}

// ImportPublicKey 解析 armored 或二进制公钥。
//
// 返回的 entity 为 any 类型以保持接口中立（不暴露 OpenPGP 类型给调用方）。
func (PGPImporter) ImportPublicKey(encoded []byte) (any, Fingerprint, error) {
	entity, fp, err := ImportPGPPublicKey(encoded)
	if err != nil {
		return nil, "", err
	}
	return entity, fp, nil
}

// ImportPGPPublicKey 解析公钥并可选择校验其自签名。
//
// 安全提示：导入公钥时**不**能信任其中的 User ID 字段——
// 任何人都能生成一个 User ID 为 "Alice" 的密钥。
// 身份确认只能靠指纹带外比对（见 docs/threat-model.md §4.1）。
func ImportPGPPublicKey(encoded []byte) (*openpgp.Entity, Fingerprint, error) {
	if len(encoded) == 0 {
		return nil, "", fmt.Errorf("%w: empty public key", ErrMalformed)
	}

	// 先尝试 armored，失败则按二进制解析。
	if bytes.Contains(encoded, []byte("-----BEGIN PGP")) {
		block, err := armor.Decode(bytes.NewReader(encoded))
		if err != nil {
			return nil, "", fmt.Errorf("%w: armor decode: %v", ErrMalformed, err)
		}
		entity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
		if err != nil {
			return nil, "", fmt.Errorf("%w: read armored entity: %v", ErrMalformed, err)
		}
		return entity, fingerprinOf(entity), nil
	}

	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(encoded)))
	if err != nil {
		return nil, "", fmt.Errorf("%w: read entity: %v", ErrMalformed, err)
	}
	return entity, fingerprinOf(entity), nil
}

// ExportPrivateKey 导出 armored 私钥（含公钥与身份）。
//
// ⚠️ 返回值是**明文**私钥材料。调用方负责保护它：
// 应经 passphrase 派生的 KEK 加密后再落盘
// （见 docs/crypto-protocol.md §10.2 与 keystore.go），
// 且绝不能写入日志、UI 或网络。
func (p *PGPProvider) ExportPrivateKey() (string, error) {
	if p.entity == nil || p.entity.PrivateKey == nil {
		return "", ErrNoSigningKey
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", fmt.Errorf("crypto: armor encode: %w", err)
	}
	if err := p.entity.SerializePrivate(w, nil); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("crypto: serialize private key: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("crypto: close armor writer: %w", err)
	}
	return buf.String(), nil
}

// ImportPGPIdentity 从 armored（或二进制）私钥导入完整身份。
//
// 与 ImportPGPPublicKey 的区别：本函数返回的是可直接用于
// 签名与解封装的 provider，而不只是一个公钥实体。
func ImportPGPIdentity(encoded string) (*PGPProvider, error) {
	raw := []byte(encoded)
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty private key", ErrMalformed)
	}

	var entity *openpgp.Entity
	var err error
	if bytes.Contains(raw, []byte("-----BEGIN PGP")) {
		block, aerr := armor.Decode(bytes.NewReader(raw))
		if aerr != nil {
			return nil, fmt.Errorf("%w: armor decode: %v", ErrMalformed, aerr)
		}
		entity, err = openpgp.ReadEntity(packet.NewReader(block.Body))
	} else {
		entity, err = openpgp.ReadEntity(packet.NewReader(bytes.NewReader(raw)))
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read entity: %v", ErrMalformed, err)
	}

	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("%w: imported key has no private part", ErrNoSigningKey)
	}
	// 主私钥必须与主公钥一致——不一致说明密钥文件损坏或被拼接篡改，
	// 继续使用会导致"能解密但签名验证永远失败"这类难排查的问题。
	if !bytes.Equal(entity.PrivateKey.PublicKey.Fingerprint[:],
		entity.PrimaryKey.Fingerprint[:]) {
		return nil, fmt.Errorf("%w: private key does not match public key", ErrAuthFailed)
	}

	return &PGPProvider{entity: entity, fp: fingerprinOf(entity)}, nil
}

// ErrNoSigningKey 表示实体没有可用于签名的私钥。
var ErrNoSigningKey = errors.New("crypto: entity has no private signing key")
