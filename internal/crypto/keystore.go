package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// 密钥存储采用两层结构（见 docs/crypto-protocol.md §10.2）：
//
//	口令 ──argon2id──▶ KEK ──加密──▶ MK（主密钥，32B 随机，永不变）
//	                                    │
//	                                    └──加密──▶ 所有本地敏感数据
//
// 为什么不直接用 KEK 加密数据：
// 用户改口令时 KEK 会变，若直接用它加密数据，所有历史消息与附件密钥
// 将永久不可读。引入 MK 后，改口令只需用新 KEK 重新封装 32 字节的 MK。

// 密钥存储相关的常量。
const (
	// MKLens 是主密钥的字节数。
	MKLens = 32

	// 默认 argon2id 参数。存储于 meta 中，随硬件升级可调。
	defaultArgonTime    = 3
	defaultArgonMemory  = 64 * 1024 // 64 MiB
	defaultArgonThreads = 1
)

// 密钥存储错误。
var (
	// ErrWrongPassphrase 表示口令错误或 wrapped MK 被篡改。
	ErrWrongPassphrase = errors.New("crypto: wrong passphrase or corrupted keystore")
	// ErrKeystoreFormat 表示 keystore 结构非法。
	ErrKeystoreFormat = errors.New("crypto: malformed keystore")
	// ErrKeystoreVersion 表示 keystore 版本不受支持。
	ErrKeystoreVersion = errors.New("crypto: unsupported keystore version")
)

// ArgonParams 是 argon2id 的派生参数。
//
// 存于 keystore 中，因此攻击者知道这些参数不构成信息泄露——
// 它们是公开的，只是用来让暴力破解变慢。
type ArgonParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB
	Threads uint8  `json:"threads"`
	Salt    []byte `json:"salt"`
}

// DefaultArgonParams 返回默认参数与一个随机 salt。
func DefaultArgonParams() ArgonParams {
	return ArgonParams{
		Time:    defaultArgonTime,
		Memory:  defaultArgonMemory,
		Threads: defaultArgonThreads,
		Salt:    randomBytes(16),
	}
}

// DeriveKEK 从口令派生密钥加密密钥。
//
// 注意：argon2id 只能减缓暴力破解，**不能弥补弱口令**。
// 见 docs/threat-model.md §3 中 A7 的说明。
func (p ArgonParams) DeriveKEK(passphrase []byte) []byte {
	return argon2.IDKey(passphrase, p.Salt, p.Time, p.Memory, p.Threads, KeyLen)
}

// Keystore 是落盘的密钥容器。
//
// JSON 字段名较短以减小体积；所有密钥材料均已加密。
type Keystore struct {
	Version int         `json:"v"`
	Argon   ArgonParams `json:"kdf"`

	// WrappedMK 是 MK 经 KEK 用 ChaCha20-Poly1305 封装的结果。
	WrappedMK []byte `json:"mk"`

	// Fingerprint 与 PublicKey 是**非机密**信息，明文存放以便在解锁前
	// 展示身份（例如让用户确认"这是在解锁哪个身份"）。
	Fingerprint string `json:"fp"`
	PublicKey   []byte `json:"pub"`

	// CreatedAt 是创建时间（unix 毫秒）。
	CreatedAt int64 `json:"ts"`
}

// keystoreAAD 绑定 keystore 的非机密字段，使攻击者无法在不被发现的情况下
// 替换指纹或公钥（那会造成身份混淆）。
func keystoreAAD(k *Keystore) []byte {
	var buf bytes.Buffer
	buf.WriteString("keytalk/v1/keystore")
	buf.WriteString(k.Fingerprint)
	buf.WriteByte(0)
	buf.Write(k.PublicKey)
	return buf.Bytes()
}

// NewKeystore 用给定口令创建一个新的 keystore。
//
// 返回的 MK 必须由调用方持有并在锁定时清零。
func NewKeystore(passphrase []byte, fp Fingerprint, publicKey []byte, createdAtMS int64) (*Keystore, []byte, error) {
	if len(passphrase) == 0 {
		return nil, nil, errors.New("crypto: passphrase must not be empty")
	}

	mk := randomBytes(MKLens)
	ks := &Keystore{
		Version:     1,
		Argon:       DefaultArgonParams(),
		Fingerprint: fp.String(),
		PublicKey:   append([]byte(nil), publicKey...),
		CreatedAt:   createdAtMS,
	}

	kek := ks.Argon.DeriveKEK(passphrase)
	defer zero(kek)

	wrapped, err := sealMK(kek, mk, keystoreAAD(ks))
	if err != nil {
		zero(mk)
		return nil, nil, err
	}
	ks.WrappedMK = wrapped
	return ks, mk, nil
}

// Unlock 用口令解出 MK。
//
// 失败返回 ErrWrongPassphrase——不区分"口令错"与"数据被篡改"，
// 避免给攻击者提供区分性信息。
func (k *Keystore) Unlock(passphrase []byte) ([]byte, error) {
	if k.Version != 1 {
		return nil, fmt.Errorf("%w: %d", ErrKeystoreVersion, k.Version)
	}
	if len(k.WrappedMK) < NonceLen+TagLen {
		return nil, fmt.Errorf("%w: wrapped mk too short", ErrKeystoreFormat)
	}
	if err := k.Argon.validate(); err != nil {
		return nil, err
	}

	kek := k.Argon.DeriveKEK(passphrase)
	defer zero(kek)

	mk, err := openMK(kek, k.WrappedMK, keystoreAAD(k))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return mk, nil
}

// ChangePassphrase 用新口令重新封装 MK。
//
// 这是引入 MK 分层的直接收益：**无需重新加密任何消息或附件**，
// 只需重写 32 字节的 MK 封装（瞬时完成）。
func (k *Keystore) ChangePassphrase(oldPass, newPass []byte) error {
	mk, err := k.Unlock(oldPass)
	if err != nil {
		return err
	}
	defer zero(mk)

	if len(newPass) == 0 {
		return errors.New("crypto: new passphrase must not be empty")
	}

	// 换 salt，避免同一 salt 下两次派生的相关性。
	k.Argon.Salt = randomBytes(16)
	kek := k.Argon.DeriveKEK(newPass)
	defer zero(kek)

	wrapped, err := sealMK(kek, mk, keystoreAAD(k))
	if err != nil {
		return err
	}
	k.WrappedMK = wrapped
	return nil
}

func (p ArgonParams) validate() error {
	if p.Time == 0 || p.Memory == 0 || p.Threads == 0 || len(p.Salt) == 0 {
		return fmt.Errorf("%w: argon params incomplete", ErrKeystoreFormat)
	}
	// 上界防护：恶意的 keystore 文件可能声明超大内存参数以制造 DoS。
	if p.Memory > 1<<20 { // 1 GiB
		return fmt.Errorf("%w: argon memory %d KiB too large", ErrKeystoreFormat, p.Memory)
	}
	if p.Time > 100 {
		return fmt.Errorf("%w: argon time %d too large", ErrKeystoreFormat, p.Time)
	}
	return nil
}

// sealMK 用 KEK 加密 MK。
//
// 布局：nonce(12) ‖ ciphertext+tag
func sealMK(kek, mk, aad []byte) ([]byte, error) {
	nonce := randomBytes(NonceLen)
	ct, err := Seal(kek, nonce, mk, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, NonceLen+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func openMK(kek, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) < NonceLen+TagLen {
		return nil, ErrKeystoreFormat
	}
	nonce := wrapped[:NonceLen]
	ct := wrapped[NonceLen:]
	return Open(kek, nonce, ct, aad)
}

// Marshal 序列化 keystore。
func (k *Keystore) Marshal() ([]byte, error) {
	return json.MarshalIndent(k, "", "  ")
}

// UnmarshalKeystore 反序列化 keystore。
func UnmarshalKeystore(data []byte) (*Keystore, error) {
	var k Keystore
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // 防止未来字段被静默忽略导致降级
	if err := dec.Decode(&k); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeystoreFormat, err)
	}
	return &k, nil
}

// --- MK 保护的本地数据编解码 ---
//
// 消息正文、附件文件名、附件密钥等本地数据都用 MK 加密。
// 统一格式：nonce(12) ‖ ciphertext+tag，AAD 绑定用途标签，
// 防止把用于 A 的密文搬到 B 的位置使用（跨用途混淆）。

// LocalDataPurpose 标识本地加密数据的用途，构成 AAD 的一部分。
type LocalDataPurpose string

const (
	// PurposeMessage 是消息正文。
	PurposeMessage LocalDataPurpose = "message-body"
	// PurposeFileName 是附件文件名。
	PurposeFileName LocalDataPurpose = "file-name"
	// PurposeFileKey 是附件对称密钥。
	PurposeFileKey LocalDataPurpose = "file-key"
	// PurposeMIME 是附件 MIME 类型。
	PurposeMIME LocalDataPurpose = "file-mime"

	// PurposeIdentityKey 是身份私钥（armored）本身。
	//
	// 单独的用途标签让私钥密文无法被搬到消息正文或附件的位置使用：
	// AAD 不同，解密必然失败（跨用途混淆防护）。
	PurposeIdentityKey LocalDataPurpose = "identity-private-key"

	// PurposePage 是聊天数据库的一个加密页。
	//
	// 整个库文件（除固定文件头）都是这种密文页，因此翻磁盘
	// 看不到任何明文。页号绑进 AAD，页被搬到别的偏移会解密失败
	// （防页交换攻击，见 internal/db 的说明）。
	PurposePage LocalDataPurpose = "db-page"

	// PurposeAttachmentBlob 是附件正文的一个加密块。
	//
	// 附件按块加密，绑定 blobID 与块号：块与块之间不能互换，
	// 一个会话的附件块也不能被搬到另一个附件下面。
	PurposeAttachmentBlob LocalDataPurpose = "attachment-blob"

	// PurposeBackup 是整个导出备份包。
	//
	// 备份用**导出口令**派生的独立 KEK 加密，不是主密钥 MK：
	// 备份要能交给别人保管，那把钥匙不该等于本机的解密能力。
	PurposeBackup LocalDataPurpose = "backup-package"
)

func purposeAAD(p LocalDataPurpose) []byte {
	return []byte("keytalk/v1/local/" + string(p))
}

// bindingAAD 把用途与额外绑定信息合成 AAD。
//
// 用 0x00 分隔而不是直接拼接：否则 ("ab","c") 与 ("a","bc")
// 会得到同一个 AAD，绑定就不再是单射，跨用途/跨会话的搬运
// 又变得可能了。
func bindingAAD(p LocalDataPurpose, binding []byte) []byte {
	base := purposeAAD(p)
	if len(binding) == 0 {
		return base
	}
	out := make([]byte, 0, len(base)+1+len(binding))
	out = append(out, base...)
	out = append(out, 0x00)
	out = append(out, binding...)
	return out
}

// EncryptLocal 用 MK 加密本地数据。
func EncryptLocal(mk []byte, purpose LocalDataPurpose, plaintext []byte) (nonce, ciphertext []byte, err error) {
	return EncryptLocalBound(mk, purpose, nil, plaintext)
}

// EncryptLocalBound 与 EncryptLocal 相同，但把 binding 并入 AAD。
//
// 用途标签只能说明"这是什么类型的数据"，说不了"这是谁的数据"。
// 消息正文加上 binding（会话指纹 + 方向 + 消息 ID）之后，
// 把 A 会话的密文搬到 B 会话的文件里会**解密失败**，
// 而不是安静地显示成 B 说过的话。磁盘可被翻看的场景下，
// 这个区别就是"篡改能否被察觉"。
func EncryptLocalBound(mk []byte, purpose LocalDataPurpose, binding, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = randomBytes(NonceLen)
	ciphertext, err = Seal(mk, nonce, plaintext, bindingAAD(purpose, binding))
	if err != nil {
		return nil, nil, err
	}
	return nonce, ciphertext, nil
}

// DecryptLocal 用 MK 解密本地数据。
func DecryptLocal(mk []byte, purpose LocalDataPurpose, nonce, ciphertext []byte) ([]byte, error) {
	return DecryptLocalBound(mk, purpose, nil, nonce, ciphertext)
}

// DecryptLocalBound 是 EncryptLocalBound 的逆操作。
//
// binding 必须与加密时**逐字节相同**，否则返回错误。
func DecryptLocalBound(mk []byte, purpose LocalDataPurpose, binding, nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != NonceLen {
		return nil, fmt.Errorf("%w: nonce len %d", ErrMalformed, len(nonce))
	}
	return Open(mk, nonce, ciphertext, bindingAAD(purpose, binding))
}

// Zero 覆写一段敏感内存。
//
// 导出它是因为 MK 现在要穿过包边界交给储存层：
// 交出密钥的生命周期，就必须同时交出擦除它的手段。
//
// ⚠️ 这是尽力而为：Go 可能已经复制过这段内存（栈增长、GC 移动）。
// 它能缩短密钥的暴露窗口，不能保证它从未被复制。
func Zero(b []byte) { zero(b) }

// --- 帧计数器的持久化编解码（用于 DB 存储 BLOB） ---

// EncodeU64 把 uint64 编码为 8 字节大端。
func EncodeU64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
