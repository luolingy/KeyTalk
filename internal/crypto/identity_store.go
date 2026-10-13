package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// IdentityStore 管理磁盘上的身份文件（identity.json 与 public.key）。
//
// # 为什么放在 crypto 而不是 core
//
// 这里处理的是**密钥材料在磁盘上的形态**：用什么 KDF、用什么 AEAD、
// AAD 绑定哪些字段、权限位多少。这些判断属于密码学，不属于应用状态。
// core 只管"现在该显示哪个界面"，不该知道私钥是怎么封装的。
//
// # 文件格式
//
// v2（当前写入）：
//
//	{
//	  "version": 2,
//	  "name": "...", "fingerprint": "...", "public_key": "...",
//	  "keystore": { argon2id 参数 + 被 KEK 封装的 MK },
//	  "sealed_private_key": { nonce, ciphertext }   // 用 MK 加密的私钥
//	}
//
// v1（仅读取兼容）：明文字段 "private_key"。
//
// v1 是早期版本的阶段性简化，**永远不会**再被写出来。
// 但必须能读——否则老用户升级后会看不到自己的身份，
// 程序会静默生成一把新密钥，指纹随之改变。
type IdentityStore struct {
	dir string
}

// NewIdentityStore 创建一个指向给定目录的身份存储。
func NewIdentityStore(dir string) *IdentityStore {
	return &IdentityStore{dir: dir}
}

// Dir 返回数据目录。
func (s *IdentityStore) Dir() string { return s.dir }

// Path 返回身份文件路径。
func (s *IdentityStore) Path() string { return filepath.Join(s.dir, "identity.json") }

// PublicKeyPath 返回可分发公钥的路径。
func (s *IdentityStore) PublicKeyPath() string { return filepath.Join(s.dir, "public.key") }

// identityFile 是 identity.json 的磁盘表示。
type identityFile struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`

	// Keystore 仅在启用口令保护时存在。
	Keystore *Keystore `json:"keystore,omitempty"`

	// SealedKey 是用 MK 加密的 armored 私钥。
	SealedKey *sealedBlob `json:"sealed_private_key,omitempty"`

	// PrivateKey 是 v1 的明文私钥。
	//
	// 只用于读取旧文件。写盘时该字段始终为空——
	// 任何"顺手回退到明文"的路径都不存在。
	PrivateKey string `json:"private_key,omitempty"`
}

type sealedBlob struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// IdentityMeta 是不需要口令就能读到的身份信息。
//
// 存在的理由：解锁界面上必须能显示"你正在解锁哪一个身份"，
// 否则用户无法判断自己打开的是不是正确的那份备份。
type IdentityMeta struct {
	Name        string
	Fingerprint Fingerprint
	// Encrypted 表示私钥受口令保护。
	// 为 false 时该身份是 v1 明文格式，无需解锁（但要警告用户）。
	Encrypted bool
	// LegacyPlaintext 表示这是一份 v1 明文身份，应当尽快重建。
	LegacyPlaintext bool
}

// ErrNoIdentity 表示数据目录里还没有身份。
var ErrNoIdentity = errors.New("crypto: no identity in this directory")

// ErrIdentityExists 表示已经存在身份，拒绝覆盖。
//
// 覆盖身份等于让用户的指纹消失，必须由调用方显式处理
// （例如先备份、再删除），不能由本包静默完成。
var ErrIdentityExists = errors.New("crypto: identity already exists")

// LoadMeta 读取身份元信息。
//
// 身份不存在时返回 ErrNoIdentity。
func (s *IdentityStore) LoadMeta() (*IdentityMeta, error) {
	idf, err := s.read()
	if err != nil {
		return nil, err
	}

	fp, err := ParseFingerprint(idf.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("身份文件里的指纹非法: %w", err)
	}

	meta := &IdentityMeta{Name: idf.Name, Fingerprint: fp}
	switch {
	case idf.Keystore != nil && idf.SealedKey != nil:
		meta.Encrypted = true
	case idf.PrivateKey != "":
		// v1：明文私钥。能读，但必须让用户知道。
		meta.LegacyPlaintext = true
	default:
		return nil, fmt.Errorf("%w: no key material", ErrKeystoreFormat)
	}
	return meta, nil
}

// Create 生成新身份，用口令加密后写盘。
//
// passphrase 为空时报错——本方法存在的意义就是加密存储。
// 需要明文身份请用 CreateUnencrypted（仅供测试与过渡）。
func (s *IdentityStore) Create(name, passphrase string) (*PGPProvider, error) {
	if passphrase == "" {
		return nil, errors.New("crypto: passphrase required to create an encrypted identity")
	}
	prov, err := generateIdentity(name)
	if err != nil {
		return nil, err
	}
	if err := s.save(name, prov, passphrase); err != nil {
		return nil, err
	}
	return prov, nil
}

// CreateUnencrypted 生成新身份并以 v1 明文格式写盘。
//
// ⚠️ 仅供自动化测试与命令行过渡使用。它会明确打印警告。
func (s *IdentityStore) CreateUnencrypted(name string) (*PGPProvider, error) {
	prov, err := generateIdentity(name)
	if err != nil {
		return nil, err
	}

	priv, err := prov.ExportPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("导出私钥: %w", err)
	}

	idf := identityFile{
		Version:     1,
		Name:        name,
		Fingerprint: prov.Fingerprint().String(),
		PublicKey:   string(prov.PublicKey()),
		PrivateKey:  priv,
	}
	if err := s.write(idf); err != nil {
		return nil, err
	}
	return prov, nil
}

// Unlock 取出私钥。
//
// 对 v1 明文身份，passphrase 被忽略（无物可解）。
func (s *IdentityStore) Unlock(passphrase string) (*PGPProvider, error) {
	prov, mk, err := s.UnlockWithMK(passphrase)
	if err != nil {
		return nil, err
	}
	// 本函数的调用方拿不到 MK，也就无从擦除，因此在这里就地擦掉。
	Zero(mk)
	return prov, nil
}

// UnlockWithMK 与 Unlock 相同，但同时**交出主密钥 MK**。
//
// # 为什么必须在这里交出去
//
// 本地持久化（消息正文、附件）要用 MK 加密，而这些数据
// 第一次被读写就是在解锁之后。MK 是随机的、不在口令里，
// 除了解锁的那一刻，别处**推导不出来**——所以只能从这里交给调用方。
//
// # 所有权
//
// 返回的 MK 归调用方所有，调用方必须在用完后 Zero 掉它。
// 失败路径上本函数已经擦除，不会泄漏半途产生的 MK。
//
// v1 明文身份没有 keystore，因此返回 (prov, nil, nil)：
// 调用方拿到 nil 就必须自己决定"没有 MK 所以无法加密落盘"
// 是否可接受，而不是当它是一把全零的密钥。
func (s *IdentityStore) UnlockWithMK(passphrase string) (*PGPProvider, []byte, error) {
	idf, err := s.read()
	if err != nil {
		return nil, nil, err
	}

	switch {
	case idf.Keystore != nil && idf.SealedKey != nil:
		mk, err := idf.Keystore.Unlock([]byte(passphrase))
		if err != nil {
			return nil, nil, err // ErrWrongPassphrase
		}

		plain, err := DecryptLocal(mk, PurposeIdentityKey, idf.SealedKey.Nonce, idf.SealedKey.Ciphertext)
		if err != nil {
			// MK 解出来了却打不开私钥，说明文件被改过。
			Zero(mk)
			return nil, nil, fmt.Errorf("%w: sealed private key failed to open", ErrKeystoreFormat)
		}
		defer zero(plain)

		prov, err := ImportPGPIdentity(string(plain))
		if err != nil {
			Zero(mk)
			return nil, nil, err
		}
		return prov, mk, nil

	case idf.PrivateKey != "":
		prov, err := ImportPGPIdentity(idf.PrivateKey)
		if err != nil {
			return nil, nil, err
		}
		return prov, nil, nil

	default:
		return nil, nil, fmt.Errorf("%w: no key material", ErrKeystoreFormat)
	}
}

// Import 从 armored 私钥导入身份，并用**新口令**重新加密保存。
//
// 这是"换机器 / 从备份恢复"的入口。
// 导入的私钥可以是明文的，也可以是旧格式；
// 落盘时一律重新封装为新口令保护的 v2。
func (s *IdentityStore) Import(armored, passphrase string, name string) (*PGPProvider, error) {
	if passphrase == "" {
		return nil, errors.New("crypto: passphrase required to import an identity")
	}
	prov, err := ImportPGPIdentity(armored)
	if err != nil {
		return nil, fmt.Errorf("导入私钥失败（内容是否为 armored 私钥？）: %w", err)
	}
	if name == "" {
		name = deriveNameFromProvider(prov)
	}
	if err := s.save(name, prov, passphrase); err != nil {
		return nil, err
	}
	return prov, nil
}

// ExportPrivateKey 导出 armored 私钥，用于备份或迁移。
//
// 必须先通过口令验证：一个能导出私钥的按钮不应该在
// 解锁后的会话里无条件可用。
func (s *IdentityStore) ExportPrivateKey(passphrase string) (string, error) {
	idf, err := s.read()
	if err != nil {
		return "", err
	}

	// 先确认口令正确，再导出。
	if idf.Keystore != nil && idf.SealedKey != nil {
		if _, err := idf.Keystore.Unlock([]byte(passphrase)); err != nil {
			return "", err
		}
	}

	prov, err := s.Unlock(passphrase)
	if err != nil {
		return "", err
	}
	defer prov.Close()

	return prov.ExportPrivateKey()
}

// ExportPublicKey 读回可安全分发的公钥文本。
func (s *IdentityStore) ExportPublicKey() (string, error) {
	idf, err := s.read()
	if err != nil {
		return "", err
	}
	return idf.PublicKey, nil
}

// --- 内部 ---

func (s *IdentityStore) read() (*identityFile, error) {
	data, err := os.ReadFile(s.Path())
	if os.IsNotExist(err) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("读取 %s: %w", s.Path(), err)
	}

	var idf identityFile
	if err := json.Unmarshal(data, &idf); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", s.Path(), err)
	}
	if idf.Version < 1 || idf.Version > 2 {
		return nil, fmt.Errorf("身份文件版本 %d 不受支持", idf.Version)
	}

	// 交叉校验：外层指纹必须与 keystore 内部的完全一致。
	//
	// 两个字段都叫"指纹"但用途不同——外层用于在解锁前展示
	// "你正在解锁哪一个身份"，内层参与 AAD 从而受完整性保护。
	// 若不做这一致性检查，攻击者只需改外层那一个字段，
	// 就能让解锁界面显示成另一个身份（身份混淆），
	// 而内层密钥其实毫发无损、解锁照样成功。
	if idf.Keystore != nil && idf.Fingerprint != idf.Keystore.Fingerprint {
		return nil, fmt.Errorf("%w: outer fingerprint does not match the "+
			"keystore's copy (identity confusion attempt?)", ErrKeystoreFormat)
	}
	return &idf, nil
}

// save 用口令加密私钥后写盘（v2）。
func (s *IdentityStore) save(name string, prov *PGPProvider, passphrase string) error {
	priv, err := prov.ExportPrivateKey()
	if err != nil {
		return fmt.Errorf("导出私钥: %w", err)
	}

	fp := prov.Fingerprint()
	ks, mk, err := NewKeystore([]byte(passphrase), fp, prov.PublicKey(), time.Now().UnixMilli())
	if err != nil {
		return err
	}
	defer zero(mk)

	nonce, ct, err := EncryptLocal(mk, PurposeIdentityKey, []byte(priv))
	if err != nil {
		return err
	}

	idf := identityFile{
		Version:     2,
		Name:        name,
		Fingerprint: fp.String(),
		PublicKey:   string(prov.PublicKey()),
		Keystore:    ks,
		SealedKey:   &sealedBlob{Nonce: nonce, Ciphertext: ct},
		// PrivateKey 故意留空：绝不写明文。
	}
	return s.write(idf)
}

func (s *IdentityStore) write(idf identityFile) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("创建数据目录 %s: %w", s.dir, err)
	}

	data, err := json.MarshalIndent(idf, "", "  ")
	if err != nil {
		return err
	}
	// 0600：身份文件只允许属主读写。
	if err := writeFileAtomic(s.Path(), data, 0o600); err != nil {
		return err
	}

	// 公钥单独存一份，方便直接发给对方。
	if err := writeFileAtomic(s.PublicKeyPath(), []byte(idf.PublicKey), 0o644); err != nil {
		return err
	}
	return nil
}

// writeFileAtomic 先写临时文件再改名。
//
// 直接覆盖写有真实风险：写到一半崩溃会留下一个残缺的
// identity.json，用户的身份就此损坏。改名是原子的。
//
// ⚠️ perm 在 Windows 上只影响"只读"属性——NTFS 没有 POSIX 权限位，
// Chmod(0600) 的实际效果是"不设为只读"。那里的机密性保护来自
// 用户配置目录继承的 ACL，而不是这个参数。不要因为在 Windows 上
// 看到 Mode().Perm() 返回 0666 就以为文件是公开可读的；
// 反过来，也不要在 Unix 上省掉这个参数。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// 成功改名后这个文件已不存在，Remove 会返回错误，忽略即可。
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// generateIdentity 生成一把新的 OpenPGP 身份。
func generateIdentity(name string) (*PGPProvider, error) {
	return GeneratePGPIdentity(PGPConfig{
		Name:  name,
		Email: name + "@keytalk.local",
		// 2048 位：兼容性与生成速度的折中。
		// x/crypto/openpgp 只支持 RSA（见 docs/crypto-protocol.md §10.4.1），
		// 生产版应换 ProtonMail/go-crypto 以使用 Ed25519。
		RSABits: 2048,
	})
}

// deriveNameFromProvider 尽力从密钥里取出用户名。
func deriveNameFromProvider(prov *PGPProvider) string {
	if n := prov.Name(); n != "" {
		return n
	}
	return "keytalk-user"
}
