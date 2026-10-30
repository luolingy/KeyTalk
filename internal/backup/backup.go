// Package backup 实现身份备份包的导出与导入。
//
// # 备份包里有什么
//
//   - identity.json 的**原始字节**（含加密后的私钥、keystore、指纹）
//   - 联系人列表（公钥、名字、是否已核对）
//   - 一个导出时的元信息（昵称、指纹、导出时间），供导入前展示
//
// 整个包用一个 JSON 包成一层，再用**导出口令**派生的 KEK 加密。
//
// # 为什么用导出口令而不是主密钥 MK
//
// MK 解开就等于本机的解密能力，而备份文件的本意是"可以放在
// U 盘里、可以交给未来的自己"。如果备份用 MK 加密，那么任何
// 拿到备份文件 + 知道登录口令的人，等于拿到了全部历史。
// 独立的口令把"恢复身份"和"解密本机历史"两件事分开：
// 导入后仍需要登录口令才能打开新库（新库的 MK 是新的）。
//
// # 为什么直接搬 identity.json 的原始字节
//
// 备份不该理解身份的字段。一旦它开始挑字段，crypto 的格式
// 每变一次，备份就要跟着变一次，而漏掉一个字段就是"备份恢复
// 后身份不能用"。搬运原始字节，格式由 crypto 自己负责。
package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
)

// FormatVersion 是备份包的格式版本。
const FormatVersion = 1

// Envelope 是备份包的明文内容。
type Envelope struct {
	Version int `json:"version"`

	// ExportedAt 是导出时间（Unix 毫秒）。
	ExportedAt int64 `json:"exported_at"`
	// Name 是本机昵称，导入前展示用。
	Name string `json:"name"`
	// Fingerprint 是身份指纹，导入前用于确认"这是不是我要的那份"。
	Fingerprint string `json:"fingerprint"`

	// IdentityJSON 是 identity.json 的原始字节。
	IdentityJSON []byte `json:"identity_json"`
	// Contacts 是通讯录。
	Contacts []Contact `json:"contacts"`
}

// Contact 是备份里的一个联系人。
type Contact struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Verified    bool   `json:"verified"`
}

// fileHeader 是备份文件的明文头。
//
// 头是明文的，因为导入时**在解密之前**就要知道用哪个 KDF 参数、
// 哪个盐——否则无法派生 KEK。头里只有盐和参数，不含任何秘密。
type fileHeader struct {
	Magic       string `json:"magic"`
	Version     int    `json:"version"`
	KDF         string `json:"kdf"`
	Salt        []byte `json:"salt"`
	TimeCost    uint32 `json:"time_cost"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
	Nonce       []byte `json:"nonce"`
}

const magic = "KTALBAK1"

// 错误。
var (
	// ErrNotABackup 表示文件不是本包的备份格式。
	ErrNotABackup = errors.New("backup: not a KeyTalk backup file")
	// ErrWrongPassphrase 表示导出口令不对（AEAD 校验失败）。
	//
	// 口令错与文件损坏在这个包里无法区分：两者都表现为
	// AEAD 校验失败。对用户而言"口令错"是更可能的原因，
	// 因此这样命名，错误信息里会同时提到两种可能。
	ErrWrongPassphrase = errors.New("backup: wrong export passphrase (or the file is damaged)")
	// ErrExists 表示目标目录已有身份，而调用方没有允许覆盖。
	ErrExists = errors.New("backup: an identity already exists in the destination")
)

// Export 把 dir 下的身份与联系人导出到 path，用 passphrase 加密。
//
// 已存在的文件**不会**被覆盖（O_EXCL）：备份是用户的救命文件，
// 静默覆盖一个旧备份可能是灾难。
func Export(dir, path string, contacts []Contact, passphrase string) error {
	if len(passphrase) < 8 {
		return fmt.Errorf("backup: export passphrase must be at least 8 characters")
	}

	identityJSON, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return fmt.Errorf("backup: reading identity.json: %w", err)
	}

	// 读指纹与昵称用于元信息。读不到不致命，只是展示层少点东西。
	meta, _ := crypto.NewIdentityStore(dir).LoadMeta()

	env := Envelope{
		Version:      FormatVersion,
		ExportedAt:   time.Now().UnixMilli(),
		IdentityJSON: identityJSON,
		Contacts:     contacts,
	}
	if meta != nil {
		env.Name = meta.Name
		env.Fingerprint = meta.Fingerprint.String()
	}

	plain, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("backup: marshalling envelope: %w", err)
	}

	// 用导出口令派生 KEK。argon2 参数与 salt 取项目统一值
	// （DefaultArgonParams 已带随机 salt）。
	params := crypto.DefaultArgonParams()
	kek := params.DeriveKEK([]byte(passphrase))
	defer crypto.Zero(kek)

	nonce, ct, err := crypto.EncryptLocal(kek, crypto.PurposeBackup, plain)
	if err != nil {
		return fmt.Errorf("backup: encrypting envelope: %w", err)
	}

	hdr := fileHeader{
		Magic:       magic,
		Version:     FormatVersion,
		KDF:         "argon2id",
		Salt:        params.Salt,
		TimeCost:    params.Time,
		MemoryKiB:   params.Memory,
		Parallelism: params.Threads,
		Nonce:       nonce,
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return err
	}

	// 文件结构：4 字节头长度 || 头 JSON || 密文。
	// 头长度固定字段让读取方不必猜边界。
	out := make([]byte, 0, 4+len(hdrJSON)+len(ct))
	out = appendU32(out, uint32(len(hdrJSON)))
	out = append(out, hdrJSON...)
	out = append(out, ct...)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("backup: creating %s: %w", path, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(out); err != nil {
		return fmt.Errorf("backup: writing %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("backup: syncing: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("backup: closing: %w", err)
	}
	committed = true
	return nil
}

// Inspect 读取备份包的明文元信息（不需要口令）。
//
// 用于导入前给用户看"这是谁的备份、什么时候导出的"，
// 好让用户确认自己选对了文件。
func Inspect(path string) (Envelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Envelope{}, fmt.Errorf("backup: reading %s: %w", path, err)
	}
	hdr, _, err := splitFile(raw)
	if err != nil {
		return Envelope{}, err
	}
	// 头里不带头用户信息；要拿到昵称必须解密。所以 Inspect
	// 只能给出格式层面的信息。昵称在 Decrypt 之后才有。
	return Envelope{Version: hdr.Version}, nil
}

// Import 用 passphrase 解开 path 的备份，并写入 dir。
//
// overwrite 为 false 且 dir 里已有身份时返回 ErrExists，
// 不静默覆盖——覆盖一个能用的身份意味着用户可能永久失去它。
func Import(path, dir, passphrase string, overwrite bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("backup: reading %s: %w", path, err)
	}
	hdr, ct, err := splitFile(raw)
	if err != nil {
		return err
	}

	params := crypto.ArgonParams{
		Time:    hdr.TimeCost,
		Memory:  hdr.MemoryKiB,
		Threads: hdr.Parallelism,
		Salt:    hdr.Salt,
	}
	kek := params.DeriveKEK([]byte(passphrase))
	defer crypto.Zero(kek)

	plain, err := crypto.DecryptLocal(kek, crypto.PurposeBackup, hdr.Nonce, ct)
	if err != nil {
		// AEAD 失败在本包里几乎总是"口令错"。
		return ErrWrongPassphrase
	}

	var env Envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return fmt.Errorf("backup: parsing envelope: %w", err)
	}
	if env.Version > FormatVersion {
		return fmt.Errorf("backup: package version %d is newer than this build (%d)",
			env.Version, FormatVersion)
	}
	if len(env.IdentityJSON) == 0 {
		return fmt.Errorf("backup: package contains no identity")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("backup: creating %s: %w", dir, err)
	}
	idPath := filepath.Join(dir, "identity.json")
	if !overwrite {
		if _, err := os.Stat(idPath); err == nil {
			return ErrExists
		}
	}

	// 先写身份，再让 crypto 校验它能读。
	//
	// 顺序很重要：如果先写联系人、身份却坏了，会留下一个
	// "有通讯录但没有身份"的半残目录。身份是根，先把它立住。
	if err := writeFileAtomic(idPath, env.IdentityJSON, 0o600); err != nil {
		return fmt.Errorf("backup: writing identity: %w", err)
	}
	// 立刻按 crypto 的规则读一遍：解不开就说明备份内容坏了，
	// 删掉刚写的文件并报错，而不是留一个打不开的身份。
	if _, err := crypto.NewIdentityStore(dir).LoadMeta(); err != nil {
		_ = os.Remove(idPath)
		return fmt.Errorf("backup: the restored identity is not readable: %w", err)
	}

	return nil
}

// DecodeEnvelope 解开备份并返回明文内容（不写盘）。
//
// 供导入界面在写入前展示"将恢复哪个身份、几个联系人"。
func DecodeEnvelope(path, passphrase string) (Envelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Envelope{}, fmt.Errorf("backup: reading %s: %w", path, err)
	}
	hdr, ct, err := splitFile(raw)
	if err != nil {
		return Envelope{}, err
	}
	params := crypto.ArgonParams{Time: hdr.TimeCost, Memory: hdr.MemoryKiB, Threads: hdr.Parallelism, Salt: hdr.Salt}
	kek := params.DeriveKEK([]byte(passphrase))
	defer crypto.Zero(kek)

	plain, err := crypto.DecryptLocal(kek, crypto.PurposeBackup, hdr.Nonce, ct)
	if err != nil {
		return Envelope{}, ErrWrongPassphrase
	}
	var env Envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return Envelope{}, fmt.Errorf("backup: parsing envelope: %w", err)
	}
	return env, nil
}

// splitFile 解析备份文件为头与密文。
func splitFile(raw []byte) (fileHeader, []byte, error) {
	var hdr fileHeader
	if len(raw) < 4 {
		return hdr, nil, ErrNotABackup
	}
	n := int(uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3]))
	if n <= 0 || 4+n > len(raw) {
		return hdr, nil, ErrNotABackup
	}
	if err := json.Unmarshal(raw[4:4+n], &hdr); err != nil {
		return hdr, nil, ErrNotABackup
	}
	if hdr.Magic != magic {
		return hdr, nil, ErrNotABackup
	}
	if hdr.KDF != "argon2id" {
		return hdr, nil, fmt.Errorf("backup: unsupported KDF %q", hdr.KDF)
	}
	return hdr, raw[4+n:], nil
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// writeFileAtomic 原子写文件。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
