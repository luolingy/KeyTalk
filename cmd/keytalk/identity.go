package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/exeliang/keytalk/internal/crypto"
)

// identityFile 是持久化的身份信息。
//
// ⚠️ 安全说明：当前版本把私钥以**明文**存盘。
//
// 这是有意的阶段性简化，**不是**最终形态：
// docs/crypto-protocol.md §10.2 设计的方案是
// passphrase → argon2id → KEK → 解开 MK，再解密身份私钥。
// internal/crypto/keystore.go 已经实现了这套机制，
// 但接通它需要一个交互式口令输入界面（UI 阶段的工作）。
//
// 在接通之前，这里会明确打印警告，绝不假装已经加密。
type identityFile struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	// PrivateKey 是 armored 私钥（**明文**，见上方警告）。
	PrivateKey string `json:"private_key"`
	// PublicKey 是 armored 公钥（可安全分发）。
	PublicKey string `json:"public_key"`
}

// loadOrCreateIdentity 载入已有身份，或生成新的。
func loadOrCreateIdentity(dir, name string, logf func(string, ...any)) (*crypto.PGPProvider, bool, error) {
	path := filepath.Join(dir, "identity.json")

	if data, err := os.ReadFile(path); err == nil {
		var idf identityFile
		if err := json.Unmarshal(data, &idf); err != nil {
			return nil, false, fmt.Errorf("解析 %s: %w", path, err)
		}
		prov, err := crypto.ImportPGPIdentity(idf.PrivateKey)
		if err != nil {
			return nil, false, fmt.Errorf("导入私钥: %w", err)
		}
		return prov, false, nil
	} else if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("读取 %s: %w", path, err)
	}

	// 生成新身份。
	logf("生成新的 OpenPGP 身份…")
	prov, err := crypto.GeneratePGPIdentity(crypto.PGPConfig{
		Name:  name,
		Email: name + "@keytalk.local",
		// 2048 位：在兼容性与生成速度之间取平衡。
		// x/crypto/openpgp 仅支持 RSA（见 crypto-protocol.md §10.4.1），
		// 生产版应换 ProtonMail/go-crypto 以使用 Ed25519。
		RSABits: 2048,
	})
	if err != nil {
		return nil, false, fmt.Errorf("生成身份: %w", err)
	}

	priv, err := prov.ExportPrivateKey()
	if err != nil {
		return nil, false, fmt.Errorf("导出私钥: %w", err)
	}

	idf := identityFile{
		Version:     1,
		Name:        name,
		Fingerprint: prov.Fingerprint().String(),
		PrivateKey:  priv,
		PublicKey:   string(prov.PublicKey()),
	}
	data, err := json.MarshalIndent(idf, "", "  ")
	if err != nil {
		return nil, false, err
	}
	// 0600：仅属主可读写。私钥文件权限不能放宽。
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, false, fmt.Errorf("写入 %s: %w", path, err)
	}

	// 单独导出公钥，方便发给对方。
	pubPath := filepath.Join(dir, "public.key")
	if err := os.WriteFile(pubPath, []byte(idf.PublicKey), 0o644); err != nil {
		return nil, false, fmt.Errorf("写入 %s: %w", pubPath, err)
	}

	fmt.Fprintf(os.Stderr, "\n⚠  私钥以明文存储在 %s\n", path)
	fmt.Fprintf(os.Stderr, "   这是当前的阶段性简化。请勿在不受信任的机器上使用真实身份。\n")
	fmt.Fprintf(os.Stderr, "   计划中的加密存储（argon2id 口令保护）尚未接通。\n\n")

	return prov, true, nil
}

// contact 是一个已验证的联系人。
type contact struct {
	name string
	fp   crypto.Fingerprint
	pub  []byte
}

// contactsFile 是持久化的联系人列表。
type contactsFile struct {
	Version  int           `json:"version"`
	Contacts []contactJSON `json:"contacts"`
}

type contactJSON struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	// Verified 表示用户已通过带外渠道确认过该指纹。
	//
	// 当前实现**不**提供未验证联系人的使用路径——
	// 未验证的指纹不构成身份，允许它存在会造成 TOFU 的典型失败。
	Verified bool `json:"verified"`
}

// loadContacts 读取联系人列表。
func loadContacts(dir string, logf func(string, ...any)) ([]contact, error) {
	path := filepath.Join(dir, "contacts.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var cf contactsFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}

	var out []contact
	for _, c := range cf.Contacts {
		fp := crypto.Fingerprint(c.Fingerprint)
		if !fp.Valid() {
			logf("跳过指纹非法的联系人 %q", c.Name)
			continue
		}
		out = append(out, contact{
			name: c.Name,
			fp:   fp,
			pub:  []byte(c.PublicKey),
		})
	}
	return out, nil
}

// saveContacts 写入联系人列表。
func saveContacts(dir string, contacts []contact) error {
	cf := contactsFile{Version: 1}
	for _, c := range contacts {
		cf.Contacts = append(cf.Contacts, contactJSON{
			Name:        c.name,
			Fingerprint: c.fp.String(),
			PublicKey:   string(c.pub),
			Verified:    true,
		})
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "contacts.json"), data, 0o600)
}

// importContacts 从公钥文件导入联系人或身份文件。
//
// 支持两种输入：
//   - 裸的公钥文件（armored public key）
//   - 对方目录里的 public.key
//
// 也支持逗号分隔的多个路径。
func importContacts(dir string, existing []contact, paths string, logf func(string, ...any)) ([]contact, error) {
	var added []contact

	for _, p := range strings.Split(paths, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return added, fmt.Errorf("读取 %s: %w", p, err)
		}

		_, fp, err := crypto.ImportPGPPublicKey(data)
		if err != nil {
			return added, fmt.Errorf("解析 %s: %w", p, err)
		}

		// 去重。
		duplicate := false
		for _, c := range existing {
			if c.fp.String() == fp.String() {
				duplicate = true
				break
			}
		}
		for _, c := range added {
			if c.fp.String() == fp.String() {
				duplicate = true
				break
			}
		}
		if duplicate {
			logf("联系人 %s 已存在，跳过", fp.Display())
			continue
		}

		name := deriveName(p, data, fp)
		c := contact{name: name, fp: fp, pub: data}
		added = append(added, c)
		existing = append(existing, c)
	}

	if len(added) > 0 {
		if err := saveContacts(dir, existing); err != nil {
			return added, fmt.Errorf("保存联系人: %w", err)
		}
	}
	return added, nil
}

// deriveName 从路径或公钥内容推断联系人显示名。
func deriveName(path string, data []byte, fp crypto.Fingerprint) string {
	// 若路径在某个目录下的 public.key，用目录名作显示名。
	dir := filepath.Dir(path)
	base := filepath.Base(dir)
	if base != "." && base != "/" && base != "" && base != "keytalk-data" {
		return base
	}
	// 退化为文件名（去掉扩展名）。
	if n := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)); n != "public" && n != "" {
		return n
	}
	// 最后退化为指纹前缀。
	return "peer-" + shortFP(fp.String())
}

// parseIndex 解析序号参数。
func parseIndex(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}

// hexDecode 是一个小工具，用于调试时解码十六进制指纹。
func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(strings.ReplaceAll(s, " ", ""))
}
