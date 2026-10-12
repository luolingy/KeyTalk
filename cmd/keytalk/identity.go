package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/exeliang/keytalk/internal/crypto"
)

// loadOrCreateIdentity 载入已有身份，或生成新的（仅供命令行模式）。
//
// # 为什么不再自己读写 identity.json
//
// 磁盘格式由 crypto.IdentityStore 统一负责：命令行与图形界面
// 必须读写**同一种**格式。此前两边各有一套实现，于是出现了
// "图形界面建的 v2 加密身份，命令行读不了"——老代码只认 v1 的
// 明文字段，遇到没有 private_key 的文件就报
// "malformed payload: empty private key"。同一种文件、两套解析，
// 必然迟早分叉。
//
// # 口令从哪来
//
// 命令行模式没有交互式口令输入，因此：
//   - 没有身份：建一份**明文**身份（e2e 脚本依赖这个行为）；
//   - 有明文身份：直接载入；
//   - 有加密身份：只有设置过 KEYTALK_PASSPHRASE 才能解锁。
//
// 口令走环境变量而不是命令行参数：参数会出现在进程列表里，
// 同机器上任何用户都能看到。
func loadOrCreateIdentity(dir, name string, logf func(string, ...any)) (*crypto.PGPProvider, bool, error) {
	store := crypto.NewIdentityStore(dir)

	meta, err := store.LoadMeta()

	if errors.Is(err, crypto.ErrNoIdentity) {
		if strings.TrimSpace(name) == "" {
			name = "keytalk-user"
		}
		prov, err := store.CreateUnencrypted(name)
		if err != nil {
			return nil, false, fmt.Errorf("生成身份: %w", err)
		}
		logf("generated a plaintext identity at %s", store.Path())
		warnPlaintextIdentity(store.Path())
		return prov, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("读取 %s: %w", store.Path(), err)
	}

	pass := os.Getenv(passphraseEnv)
	if meta.Encrypted && pass == "" {
		return nil, false, fmt.Errorf(
			"身份 %s 已用口令加密，而命令行模式无法交互式输入口令。\n"+
				"  请改用图形界面（直接双击 keytalk.exe），\n"+
				"  或先设置环境变量 %s 再重试。",
			store.Path(), passphraseEnv)
	}

	prov, err := store.Unlock(pass)
	if err != nil {
		return nil, false, fmt.Errorf("解锁身份: %w", err)
	}
	if meta.LegacyPlaintext {
		warnPlaintextIdentity(store.Path())
	}
	return prov, false, nil
}

// passphraseEnv 是命令行模式下提供口令的环境变量名。
const passphraseEnv = "KEYTALK_PASSPHRASE"

// warnPlaintextIdentity 明确告知私钥正以明文存放。
//
// 绝不假装已经加密：用户有权知道自己的私钥在磁盘上是什么状态。
func warnPlaintextIdentity(path string) {
	fmt.Fprintf(os.Stderr, "\n⚠ 私钥以明文存放在 %s\n", path)
	fmt.Fprintf(os.Stderr, "   这是命令行模式的过渡行为。双击启动图形界面可设置口令加密。\n\n")
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
