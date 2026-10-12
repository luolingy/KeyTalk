package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/exeliang/keytalk/internal/crypto"
)

// Setup 是"App 之前"的那一段生命周期：生成身份、导入身份、解锁。
//
// # 为什么需要单独一个类型
//
// core.New 要求已经有一份可用身份，而身份从现在起可以由用户在
// 界面里创建。于是启动顺序变成：
//
//	还没有身份 ──▶ 问用户（生成 / 导入 / 解锁）──▶ 有身份了 ──▶ 组装 App
//
// 前两步不属于 App 的职责（App 是"已经有身份之后"的状态机），
// 所以单独成类，而不是把 App 改造成"身份可为空"。
// 那样会让 app.go 里每一处 Identity 的使用都要判空。
//
// # 线程安全
//
// 生成 RSA 密钥要几百毫秒，必须放到后台 goroutine，
// 否则界面会卡住一帧。因此这里全部加锁。
type Setup struct {
	mu  sync.Mutex
	cfg SetupConfig

	store    *crypto.IdentityStore
	stage    SetupStage
	meta     *crypto.IdentityMeta
	identity *crypto.PGPProvider
	name     string
	contacts []ContactConfig
	app      *App
}

// SetupStage 描述配置阶段的进度。
type SetupStage int

const (
	// StageNeedsIdentity：数据目录里还没有身份。
	StageNeedsIdentity SetupStage = iota
	// StageNeedsUnlock：身份存在且受口令保护，等待解锁。
	StageNeedsUnlock
	// StageReady：身份可用，可以组装 App 了。
	StageReady
)

// PersistFunc 把联系人列表写回磁盘。
//
// core 不自己决定存到哪里：目录是 cmd 的事。
type PersistFunc func([]ContactConfig) error

// SetupConfig 是配置阶段所需的一切。
type SetupConfig struct {
	// DataDir 是身份与联系人的存放目录（必填）。
	DataDir string

	// BuildApp 在身份就绪后被调用一次，用来组装真正的 App。
	//
	// 做成回调而不是让 core 自己建传输层：core 只认
	// transport.Transport 接口，不该知道 mDNS 与 TCP 端口
	// （见 docs/architecture.md §1.1）。
	BuildApp func(identity crypto.IdentityProvider, contacts []ContactConfig,
		persist PersistFunc) (*App, error)

	Logf func(string, ...any)
}

// NewSetup 打开（或初始化）一个数据目录的配置阶段。
func NewSetup(cfg SetupConfig) (*Setup, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("core: SetupConfig.DataDir is required")
	}
	if cfg.BuildApp == nil {
		return nil, errors.New("core: SetupConfig.BuildApp is required")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}

	s := &Setup{cfg: cfg, store: crypto.NewIdentityStore(cfg.DataDir)}
	if err := s.loadContacts(); err != nil {
		return nil, err
	}
	if err := s.refresh(); err != nil {
		return nil, err
	}
	return s, nil
}

// refresh 重新判断当前处于哪个阶段。
func (s *Setup) refresh() error {
	meta, err := s.store.LoadMeta()
	switch {
	case errors.Is(err, crypto.ErrNoIdentity):
		s.stage = StageNeedsIdentity
		s.meta = nil
		return nil
	case err != nil:
		return err
	}

	s.meta = meta
	s.name = meta.Name

	if meta.Encrypted {
		s.stage = StageNeedsUnlock
		return nil
	}

	// v1 明文身份：没有东西可解，直接取出。
	// 仍然进入 Ready——拒绝启动等于惩罚老用户。
	prov, err := s.store.Unlock("")
	if err != nil {
		return fmt.Errorf("载入明文身份: %w", err)
	}
	s.identity = prov
	s.stage = StageReady
	return nil
}

// Stage 返回当前阶段。
func (s *Setup) Stage() SetupStage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stage
}

// Ready 报告身份是否可用。
func (s *Setup) Ready() bool { return s.Stage() == StageReady }

// Meta 返回解锁前可读的身份信息（没有身份时为 nil）。
func (s *Setup) Meta() *crypto.IdentityMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta
}

// DataDir 返回数据目录。
func (s *Setup) DataDir() string { return s.cfg.DataDir }

// Store 暴露底层身份存储，供界面读取公钥等只读信息。
func (s *Setup) Store() *crypto.IdentityStore { return s.store }

// Contacts 返回已导入的联系人。
func (s *Setup) Contacts() []ContactConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ContactConfig(nil), s.contacts...)
}

// IdentityName 返回当前身份显示名。
func (s *Setup) IdentityName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name
}

// Fingerprint 返回当前身份的指纹。
//
// 身份尚未就绪时返回空指纹（Valid() 为 false），
// 这样界面可以在任何阶段安全调用而不必先判阶段。
func (s *Setup) Fingerprint() crypto.Fingerprint {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identity == nil {
		return ""
	}
	return s.identity.Fingerprint()
}

// CreateIdentity 生成新身份并加密保存。
//
// ⚠️ 会阻塞数百毫秒（RSA 2048 生成）。调用方应在后台 goroutine 里跑。
func (s *Setup) CreateIdentity(name, passphrase string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("显示名不能为空")
	}
	if len(passphrase) < minPassphraseLen {
		return fmt.Errorf("口令至少需要 %d 个字符", minPassphraseLen)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	prov, err := s.store.Create(name, passphrase)
	if err != nil {
		return err
	}
	s.identity = prov
	s.name = name
	s.stage = StageReady
	s.cfg.Logf("setup: identity created for %q (%s)", name, prov.Fingerprint().Display())
	return nil
}

// minPassphraseLen 是最短口令长度。
//
// 12 是折中：argon2id 只能减缓暴力破解，不能弥补弱口令
// （见 docs/threat-model.md §3 的 A7）。但把门槛定得太高，
// 用户会改去用更差的办法（比如把口令写在便签上）。
const minPassphraseLen = 12

// Unlock 用口令取出已存在的身份。
//
// ⚠️ 会阻塞（argon2id 需要 ~64MiB 内存与数百毫秒）。
func (s *Setup) Unlock(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	prov, err := s.store.Unlock(passphrase)
	if err != nil {
		return err
	}
	s.identity = prov
	s.stage = StageReady
	s.cfg.Logf("setup: identity unlocked (%s)", prov.Fingerprint().Display())
	return nil
}

// ImportIdentity 从 armored 私钥恢复身份，并用新口令重新加密。
//
// name 为空时从密钥里取。
func (s *Setup) ImportIdentity(armored, passphrase, name string) error {
	armored = strings.TrimSpace(armored)
	if armored == "" {
		return errors.New("请先粘贴私钥内容")
	}
	if len(passphrase) < minPassphraseLen {
		return fmt.Errorf("口令至少需要 %d 个字符", minPassphraseLen)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	prov, err := s.store.Import(armored, passphrase, strings.TrimSpace(name))
	if err != nil {
		return err
	}
	s.identity = prov
	// 从密钥里回读显示名，避免用户手输错。
	if n := prov.Name(); n != "" {
		s.name = n
	} else {
		s.name = strings.TrimSpace(name)
	}
	s.stage = StageReady
	s.cfg.Logf("setup: identity imported (%s)", prov.Fingerprint().Display())
	return nil
}

// ErrSetupNotReady 表示身份尚未就绪。
var ErrSetupNotReady = errors.New("core: identity is not ready yet")

// App 返回组装好的 App（首次调用时创建）。
//
// ⚠️ 会创建传输层并开始监听，可能耗时数十毫秒。
func (s *Setup) App() (*App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.app != nil {
		return s.app, nil
	}
	if s.stage != StageReady || s.identity == nil {
		return nil, ErrSetupNotReady
	}

	app, err := s.cfg.BuildApp(s.identity, s.contacts, s.saveContactsLocked)
	if err != nil {
		return nil, err
	}
	s.app = app
	return app, nil
}

// AddContact 导入一个联系人公钥并立即持久化。
//
// 返回解析出的联系人信息，供界面显示指纹以做带外核对。
func (s *Setup) AddContact(name, armoredPubKey string) (ContactConfig, error) {
	armoredPubKey = strings.TrimSpace(armoredPubKey)
	if armoredPubKey == "" {
		return ContactConfig{}, errors.New("请先粘贴公钥内容")
	}

	// 只取指纹，实体本身丢掉——联系人表里存的是 armored 文本，
	// 由会话层按需解析。
	_, fp, err := crypto.ImportPGPPublicKey([]byte(armoredPubKey))
	if err != nil {
		return ContactConfig{}, fmt.Errorf("这不是一个有效的公钥（需要 armored 文本）: %w", err)
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return ContactConfig{}, errors.New("请输入联系人名字")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 拒绝重复指纹：同一把密钥以两个名字出现，会让用户
	// 以为安全地加了两个人，实际上只有一个身份。
	for _, c := range s.contacts {
		if c.Fingerprint == fp.String() {
			return c, fmt.Errorf("该公钥已经在联系人里（%s）", c.Name)
		}
	}

	c := ContactConfig{Name: name, Fingerprint: fp.String(), PublicKey: []byte(armoredPubKey)}
	s.contacts = append(s.contacts, c)

	if err := s.saveContactsLocked(s.contacts); err != nil {
		// 回滚：内存里成功了磁盘上没成功，重启后会不一致。
		s.contacts = s.contacts[:len(s.contacts)-1]
		return ContactConfig{}, err
	}
	return c, nil
}

// PersistPublicKeyFile 确保 public.key 存在，返回其路径。
func (s *Setup) PersistPublicKeyFile() (string, error) {
	if !s.Ready() {
		return "", ErrSetupNotReady
	}
	return s.store.PublicKeyPath(), nil
}

// ExportPrivateKey 导出一份加密前的 armored 私钥（备份用）。
func (s *Setup) ExportPrivateKey(passphrase string) (string, error) {
	return s.store.ExportPrivateKey(passphrase)
}

// ExportPublicKey 返回可安全分发的公钥文本。
func (s *Setup) ExportPublicKey() (string, error) {
	return s.store.ExportPublicKey()
}

// Close 释放身份。不关闭 App——那是调用方的事。
func (s *Setup) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identity != nil {
		s.identity.Close()
		s.identity = nil
	}
}

// --- 联系人持久化 ---

// loadContacts 读取 contacts.json（不存在即为空）。
func (s *Setup) loadContacts() error {
	cs, err := LoadContactFile(s.cfg.DataDir, s.cfg.Logf)
	if err != nil {
		return err
	}
	s.contacts = cs
	return nil
}

func (s *Setup) saveContactsLocked(cs []ContactConfig) error {
	return SaveContactFile(s.cfg.DataDir, cs)
}

// contactsFile 是 contacts.json 的磁盘格式。
type contactsFile struct {
	Version  int             `json:"version"`
	Contacts []contactRecord `json:"contacts"`
}

type contactRecord struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	// Verified 表示用户已通过带外渠道确认过该指纹。
	Verified bool `json:"verified"`
}

// LoadContactFile 读取数据目录里的联系人列表。
//
// logf 可为 nil。单条记录损坏时跳过并记录，而不是让整个列表
// 读不出来——但**绝不静默跳过**：联系人凭空消失会让用户
// 以为对方把自己删了，必须留下痕迹。
func LoadContactFile(dir string, logf func(string, ...any)) ([]ContactConfig, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	path := filepath.Join(dir, "contacts.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取 %s: %w", path, err)
	}

	var cf contactsFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}

	out := make([]ContactConfig, 0, len(cf.Contacts))
	for _, c := range cf.Contacts {
		fp, err := crypto.ParseFingerprint(c.Fingerprint)
		if err != nil {
			logf("core: 跳过 %s 里格式非法的联系人 %q: %v", path, c.Name, err)
			continue
		}
		out = append(out, ContactConfig{
			Name:        c.Name,
			Fingerprint: fp.String(),
			PublicKey:   []byte(c.PublicKey),
		})
	}
	return out, nil
}

// SaveContactFile 原子地写回联系人列表。
func SaveContactFile(dir string, cs []ContactConfig) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建数据目录 %s: %w", dir, err)
	}

	cf := contactsFile{Version: 1}
	for _, c := range cs {
		cf.Contacts = append(cf.Contacts, contactRecord{
			Name:        c.Name,
			Fingerprint: c.Fingerprint,
			PublicKey:   string(c.PublicKey),
			// 能进入联系人列表就意味着用户已确认过指纹：
			// 本项目的产品决策是绝不静默信任未核对的身份。
			Verified: true,
		})
	}

	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(dir, "contacts.json")
	tmp, err := os.CreateTemp(dir, ".contacts-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// 公钥不是机密；用 0644 便于用户直接查看与复制。
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
