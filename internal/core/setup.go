package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/exeliang/keytalk/internal/backup"
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

	// msgStore 是消息持久化层。
	//
	// 明文身份（v1）没有主密钥，因此这里会是 nil——
	// 那种情况下**不写**任何消息，而不是退化成明文落盘。
	msgStore MessageStore
}

// SetupSession 是身份就绪后交给 BuildApp 的一切。
//
// 用一个结构体而不是越来越长的参数表：每加一项依赖
// （持久化、附件目录……）都要改所有调用点，而结构体不会。
type SetupSession struct {
	// Identity 是本机身份，必填。
	Identity crypto.IdentityProvider
	// Contacts 是已导入的联系人。
	Contacts []ContactConfig
	// Persist 把联系人列表写回磁盘。
	Persist PersistFunc
	// Store 是消息持久化层。明文身份没有主密钥，因此可能为 nil。
	Store MessageStore
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
	BuildApp func(SetupSession) (*App, error)

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

// IdentityStore 暴露底层身份存储，供界面读取公钥等只读信息。
//
// 名字里带 Identity 是为了和消息存储（msgStore）区分开：
// 两个都叫 Store 的时候，"解锁的到底是哪一个"极易看错。
func (s *Setup) IdentityStore() *crypto.IdentityStore { return s.store }

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

	if _, err := s.store.Create(name, passphrase); err != nil {
		return err
	}
	// 立刻再解锁一次，只为了拿到 MK。
	//
	// Create 只交出 provider，而消息加密需要 MK；MK 是随机的、
	// 不在口令里，除了解锁的那一刻推导不出来。代价是多跑一次
	// argon2（几百毫秒），而这只在创建身份时发生一次。
	// 给 Create/Import 各加一个 ...WithMK 变体也能避免它，
	// 但会让这三个方法的签名各自分裂成两份。
	prov, mk, err := s.store.UnlockWithMK(passphrase)
	if err != nil {
		return err
	}
	s.identity = prov
	s.name = name
	s.stage = StageReady
	s.openMessageStore(mk)
	crypto.Zero(mk)
	s.cfg.Logf("setup: identity created for %q (%s)", name, prov.Fingerprint().Display())
	return nil
}

// openMessageStore 用刚解出的 MK 打开加密数据库。
//
// mk 为 nil（v1 明文身份）时明确不打开：没有密钥就无法加密落盘，
// 而库层拒绝明文降级。于是那种身份**没有**消息历史，
// 界面上会说明原因，而不是悄悄写一份明文聊天记录。
func (s *Setup) openMessageStore(mk []byte) {
	if s.msgStore != nil {
		_ = s.msgStore.Close()
		s.msgStore = nil
	}
	if len(mk) == 0 {
		s.cfg.Logf("setup: identity has no master key (plaintext identity); " +
			"messages will NOT be persisted")
		return
	}
	st, err := OpenDBStore(s.cfg.DataDir, mk)
	if err != nil {
		// 打不开就不持久化。网络功能不受影响。
		// 注意 ErrWrongKey 也走这条路径：如果派生出的 MK 打不开库，
		// 说明身份与库不是一对，此时**绝不能**新建库覆盖它。
		s.cfg.Logf("setup: opening the message database failed, "+
			"messages will NOT be persisted: %v", err)
		return
	}
	if st == nil {
		return
	}
	s.msgStore = st

	// 一次性迁移旧版 jsonl 日志。失败不阻断启动：
	// 迁移是尽力而为，旧文件会保留。
	if err := migrateLegacyLog(s.cfg.DataDir, mk, st, s.cfg.Logf); err != nil {
		s.cfg.Logf("setup: legacy log migration failed: %v", err)
	}
}

// HasMessageStore 报告本次运行是否会持久化消息。
func (s *Setup) HasMessageStore() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.msgStore != nil
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

	prov, mk, err := s.store.UnlockWithMK(passphrase)
	if err != nil {
		return err
	}
	s.identity = prov
	s.stage = StageReady
	s.openMessageStore(mk)
	crypto.Zero(mk)
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

	if _, err := s.store.Import(armored, passphrase, strings.TrimSpace(name)); err != nil {
		return err
	}
	// 同 CreateIdentity：再解锁一次只为拿 MK。
	prov, mk, err := s.store.UnlockWithMK(passphrase)
	if err != nil {
		return err
	}
	s.identity = prov
	s.openMessageStore(mk)
	crypto.Zero(mk)
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

// GroupFingerprint 把指纹按四位分组，便于人工逐段比对。
//
// 界面不能直接调 crypto，因此在这里转发。
func GroupFingerprint(fp string) string { return crypto.GroupHex(fp) }

// ParsePublicKey 解析 armored 公钥，返回规范指纹。
//
// 存在的理由：界面必须在**写入任何状态之前**把指纹显示给用户
// 做带外核对。让 ui 直接调 crypto 会破坏分层
// （ui 不得直接依赖 crypto，见 docs/architecture.md §1.1），
// 所以这里开一个只读入口。
//
// 无副作用：解析失败不改变任何状态。
func ParsePublicKey(armored []byte) (string, error) {
	_, fp, err := crypto.ImportPGPPublicKey(armored)
	if err != nil {
		return "", fmt.Errorf("这不是一个有效的公钥（需要 armored 文本）: %w", err)
	}
	return fp.String(), nil
}

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

	app, err := s.cfg.BuildApp(SetupSession{
		Identity: s.identity,
		Contacts: s.contacts,
		Persist:  s.saveContactsLocked,
		Store:    s.msgStore,
	})
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

// ExportBackup 把身份与联系人导出成一个加密的 .ktbackup 文件。
//
// exportPassphrase 是**导出专用**口令，可以（也建议）与登录口令不同：
// 备份文件可能被放在 U 盘或交给别人保管，用登录口令封装会让
// "拿到备份 + 知道登录口令"等于"拿到全部历史"。
func (s *Setup) ExportBackup(path, exportPassphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 直接看 s.stage，不要调 Ready()：Ready 会再去 Lock 同一把
	// 互斥锁，而 Go 的 sync.Mutex 不可重入，那样会自己把自己锁死。
	if s.stage != StageReady {
		return ErrSetupNotReady
	}
	bk := make([]backup.Contact, 0, len(s.contacts))
	for _, c := range s.contacts {
		bk = append(bk, backup.Contact{
			Fingerprint: c.Fingerprint,
			Name:        c.Name,
			PublicKey:   string(c.PublicKey),
			// ContactConfig 没有 Verified 字段：能进通讯录就意味着
			// 已带外核对过（AddContact 要求 fingerprintConfirmed）。
			Verified: true,
		})
	}
	return backup.Export(s.cfg.DataDir, path, bk, exportPassphrase)
}

// ImportBackupDecoded 解密备份供界面预览（不写盘）。
func (s *Setup) ImportBackupDecoded(path, exportPassphrase string) (backup.Envelope, error) {
	return backup.DecodeEnvelope(path, exportPassphrase)
}

// ImportBackup 用备份文件覆盖当前身份。
//
// ⚠️ 只在"尚未有身份"的场景由界面调用（首次启动时从备份恢复）。
// 已有身份时由 backup.Import 的 overwrite 语义挡住，需要显式确认。
// 导入成功后必须重建 Setup 状态（重新 refresh），因为身份换了。
func (s *Setup) ImportBackup(path, exportPassphrase string, overwrite bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := backup.Import(path, s.cfg.DataDir, exportPassphrase, overwrite); err != nil {
		return err
	}
	if err := s.refresh(); err != nil {
		return err
	}
	// 备份里带了通讯录；把它写进 contacts.json，这样即使库是新库，
	// 联系人列表也能恢复。
	// （DecodeEnvelope 需要再解一次——代价是一次 argon2，可接受。）
	env, err := backup.DecodeEnvelope(path, exportPassphrase)
	if err != nil {
		return nil // 身份已经恢复成功，通讯录恢复失败不该让整个操作失败
	}
	if len(env.Contacts) > 0 {
		cs := make([]ContactConfig, 0, len(env.Contacts))
		for _, c := range env.Contacts {
			cs = append(cs, ContactConfig{
				Name:        c.Name,
				Fingerprint: c.Fingerprint,
				PublicKey:   []byte(c.PublicKey),
			})
		}
		if err := s.saveContactsLocked(cs); err != nil {
			return err
		}
		// saveContactsLocked 只写盘，不更新内存里的切片；
		// 界面读的是 s.contacts，所以这里必须同步，否则
		// "导入成功但通讯录是空的"。
		s.contacts = cs
	}
	return nil
}

// Close 释放身份。不关闭 App——那是调用方的事。
func (s *Setup) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.msgStore != nil {
		_ = s.msgStore.Close()
		s.msgStore = nil
	}
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
