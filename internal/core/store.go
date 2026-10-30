package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/exeliang/keytalk/internal/db"
)

// MessageStore 是 core 对持久化层的最小依赖。
//
// 定义成接口而不是直接用 *db.DB，有两个理由：
//  1. core 不必知道库是加密数据库还是别的实现；
//  2. 测试可以塞一个内存实现，不必每次都开真库。
//
// 实现由 internal/db 提供（见 dbStore 适配器）。
type MessageStore interface {
	// LoadMessages 返回全部消息，按时间升序。
	LoadMessages() ([]db.Message, error)
	// AppendMessage 插入或按 ID 覆盖一条消息。
	AppendMessage(m db.Message) error
	// LoadContacts 返回全部联系人。
	LoadContacts() ([]db.Contact, error)
	// SaveContact 插入或按指纹覆盖一个联系人。
	SaveContact(c db.Contact) error
	// Close 擦除密钥并关闭。
	Close() error
}

// dbStore 把 *db.DB 适配成 MessageStore。
//
// 每个方法自带一个短事务。聊天场景下每次落一条消息就是一次事务，
// 这比"整个会话一个长事务"更能保证意外退出时不丢已确认的消息。
type dbStore struct{ d *db.DB }

// OpenDBStore 在 dir 打开（或创建）加密库并返回 MessageStore。
//
// mk 为 nil 时返回 nil, nil：没有主密钥就不持久化，
// 与旧 storage 层"拒绝明文降级"的立场一致。
func OpenDBStore(dir string, mk []byte) (MessageStore, error) {
	if len(mk) == 0 {
		return nil, nil
	}
	d, err := db.Open(dir, mk)
	if err != nil {
		return nil, err
	}
	return &dbStore{d: d}, nil
}

func (s *dbStore) LoadMessages() ([]db.Message, error) {
	if err := s.d.Begin(); err != nil {
		return nil, err
	}
	msgs, err := s.d.Messages().All()
	if err != nil {
		_ = s.d.Rollback()
		return nil, err
	}
	// 只读事务回滚即可：没有改写需要提交，回滚同时释放事务状态。
	if err := s.d.Rollback(); err != nil {
		return nil, err
	}
	return msgs, nil
}

func (s *dbStore) AppendMessage(m db.Message) error {
	if err := s.d.Begin(); err != nil {
		return err
	}
	if err := s.d.Messages().Put(m); err != nil {
		_ = s.d.Rollback()
		return err
	}
	return s.d.Commit()
}

func (s *dbStore) LoadContacts() ([]db.Contact, error) {
	if err := s.d.Begin(); err != nil {
		return nil, err
	}
	cs, err := s.d.Contacts().All()
	if err != nil {
		_ = s.d.Rollback()
		return nil, err
	}
	if err := s.d.Rollback(); err != nil {
		return nil, err
	}
	return cs, nil
}

func (s *dbStore) SaveContact(c db.Contact) error {
	if err := s.d.Begin(); err != nil {
		return err
	}
	if err := s.d.Contacts().Upsert(c); err != nil {
		_ = s.d.Rollback()
		return err
	}
	return s.d.Commit()
}

func (s *dbStore) Close() error { return s.d.Close() }

// migrateLegacyLog 把旧版 <dataDir>/messages/*.jsonl 一次性导入新库。
//
// # 为什么迁移之后保留原文件
//
// 自研存储引擎最大的风险不是加密，是数据损坏。导入成功后把
// messages/ 改成 messages.migrated/ 而不是删除，万一新库有问题，
// 用户的历史还在原地。占用的磁盘空间换来可回退性，值得。
//
// # 谁调用
//
// 由 cmd 层在拿到 MK、打开 dbStore 之后调用一次。core 不自动
// 调用它：迁移需要旧 storage 包读 jsonl，而 core 不该依赖旧代码。
func migrateLegacyLog(dir string, mk []byte, store MessageStore, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	msgDir := filepath.Join(dir, "messages")
	if _, err := os.Stat(msgDir); os.IsNotExist(err) {
		return nil // 没有旧数据，正常路径
	}

	entries, err := os.ReadDir(msgDir)
	if err != nil {
		return fmt.Errorf("migration: reading %s: %w", msgDir, err)
	}

	imported, skipped := 0, 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		peerFP := strings.TrimSuffix(e.Name(), ".jsonl")
		recs, err := readLegacyLogFile(filepath.Join(msgDir, e.Name()), peerFP, mk)
		if err != nil {
			// 单个文件读不了（密钥不对、损坏）就跳过，不阻断启动。
			logf("migration: skipping %s: %v", e.Name(), err)
			skipped++
			continue
		}
		for _, m := range recs {
			if err := store.AppendMessage(m); err != nil {
				return fmt.Errorf("migration: importing %s: %w", e.Name(), err)
			}
			imported++
		}
	}

	if imported == 0 && skipped == 0 {
		return nil
	}
	if err := os.Rename(msgDir, filepath.Join(dir, "messages.migrated")); err != nil {
		// 改名失败不影响数据已导入；只是失去回退副本。
		logf("migration: could not rename %s (data was imported): %v", msgDir, err)
	}
	logf("migration: imported %d message(s) from the legacy log, skipped %d file(s)",
		imported, skipped)
	return nil
}
