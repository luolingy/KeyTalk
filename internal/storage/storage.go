// Package storage 负责消息在本地磁盘上的持久化。
//
// # 为什么正文必须加密
//
// 落盘的是 MK 加密后的密文（见 docs/crypto-protocol.md §10.2）。
// 目的不是防本机上的恶意进程——那个进程能读内存、也能读口令——
// 而是防"设备被翻看"：捡到笔记本、备份被同步到网盘、
// 旧硬盘被卖掉，这些场景下攻击者只拿到文件，拿不到口令。
//
// 因此本包**拒绝明文落盘**：没有 MK 就不写，而不是退化成明文。
// 见 ErrNoKey。
//
// # 存储格式
//
// 每个会话一个追加式日志文件：
//
//	<dataDir>/messages/<对端指纹>.jsonl
//
// 每行一个 JSON 对象。选追加式日志而不是 SQLite 的原因见
// docs/architecture.md §3.6 的说明：本项目的模块缓存环境
// 无法获取纯 Go 的 SQLite 驱动，而"消息能活过重启"这个用户
// 可见的价值不应该被一个依赖卡住。
//
// 追加式日志的两个性质正好合适：写入是单次 write（崩溃最多
// 留下半行，读取时跳过），以及状态变更（待发→已发）可以
// 追加一条同 ID 的新记录而不是原地改写。
package storage

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
)

// ErrNoKey 表示没有主密钥，因此无法加密落盘。
//
// 明文身份（v1，命令行 -setup 生成的那种）没有 keystore，
// 也就没有 MK。此时我们**不写任何消息**：宁可没有历史，
// 也不要在磁盘上留一份明文聊天记录。
var ErrNoKey = errors.New("storage: no master key available (identity is not passphrase-protected)")

// 消息状态。
//
// 与 docs/architecture.md §5 的 messages.state 对应。
const (
	// StatePending 表示尚未确认交给传输层。
	StatePending = 0
	// StateSent 表示已交给传输层。
	//
	// ⚠️ **不**表示对方已收到：纯 P2P 下没有送达回执。
	// 界面上不能把它显示成"已读"。
	StateSent = 1
	// StateFailed 表示发送失败，不再重试。
	StateFailed = 2
)

// MessageRecord 是一条消息的持久化形态。
type MessageRecord struct {
	// ID 在**全局**范围内唯一。
	//
	// 早期实现的 ID 是进程内自增的 "m1"、"m2"……，
	// 落盘后重启再发一条又得到 "m1"，会与历史记录撞号。
	ID string
	// PeerFP 是会话对端的完整指纹（hex）。
	PeerFP string
	// Outgoing 表示本机发出。
	Outgoing bool
	// Text 是明文正文。**只在内存与接口层出现**，
	// 落盘时一律加密。
	Text string
	// SentAt 是发送/接收时间。
	SentAt time.Time
	// State 见 StatePending / StateSent / StateFailed。
	State int
}

// Store 是消息持久化接口。
//
// 定义在这里、由 core 以接口形式依赖，是为了让 core 不必知道
// 下面是文件还是数据库。
type Store interface {
	// Append 追加一条记录。同一 ID 重复追加表示**更新**，
	// 读取时以最后一次为准。
	Append(rec MessageRecord) error
	// Load 返回全部消息，按时间升序；同一 ID 取最后一次写入。
	Load() ([]MessageRecord, error)
	// Close 擦除内存中的密钥并关闭文件。
	Close() error
}

// LogStore 是基于追加式日志的 Store 实现。
type LogStore struct {
	dir string

	mu     sync.Mutex
	mk     []byte
	closed bool
	// badLines 累计跳过的损坏行数，供调用方报告。
	badLines int
}

// Open 打开（必要时创建）消息存储。
//
// mk 为 nil 时返回 ErrNoKey：没有密钥就不落盘，
// 绝不明文降级。
//
// mk 的所有权转移给本对象，Close 时会被擦除；调用方不应再持有它。
func Open(dir string, mk []byte) (*LogStore, error) {
	if len(mk) == 0 {
		return nil, ErrNoKey
	}
	msgDir := filepath.Join(dir, "messages")
	if err := os.MkdirAll(msgDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建消息目录 %s: %w", msgDir, err)
	}
	return &LogStore{dir: msgDir, mk: append([]byte(nil), mk...)}, nil
}

// Dir 返回消息目录。
func (s *LogStore) Dir() string { return s.dir }

// BadLines 返回读取过程中跳过的损坏行数。
func (s *LogStore) BadLines() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.badLines
}

// onDiskLine 是磁盘上的一行。
type onDiskLine struct {
	V   int    `json:"v"`
	ID  string `json:"id"`
	Out bool   `json:"out"`
	At  int64  `json:"at"`
	St  int    `json:"st"`
	N   string `json:"n"`
	C   string `json:"c"`
}

// binding 构造本条记录的 AAD 绑定串。
//
// 绑定对端指纹、消息 ID 与状态：
//   - 对端指纹：把 A 会话的密文搬到 B 会话的文件里会解密失败，
//     而不是安静地显示成 B 说过的话；
//   - 消息 ID：密文不能在不同记录之间挪位置；
//   - 状态：JSON 里的 st 字段是明文的，绑定它之后
//     把 StateFailed 改成 StateSent 会解密失败，
//     界面不会把一条根本没发出去的消息显示成已发送。
//
// 刻意**不**绑定数据目录的绝对路径：用户把数据目录搬个地方
// （换盘、换用户名）就会导致全部历史无法解密。
func binding(peerFP, id string, state int) []byte {
	var b strings.Builder
	b.WriteString(peerFP)
	b.WriteByte(0)
	b.WriteString(id)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(state))
	return []byte(b.String())
}

// Append 追加一条记录。
func (s *LogStore) Append(rec MessageRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("storage: store is closed")
	}
	if rec.ID == "" || rec.PeerFP == "" {
		return errors.New("storage: record needs both an ID and a peer fingerprint")
	}

	path, err := s.pathFor(rec.PeerFP)
	if err != nil {
		return err
	}

	nonce, ct, err := crypto.EncryptLocalBound(s.mk, crypto.PurposeMessage,
		binding(rec.PeerFP, rec.ID, rec.State), []byte(rec.Text))
	if err != nil {
		return fmt.Errorf("加密消息正文: %w", err)
	}

	line := onDiskLine{
		V:   1,
		ID:  rec.ID,
		Out: rec.Outgoing,
		At:  rec.SentAt.UnixMilli(),
		St:  rec.State,
		N:   base64.StdEncoding.EncodeToString(nonce),
		C:   base64.StdEncoding.EncodeToString(ct),
	}
	data, err := json.Marshal(line)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// O_APPEND 保证并发写入不会互相覆盖；单次 Write 保证
	// 崩溃时最多留下半行，而半行在读取时会被跳过。
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开 %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("写入 %s: %w", path, err)
	}
	return nil
}

// Load 读取全部消息。
//
// 单个会话读取失败不影响其他会话：宁可少一个会话的历史，
// 也不要因为一个坏文件让整个界面打不开。
func (s *LogStore) Load() ([]MessageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("storage: store is closed")
	}

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取消息目录 %s: %w", s.dir, err)
	}

	var out []MessageRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		peerFP := strings.TrimSuffix(e.Name(), ".jsonl")
		recs, err := s.loadFile(filepath.Join(s.dir, e.Name()), peerFP)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].SentAt.Equal(out[j].SentAt) {
			return out[i].SentAt.Before(out[j].SentAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// loadFile 读取单个会话的日志，按 ID 折叠为"最后一次写入生效"。
func (s *LogStore) loadFile(path, peerFP string) ([]MessageRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 %s: %w", path, err)
	}
	defer f.Close()

	// 按 ID 记录写入顺序，最后一条覆盖前面的。
	byID := make(map[string]MessageRecord)
	var order []string

	sc := bufio.NewScanner(f)
	// 单行可以很长（长消息）。1 MiB 上限足够，且防止
	// 一个畸形文件把内存吃光。
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}

		var line onDiskLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			// 崩溃留下的半行、或人为损坏的行。
			s.badLines++
			continue
		}

		nonce, err1 := base64.StdEncoding.DecodeString(line.N)
		ct, err2 := base64.StdEncoding.DecodeString(line.C)
		if err1 != nil || err2 != nil {
			s.badLines++
			continue
		}

		plain, err := crypto.DecryptLocalBound(s.mk, crypto.PurposeMessage,
			binding(peerFP, line.ID, line.St), nonce, ct)
		if err != nil {
			// 解密失败意味着这一行被改过、或被从别处搬过来。
			// 报出来而不是静默跳过——这正是 AAD 绑定存在的意义。
			s.badLines++
			continue
		}

		if _, seen := byID[line.ID]; !seen {
			order = append(order, line.ID)
		}
		byID[line.ID] = MessageRecord{
			ID:       line.ID,
			PeerFP:   peerFP,
			Outgoing: line.Out,
			Text:     string(plain),
			SentAt:   time.UnixMilli(line.At),
			State:    line.St,
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取 %s: %w", path, err)
	}

	out := make([]MessageRecord, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

// pathFor 返回某个对端的日志文件路径。
//
// ⚠️ 对端指纹来自网络数据，**必须**校验为十六进制才能当文件名用。
// 不校验的话 "../../../.ssh/authorized_keys" 就是一个合法的
// "指纹"，一次 Append 就能往任意路径写文件。
func (s *LogStore) pathFor(peerFP string) (string, error) {
	if !isHex(peerFP) {
		return "", fmt.Errorf("storage: peer fingerprint %q is not hexadecimal", peerFP)
	}
	return filepath.Join(s.dir, peerFP+".jsonl"), nil
}

// isHex 报告 s 是否是非空的、只含 [0-9A-Fa-f] 的字符串。
func isHex(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'f',
			c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// Close 擦除密钥并标记关闭。幂等。
func (s *LogStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	crypto.Zero(s.mk)
	s.mk = nil
	return nil
}
