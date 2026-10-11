package crypto

import (
	"fmt"
	"time"
)

// timeNow 是 time.Now 的间接引用，便于测试替换。
//
// 用变量而非直接调用，使测试可以把"当前时间"固定下来，
// 从而稳定地覆盖时间戳容忍窗口逻辑。
var timeNow = time.Now

// SetTimeSource 替换时间源，仅供测试使用。
// 返回一个恢复函数。
func SetTimeSource(f func() time.Time) func() {
	old := timeNow
	if f != nil {
		timeNow = f
	}
	return func() { timeNow = old }
}

// --- 以下为纯逻辑校验，不依赖任何 OpenPGP 实现，可独立测试 ---

// ValidateKEM 对解析后的 KEM 载荷执行未涉密的健全性校验。
//
// 与签名/解密无关的检查集中在此，便于在不构造真实密钥的情况下单测。
func ValidateKEM(kp *KEMPlaintext, self, expected Fingerprint, nowMSv int64) error {
	if kp == nil {
		return fmt.Errorf("%w: nil kem payload", ErrMalformed)
	}
	if kp.SenderFP.String() != expected.String() {
		return fmt.Errorf("%w: kem sender %s != expected %s",
			ErrAuthFailed, kp.SenderFP.Display(), expected.Display())
	}
	if kp.RecipientFP.String() != self.String() {
		return fmt.Errorf("%w: kem addressed to %s, we are %s",
			ErrAuthFailed, kp.RecipientFP.Display(), self.Display())
	}
	if len(kp.EphPub) != ECDHPubLen {
		return fmt.Errorf("%w: eph pub len %d", ErrMalformed, len(kp.EphPub))
	}
	return CheckTimestamp(kp.Timestamp, nowMSv)
}

// SessionIDSet 记录最近使用过的会话标识，用于拒绝复用。
//
// 握手层重放防护的一部分：一个已被使用过的 sid 不应再次被接受，
// 即使其签名合法（可能是录制后重放）。
type SessionIDSet struct {
	capacity int
	order    [][SessionIDLen]byte
	seen     map[[SessionIDLen]byte]struct{}
}

// NewSessionIDSet 创建一个容量受限的 sid 去重集合。
func NewSessionIDSet(capacity int) *SessionIDSet {
	if capacity <= 0 {
		capacity = 1024
	}
	return &SessionIDSet{
		capacity: capacity,
		order:    make([][SessionIDLen]byte, 0, capacity),
		seen:     make(map[[SessionIDLen]byte]struct{}, capacity),
	}
}

// AddIfNew 在 sid 未被见过时记录并返回 true；否则返回 false（判定为重放）。
func (s *SessionIDSet) AddIfNew(id [SessionIDLen]byte) bool {
	if _, ok := s.seen[id]; ok {
		return false
	}
	s.seen[id] = struct{}{}
	s.order = append(s.order, id)
	// 超过容量则淘汰最旧的。
	for len(s.order) > s.capacity {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.seen, old)
	}
	return true
}

// Len 返回当前记录的条目数。
func (s *SessionIDSet) Len() int { return len(s.order) }
