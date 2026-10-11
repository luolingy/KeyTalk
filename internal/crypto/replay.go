package crypto

import "sync"

// ReplayWindowSize 是滑动窗口的位图大小。
//
// 这是"容忍乱序深度"与"内存/位图开销"的折中。
// 局域网 RTT 极低，实际乱序很浅；若未来走公网可调大。
const ReplayWindowSize = 1024

// ReplayWindow 是 seq 滑动窗口，用于检测重放与过旧的帧。
//
// 每个 (会话, 代次) 组合持有一个独立窗口——因为 seq 在每个 epoch 内独立计数。
//
// 并发安全：内部有锁。但设计上一个会话只有 reader goroutine 调用 Accept，
// 加锁仅作为防御性措施。
type ReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	seen    [ReplayWindowSize / 8]byte
	init    bool
}

// ReplayResult 是 Accept 的判定结果。
type ReplayResult int

const (
	// AcceptOK 表示接受该帧。
	AcceptOK ReplayResult = iota
	// AcceptReplay 表示重复的 seq，判定为重放。
	AcceptReplay
	// AcceptTooOld 表示 seq 早于窗口下界。
	//
	// 注意：这**不得**单独作为攻击证据——可能是网络乱序导致的长延迟。
	AcceptTooOld
)

func (r ReplayResult) String() string {
	switch r {
	case AcceptOK:
		return "ok"
	case AcceptReplay:
		return "replay"
	case AcceptTooOld:
		return "too-old"
	default:
		return "unknown"
	}
}

// Accept 判定 seq 是否可接受，并在接受时更新窗口。
//
// 调用顺序要求：**必须在解密之前调用**（见 docs/crypto-protocol.md §7.5），
// 这样重放包不会消耗解密算力，也避免通过解密耗时差异做侧信道探测。
//
// 由于调用方在解密前调用，若解密随后失败，该 seq 已被标记为"见过"。
// 这是可接受的：攻击者若能伪造一个 seq 使解密失败，他同样能直接丢弃真实帧造成 DoS。
// 为避免这一点，调用方可使用 Accept / Reject 两阶段接口（本实现提供 TryAccept）。
func (w *ReplayWindow) Accept(seq uint64) ReplayResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.acceptLocked(seq)
}

func (w *ReplayWindow) acceptLocked(seq uint64) ReplayResult {
	if !w.init {
		w.highest = seq
		w.init = true
		w.setBit(seq)
		return AcceptOK
	}

	if seq > w.highest {
		// 窗口右移。
		w.shiftLocked(seq - w.highest)
		w.highest = seq
		w.setBit(seq)
		return AcceptOK
	}

	diff := w.highest - seq
	if diff >= ReplayWindowSize {
		return AcceptTooOld
	}
	if w.getBit(seq) {
		return AcceptReplay
	}
	w.setBit(seq)
	return AcceptOK
}

// Revoke 撤销某个 seq 的"已接受"标记。
//
// 用于 "先检查重放、后解密" 流程中解密失败的回滚：
// 若解密失败，调用方应 Revoke 该 seq，使真正的合法帧不会因为
// 攻击者抢先投递了一个同 seq 的伪帧而被永久拒绝。
//
// 只对窗口内的 seq 有效；若 seq 已成为 highest，则回退 highest 需要重建窗口，
// 因此这种情况下不撤销（保守策略，宁可有极小概率拒绝一个合法帧）。
func (w *ReplayWindow) Revoke(seq uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init || seq > w.highest || w.highest-seq >= ReplayWindowSize {
		return
	}
	w.clearBit(seq)
}

// Highest 返回已接受的最大 seq。
func (w *ReplayWindow) Highest() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highest
}

// Init 报告窗口是否已初始化（即是否接受过任何帧）。
func (w *ReplayWindow) Init() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.init
}

// Reset 清空窗口，用于密钥轮换时启用新一代。
func (w *ReplayWindow) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.highest = 0
	w.seen = [ReplayWindowSize / 8]byte{}
	w.init = false
}

func (w *ReplayWindow) shiftLocked(delta uint64) {
	if delta >= ReplayWindowSize {
		w.seen = [ReplayWindowSize / 8]byte{}
		return
	}
	bits := int(delta)
	bytes := bits / 8
	rem := uint(bits % 8)

	if bytes > 0 {
		copy(w.seen[:], w.seen[bytes:])
		for i := len(w.seen) - bytes; i < len(w.seen); i++ {
			w.seen[i] = 0
		}
	}
	if rem > 0 {
		for i := len(w.seen) - 1; i >= 0; i-- {
			hi := w.seen[i] << rem
			var lo byte
			if i > 0 {
				lo = w.seen[i-1] >> (8 - rem)
			}
			w.seen[i] = hi | lo
		}
	}
}

// bitIndex 把绝对 seq 映射为窗口内的下标。
// 前提：seq 落在 [highest-ReplayWindowSize+1, highest] 内。
func (w *ReplayWindow) bitIndex(seq uint64) (byteIdx int, mask byte) {
	off := w.highest - seq // 0 = highest
	byteIdx = int(off) / 8
	mask = 1 << (uint(off) % 8)
	return
}

func (w *ReplayWindow) setBit(seq uint64) {
	i, m := w.bitIndex(seq)
	w.seen[i] |= m
}

func (w *ReplayWindow) clearBit(seq uint64) {
	i, m := w.bitIndex(seq)
	w.seen[i] &^= m
}

func (w *ReplayWindow) getBit(seq uint64) bool {
	i, m := w.bitIndex(seq)
	return w.seen[i]&m != 0
}
