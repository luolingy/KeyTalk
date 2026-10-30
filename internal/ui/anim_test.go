package ui

import (
	"testing"
	"time"
)

// TestAnimStateProgress 验证进度随时间从 0 走到 1 后停住。
func TestAnimStateProgress(t *testing.T) {
	var s animState
	start := time.Unix(1000, 0)
	s.trigger("msg-1", start)

	// 起始瞬间：进度 0，且仍在进行。
	p, active := s.progress(start)
	if p != 0 || !active {
		t.Errorf("at start: progress=%v active=%v, want 0 true", p, active)
	}

	// 一半时长：进度约 0.5，仍在进行。
	half := start.Add(animDuration / 2)
	p, active = s.progress(half)
	if !active {
		t.Error("at half duration the animation should still be active")
	}
	if p < 0.4 || p > 0.6 {
		t.Errorf("at half duration progress=%v, want ~0.5", p)
	}

	// 结束：进度 1，不再进行。
	done := start.Add(animDuration)
	p, active = s.progress(done)
	if p != 1 || active {
		t.Errorf("at end: progress=%v active=%v, want 1 false", p, active)
	}

	// 远超结束：仍然是 1、不活动（不能越过 1）。
	p, active = s.progress(start.Add(time.Hour))
	if p != 1 || active {
		t.Errorf("long after end: progress=%v active=%v, want 1 false", p, active)
	}
}

// TestAnimStateZeroIsComplete 验证未开始时进度为 1（静态内容不透明）。
//
// 这条很重要：没有动画的场合（历史消息、常驻提示）必须完全显现，
// 若为零值返回 0，整个界面会变透明。
func TestAnimStateZeroIsComplete(t *testing.T) {
	var s animState
	p, active := s.progress(time.Now())
	if p != 1 || active {
		t.Errorf("zero-value animState returned progress=%v active=%v, want 1 false", p, active)
	}
}

// TestAnimStateTriggerSameKeyNoRestart 验证同 key 不重新计时。
//
// 否则每一帧都 trigger，动画永远停在起点。
func TestAnimStateTriggerSameKeyNoRestart(t *testing.T) {
	var s animState
	t0 := time.Unix(2000, 0)
	s.trigger("same", t0)

	// 过了一半时长，用同一个 key 再 trigger：不应重置 start。
	half := t0.Add(animDuration / 2)
	s.trigger("same", half)
	if !s.start.Equal(t0) {
		t.Errorf("re-triggering the same key reset the start time: %v -> %v", t0, s.start)
	}
}

// TestAnimStateTriggerNewKeyRestarts 验证换 key 会重新计时。
func TestAnimStateTriggerNewKeyRestarts(t *testing.T) {
	var s animState
	t0 := time.Unix(3000, 0)
	s.trigger("a", t0)

	t1 := t0.Add(animDuration)
	s.trigger("b", t1)
	if !s.start.Equal(t1) {
		t.Errorf("a new key did not restart the animation: start=%v, want %v", s.start, t1)
	}
}

// TestAnimNegativeElapsedClamped 验证时钟倒退时进度被夹到 0。
func TestAnimNegativeElapsedClamped(t *testing.T) {
	var s animState
	start := time.Unix(4000, 0)
	s.trigger("x", start)

	// 用一个比 start 更早的 now 取进度。
	p, active := s.progress(start.Add(-time.Second))
	if p != 0 || !active {
		t.Errorf("negative elapsed: progress=%v active=%v, want 0 true", p, active)
	}
}

// TestEaseOutCubic 验证缓出曲线端点与单调性。
func TestEaseOutCubic(t *testing.T) {
	if easeOutCubic(0) != 0 {
		t.Error("easeOutCubic(0) should be 0")
	}
	if easeOutCubic(1) != 1 {
		t.Error("easeOutCubic(1) should be 1")
	}
	// 越界输入被夹住。
	if easeOutCubic(-0.5) != 0 || easeOutCubic(1.5) != 1 {
		t.Error("easeOutCubic should clamp out-of-range inputs")
	}
	// 单调递增。
	prev := float32(-1)
	for i := 0; i <= 20; i++ {
		v := easeOutCubic(float32(i) / 20)
		if v < prev {
			t.Errorf("easeOutCubic is not monotonic at %d/20: %v < %v", i, v, prev)
		}
		prev = v
	}
	// 缓出特性：中点应当已经超过线性（> 0.5）。
	if easeOutCubic(0.5) <= 0.5 {
		t.Errorf("easeOutCubic(0.5)=%v should be greater than 0.5 for an ease-out curve", easeOutCubic(0.5))
	}
}
