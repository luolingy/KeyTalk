package ui

import (
	"time"
)

// animDuration 是新消息气泡入场动画的时长。
//
// 180ms 的选择：短到不拖慢阅读，长到眼睛能看见"出现"这个动作。
// 超过 250ms 会让人觉得界面迟钝；低于 100ms 基本看不出来。
const animDuration = 180 * time.Millisecond

// animState 是一个基于时间的一次性入场动画。
//
// # 为什么是"时间驱动"而不是"帧计数"
//
// Gio 只在有输入或主动 Invalidate 时才重绘。若用"每帧加一点"的方式，
// 动画速度会随刷新率与系统负载漂移——慢机器上动画会一卡一卡地拖长。
// 用挂钟时间算进度，无论掉多少帧，动画总在 animDuration 内结束。
type animState struct {
	// start 是动画开始时刻；零值表示没有动画。
	start time.Time
	// key 是这个动画对应的对象标识（例如消息 ID）。
	//
	// 有了它，同一条消息不会因为多次进入绘制而反复重启动画；
	// 只有"换了一条新消息"才重新计时。
	key string
}

// trigger 为 key 重启动画。如果 key 与当前动画相同则不动。
//
// now 取自当前帧的 gtx.Now，与 progress 用的时钟保持一致——
// 否则两个时钟之间有偏差时，首帧会算出负的 elapsed。
func (s *animState) trigger(key string, now time.Time) {
	if s.key == key && !s.start.IsZero() {
		return
	}
	s.key = key
	s.start = now
}

// progress 返回当前动画进度 0→1，以及是否仍在进行中。
//
// 未开始（start 为零）时返回 1，表示"完全显现"——这样没有动画的
// 静态场景不会被画成透明的。
func (s *animState) progress(now time.Time) (float32, bool) {
	if s.start.IsZero() {
		return 1, false
	}
	elapsed := now.Sub(s.start)
	if elapsed >= animDuration {
		return 1, false
	}
	if elapsed < 0 {
		return 0, true
	}
	return float32(elapsed) / float32(animDuration), true
}

// easeOutCubic 让动画收尾更自然：起步快、结束慢。
//
// 线性进度在结尾会显得"啪"地停住；缓出让它柔和地落定。
func easeOutCubic(t float32) float32 {
	if t <= 0 {
		return 0
	}
	if t >= 1 {
		return 1
	}
	inv := 1 - t
	return 1 - inv*inv*inv
}
