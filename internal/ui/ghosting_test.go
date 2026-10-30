package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoReplayedRecordingsInBackgrounds 防止"文字重影"回归。
//
// # 曾经的 bug
//
// 画一个带圆角底色的控件时，惯用写法是：
//
//	layout.Background{}.Layout(gtx, background, content)
//
// 其中 background 只负责**涂底色**，content 负责画内容。
// layout.Background 内部已经替我们把 content 录制成宏、
// 先画 background、再把宏放回去（见 layout/stack.go 的
// Background.Layout）。
//
// 而早先的实现为了"测量内容尺寸"，在 background 里这样做：
//
//	m := op.Record(gtx.Ops)
//	dims := content(gtx)
//	op.Defer(gtx.Ops, m.Stop())   // ← 灾难
//	fillRounded(gtx, bg, dims.Size, r)
//
// op.Defer **会重放**录制的操作：于是内容被真真切切画了一遍，
// 接着底色盖在它上面，最后 layout.Background 又把 content
// 画了第二遍。同一段文字被绘制两次，上面那层是干净的、
// 下面那层被底色压住一半——看起来就是"重影"。
//
// # 正确写法
//
// 只测量、不重放：
//
//	m := op.Record(gtx.Ops)
//	dims := content(gtx)
//	m.Stop()                      // ← 丢弃录制，只留 dims
//	fillRounded(gtx, bg, dims.Size, r)
//
// # 为什么用源码扫描而不是渲染断言
//
// Gio 是立即模式，绘制指令写进一个不透明的 ops 缓冲，
// 从外部无法可靠地数出"这段文字被画了几次"。而这类 bug 的
// 形态极其固定（就是 background 里的 op.Defer），
// 所以直接禁止这个写法，成本最低、抓得最准。
func TestNoReplayedRecordingsInBackgrounds(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no Go files found; is the working directory the ui package?")
	}

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(src), "\n")

		for i, line := range lines {
			// 只关心本项目自己的代码；注释里出现这个词组无所谓，
			// 但 op.Defer( 是一行真实调用。
			if !strings.Contains(line, "op.Defer(") {
				continue
			}
			// 允许显式的白名单：将来若确实需要 Defer 某个调用，
			// 在这里登记并写明理由，而不是放开整条规则。
			t.Errorf("%s:%d 使用了 op.Defer —— 在 layout.Background 的\n"+
				"背景闭包里它会把内容重放一次，导致文字重影。\n"+
				"改成只用 m.Stop() 测量尺寸。\n源码: %s",
				f, i+1, strings.TrimSpace(line))
		}
	}
}
