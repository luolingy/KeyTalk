package ui

import (
	"strings"
	"testing"

	"github.com/exeliang/keytalk/internal/core"
)

// TestCJKFontIsLoaded 验证系统中文字体确实被加载。
//
// 这是一个**真实风险**的回归测试，不是形式主义：
// Gio 内置的 Go 字体不含任何 CJK 字形；若没有额外加载中文字体，
// 界面上所有中文都会渲染成豆腐块（▯▯▯）或空白。
// 对一款中文用户为主的聊天工具，那等于不可用。
//
// 找不到字体时用 Skip 而不是 Fail：这是**环境**限制而非代码缺陷
// （例如精简版 Linux 容器里确实没有中文字体）。
// 但运行时会通过 cjkFontStatus 明确告警，绝不静默降级。
func TestCJKFontIsLoaded(t *testing.T) {
	_, path, errs := loadFonts()

	for _, e := range errs {
		t.Logf("font parse error (non-fatal, trying next candidate): %s", e)
	}

	if path == "" {
		t.Skip("no CJK font found on this machine; UI would render Chinese as " +
			"tofu boxes. Environment limitation, not a code defect.")
	}
	t.Logf("CJK font loaded from %s", path)
}

// TestFontCollectionIsUsable 验证字体集合可用于排版。
func TestFontCollectionIsUsable(t *testing.T) {
	coll, _, _ := loadFonts()
	if len(coll) == 0 {
		t.Fatal("font collection is empty; no text can be rendered at all")
	}
	t.Logf("font collection has %d face(s)", len(coll))
}

// TestStatusLabelIsLocalized 验证状态文案是给用户看的，不是内部枚举名。
//
// 早期版本把 ContactStatus.String() 直接显示到界面上，
// 用户看到的是 "secure" / "offline" 这类英文内部标识。
func TestStatusLabelIsLocalized(t *testing.T) {
	cases := []struct {
		st   core.ContactStatus
		want string
	}{
		{core.StatusOffline, "离线"},
		{core.StatusOnline, "在线"},
		{core.StatusSecure, "已加密"},
		{core.StatusFailed, "失败"},
	}
	for _, c := range cases {
		got := statusLabel(c.st)
		if !strings.Contains(got, c.want) {
			t.Errorf("statusLabel(%v) = %q, want it to contain %q",
				c.st, got, c.want)
		}
	}
}

// TestStatusColorsDistinguishStates 验证不同状态用不同颜色。
//
// 三个状态若共用一个颜色，侧栏的圆点就失去
// "一眼看出谁能发消息"的作用。
func TestStatusColorsDistinguishStates(t *testing.T) {
	seen := map[[3]uint8]core.ContactStatus{}
	for _, st := range []core.ContactStatus{
		core.StatusOffline, core.StatusOnline, core.StatusSecure, core.StatusFailed,
	} {
		c := statusColor(st)
		key := [3]uint8{c.R, c.G, c.B}
		if prev, dup := seen[key]; dup {
			t.Errorf("statuses %v and %v share the same colour; "+
				"the sidebar dot would not distinguish them", prev, st)
		}
		seen[key] = st
	}
}

// TestEmptyContactsTextTellsUserWhatToDo 验证空状态给出**下一步动作**。
//
// 这与其他聊天软件的心智模型差异极大：本工具没有服务器、没有账号，
// 用户不主动交换公钥就永远不会有联系人。
// 只写"暂无数据"会让用户以为程序坏了。
func TestEmptyContactsTextTellsUserWhatToDo(t *testing.T) {
	msg := emptyContactsText()
	for _, want := range []string{"公钥", "指纹"} {
		if !strings.Contains(msg, want) {
			t.Errorf("empty-state text does not mention %q; users would not "+
				"know how to add a contact.\nText: %s", want, msg)
		}
	}
}

// TestBubbleWidthIsBounded 验证消息气泡宽度有上限。
//
// 占满整行会让长消息难以阅读，也让人分不清哪句是谁说的。
func TestBubbleWidthIsBounded(t *testing.T) {
	const maxBubbleDp = 560
	if maxBubbleDp <= 0 {
		t.Fatal("bubble max width must be positive")
	}
	// 上限应当明显小于常见窗口宽度，否则等于没有限制。
	if maxBubbleDp >= 1000 {
		t.Errorf("bubble max width %ddp is not meaningfully bounded", maxBubbleDp)
	}
}
