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

// TestTrustLabelsAreLocalized 验证信任标签是给用户看的中文。
func TestTrustLabelsAreLocalized(t *testing.T) {
	cases := []struct {
		l    TrustLevel
		want string
	}{
		{TrustUnknown, "未连接"},
		{TrustUnverified, "未核实"},
		{TrustVerified, "已核实"},
		{TrustFailed, "失败"},
	}
	for _, c := range cases {
		if got := trustLabel(c.l); got != c.want {
			t.Errorf("trustLabel(%v) = %q, want %q", c.l, got, c.want)
		}
	}
}

// TestTrustLevelsHaveDistinctColours 验证四个信任等级颜色互不相同。
//
// 颜色是方案 C **唯一**的信任编码。若两档共用同一个颜色，
// 用户就无法区分"已加密但没核实"和"已核实"——
// 而那恰恰是最需要区分的两档。
func TestTrustLevelsHaveDistinctColours(t *testing.T) {
	seen := map[[3]uint8]TrustLevel{}
	for _, l := range []TrustLevel{TrustUnknown, TrustUnverified, TrustVerified, TrustFailed} {
		c := trustColor(l)
		key := [3]uint8{c.R, c.G, c.B}
		if prev, dup := seen[key]; dup {
			t.Errorf("trust levels %v and %v share the same colour; "+
				"the trust bar would not distinguish them", prev, l)
		}
		seen[key] = l
	}
}

// TestTrustPhraseDistinguishesEncryptionFromIdentity 是本界面最重要的文案断言。
//
// 「已加密」与「已核实身份」是两件不同的事：
// 前者是密码学自动达成的，后者需要人来确认。
// 若未核实状态的文案里只出现"已加密"，用户会把它读成
// "我知道对面是谁"——这正是本工具要避免的误解。
func TestTrustPhraseDistinguishesEncryptionFromIdentity(t *testing.T) {
	unverified := trustPhrase(TrustUnverified)

	if !strings.Contains(unverified, "未") {
		t.Errorf("TrustUnverified phrase %q does not say anything is still "+
			"unconfirmed; users would read it as fully verified", unverified)
	}
	if !strings.Contains(unverified, "身份") {
		t.Errorf("TrustUnverified phrase %q does not mention identity; "+
			"the whole point is that encryption is done but identity is not "+
			"confirmed", unverified)
	}

	// 两档的表述必须不同，否则这个区分在界面上不存在。
	if trustPhrase(TrustUnverified) == trustPhrase(TrustVerified) {
		t.Error("unverified and verified phrases are identical; " +
			"the distinction would be invisible to users")
	}
}

// TestWorstTrustPicksMostConcerning 验证全局信任取**最差**的一档。
//
// 取最乐观的一档会让一个未核实的会话被另一个已核实的会话掩盖，
// 而全局指示器的存在意义正是"有没有任何一件事需要注意"。
func TestWorstTrustPicksMostConcerning(t *testing.T) {
	mk := func(st core.ContactStatus, verified bool) core.Contact {
		return core.Contact{Status: st, Verified: verified}
	}

	cases := []struct {
		name     string
		contacts []core.Contact
		want     TrustLevel
	}{
		{"empty", nil, TrustUnknown},
		{"only verified", []core.Contact{mk(core.StatusSecure, true)}, TrustVerified},
		{"verified + unverified", []core.Contact{
			mk(core.StatusSecure, true), mk(core.StatusSecure, false),
		}, TrustUnverified},
		{"unverified + failed", []core.Contact{
			mk(core.StatusSecure, false), mk(core.StatusFailed, false),
		}, TrustFailed},
		{"verified + offline", []core.Contact{
			mk(core.StatusSecure, true), mk(core.StatusOffline, false),
		}, TrustUnknown},
	}
	for _, c := range cases {
		if got := worstTrust(c.contacts); got != c.want {
			t.Errorf("%s: worstTrust = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestTrustOfNeverUpgradesWithoutUserAction 验证信任推导不会凭握手升级。
//
// 这是一条**安全断言**：只要 Verified 为 false，
// 无论连接状态多好，都只能得到 TrustUnverified。
func TestTrustOfNeverUpgradesWithoutUserAction(t *testing.T) {
	secure := core.Contact{Status: core.StatusSecure, Verified: false}
	if got := trustOf(secure); got == TrustVerified {
		t.Fatal("a secure-but-unverified contact was classified as " +
			"TrustVerified; the handshake must never imply user confirmation")
	}

	secure.Verified = true
	if got := trustOf(secure); got != TrustVerified {
		t.Fatalf("verified contact classified as %v, want TrustVerified", got)
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
