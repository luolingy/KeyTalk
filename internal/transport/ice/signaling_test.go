package ice

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// encodeRawForTest 把一段原始 JSON 包成 KTICE1: 前缀的文本，
// 用于构造"前缀/base64 合法但内容不合规"的样本。
func encodeRawForTest(t *testing.T, jsonBody string) string {
	t.Helper()
	return "KTICE1:" + base64.StdEncoding.EncodeToString([]byte(jsonBody))
}

// --- 配置与 URL 校验 ---

// TestValidSTUNURLsDefaults 验证空配置时用公共 STUN 默认值。
func TestValidSTUNURLsDefaults(t *testing.T) {
	c := Config{}
	urls, err := c.ValidSTUNURLs()
	if err != nil {
		t.Fatalf("ValidSTUNURLs: %v", err)
	}
	if len(urls) != len(DefaultSTUNURLs) {
		t.Errorf("got %d default STUN urls, want %d", len(urls), len(DefaultSTUNURLs))
	}
}

// TestValidSTUNURLsRejectsTurn 验证把 turn: 放进 STUNURLs 会被拒绝。
//
// 理由：把"免费反射"与"付费中继"在配置上分开，成本才可见。
func TestValidSTUNURLsRejectsTurn(t *testing.T) {
	c := Config{STUNURLs: []string{"turn:example.com:3478?transport=udp"}}
	if _, err := c.ValidSTUNURLs(); err == nil {
		t.Fatal("a turn: URL was accepted as a STUN URL")
	}
}

// TestValidSTUNURLsRejectsGarbage 验证乱字符串被拒绝。
func TestValidSTUNURLsRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not-a-url", "http://example.com", "stun:"} {
		c := Config{STUNURLs: []string{bad}}
		if _, err := c.ValidSTUNURLs(); err == nil {
			t.Errorf("garbage %q was accepted as a STUN URL", bad)
		}
	}
}

// TestValidTURNURLsEmpty 验证不配 TURN 是合法的（返回 nil,nil）。
func TestValidTURNURLsEmpty(t *testing.T) {
	c := Config{}
	urls, err := c.ValidTURNURLs()
	if err != nil {
		t.Fatalf("no TURN should be legal: %v", err)
	}
	if urls != nil {
		t.Errorf("expected nil TURN urls, got %v", urls)
	}
}

// TestValidTURNURLsRequiresCredentials 验证配了 TURN 却没凭据会报错。
func TestValidTURNURLsRequiresCredentials(t *testing.T) {
	c := Config{TURNURLs: []string{"turn:example.com:3478?transport=udp"}}
	if _, err := c.ValidTURNURLs(); err == nil {
		t.Fatal("TURN without credentials was accepted")
	}
}

// TestValidTURNURLsOK 验证完整配置被接受，且凭据覆盖 URL 内凭据。
func TestValidTURNURLsOK(t *testing.T) {
	c := Config{
		TURNURLs:        []string{"turn:example.com:3478?transport=udp"},
		TURNCredentials: Credentials{Username: "alice", Password: "s3cret"},
	}
	urls, err := c.ValidTURNURLs()
	if err != nil {
		t.Fatalf("ValidTURNURLs: %v", err)
	}
	if len(urls) != 1 {
		t.Fatalf("got %d urls, want 1", len(urls))
	}
	if urls[0].Username != "alice" || urls[0].Password != "s3cret" {
		t.Errorf("credentials not applied: %q/%q", urls[0].Username, urls[0].Password)
	}
}

// TestValidTURNURLsRejectsSTUN 验证把 stun: 放进 TURNURLs 会被拒绝。
func TestValidTURNURLsRejectsSTUN(t *testing.T) {
	c := Config{
		TURNURLs:        []string{"stun:example.com:3478"},
		TURNCredentials: Credentials{Username: "a", Password: "b"},
	}
	if _, err := c.ValidTURNURLs(); err == nil {
		t.Fatal("a stun: URL was accepted as a TURN URL")
	}
}

// --- 信令编解码 ---

// TestSignalRoundTrip 验证信号编码后能原样解回。
func TestSignalRoundTrip(t *testing.T) {
	cands := []string{"cand1", "cand2"}
	s := NewSignal("FP123", "ufrag1", "pwd1", cands)
	text, err := encodeSignal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, "KTICE1:") {
		t.Errorf("encoded signal has no prefix: %q", text)
	}
	got, err := DecodeSignal(text)
	if err != nil {
		t.Fatalf("DecodeSignal: %v", err)
	}
	if got.Ufrag != "ufrag1" || got.Pwd != "pwd1" || got.Fingerprint != "FP123" {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if len(got.Candidates) != 2 || got.Candidates[1] != "cand2" {
		t.Errorf("candidates lost: %+v", got.Candidates)
	}
}

// TestDecodeSignalRejectsWrongPrefix 验证非本项目文本被拒绝。
func TestDecodeSignalRejectsWrongPrefix(t *testing.T) {
	for _, bad := range []string{"", "hello", "KTICE1", "ktice1:abc", "foo:YWJj"} {
		if _, err := DecodeSignal(bad); !errors.Is(err, ErrSignalFormat) {
			t.Errorf("DecodeSignal(%q) = %v, want ErrSignalFormat", bad, err)
		}
	}
}

// TestDecodeSignalRejectsBadBase64 验证前缀对但 base64 坏。
func TestDecodeSignalRejectsBadBase64(t *testing.T) {
	if _, err := DecodeSignal("KTICE1:!!!notbase64!!!"); err == nil {
		t.Fatal("bad base64 was accepted")
	}
}

// TestDecodeSignalRejectsMissingFields 验证缺凭据/候选被拒绝。
func TestDecodeSignalRejectsMissingFields(t *testing.T) {
	// 构造一个合法 base64 但缺 ufrag 的 JSON。
	bad := encodeRawForTest(t, `{"v":1,"ufrag":"","pwd":"x","candidates":["c"]}`)
	if _, err := DecodeSignal(bad); err == nil {
		t.Fatal("a signal with empty ufrag was accepted")
	}
	noCand := encodeRawForTest(t, `{"v":1,"ufrag":"u","pwd":"p","candidates":[]}`)
	if _, err := DecodeSignal(noCand); err == nil {
		t.Fatal("a signal with no candidates was accepted")
	}
}

// TestDecodeSignalRejectsFutureVersion 验证未来版本被明确拒绝。
func TestDecodeSignalRejectsFutureVersion(t *testing.T) {
	future := encodeRawForTest(t, `{"v":99,"ufrag":"u","pwd":"p","candidates":["c"]}`)
	if _, err := DecodeSignal(future); err == nil {
		t.Fatal("a future signal version was accepted")
	}
}

// TestSignalAge 验证年龄计算。
func TestSignalAge(t *testing.T) {
	s := NewSignal("fp", "u", "p", []string{"c"})
	now := time.Unix(s.CreatedAt, 0).Add(90 * time.Second)
	if got := s.Age(now); got != 90*time.Second {
		t.Errorf("Age = %v, want 90s", got)
	}
	// 时间戳在未来：夹到 0。
	if got := NewSignal("fp", "u", "p", []string{"c"}).Age(time.Unix(0, 0)); got != 0 {
		t.Errorf("Age of a future signal = %v, want 0", got)
	}
}
