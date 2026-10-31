package ice

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// 信令 blob 的版本。
const signalingVersion = 1

// Signal 是一端交给对端的信息（offer 或 answer）。
//
// 因为本项目**没有会合服务器**，这段 JSON 由用户手动复制粘贴给对方
// （或经任何带外渠道传递，如已有联系人互发）。它不含任何私钥，
// 只含 ICE 凭据与候选地址——这些**可以被信令通道看到**的元数据，
// 与 docs/nat-traversal.md §8.3 声明的一致。
type Signal struct {
	Version int `json:"v"`
	// Fingerprint 是发出方的 OpenPGP 指纹，仅用于让人确认"这是谁"。
	Fingerprint string `json:"fp"`
	// Ufrag / Pwd 是本地 ICE 凭据。
	Ufrag string `json:"ufrag"`
	Pwd   string `json:"pwd"`
	// Candidates 是本地候选，每个是 pion Candidate.Marshal() 的字符串。
	Candidates []string `json:"candidates"`
	// CreatedAt 是生成时间（Unix 秒），便于人工判断是否过期。
	CreatedAt int64 `json:"ts"`
}

// ErrSignalFormat 表示信号文本不是本项目的格式。
var ErrSignalFormat = errors.New("ice: not a KeyTalk ICE signal")

// encodeSignal 把 Signal 编码成用户可复制粘贴的文本。
//
// 用 base64 包一层的原因：候选字符串里含 IP:port 与空格，
// 直接放 JSON 也能读，但整体包一层 base64 后是一个**单行、无空格**的
// 文本块，粘贴到任何聊天工具都不会被自动折行或转义破坏。
// 前缀 "KTICE1:" 让对端能一眼识别并拒绝无关内容。
func encodeSignal(s Signal) (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return "KTICE1:" + base64.StdEncoding.EncodeToString(raw), nil
}

// DecodeSignal 解析用户粘贴的信号文本。
func DecodeSignal(text string) (Signal, error) {
	text = trimSpace(text)
	const prefix = "KTICE1:"
	if len(text) <= len(prefix) || text[:len(prefix)] != prefix {
		return Signal{}, ErrSignalFormat
	}
	raw, err := base64.StdEncoding.DecodeString(text[len(prefix):])
	if err != nil {
		return Signal{}, fmt.Errorf("%w: bad base64: %v", ErrSignalFormat, err)
	}
	var s Signal
	if err := json.Unmarshal(raw, &s); err != nil {
		return Signal{}, fmt.Errorf("%w: bad JSON: %v", ErrSignalFormat, err)
	}
	if s.Version != signalingVersion {
		return Signal{}, fmt.Errorf("ice: signal version %d is not supported (this build speaks %d)",
			s.Version, signalingVersion)
	}
	if s.Ufrag == "" || s.Pwd == "" {
		return Signal{}, fmt.Errorf("%w: missing ICE credentials", ErrSignalFormat)
	}
	if len(s.Candidates) == 0 {
		return Signal{}, fmt.Errorf("%w: no candidates (did gathering finish?)", ErrSignalFormat)
	}
	return s, nil
}

// NewSignal 构造一个带当前时间的 Signal。
func NewSignal(fp, ufrag, pwd string, candidates []string) Signal {
	cp := make([]string, len(candidates))
	copy(cp, candidates)
	return Signal{
		Version: signalingVersion, Fingerprint: fp,
		Ufrag: ufrag, Pwd: pwd, Candidates: cp, CreatedAt: time.Now().Unix(),
	}
}

// Age 返回信号生成至今的时长；时间戳异常时返回 0。
func (s Signal) Age(now time.Time) time.Duration {
	if s.CreatedAt <= 0 {
		return 0
	}
	d := now.Sub(time.Unix(s.CreatedAt, 0))
	if d < 0 {
		return 0
	}
	return d
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
