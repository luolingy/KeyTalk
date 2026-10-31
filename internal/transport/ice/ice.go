// Package ice 实现"公网可直连"的传输层：基于 pion/ice 的 ICE 打洞，
// 失败时回落到用户自备的 TURN 中继。
//
// # 分工（与用户的约定）
//
//   - STUN：使用**公共**服务器（默认列表），用于发现自己的公网映射；
//   - TURN / 中继：由**用户自己配置**服务器地址与凭据；
//   - 没有自己的会合服务器：信令通过**用户手动搬运**的 offer/answer 完成
//     （见 signaling.go）。这是"零服务器、可公网连"的最低可行形态。
//
// # 为什么是 ICE 而不是"自己打洞"
//
// 打洞的难点不在"同时发包"，而在候选收集、连通性检查、优先级、
// 角色冲突处理、保活——这些 ICE（RFC 8445）已经解决。自己重造是负收益。
// pion/ice 是纯 Go 实现，与本项目其余部分一致。
//
// # 与 E2EE 的关系
//
// 本层只搬运**不透明字节**。它不 import crypto，也不知道内容是否加密。
// ICE 可能经 TURN 中继，中继服务器只能看到密文 UDP 包——
// 这与 docs/nat-traversal.md §10.1 的结论一致。
package ice

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pion/stun/v4"
)

// 编译期约束提示：本包不得 import internal/crypto。
// （Go 无法在包内断言"未 import 某包"，这条由 code review 与分层测试守护。）

// DefaultSTUNURLs 是默认的公共 STUN 服务器列表。
//
// 为什么是多个：单个 STUN 无法判断 NAT 行为，且任意一个都可能失效。
// 这些是社区常用的公共节点；它们**没有 SLA**，可能随时失效或限流。
// 失败时的行为必须是"明确报错/降级"，而不是静默假装直连成功。
//
// ⚠️ 我无法在离线环境核实这些节点的当前可用性、条款与限速策略。
// 上线前需自行验证；面向中国大陆用户时，公共 STUN 可达性无保障，
// 应优先自建（本项目约定：STUN 用公共，故此处只提供公共默认值）。
var DefaultSTUNURLs = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun1.l.google.com:19302",
	"stun:stun.cloudflare.com:3478",
}

// Config 是 ICE 传输层的配置。
type Config struct {
	// Fingerprint 是本机 OpenPGP 指纹（用于日志与对端标识，不作为认证）。
	Fingerprint string

	// STUNURLs 是 STUN 服务器列表。为空时用 DefaultSTUNURLs。
	//
	// 只应为 "stun:" 方案；含 "turn:" 的 URL 请放进 TURNURLs，
	// 以便把"免费反射"与"付费中继"在配置上分开（成本可见）。
	STUNURLs []string

	// TURNURLs 是用户自备的 TURN 服务器列表，形如：
	//
	//	turn:turn.example.com:3478?transport=udp
	//	turns:turn.example.com:5349
	//
	// 凭据通过 TURNCredentials 提供。
	TURNURLs []string

	// TURNCredentials 是 TURN 用户名/密码。
	TURNCredentials Credentials

	// PortMin / PortMax 是本地 UDP 端口范围（0 表示由系统分配）。
	//
	// 固定范围便于用户配置防火墙。
	PortMin, PortMax uint16

	// NetworkTypes 限定候选类型，默认 UDP4+UDP6。
	// 见 NetworkType 常量。
	Networks []NetworkType

	// Logf 是可选日志回调。
	Logf func(format string, args ...any)
}

// Credentials 是 TURN 凭据。
type Credentials struct {
	Username string
	Password string
}

// NetworkType 是本层支持的底层网络类型。
type NetworkType int

const (
	// NetworkUDP4 是 IPv4 UDP。
	NetworkUDP4 NetworkType = iota
	// NetworkUDP6 是 IPv6 UDP。
	NetworkUDP6
	// NetworkTCP4 是 IPv4 TCP（仅 TURN over TCP 用）。
	NetworkTCP4
	// NetworkTCP6 是 IPv6 TCP（仅 TURN over TCP 用）。
	NetworkTCP6
)

// ValidSTUNURLs 校验并返回 STUN URL 列表（空则用默认）。
func (c *Config) ValidSTUNURLs() ([]string, error) {
	urls := c.STUNURLs
	if len(urls) == 0 {
		urls = DefaultSTUNURLs
	}
	for _, u := range urls {
		if err := validateURL(u, "stun"); err != nil {
			return nil, err
		}
	}
	return urls, nil
}

// ValidTURNURLs 校验 TURN URL 与凭据。
//
// 返回 nil, nil 表示用户没有配置 TURN（即不使用中继）。
// 这是合法的：没有 TURN 时只能在能直连的网络里工作，
// 打洞失败就没有兜底——这必须让用户知情（见 NatStatus）。
func (c *Config) ValidTURNURLs() ([]*stun.URI, error) {
	if len(c.TURNURLs) == 0 {
		return nil, nil
	}
	if c.TURNCredentials.Username == "" || c.TURNCredentials.Password == "" {
		return nil, errors.New("ice: TURN URLs are configured but credentials are empty")
	}
	out := make([]*stun.URI, 0, len(c.TURNURLs))
	for _, raw := range c.TURNURLs {
		if err := validateURL(raw, "turn", "turns"); err != nil {
			return nil, err
		}
		u, err := stun.ParseURI(raw)
		if err != nil {
			return nil, fmt.Errorf("ice: parsing TURN URL %q: %w", raw, err)
		}
		// 凭据以配置为准，覆盖 URL 里可能出现的旧值。
		u.Username = c.TURNCredentials.Username
		u.Password = c.TURNCredentials.Password
		out = append(out, u)
	}
	return out, nil
}

// allURLs 把 STUN 与 TURN 合并成 AgentConfig.Urls 需要的形式。
func (c *Config) allURLs() ([]*stun.URI, error) {
	stunURLs, err := c.ValidSTUNURLs()
	if err != nil {
		return nil, err
	}
	out := make([]*stun.URI, 0, len(stunURLs)+len(c.TURNURLs))
	for _, raw := range stunURLs {
		u, err := stun.ParseURI(raw)
		if err != nil {
			return nil, fmt.Errorf("ice: parsing STUN URL %q: %w", raw, err)
		}
		out = append(out, u)
	}
	turnURLs, err := c.ValidTURNURLs()
	if err != nil {
		return nil, err
	}
	out = append(out, turnURLs...)
	return out, nil
}

// validateURL 校验一个 URL 的方案在允许集合内且可解析。
func validateURL(raw string, allowed ...string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("ice: empty URL")
	}
	// 提取 scheme。
	idx := strings.IndexByte(raw, ':')
	if idx <= 0 {
		return fmt.Errorf("ice: URL %q has no scheme", raw)
	}
	scheme := strings.ToLower(raw[:idx])
	ok := false
	for _, a := range allowed {
		if scheme == a {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("ice: URL %q has scheme %q, want one of %v", raw, scheme, allowed)
	}
	if _, err := stun.ParseURI(raw); err != nil {
		return fmt.Errorf("ice: malformed URL %q: %w", raw, err)
	}
	return nil
}

func (c *Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// NatStatus 描述本机当前的公网可达性状况，供 UI 如实展示。
//
// ⚠️ 存在的理由：STUN 全失败时，用户会**静默退化为"只能同局域网"**，
// 日志里只有一个 timeout，极难排查。把这个状态显式暴露出来，
// 是让用户知道"为什么连不上"的唯一办法。
type NatStatus struct {
	// STUNReachable 表示是否至少有一个 STUN 服务器返回了公网映射。
	STUNReachable bool
	// PublicAddr 是 STUN 反射得到的公网地址（"ip:port"），未知时为空。
	PublicAddr string
	// TurnConfigured 表示用户是否配置了 TURN（即是否有中继兜底）。
	TurnConfigured bool
	// Detail 是给用户看的说明。
	Detail string
}
