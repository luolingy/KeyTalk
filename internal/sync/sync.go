// Package sync 实现局域网内的聊天记录同步。
//
// # 只同步消息，不同步私钥
//
// 这是一个刻意的安全边界，不是未完成的功能。私钥一旦离开本机，
// 任何一台设备被攻破就等于整个身份被攻破——而且用户通常不会再
// 去想"那台旧手机"还在不在。同步消息则不同：消息本来就是双方
// 各自都有的东西，搬一份过去不扩大暴露面。
//
// 因此本包：
//   - 同步的是 Message（正文、方向、时间、状态、ID）；
//   - 绝不触及 identity.json、MK、私钥；
//   - 只在**已建立 E2EE 会话**的联系人之间进行（由调用方保证）。
//
// # 协议
//
// 同步是一个请求/响应，跑在已有的加密文本通道上：
//
//	发起方                          响应方
//	  --- SYNC_REQ {since, limit} -->      （我想要 since 之后的消息）
//	  <-- SYNC_RESP {messages, more} --   （给你这批，还有的话 more=true）
//	  --- SYNC_REQ {since=更晚} -->        （继续要下一批）
//	  ...
//	  <-- SYNC_RESP {messages, more=false}
//
// # 为什么按批次而不是一次全给
//
// 历史可能有几千条。一次全塞进一个加密帧会撞上传输层的帧大小上限，
// 也会让内存瞬间膨胀。按批（默认 200 条）拉，每批都是一个独立的
// 加密帧，失败只影响这一批。
//
// # 去重与冲突
//
// 合并不信任对端：消息按 ID 去重，同一 ID 两边都有时按
// "已发送 > 待发 > 失败"取状态更"确定"的那条；正文不同则保留本地
// 并记一条冲突，因为静默覆盖等于让对方改写你的历史。
package sync

import (
	"encoding/json"
	"fmt"
)

// 帧类型。
const (
	// TypeRequest 是"给我 since 之后的消息"。
	TypeRequest = "sync.req"
	// TypeResponse 是"这批给你"。
	TypeResponse = "sync.resp"
)

// DefaultBatchSize 是每批同步的消息条数上限。
const DefaultBatchSize = 200

// MaxBatchBytes 是单批响应的近似字节上限。
//
// 传输层的单帧硬上界是 wire.MaxFrame（1 MiB）。同步响应要编码
// 进一个加密帧，因此必须比它小，留出 JSON 键名、base64 与 AEAD
// 标签的余量。取 512 KiB 是保守值。
const MaxBatchBytes = 512 << 10

// Message 是同步线上表示的消息。
//
// 字段与 db.Message 一一对应，但刻意独立定义：线格式是协议，
// 磁盘格式是存储，两者的兼容性约束不同，绑在一起会让任何一方
// 的改动都变成破坏性变更。
type Message struct {
	ID       string `json:"id"`
	PeerFP   string `json:"peer_fp"`
	Outgoing bool   `json:"out"`
	Text     string `json:"text"`
	SentAtMS int64  `json:"at"`
	State    int    `json:"st"`
}

// Request 是同步请求。
type Request struct {
	Type string `json:"type"`
	// SinceMS 是"只要比这个时间更新的消息"。
	SinceMS int64 `json:"since"`
	// SinceID 与 SinceMS 一起构成游标，处理同一毫秒里的多条消息。
	//
	// 只用时间戳做游标会在"一毫秒内有多条消息"时打转：
	// 下一批的 since 等于上批最后一条的时间，那一条又会被重新选中。
	// 带上 ID 之后游标是严格全序的。
	SinceID string `json:"since_id,omitempty"`
	// Limit 是本批最多要多少条（0 表示用默认值）。
	Limit int `json:"limit,omitempty"`
}

// Response 是同步响应。
type Response struct {
	Type string `json:"type"`
	// Messages 是本批消息，按时间升序。
	Messages []Message `json:"messages"`
	// More 表示还有更多（发起方应当继续请求）。
	More bool `json:"more"`
	// CursorMS / CursorID 是下一批的游标（本批最后一条的时间与 ID）。
	CursorMS int64  `json:"cursor"`
	CursorID string `json:"cursor_id,omitempty"`
}

// EncodeRequest 序列化请求。
func EncodeRequest(r Request) ([]byte, error) {
	r.Type = TypeRequest
	return json.Marshal(r)
}

// EncodeResponse 序列化响应。
func EncodeResponse(r Response) ([]byte, error) {
	r.Type = TypeResponse
	return json.Marshal(r)
}

// frameProbe 用于判断一段字节是哪一类帧。
type frameProbe struct {
	Type string `json:"type"`
}

// Decode 判断帧类型并解出对应的结构。
//
// 返回的具体类型是 Request 或 Response。
func Decode(raw []byte) (any, error) {
	var probe frameProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("sync: malformed frame: %w", err)
	}
	switch probe.Type {
	case TypeRequest:
		var r Request
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("sync: malformed request: %w", err)
		}
		return r, nil
	case TypeResponse:
		var r Response
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("sync: malformed response: %w", err)
		}
		return r, nil
	default:
		// 未知类型不当作错误：对方可能说了别的话。
		// 调用方据此忽略而不是断开连接。
		return nil, fmt.Errorf("sync: unknown frame type %q", probe.Type)
	}
}

// IsSyncFrame 判断一段字节是否是同步帧。
//
// 同步帧和普通聊天消息共用一条文本通道，因此接收方必须先区分。
// 普通消息是纯文本，解析 JSON 会失败或没有 type 字段——两种情况
// 都返回 false，交回普通消息路径处理。
func IsSyncFrame(raw []byte) bool {
	var probe frameProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.Type == TypeRequest || probe.Type == TypeResponse
}

// BuildResponse 为一批消息构造响应。
//
// all 必须是按 (SentAtMS, ID) 升序的全部分消息。
// 游标是 (sinceMS, sinceID) 这一对：严格排在它之后的消息才入选。
// 只用时间戳会在同一毫秒内多条消息时来回打转。
func BuildResponse(all []Message, sinceMS int64, sinceID string, limit int) Response {
	if limit <= 0 {
		limit = DefaultBatchSize
	}

	// 过滤出游标之后的消息。比较函数与排序一致。
	after := func(m Message) bool {
		if m.SentAtMS != sinceMS {
			return m.SentAtMS > sinceMS
		}
		return m.ID > sinceID
	}
	pending := make([]Message, 0, len(all))
	for _, m := range all {
		if after(m) {
			pending = append(pending, m)
		}
	}

	resp := Response{Messages: []Message{}, CursorMS: sinceMS, CursorID: sinceID}
	if len(pending) == 0 {
		return resp
	}

	// 同时受条数与字节预算约束：单条超长消息也不能把一批撑爆，
	// 撑爆一帧会让整个同步批失败。
	var bytesSoFar int
	take := 0
	for take < len(pending) && take < limit {
		size := len(pending[take].Text) + len(pending[take].ID) + 64
		if take > 0 && bytesSoFar+size > MaxBatchBytes {
			break
		}
		bytesSoFar += size
		take++
	}
	if take == 0 {
		take = 1 // 单条就超预算：仍然发这一条，否则永久卡住
	}

	resp.Messages = pending[:take]
	last := pending[take-1]
	resp.CursorMS = last.SentAtMS
	resp.CursorID = last.ID
	resp.More = take < len(pending)
	return resp
}

// stateRank 给出状态的"确定性"排名：越大越确定。
//
// 已发送/已收到是终态，最确定；待发其次；失败最不确定
// （失败的消息可能在对端其实成功了）。
func stateRank(s int) int {
	switch s {
	case 1, 3: // StateSent, StateReceived
		return 3
	case 0: // StatePending
		return 2
	case 2: // StateFailed
		return 1
	default:
		return 0
	}
}

// Merger 把对端来的消息合并进本地。
//
// 不信任对端：按 ID 去重，冲突时保留更确定的状态与本地正文。
type Merger struct {
	// byID 是本地已有的消息（ID → 消息）。
	byID map[string]Message

	// applied 是本次合并真正新增或更新的消息。
	applied []Message
	// conflicts 是同一个 ID 但正文不同的情况。
	conflicts []Conflict
}

// Conflict 记录一条被拒绝的覆盖尝试。
type Conflict struct {
	ID     string
	Local  string
	Remote string
}

// NewMerger 用本地已有消息构造一个合并器。
func NewMerger(local []Message) *Merger {
	byID := make(map[string]Message, len(local))
	for _, m := range local {
		byID[m.ID] = m
	}
	return &Merger{byID: byID}
}

// Apply 合并一条对端消息。
//
// 规则：
//   - 没见过这个 ID：直接加入。
//   - 见过，正文相同：只在远端状态更确定时更新状态。
//   - 见过，正文不同：保留本地，记一条冲突（不静默覆盖）。
func (mg *Merger) Apply(remote Message) {
	if remote.ID == "" {
		return // 没有 ID 的消息无法去重，丢弃
	}
	local, exists := mg.byID[remote.ID]
	if !exists {
		mg.byID[remote.ID] = remote
		mg.applied = append(mg.applied, remote)
		return
	}

	if local.Text != remote.Text {
		// 同一个 ID 却是两段不同的话。这可能是哈希碰撞、也可能是
		// 对端在篡改。无论哪种，静默采用远端都等于让对方改写历史。
		mg.conflicts = append(mg.conflicts, Conflict{
			ID: remote.ID, Local: local.Text, Remote: remote.Text,
		})
		return
	}

	// 正文一致，只可能比状态。
	if stateRank(remote.State) > stateRank(local.State) {
		local.State = remote.State
		mg.byID[remote.ID] = local
		mg.applied = append(mg.applied, local)
	}
}

// Result 返回本次合并的结果。
func (mg *Merger) Result() (applied []Message, conflicts []Conflict) {
	return mg.applied, mg.conflicts
}

// All 返回合并后的完整消息集合。
func (mg *Merger) All() []Message {
	out := make([]Message, 0, len(mg.byID))
	for _, m := range mg.byID {
		out = append(out, m)
	}
	return out
}
