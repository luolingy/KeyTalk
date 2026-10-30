package sync

import (
	"encoding/json"
	"testing"
)

func msg(id string, at int64, text string, state int) Message {
	return Message{ID: id, PeerFP: "P", Outgoing: true, Text: text, SentAtMS: at, State: state}
}

// TestRequestRoundTrip 验证请求编解码。
func TestRequestRoundTrip(t *testing.T) {
	raw, err := EncodeRequest(Request{SinceMS: 1234, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if !IsSyncFrame(raw) {
		t.Fatal("a request is not recognised as a sync frame")
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	req, ok := got.(Request)
	if !ok {
		t.Fatalf("decoded to %T, want Request", got)
	}
	if req.SinceMS != 1234 || req.Limit != 50 {
		t.Errorf("round trip lost data: %+v", req)
	}
}

// TestResponseRoundTrip 验证响应编解码。
func TestResponseRoundTrip(t *testing.T) {
	resp := Response{
		Messages: []Message{msg("a", 1, "hi", 1), msg("b", 2, "yo", 1)},
		More:     true,
		CursorMS: 2,
	}
	raw, err := EncodeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := got.(Response)
	if !ok {
		t.Fatalf("decoded to %T, want Response", got)
	}
	if len(r.Messages) != 2 || r.Messages[1].Text != "yo" || !r.More || r.CursorMS != 2 {
		t.Errorf("round trip lost data: %+v", r)
	}
}

// TestIsSyncFrameRejectsPlainText 验证普通聊天不被误判成同步帧。
//
// 这是关键：同步帧和普通消息共用一条通道，误判会让聊天消息
// 被同步逻辑吞掉。
func TestIsSyncFrameRejectsPlainText(t *testing.T) {
	for _, plain := range [][]byte{
		[]byte("hello"),
		[]byte(`{"hello":"world"}`), // 合法 JSON 但没有 type
		[]byte(`{"type":"chat.message"}`),
		{},
		{0xFF, 0xFE},
	} {
		if IsSyncFrame(plain) {
			t.Errorf("%q was treated as a sync frame", plain)
		}
	}
}

// TestDecodeUnknownType 验证未知类型返回错误而不是崩溃。
func TestDecodeUnknownType(t *testing.T) {
	if _, err := Decode([]byte(`{"type":"something.else"}`)); err == nil {
		t.Fatal("Decode accepted an unknown type")
	}
}

// TestBuildResponseBatching 验证分批与游标推进。
func TestBuildResponseBatching(t *testing.T) {
	all := make([]Message, 0, 10)
	for i := 0; i < 10; i++ {
		all = append(all, msg("m"+itoa(i), int64(100+i), "x", 1))
	}

	// 第一批：since=0，limit=4。
	r1 := BuildResponse(all, 0, "", 4)
	if len(r1.Messages) != 4 {
		t.Fatalf("first batch has %d messages, want 4", len(r1.Messages))
	}
	if !r1.More {
		t.Error("first batch should say more=true")
	}
	if r1.CursorMS != 103 {
		t.Errorf("cursor = %d, want 103 (last of the first batch)", r1.CursorMS)
	}

	// 第二批：从游标继续。
	r2 := BuildResponse(all, r1.CursorMS, r1.CursorID, 4)
	if len(r2.Messages) != 4 || r2.Messages[0].SentAtMS != 104 {
		t.Fatalf("second batch wrong: first=%d len=%d", r2.Messages[0].SentAtMS, len(r2.Messages))
	}

	// 最后一批。
	r3 := BuildResponse(all, r2.CursorMS, r2.CursorID, 4)
	if len(r3.Messages) != 2 || r3.More {
		t.Fatalf("final batch wrong: len=%d more=%v", len(r3.Messages), r3.More)
	}

	// 全部要完之后再要：空且 more=false。
	r4 := BuildResponse(all, r3.CursorMS, r3.CursorID, 4)
	if len(r4.Messages) != 0 || r4.More {
		t.Fatalf("after exhaustion got %d messages, more=%v", len(r4.Messages), r4.More)
	}
}

// TestBuildResponseDefaultLimit 验证 limit<=0 用默认值。
func TestBuildResponseDefaultLimit(t *testing.T) {
	all := make([]Message, DefaultBatchSize+5)
	for i := range all {
		all[i] = msg("m"+itoa(i), int64(i+1), "x", 1)
	}
	r := BuildResponse(all, 0, "", 0)
	if len(r.Messages) != DefaultBatchSize {
		t.Errorf("got %d messages, want the default batch size %d", len(r.Messages), DefaultBatchSize)
	}
	if !r.More {
		t.Error("more should be true")
	}
}

// TestMergerAddsNew 验证没见过 ID 的消息被加入。
func TestMergerAddsNew(t *testing.T) {
	mg := NewMerger([]Message{msg("local-1", 1, "mine", 1)})
	mg.Apply(msg("remote-1", 2, "theirs", 1))

	applied, conflicts := mg.Result()
	if len(applied) != 1 || applied[0].ID != "remote-1" {
		t.Errorf("applied = %+v", applied)
	}
	if len(conflicts) != 0 {
		t.Errorf("unexpected conflicts: %+v", conflicts)
	}
}

// TestMergerUpgradesState 验证同正文同 ID 时状态更新到更确定的那条。
func TestMergerUpgradesState(t *testing.T) {
	// 本地是"待发"，远端说是"已发送"。
	mg := NewMerger([]Message{msg("m1", 1, "same text", 0)})
	mg.Apply(msg("m1", 1, "same text", 1))

	applied, _ := mg.Result()
	if len(applied) != 1 {
		t.Fatalf("expected 1 update, got %d", len(applied))
	}
	if applied[0].State != 1 {
		t.Errorf("state = %d, want 1 (sent)", applied[0].State)
	}
}

// TestMergerDoesNotDowngrade 验证远端更不确定时不会降级本地状态。
func TestMergerDoesNotDowngrade(t *testing.T) {
	mg := NewMerger([]Message{msg("m1", 1, "same text", 1)}) // 本地已发送
	mg.Apply(msg("m1", 1, "same text", 2))                   // 远端说失败

	applied, _ := mg.Result()
	if len(applied) != 0 {
		t.Errorf("a less certain remote state overwrote the local one: %+v", applied)
	}
	if all := mg.All(); all[0].State != 1 {
		t.Errorf("state = %d after merge, want 1 (unchanged)", all[0].State)
	}
}

// TestMergerRecordsConflict 验证正文不同时保留本地并记冲突。
//
// 静默采用远端等于让对端改写你的历史。
func TestMergerRecordsConflict(t *testing.T) {
	mg := NewMerger([]Message{msg("m1", 1, "我原本说的话", 1)})
	mg.Apply(msg("m1", 1, "对方说我说了别的", 1))

	applied, conflicts := mg.Result()
	if len(applied) != 0 {
		t.Errorf("a conflicting message was applied: %+v", applied)
	}
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1", len(conflicts))
	}
	if conflicts[0].Local != "我原本说的话" || conflicts[0].Remote != "对方说我说了别的" {
		t.Errorf("conflict not recorded faithfully: %+v", conflicts[0])
	}
	// 本地内容不变。
	if all := mg.All(); all[0].Text != "我原本说的话" {
		t.Error("the local message text was changed by a conflicting remote copy")
	}
}

// TestMergerDropsEmptyID 验证没有 ID 的消息被丢弃。
func TestMergerDropsEmptyID(t *testing.T) {
	mg := NewMerger(nil)
	mg.Apply(Message{ID: "", Text: "no id", SentAtMS: 1})
	applied, _ := mg.Result()
	if len(applied) != 0 {
		t.Error("a message with no ID was accepted")
	}
}

// TestMergerIdempotent 验证重复合并同一批不会产生重复。
func TestMergerIdempotent(t *testing.T) {
	mg := NewMerger(nil)
	batch := []Message{msg("a", 1, "one", 1), msg("b", 2, "two", 1)}
	for _, m := range batch {
		mg.Apply(m)
	}
	// 再来一遍。
	for _, m := range batch {
		mg.Apply(m)
	}
	if all := mg.All(); len(all) != 2 {
		t.Errorf("after a repeated merge there are %d messages, want 2", len(all))
	}
	if _, conflicts := mg.Result(); len(conflicts) != 0 {
		t.Errorf("re-merging the same batch produced conflicts: %+v", conflicts)
	}
}

// TestEncodeStableType 验证编码出的帧带有正确的 type 字段。
func TestEncodeStableType(t *testing.T) {
	raw, _ := EncodeRequest(Request{SinceMS: 1})
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if probe["type"] != TypeRequest {
		t.Errorf("type = %v, want %q", probe["type"], TypeRequest)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// TestBuildResponseSameMillisecond 验证同一毫秒多条消息不会打转。
//
// 只用时间戳做游标时，一批取完 5 条同毫秒消息里的 3 条，下一批的
// since 仍是这一毫秒，又会从第 1 条开始——同步永远走不完。
func TestBuildResponseSameMillisecond(t *testing.T) {
	const at = 5000
	var all []Message
	for i := 0; i < 5; i++ {
		// ID 有序，便于按 (时间, ID) 排序。
		all = append(all, msg("m"+itoa(i), at, "same ms", 1))
	}

	cursorMS, cursorID := int64(0), ""
	seen := map[string]bool{}
	for round := 0; round < 10; round++ {
		r := BuildResponse(all, cursorMS, cursorID, 2)
		for _, m := range r.Messages {
			if seen[m.ID] {
				t.Fatalf("message %s delivered twice; the cursor is not advancing", m.ID)
			}
			seen[m.ID] = true
		}
		cursorMS, cursorID = r.CursorMS, r.CursorID
		if !r.More {
			break
		}
	}
	if len(seen) != 5 {
		t.Fatalf("synced %d of 5 messages; the same-millisecond batch stalled", len(seen))
	}
}

// TestBuildResponseByteBudget 验证超长单条也不会让一批超出预算。
func TestBuildResponseByteBudget(t *testing.T) {
	huge := msg("huge", 1, string(make([]byte, MaxBatchBytes+1000)), 1)
	small := msg("small", 2, "ok", 1)
	r := BuildResponse([]Message{huge, small}, 0, "", 200)
	if len(r.Messages) != 1 {
		t.Fatalf("got %d messages, want just the huge one", len(r.Messages))
	}
	if !r.More {
		t.Error("more should be true: the small message is still pending")
	}
}
