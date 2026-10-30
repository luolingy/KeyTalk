package core

import (
	"fmt"
	"path/filepath"

	"github.com/exeliang/keytalk/internal/db"
	"github.com/exeliang/keytalk/internal/storage"
)

// readLegacyLogFile 读取旧版单个 jsonl 日志并转成 db.Message。
//
// 直接复用 internal/storage 的读取实现，而不是在这里重写一遍
// 解密与 AAD 绑定：旧格式的 binding 是 "peerFP\0id\0state"，
// 任何一处细节写错都会让迁移静默丢消息。让唯一读过这个格式的
// 代码去读，比复制一份更安全。
func readLegacyLogFile(path, peerFP string, mk []byte) ([]db.Message, error) {
	// storage.Open 需要一个目录；这里把文件所在的 messages/
	// 目录传进去，再用它的 Load 读出全部。
	dir := filepath.Dir(filepath.Dir(path))
	st, err := storage.Open(dir, mk)
	if err != nil {
		return nil, fmt.Errorf("opening legacy store: %w", err)
	}
	defer st.Close()

	recs, err := st.Load()
	if err != nil {
		return nil, fmt.Errorf("loading legacy store: %w", err)
	}

	out := make([]db.Message, 0, len(recs))
	for _, r := range recs {
		// 旧记录可能属于别的会话文件；只取本次文件对应的。
		if r.PeerFP != peerFP {
			continue
		}
		out = append(out, db.Message{
			ID:       r.ID,
			PeerFP:   r.PeerFP,
			Outgoing: r.Outgoing,
			Text:     r.Text,
			SentAtMS: r.SentAt.UnixMilli(),
			// 旧状态值 0/1/2 与新 db 的常量一致；
			// 入站消息在旧层里就是 StateSent。
			State: r.State,
		})
	}
	return out, nil
}
