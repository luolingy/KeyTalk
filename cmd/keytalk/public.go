package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/session"
	"github.com/exeliang/keytalk/internal/transport"
	icetr "github.com/exeliang/keytalk/internal/transport/ice"
)

// runPublic 是公网（ICE）模式：没有会合服务器，信令靠用户手动搬运。
//
//	第一台： keytalk -ice-offer          → 打印一段 KTICE1:... 信令，发给对方
//	第二台： keytalk -ice-answer KTICE1:... → 建立连接
//
// 角色约定：**提供 answer 的一方是发起方（controlling）**。
// 这个约定必须固定，否则两端都以为自己是 controlling 或都不是，
// ICE 会卡在角色冲突上。
func runPublic(ctx context.Context, opt *options, fp crypto.Fingerprint,
	identity *crypto.PGPProvider, contacts []contact, logf func(string, ...any)) error {

	tr := icetr.New(icetr.Config{
		Fingerprint: fp.String(),
		STUNURLs:    splitList(opt.stun),
		TURNURLs:    splitList(opt.turn),
		TURNCredentials: icetr.Credentials{
			Username: opt.turnUser,
			Password: opt.turnPass,
		},
		Logf: logf,
	})

	if err := tr.Start(ctx); err != nil {
		return fmt.Errorf("启动公网传输: %w", err)
	}
	defer func() { _ = tr.Close() }()

	// --- 仅生成 offer：打印信令后退出 ---
	if opt.iceOffer && opt.iceAnswer == "" {
		sig, err := tr.LocalSignal(30 * time.Second)
		if err != nil {
			return fmt.Errorf("收集候选: %w", err)
		}
		fmt.Println("\n把下面整段文本发给对方（这是你的连接信令，不含私钥）：")
		fmt.Println()
		fmt.Println(sig)
		fmt.Println()
		fmt.Println("对方用下面这条命令连接你：")
		fmt.Printf("  keytalk -ice-answer %s\n", sig)
		return nil
	}

	// --- 用对方信令连接 ---
	peerSignal := strings.TrimSpace(opt.iceAnswer)
	// 允许用户把 "keytalk -ice-answer X" 整行粘进来：取出 KTICE1: 之后的部分。
	if i := strings.Index(peerSignal, "KTICE1:"); i > 0 {
		peerSignal = peerSignal[i:]
	}
	sig, err := icetr.DecodeSignal(peerSignal)
	if err != nil {
		return fmt.Errorf("对方信令无效: %w", err)
	}

	// 发起方：本端在 -ice-answer 里出现，所以 controlling=true。
	if err := tr.Connect(ctx, peerSignal, true); err != nil {
		return fmt.Errorf("建立连接: %w", err)
	}

	// 报告 NAT 状况——绝不能让用户在连不上时毫无线索。
	status := tr.NatStatus()
	fmt.Printf("\n✓ 已建立公网连接\n")
	fmt.Printf("  NAT 状况: %s\n", status.Detail)
	if status.PublicAddr != "" {
		fmt.Printf("  公网映射: %s\n", status.PublicAddr)
	}

	// 用 session.Manager 承载加密会话。
	mgr := session.New(session.Config{
		Identity:  identity,
		Importer:  &crypto.PGPImporter{},
		Transport: tr,
		Logf:      logf,
	})
	peerID := session.PeerID(sig.Fingerprint)
	var peerPub []byte
	for _, c := range contacts {
		if c.fp.String() == sig.Fingerprint {
			peerPub = c.pub
			break
		}
	}
	if peerPub == nil {
		return fmt.Errorf("对方指纹 %s 不在联系人里；请先用 -contact 导入其公钥", sig.Fingerprint)
	}
	mgr.AddPeer(peerID, session.PeerConfig{Fingerprint: crypto.Fingerprint(sig.Fingerprint), PublicKey: peerPub})
	mgr.SetTransportPeer(peerID, transport.PeerID(sig.Fingerprint))

	go mgr.Start(ctx)

	fmt.Println("\n输入消息回车发送；输入 /quit 退出。")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		// 先非阻塞地排空事件。
		drainPublicEvents(ctx, mgr)
		if !scanner.Scan() {
			return nil
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "/quit" || line == "/exit" {
			return nil
		}
		if line == "" {
			continue
		}
		if err := mgr.SendText(peerID, line); err != nil {
			fmt.Printf("  [发送失败] %v\n", err)
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

// drainPublicEvents 非阻塞地消费会话事件并打印。
func drainPublicEvents(ctx context.Context, mgr *session.Manager) {
	for {
		select {
		case ev, ok := <-mgr.Events():
			if !ok {
				return
			}
			if m, ok := ev.(session.Message); ok && m.Plaintext != nil {
				fmt.Printf("\n  对方: %s\n> ", m.Plaintext.Text)
			}
		default:
			return
		}
	}
}

// splitList 把逗号分隔的列表切成去空的切片。
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// newTraceID 生成一个短随机 ID（用于日志关联）。
func newTraceID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

var _ = newTraceID
