package core

import (
	"testing"
	"time"
)

// TestPeerDisconnectIsDetected 验证对端进程退出后，
// 本端能观察到会话结束。
//
// 这个测试来自一个真实的用户报告："一个人显示已连接，
// 另一个人显示正在握手"。根因是状态**从不回落**：
// 对端消失后本端仍停留在 StatusSecure。
func TestPeerDisconnectIsDetected(t *testing.T) {
	p := setupPair(t)
	defer p.cleanup()

	waitForStatus(t, p.aliceApp, p.bobFP.String(), StatusSecure, 45*time.Second)
	waitForStatus(t, p.bobApp, p.aliceFP.String(), StatusSecure, 45*time.Second)
	t.Log("precondition: both sides secure")

	// bob 退出（模拟用户关掉窗口）。
	p.bobApp.Shutdown()
	t.Log("bob shut down; waiting for alice to notice")

	deadline := time.Now().Add(40 * time.Second)
	var last Contact
	for time.Now().Before(deadline) {
		c, _ := p.aliceApp.Contact(p.bobFP.String())
		last = c
		if c.Status != StatusSecure {
			t.Logf("alice noticed the disconnect: status=%v err=%q", c.Status, c.LastError)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("alice still reports StatusSecure %v after bob exited. "+
		"The status never falls back, so a dead peer looks connected. "+
		"last=%+v", time.Since(time.Now()), last)
}
