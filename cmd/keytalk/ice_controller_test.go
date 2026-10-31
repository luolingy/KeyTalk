package main

import (
	"context"
	"testing"
	"time"

	icetr "github.com/exeliang/keytalk/internal/transport/ice"
)

// prepareLoopback 给控制器换上一个 loopback 模式的底层 transport，
// 绕开 ensureTransport 的生产配置（那里不收集 loopback 候选）。
func prepareLoopback(t *testing.T, c *iceController) {
	t.Helper()
	tr := icetr.New(icetr.Config{Fingerprint: c.fingerprint})
	tr.EnableLoopbackForTest()
	if err := tr.Start(context.Background()); err != nil {
		t.Fatalf("starting loopback transport: %v", err)
	}
	c.chosen = nil
	c.pending = tr
}

// TestICEControllerOfferAndConnect 端到端验证界面背后的公网控制器：
// 两个控制器各自 GenerateOffer（拿到信令），再用对方的信令 Connect
// （一方 controlling，一方 accepting），最终双方都报告 Connected。
//
// 这是"公网连接面板"背后真正的逻辑通路——面板只是收集输入、
// 调用这些方法、展示结果。跑在 loopback 上，不依赖外部网络。
func TestICEControllerOfferAndConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	newCtl := func(fp string) *iceController {
		c := newICEController(options{}, func(string, ...any) {})
		c.setFingerprint(fp)
		return c
	}
	a := newCtl("CTRLAAA0")
	b := newCtl("CTRLBBB0")
	prepareLoopback(t, a)
	prepareLoopback(t, b)

	sigA, err := a.GenerateOffer(ctx)
	if err != nil {
		t.Fatalf("a.GenerateOffer: %v", err)
	}
	sigB, err := b.GenerateOffer(ctx)
	if err != nil {
		t.Fatalf("b.GenerateOffer: %v", err)
	}
	if !isSignal(sigA) || !isSignal(sigB) {
		t.Fatal("GenerateOffer did not produce KTICE1 signals")
	}

	// a 发起（controlling），b 接受（非 controlling）。二者必须并发，
	// 否则先跑的一方会卡在等待对端候选。
	errc := make(chan error, 2)
	go func() { _, e := a.Connect(ctx, sigB); errc <- wrap("a", e) }()
	go func() { _, e := b.accept(ctx, sigA); errc <- wrap("b", e) }()

	for i := 0; i < 2; i++ {
		select {
		case e := <-errc:
			if e != nil {
				t.Fatalf("connect: %v", e)
			}
		case <-ctx.Done():
			t.Fatal("timed out establishing the connection")
		}
	}

	if !a.Status().Connected {
		t.Error("a should report Connected")
	}
	if !b.Status().Connected {
		t.Error("b should report Connected")
	}
}

func wrap(who string, err error) error {
	if err == nil {
		return nil
	}
	return &namedErr{who: who, err: err}
}

type namedErr struct {
	who string
	err error
}

func (e *namedErr) Error() string { return e.who + ": " + e.err.Error() }

func isSignal(s string) bool {
	return len(s) > 7 && s[:7] == "KTICE1:"
}
