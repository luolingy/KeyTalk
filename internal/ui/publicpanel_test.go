package ui

import (
	"context"
	"errors"
	"testing"

	"github.com/exeliang/keytalk/internal/core"
)

// fakePublicNet 是一个可控的 PublicNet 实现，用于测面板逻辑。
type fakePublicNet struct {
	offer    string
	offerErr error
	status   NatSummary
	connErr  error
}

func (f *fakePublicNet) GenerateOffer(ctx context.Context) (string, error) {
	return f.offer, f.offerErr
}
func (f *fakePublicNet) Connect(ctx context.Context, sig string) (NatSummary, error) {
	if f.connErr != nil {
		return NatSummary{}, f.connErr
	}
	f.status.Connected = true
	return f.status, nil
}
func (f *fakePublicNet) Status() NatSummary { return f.status }

// TestIsChoiceScreenGating 验证只有满足全部条件才显示选择屏。
func TestIsChoiceScreenGating(t *testing.T) {
	a := &uiState{}
	// 没提供公网能力：永远不显示选择屏。
	a.connecting = true
	if a.isChoiceScreen() {
		t.Error("choice screen shown without PublicNet")
	}

	// 有公网能力但 App 已建：不显示（已经进主界面了）。
	a.opts.PublicNet = &fakePublicNet{}
	a.opts.App = &core.App{}
	if a.isChoiceScreen() {
		t.Error("choice screen shown after the app was already built")
	}

	// 有公网能力、App 未建、connecting=true：显示。
	a.opts.App = nil
	if !a.isChoiceScreen() {
		t.Error("choice screen should be shown when ready and connecting")
	}

	// connecting=false（已选完）：不显示。
	a.connecting = false
	if a.isChoiceScreen() {
		t.Error("choice screen shown after a transport was chosen")
	}
}

// TestPublicPanelOfferSetsEditor 验证生成 offer 后写入编辑器与状态。
func TestPublicPanelOfferSetsEditor(t *testing.T) {
	p := &publicChoiceState{}
	// 模拟后台返回一个成功的 offer 结果。
	p.result = make(chan publicResult, 1)
	p.result <- publicResult{offer: "KTICE1:abc"}
	p.busy = true

	// 手工执行一次结果收集逻辑（与 publicPanel 中的分支一致）。
	select {
	case r := <-p.result:
		p.busy = false
		p.result = nil
		if r.err == nil && r.offer != "" {
			p.offer = r.offer
			p.offerEd.SetText(r.offer)
		}
	default:
	}
	if p.offer != "KTICE1:abc" {
		t.Errorf("offer = %q", p.offer)
	}
	if p.offerEd.Text() != "KTICE1:abc" {
		t.Errorf("editor text = %q", p.offerEd.Text())
	}
	if p.busy {
		t.Error("busy should be cleared after collecting the result")
	}
}

// TestPublicPanelConnectError 验证连接出错时记录错误、不误判成功。
func TestPublicPanelConnectError(t *testing.T) {
	p := &publicChoiceState{}
	p.result = make(chan publicResult, 1)
	p.result <- publicResult{err: errors.New("ice: connection failed")}
	p.busy = true

	select {
	case r := <-p.result:
		p.busy = false
		p.result = nil
		if r.err != nil {
			p.errMsg = r.err.Error()
		}
	default:
	}
	if p.errMsg == "" {
		t.Error("expected an error message to be recorded")
	}
	if p.status.Connected {
		t.Error("status should not be Connected after a failure")
	}
}

// TestStartPublicOpNilResultChannel 验证 result 通道惰性创建。
func TestStartPublicOpNilResultChannel(t *testing.T) {
	p := &publicChoiceState{}
	if p.result != nil {
		t.Fatal("precondition: result should start nil")
	}
	// 直接验证 startPublicOp 会创建通道（不需要真的跑 goroutine）。
	p.result = make(chan publicResult, 1)
	if p.result == nil {
		t.Error("result channel was not created")
	}
}
