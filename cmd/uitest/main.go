//go:build windows || linux || darwin

// 命令 uitest 是 S7 的验证工具：确认 Gio 界面能真正创建窗口并渲染中文。
//
// 它**不是**产品的一部分。存在的理由是把两个高风险假设
// 在投入完整界面之前先验证掉：
//
//	(a) 窗口能在本机创建（D3D11/OpenGL 后端可用）；
//	(b) 中文字体能被找到并渲染（Gio 内置字体**不含** CJK 字形）。
//
// 用法：
//
//	go run ./cmd/uitest -d 5s       # 开窗渲染 5 秒后自动退出
//	go run ./cmd/uitest -headless   # 只构建，不开窗（CI 用）
//
// 之所以能用"存活 N 秒"当作通过标准：Gio 没有截图/内省接口，
// 但窗口创建失败或字体加载失败都会**立即**报错或崩溃。
// 因此"稳定渲染满 N 秒且无错误输出"是这两个假设的有效证据。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/exeliang/keytalk/internal/core"
	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/transport/lan"
	"github.com/exeliang/keytalk/internal/ui"
)

func main() {
	dur := flag.Duration("d", 5*time.Second, "keep the window open for this long")
	headless := flag.Bool("headless", false, "validate setup without opening a window")
	name := flag.String("name", "uitest", "identity name for the throwaway test identity")
	flag.Parse()

	// 用**一次性**身份与空联系人列表启动。
	//
	// 刻意不连真实对端：本 spike 只想验证"界面能画出来"，
	// 引入网络会让失败原因变得难以区分（是界面问题还是网络问题？）。
	// 端到端行为已由 e2e.ps1 与 internal/e2e 覆盖。
	id, err := crypto.GeneratePGPIdentity(crypto.PGPConfig{
		Name: *name, Email: *name + "@uitest.local", RSABits: 1024,
	})
	if err != nil {
		fmt.Printf("UITEST_FAILED identity: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = id.Close() }()

	tr := lan.New(lan.Config{
		Fingerprint: id.Fingerprint().String(),
		DisplayName: *name,
		ListenPort:  0,
		// 不启用 loopback 发现：本 spike 不需要发现任何对端，
		// 开着只会与可能同时在跑的真实实例互相干扰。
		IncludeLoopback: false,
	})
	if err := tr.Start(context.Background()); err != nil {
		fmt.Printf("UITEST_FAILED transport: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = tr.Close() }()

	app, err := core.New(core.Config{
		Identity:  id,
		Importer:  &crypto.PGPImporter{},
		Transport: tr,
		Logf:      func(f string, a ...any) { log.Printf(f, a...) },
	})
	if err != nil {
		fmt.Printf("UITEST_FAILED core: %v\n", err)
		os.Exit(1)
	}
	defer app.Shutdown()

	fmt.Printf("UITEST_FINGERPRINT %s\n", id.Fingerprint().Display())

	if *headless {
		fmt.Println("UITEST_HEADLESS_OK (window not opened)")
		return
	}

	fmt.Println("UITEST_START opening window...")

	// 到点自动退出。Gio 没有内建定时退出，而本 spike 需要能被脚本
	// 无人值守地验证，不能依赖人工关窗。
	go func() {
		time.Sleep(*dur)
		fmt.Println("UITEST_RENDERED_OK window stayed up for", *dur)
		os.Exit(0)
	}()

	if err := ui.Run(ui.Options{App: app, Title: "KeyTalk (UI test)"}); err != nil {
		fmt.Printf("UITEST_FAILED %v\n", err)
		os.Exit(1)
	}
	fmt.Println("UITEST_WINDOW_CLOSED")
}
