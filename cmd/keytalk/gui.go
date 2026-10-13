//go:build windows || linux || darwin

package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/exeliang/keytalk/internal/core"
	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/transport/lan"
	"github.com/exeliang/keytalk/internal/ui"
)

// runGUI 以图形界面运行。
//
// # 与命令行入口的分工
//
// 命令行入口手工拼装 session.Manager；图形入口把组装交给 core。
// 两者最终跑的是同一套 crypto/transport 实现，行为一致。
//
// # 身份是延迟创建的
//
// 本函数**不**创建身份。身份由 core.Setup 在界面里创建、
// 导入或解锁——这样用户才有机会给私钥设口令，也才能从备份恢复。
// 传输层与 core.App 同样延迟到身份就绪后才建（见 BuildApp）。
//
// # 契约提醒
//
// core.App 内部会调用 transport.Events()。本函数**不得**再读
// 同一个通道（见 transport.Transport 接口上的"Events() 只能有
// 一个消费者"）。在线状态由 core 轮询 Peers() 得出。
// 这个坑本项目踩过三次，因此 gtr 只在 BuildApp 里创建一次。
func runGUI(ctx context.Context, opt options, logf func(string, ...any)) error {

	// netState 记录传输层的诊断信息，供界面的"配置信息"面板显示。
	//
	// 用互斥锁保护：BuildApp 由界面 goroutine 调用，
	// 而 NetInfoFunc 也在界面 goroutine 上被调用——理论上同属一个
	// goroutine，但 core.Setup 未来可能改变调用时机，
	// 加锁的代价可以忽略，漏掉它的代价是数据竞争。
	var (
		netMu        sync.Mutex
		listenAddr   string
		discoActive  bool
		discoErrText string
	)

	setup, err := core.NewSetup(core.SetupConfig{
		DataDir: opt.dataDir,
		Logf:    logf,
		BuildApp: func(sess core.SetupSession) (*core.App, error) {

			fp := sess.Identity.Fingerprint()

			gtr := lan.New(lan.Config{
				Fingerprint:     fp.String(),
				DisplayName:     opt.name,
				ListenPort:      opt.listenPort,
				ProtocolVersion: "1",
				Logf:            logf,
			})
			if err := gtr.Start(ctx); err != nil {
				return nil, fmt.Errorf("启动网络: %w", err)
			}

			netMu.Lock()
			listenAddr = gtr.LocalAddr().String()
			discoActive = gtr.DiscoveryActive()
			if !discoActive {
				// 如实报告，绝不宣称一个没有运行的功能。
				discoErrText = fmt.Sprintf("%v", gtr.DiscoveryError())
				logf("gui: WARNING mDNS discovery unavailable: %v", gtr.DiscoveryError())
			}
			netMu.Unlock()

			// 关键：把**已核对**的指纹显式传入。
			// core 会拒绝在"有联系人但未标记已核对"时启动——这是有意的：
			// 本项目的产品决策是绝不静默信任未核对的身份。
			//
			// 联系人要么来自本地 contacts.json（即用户此前导入公钥时
			// 确认过），要么来自界面里勾选了"已核对指纹"的添加动作。
			// 两条路都经过用户确认，因此这里全部视为已核对。
			fps := make([]string, 0, len(sess.Contacts))
			for _, c := range sess.Contacts {
				fps = append(fps, c.Fingerprint)
			}

			app, err := core.New(core.Config{
				Identity:            sess.Identity,
				Importer:            &crypto.PGPImporter{},
				Transport:           gtr,
				Contacts:            sess.Contacts,
				TrustedFingerprints: fps,
				Persist:             sess.Persist,
				Store:               sess.Store,
				Logf:                logf,
			})
			if err != nil {
				// 关掉刚起来的传输层，否则监听端口会泄漏到进程退出。
				_ = gtr.Close()
				return nil, fmt.Errorf("初始化 core: %w", err)
			}

			logf("gui: app ready, fingerprint %s, listening %s", fp.Display(), listenAddr)
			return app, nil
		},
	})
	if err != nil {
		return fmt.Errorf("初始化配置阶段: %w", err)
	}
	defer setup.Close()

	// 控制台上说清楚这一屏会做什么，方便命令行启动时排查。
	fmt.Printf("数据目录: %s\n", opt.dataDir)
	switch setup.Stage() {
	case core.StageNeedsIdentity:
		fmt.Println("尚无身份：界面中会引导你创建或从备份导入。")
	case core.StageNeedsUnlock:
		fmt.Println("身份已加密：界面中需要输入口令解锁。")
	default:
		fmt.Println("身份已就绪。")
	}

	return ui.Run(ui.Options{
		// App 故意留空：由 Setup 在身份就绪后组装。
		Setup: setup,
		Title: "KeyTalk",
		Logf:  logf,
		NetInfoFunc: func() ui.NetInfo {
			netMu.Lock()
			defer netMu.Unlock()
			return ui.NetInfo{
				ListenAddr:      listenAddr,
				DiscoveryActive: discoActive,
				DiscoveryError:  discoErrText,
			}
		},
	})
}
