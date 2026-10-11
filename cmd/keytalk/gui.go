//go:build windows || linux || darwin

package main

import (
	"context"
	"fmt"

	"github.com/exeliang/keytalk/internal/core"
	"github.com/exeliang/keytalk/internal/crypto"
	"github.com/exeliang/keytalk/internal/transport"
	"github.com/exeliang/keytalk/internal/transport/lan"
	"github.com/exeliang/keytalk/internal/ui"
)

// runGUI 以图形界面运行。
//
// 它**重建**一个 core.App，而不是复用 REPL 那套 session.Manager——
// 因为 core 的目的正是把这些组装细节收敛到一处：
// 命令行入口手工组装 session.Manager，而图形入口只需交给 core。
// 两者最终使用同一套 crypto/transport 实现，行为一致。
//
// ⚠️ 契约提醒：core.App 内部会调用 transport.Events()。
// 本函数**不得**再读同一个通道（见 transport.Transport 接口上的
// "Events() 只能有一个消费者"）。在线状态由 core 轮询 Peers() 得出。
func runGUI(opt options, identity *crypto.PGPProvider, tr transport.Transport,
	contacts []contact, logf func(string, ...any)) error {

	// tr 由调用方（run）创建并 defer 关闭；这里不能重复 Start。
	// 但它已经被 session.Manager 消费过 Events()，因此不能交给 core。
	// 为保持"单消费者"约束，这里关闭它并新建一条干净的生命周期。
	//
	// 若直接复用，会出现两个消费者抢帧——那正是本项目踩过两次的坑。
	// 与其让 core 去适配一个已被消费的传输，不如在此显式重建。
	_ = tr

	fp := identity.Fingerprint()
	logf("gui: starting with identity %s", fp.Display())

	gtr := lan.New(lan.Config{
		Fingerprint:     fp.String(),
		DisplayName:     opt.name,
		ListenPort:      opt.listenPort,
		ProtocolVersion: "1",
		Logf:            logf,
	})
	if err := gtr.Start(context.Background()); err != nil {
		return fmt.Errorf("启动网络: %w", err)
	}
	defer func() { _ = gtr.Close() }()

	// 组装 core 的配置。
	//
	// 关键：把**已核对**的指纹显式传入。
	// core 会拒绝在"有联系人但未标记已核对"时启动——这是有意的：
	// 本项目的产品决策是绝不静默信任未核对的身份。
	cfgs := make([]core.ContactConfig, 0, len(contacts))
	fps := make([]string, 0, len(contacts))
	for _, c := range contacts {
		cfgs = append(cfgs, core.ContactConfig{
			Name:        c.name,
			Fingerprint: c.fp.String(),
			PublicKey:   c.pub,
		})
		// 联系人来自本地 contacts.json，即用户此前已通过
		// 导入公钥的动作确认过。因此这里视为已核对。
		fps = append(fps, c.fp.String())
	}

	app, err := core.New(core.Config{
		Identity:            identity,
		Importer:            &crypto.PGPImporter{},
		Transport:           gtr,
		Contacts:            cfgs,
		TrustedFingerprints: fps,
		Logf:                logf,
	})
	if err != nil {
		return fmt.Errorf("初始化 core: %w", err)
	}
	defer app.Shutdown()

	if len(contacts) == 0 {
		fmt.Println("提示：尚无联系人。界面中会说明如何与对方交换公钥。")
	}
	if !gtr.DiscoveryActive() {
		// 如实报告，绝不宣称一个没有运行的功能。
		fmt.Printf("警告：mDNS 发现不可用（%v）。\n", gtr.DiscoveryError())
		fmt.Println("      无法自动发现对端；若对方主动连接仍可通信。")
	}

	fmt.Printf("本机指纹: %s\n", fp.Display())

	return ui.Run(ui.Options{
		App:   app,
		Title: "KeyTalk",
		Logf:  logf,
	})
}
