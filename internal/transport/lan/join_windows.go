//go:build windows

package lan

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// joinGroupPlatform 在 Windows 上加入组播组。
//
// 与 Unix 的差异：Windows 上 SetMulticastInterface 需要接口的
// **索引**而非名称，x/net 的 ipv4/ipv6 包在 Windows 上会正确
// 处理这一转换，因此这里的代码与 Unix 一致。
//
// 已知平台差异（不影响正确性）：
//   - Windows 默认会在所有接口上接收组播，未加入的接口也可能收到；
//   - 防火墙可能拦截入站组播，首次运行会弹窗询问。
//     这是 docs/transport-lan.md §10 提到的用户提示来源。
func joinGroupPlatform(uc *net.UDPConn, gaddr *net.UDPAddr, ifi net.Interface) error {
	if gaddr.IP.To4() != nil {
		p := ipv4.NewPacketConn(uc)
		if err := p.SetMulticastInterface(&ifi); err != nil {
			return err
		}
		// mDNS 要求 TTL=255（RFC 6762 §11）。
		_ = p.SetMulticastTTL(255)
		// 接收自己发出的组播（本机多实例测试需要）。
		_ = p.SetMulticastLoopback(true)
		return p.JoinGroup(&ifi, gaddr)
	}

	p := ipv6.NewPacketConn(uc)
	if err := p.SetMulticastInterface(&ifi); err != nil {
		return err
	}
	_ = p.SetMulticastHopLimit(255)
	_ = p.SetMulticastLoopback(true)
	return p.JoinGroup(&ifi, gaddr)
}
