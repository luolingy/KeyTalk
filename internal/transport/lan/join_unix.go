//go:build !windows

package lan

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// joinGroupPlatform 在 Unix 上使用 x/net 的 ipv4/ipv6 包加入组播组。
//
// 带接口绑定（而非"默认接口"）是必须的：多网卡机器上，
// 不带接口的加入只会生效于系统路由表选中的那一个接口，
// 而 mDNS 要求在所有相关接口上都收发。
func joinGroupPlatform(uc *net.UDPConn, gaddr *net.UDPAddr, ifi net.Interface) error {
	if gaddr.IP.To4() != nil {
		p := ipv4.NewPacketConn(uc)
		// 设置组播接口 + TTL。
		if err := p.SetMulticastInterface(&ifi); err != nil {
			return err
		}
		// mDNS 要求 TTL=255（RFC 6762 §11）。
		_ = p.SetMulticastTTL(255)
		// 接收自己发出的组播（本机多实例测试需要）。
		_ = p.SetMulticastLoopback(true)
		if err := p.JoinGroup(&ifi, gaddr); err != nil {
			return err
		}
		return nil
	}

	p := ipv6.NewPacketConn(uc)
	if err := p.SetMulticastInterface(&ifi); err != nil {
		return err
	}
	_ = p.SetMulticastHopLimit(255)
	_ = p.SetMulticastLoopback(true)
	if err := p.JoinGroup(&ifi, gaddr); err != nil {
		return err
	}
	return nil
}
