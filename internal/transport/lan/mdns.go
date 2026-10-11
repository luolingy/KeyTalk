package lan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// mDNS 协议常量（RFC 6762 / RFC 6763）。
const (
	// mdnsIPv4 是 mDNS 的 IPv4 组播地址 224.0.0.251。
	mdnsIPv4 = "224.0.0.251"

	// mdnsIPv6 是 mDNS 的 IPv6 组播地址 ff02::fb。
	mdnsIPv6 = "ff02::fb"

	// mdnsPort 是 mDNS 的标准端口 5353。
	mdnsPort = 5353

	// mdnsTTL 是 SRV/TXT 记录的推荐 TTL（RFC 6762 §10 建议 120 秒）。
	//
	// 选 120s 而非常见的 4500s：局域网内对端可能随时离线，
	// 过长的 TTL 会让"已离线的对端"长时间停留在发现列表里。
	mdnsTTL = 120

	// mdnsGoodbyeTTL 是"告别包"的 TTL（RFC 6762 §10.1）。
	// 发送 TTL=0 的记录表示"我要下线了"，让对端立即移除。
	mdnsGoodbyeTTL = 0

	// ServiceType 是本项目的 mDNS 服务类型（见 docs/transport-lan.md §3.1）。
	ServiceType = "_keytalk._tcp"

	// domain 是 mDNS 的域名后缀。
	domain = "local."
)

// TXT 记录的键名（见 docs/transport-lan.md §3.1）。
const (
	txtKeyFingerprint = "fp" // 完整 OpenPGP 指纹（仅用于筛选，不可信）
	txtKeyVersion     = "v"  // 协议版本
	txtKeyName        = "n"  // 显示名（用户自定义，可能重复）
)

// errNoInterfaces 表示本机没有任何可用的组播接口。
var errNoInterfaces = errors.New("lan: no multicast-capable interfaces")

// advertiser 负责 mDNS 的服务注册（对外宣告自己）。
//
// 它周期性发送 announcement，并在 Close 时发送 goodbye。
// 周期性重发是必要的：mDNS 是"无状态"的，晚加入的节点
// 若错过了初始 announcement，就不会知道我们存在。
type advertiser struct {
	service  string // 完整服务实例名，如 "keytalk-abc._keytalk._tcp.local."
	host     string // 主机名，如 "keytalk-abc.local."
	port     uint16
	txt      map[string]string
	conn     *mdnsConn
	interval time.Duration

	closeOnce sync.Once
	closed    chan struct{}
}

// mdnsConn 封装组播 socket 的收发。
//
// 需要同时处理 IPv4 与 IPv6：只用 IPv4 会在纯 IPv6 网络上失效，
// 且多网卡时需要往每个接口都发一遍。
//
// ⚠️ 关键设计点：**每个接口一个 socket**。
//
// 早期版本用一个 socket 并在循环里对每个接口调用
// SetMulticastInterface——那是个错误：该调用是**有状态的**，
// 循环结束后只有**最后一个**接口生效。在多网卡机器上
// （本机就有 WLAN、VMware、WSL、VPN 等多个接口），
// 于是宣告被发到 VMware/WSL 这类虚拟网卡上，真实局域网上的
// 对端什么也收不到——表现为"发现静默失败"。
type mdnsConn struct {
	conns []*mdnsSocket
}

// mdnsSocket 是绑定在**单个**接口上的组播 socket。
type mdnsSocket struct {
	uc   *net.UDPConn
	ifi  net.Interface
	ipv6 bool
}

// openMDNS 在每个可用接口上各建一个组播 socket。
//
// 绑定 5353 是 mDNS 的规范要求：响应必须从 5353 端口发出，
// 否则严格的对端会忽略（源端口校验）。
func openMDNS() (*mdnsConn, error) {
	mc := &mdnsConn{}
	var errs []string

	intf, err := multicastInterfaces()
	if err != nil {
		return nil, err
	}

	for _, ifi := range intf {
		ifi := ifi
		// IPv4：绝大多数局域网用这个。
		if s, err := listenMDNSOnInterface("udp4", mdnsIPv4, ifi, false); err == nil {
			mc.conns = append(mc.conns, s)
		} else {
			errs = append(errs, fmt.Sprintf("ipv4/%s: %v", ifi.Name, err))
		}
		// IPv6：失败不算致命（很多环境没有可用的 IPv6 组播）。
		if s, err := listenMDNSOnInterface("udp6", mdnsIPv6, ifi, true); err == nil {
			mc.conns = append(mc.conns, s)
		}
	}

	if len(mc.conns) == 0 {
		return nil, fmt.Errorf("lan: cannot join mDNS group: %s", strings.Join(errs, "; "))
	}
	return mc, nil
}

// listenMDNSOnInterface 在指定接口上创建一个加入组播组的 UDP socket。
//
// ⚠️ 必须设置 SO_REUSEADDR/SO_REUSEPORT。
//
// 原因：mDNS 规定服务监听 5353 端口，而同一台机器上通常**已经**有
// 别的进程占着它（Windows 的 Bonjour/Dnscache、Linux 的 Avahi、
// 或者同机的另一个 KeyTalk 实例），而我们自己也要为每个接口各建一个
// socket。没有 SO_REUSEADDR 时，第二个 socket 会 EADDRINUSE，
// 导致除第一个接口外全部失效。
//
// RFC 6762 §15.1 明确讨论了多进程共享 5353 的情形。
func listenMDNSOnInterface(network, group string, ifi net.Interface, ipv6 bool) (*mdnsSocket, error) {
	gaddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(group, fmt.Sprint(mdnsPort)))
	if err != nil {
		return nil, err
	}

	lc := net.ListenConfig{Control: reusePortControl}

	laddr := &net.UDPAddr{Port: mdnsPort}
	if ipv6 {
		laddr.IP = net.IPv6unspecified
	} else {
		laddr.IP = net.IPv4zero
	}

	pc, err := lc.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("lan: unexpected conn type %T", pc)
	}

	// 该 socket **专属于**这个接口：加入组播并设定发送接口。
	// 因为只有一个接口，就不存在"最后一个覆盖前面"的问题。
	if err := joinGroup(uc, gaddr, ifi); err != nil {
		_ = uc.Close()
		return nil, err
	}

	return &mdnsSocket{uc: uc, ifi: ifi, ipv6: ipv6}, nil
}

// multicastInterfaces 返回支持组播且已启用的接口。
//
// 必须过滤：
//   - 已 down 的接口
//   - 不支持组播的接口（如某些 VPN 隧道）
//   - loopback（除非是要做本机多实例测试，见 includeLoopback）
func multicastInterfaces() ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		if ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		out = append(out, ifi)
	}
	if len(out) == 0 {
		return nil, errNoInterfaces
	}
	return out, nil
}

// writeToAll 向**每个接口**各发一次。
//
// 必须逐接口发送：组播不会跨越接口（除非路由器显式转发），
// 只发一次的话，只有被路由表选中的那个接口上的对端能收到。
func (m *mdnsConn) writeToAll(b []byte) error {
	var lastErr error
	sent := false
	for _, s := range m.conns {
		group := mdnsIPv4
		network := "udp4"
		if s.ipv6 {
			group = mdnsIPv6
			network = "udp6"
		}
		dst, err := net.ResolveUDPAddr(network, net.JoinHostPort(group, fmt.Sprint(mdnsPort)))
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := s.uc.WriteToUDP(b, dst); err != nil {
			lastErr = err
			continue
		}
		sent = true
	}
	if !sent && lastErr != nil {
		return lastErr
	}
	return nil
}

// close 关闭所有 socket。
func (m *mdnsConn) close() error {
	var lastErr error
	for _, s := range m.conns {
		if err := s.uc.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// makeServiceName 构造 mDNS 服务实例名。
//
// 实例名必须唯一以避免冲突，故用指纹前 8 位做后缀。
// （完整指纹太长，会超出单个 DNS 标签 63 字节的限制，且没必要。）
func makeServiceName(fp string) string {
	short := fp
	if len(short) > 8 {
		short = short[:8]
	}
	return fmt.Sprintf("keytalk-%s.%s.%s", short, ServiceType, domain)
}

// makeHostName 构造主机名。
func makeHostName(fp string) string {
	short := fp
	if len(short) > 8 {
		short = short[:8]
	}
	return fmt.Sprintf("keytalk-%s.%s", short, domain)
}

// toDNSName 把点分名称转为 dnsmessage.Name。
func toDNSName(s string) (dnsmessage.Name, error) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return dnsmessage.Name{}, errors.New("lan: empty dns name")
	}
	return dnsmessage.NewName(s + ".")
}

// announcement 构造一条 mDNS 宣告（或告别）报文。
//
// 包含三条记录：
//   - PTR: _keytalk._tcp.local. -> 服务实例名   （让浏览器发现服务）
//   - SRV: 服务实例名 -> 主机名 + 端口           （告知端口）
//   - TXT: 服务实例名 -> 键值对                 （承载指纹等元数据）
//
// 全部放在 Answers 段：mDNS 的宣告是"自愿回答"（RFC 6762 §8.3），
// 不需要对应的问题。
func announcement(service, host string, port uint16, txt map[string]string, ttl uint32) ([]byte, error) {
	svcName, err := toDNSName(service)
	if err != nil {
		return nil, err
	}
	hostName, err := toDNSName(host)
	if err != nil {
		return nil, err
	}
	typeName, err := toDNSName(ServiceType + "." + domain)
	if err != nil {
		return nil, err
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		// mDNS 要求 ID 为 0（RFC 6762 §18.1）。
		ID: 0,
		// 响应报文：QR=1, AA=1（权威回答）。
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   false,
		RecursionAvailable: false,
	})
	b.EnableCompression()
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}

	// PTR：服务类型 -> 实例名
	if err := b.PTRResource(dnsmessage.ResourceHeader{
		Name:  typeName,
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
		TTL:   ttl,
	}, dnsmessage.PTRResource{
		PTR: svcName,
	}); err != nil {
		return nil, err
	}

	// SRV：实例名 -> 主机名 + 端口
	if err := b.SRVResource(dnsmessage.ResourceHeader{
		Name:  svcName,
		Type:  dnsmessage.TypeSRV,
		Class: dnsmessage.ClassINET,
		TTL:   ttl,
	}, dnsmessage.SRVResource{
		Priority: 0,
		Weight:   0,
		Port:     port,
		Target:   hostName,
	}); err != nil {
		return nil, err
	}

	// TXT：实例名 -> 元数据
	var txts []string
	for k, v := range txt {
		// TXT 单条字符串上限 255 字节；超长会导致编码失败。
		s := k + "=" + v
		if len(s) > 255 {
			s = s[:255]
		}
		txts = append(txts, s)
	}
	if len(txts) == 0 {
		// 至少要有一条（空 TXT），否则部分实现会忽略该记录。
		txts = []string{""}
	}
	if err := b.TXTResource(dnsmessage.ResourceHeader{
		Name:  svcName,
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
		TTL:   ttl,
	}, dnsmessage.TXTResource{TXT: txts}); err != nil {
		return nil, err
	}

	return b.Finish()
}

// queryPacket 构造一条 PTR 查询报文，用于主动询问"有哪些 keytalk 服务"。
//
// 主动查询是必要的：仅靠被动监听 announcement，后启动的节点
// 要等到对端下一次周期宣告才能发现对方。主动查询能立即获得响应。
func queryPacket() ([]byte, error) {
	typeName, err := toDNSName(ServiceType + "." + domain)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 0,
		Response:           false,
		Authoritative:      false,
		RecursionDesired:   false,
		RecursionAvailable: false,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  typeName,
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// parsedRecord 是从 mDNS 报文中提取出的一条服务记录。
type parsedRecord struct {
	Service  string
	Host     string
	Port     uint16
	TXT      map[string]string
	Addr     net.IP // 若报文来自 A/AAAA 记录
	TTL      uint32
	SourceIP net.IP // 发送方 IP，作为地址的兜底来源
}

// parseMDNS 解析一条 mDNS 报文，提取所有 keytalk 服务记录。
//
// 返回的切片可能为空（报文与本服务无关），这**不是**错误——
// 局域网里有大量其他 mDNS 流量（打印机、AirPlay 等）。
//
// srcIP 是报文的来源地址。mDNS 的 SRV 记录只给主机名不给 IP，
// 需要另外的 A 记录解析；本项目直接用来源 IP 作为连接地址，
// 这更简单也更可靠（避免额外的 A 查询往返）。
func parseMDNS(msg []byte, srcIP net.IP) ([]parsedRecord, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	// 只处理响应报文。
	if !hdr.Response {
		return nil, nil
	}

	if err := p.SkipAllQuestions(); err != nil {
		return nil, nil
	}

	// 按服务实例名聚合三条记录（PTR/SRV/TXT 分散在不同 Resource 中）。
	byService := map[string]*parsedRecord{}
	var order []string

	get := func(name string) *parsedRecord {
		if r, ok := byService[name]; ok {
			return r
		}
		r := &parsedRecord{TXT: map[string]string{}, SourceIP: srcIP}
		byService[name] = r
		order = append(order, name)
		return r
	}

	// 两类名称必须分别判断（这是很容易搞错的一点）：
	//
	//   PTR 记录的**名称**是服务类型本身：
	//       _keytalk._tcp.local.            ← 注意：前面没有点
	//   PTR 记录的**目标**（即服务实例名）才是：
	//       keytalk-AABBCCDD._keytalk._tcp.local.
	//
	//   而 SRV/TXT 记录的**名称**就是服务实例名。
	//
	// 早期版本用同一个 ".<type>.<domain>" 后缀去匹配两者，
	// 导致 PTR 记录被全部丢弃、一条都解析不出来。
	typeName := ServiceType + "." + domain         // _keytalk._tcp.local.
	instSuffix := "." + ServiceType + "." + domain // ._keytalk._tcp.local.

	isTypeName := func(s string) bool {
		return strings.EqualFold(strings.TrimSuffix(s, "."), strings.TrimSuffix(typeName, "."))
	}
	isInstanceName := func(s string) bool {
		return strings.HasSuffix(strings.ToLower(s), strings.ToLower(instSuffix))
	}

	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			break
		}

		switch rh.Type {
		case dnsmessage.TypePTR:
			res, err := p.PTRResource()
			if err != nil {
				return nil, err
			}
			// 本条 PTR 必须挂在我们的服务类型下。
			if !isTypeName(rh.Name.String()) {
				continue
			}
			name := res.PTR.String()
			if !isInstanceName(name) {
				continue
			}
			r := get(name)
			r.Service = name
			r.TTL = rh.TTL

		case dnsmessage.TypeSRV:
			res, err := p.SRVResource()
			if err != nil {
				return nil, err
			}
			if !isInstanceName(rh.Name.String()) {
				continue
			}
			r := get(rh.Name.String())
			r.Service = rh.Name.String()
			r.Host = res.Target.String()
			r.Port = res.Port
			r.TTL = rh.TTL

		case dnsmessage.TypeTXT:
			res, err := p.TXTResource()
			if err != nil {
				return nil, err
			}
			if !isInstanceName(rh.Name.String()) {
				continue
			}
			r := get(rh.Name.String())
			r.Service = rh.Name.String()
			r.TTL = rh.TTL
			for _, kv := range res.TXT {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					continue
				}
				r.TXT[k] = v
			}

		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}

	var out []parsedRecord
	for _, name := range order {
		r := byService[name]
		// 必须有端口才算有效记录（SRV 缺失则无法连接）。
		if r.Port == 0 {
			continue
		}
		out = append(out, *r)
	}
	return out, nil
}

// joinGroup 在指定接口上加入组播组。
//
// 各平台系统调用不同，由 build tag 分文件实现：
//   - join_unix.go: 使用 golang.org/x/net/ipv4/ipv6
//   - join_other.go: 退化为不带接口绑定的加入
func joinGroup(uc *net.UDPConn, gaddr *net.UDPAddr, ifi net.Interface) error {
	return joinGroupPlatform(uc, gaddr, ifi)
}

// readLoop 持续从所有 socket 读取报文并回调。
//
// 每个 socket 一个 goroutine：它们各自阻塞在读上，
// 合用一个 goroutine 会让慢接口拖住快接口。
func (m *mdnsConn) readLoop(ctx context.Context, onPacket func([]byte, net.IP)) {
	var wg sync.WaitGroup
	for _, s := range m.conns {
		wg.Add(1)
		go func(s *mdnsSocket) {
			defer wg.Done()
			buf := make([]byte, 9000) // 抖动容忍：mDNS 报文通常 <1500
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_ = s.uc.SetReadDeadline(time.Now().Add(time.Second))
				n, src, err := s.uc.ReadFromUDP(buf)
				if err != nil {
					// 超时是正常的（用于检查 ctx 取消）。
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					return
				}
				if n == 0 {
					continue
				}
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				onPacket(pkt, src.IP)
			}
		}(s)
	}
	wg.Wait()
}
