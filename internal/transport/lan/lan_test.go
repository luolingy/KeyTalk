package lan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/exeliang/keytalk/internal/transport"
)

// --- mDNS 报文编解码 ---

func TestAnnouncementRoundTrip(t *testing.T) {
	fp := "AABBCCDDEEFF00112233445566778899AABBCCDD"
	txt := map[string]string{
		txtKeyFingerprint: fp,
		txtKeyVersion:     "1",
		txtKeyName:        "Alice 的电脑",
	}

	pkt, err := announcement(makeServiceName(fp), makeHostName(fp), 4242, txt, mdnsTTL)
	if err != nil {
		t.Fatalf("announcement: %v", err)
	}

	recs, err := parseMDNS(pkt, net.ParseIP("192.168.1.50"))
	if err != nil {
		t.Fatalf("parseMDNS: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}

	r := recs[0]
	if r.Port != 4242 {
		t.Errorf("port = %d, want 4242", r.Port)
	}
	if got := r.TXT[txtKeyFingerprint]; got != fp {
		t.Errorf("fingerprint = %q, want %q", got, fp)
	}
	if got := r.TXT[txtKeyName]; got != "Alice 的电脑" {
		t.Errorf("display name = %q (non-ASCII may be mangled)", got)
	}
	if r.Host != makeHostName(fp) {
		t.Errorf("host = %q, want %q", r.Host, makeHostName(fp))
	}
	if r.SourceIP == nil || r.SourceIP.String() != "192.168.1.50" {
		t.Errorf("source ip = %v, want 192.168.1.50", r.SourceIP)
	}
}

func TestParseIgnoresQueriesAndForeignServices(t *testing.T) {
	// 查询报文不是响应，应被忽略。
	q, err := queryPacket()
	if err != nil {
		t.Fatal(err)
	}
	recs, err := parseMDNS(q, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("query produced %d records, want 0", len(recs))
	}

	// 与本服务无关的报文（例如打印机）不应产生记录。
	other, err := announcement("printer._ipp._tcp.local.", "printer.local.", 631,
		map[string]string{"ty": "LaserJet"}, mdnsTTL)
	if err != nil {
		t.Fatal(err)
	}
	recs, err = parseMDNS(other, net.ParseIP("10.0.0.2"))
	if err != nil {
		t.Fatalf("parse foreign: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("foreign service produced %d records, want 0", len(recs))
	}
}

// 关键健壮性用例：畸形报文绝不能导致 panic（网络输入不可信）。
func TestParseMDNSMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x00},
		{0xff, 0xff, 0xff, 0xff},
		bytes.Repeat([]byte{0xAA}, 100),
		append([]byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0x03, 0xff, 0xff, 0xff),
		// 声明大量记录但无内容。
		{0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			_, _ = parseMDNS(c, net.ParseIP("127.0.0.1"))
		}()
	}
}

func TestServiceAndHostNames(t *testing.T) {
	fp := "AABBCCDDEEFF0011"
	if got := makeServiceName(fp); got != "keytalk-AABBCCDD._keytalk._tcp.local." {
		t.Errorf("service name = %q", got)
	}
	if got := makeHostName(fp); got != "keytalk-AABBCCDD.local." {
		t.Errorf("host name = %q", got)
	}
	// 短指纹不应 panic（切片越界）。
	if got := makeServiceName("AB"); got != "keytalk-AB._keytalk._tcp.local." {
		t.Errorf("short fp service name = %q", got)
	}
}

// --- 帧编解码与并发安全 ---

func TestWriteReadFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello 世界 frame payload")
	if err := writeFrame(&buf, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestReadFrameRejectsOversizeDeclaration(t *testing.T) {
	// 恶意对端声明 4 GiB：必须在分配内存**之前**拒绝。
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0xFFFFFFFF)
	buf.Write(hdr[:])

	_, err := readFrame(&buf)
	if !errors.Is(err, transport.ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameRejectsZeroLength(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})
	if _, err := readFrame(&buf); err == nil {
		t.Fatal("zero-length frame must be rejected")
	}
}

func TestWriteFrameRejectsOversizePayload(t *testing.T) {
	var buf bytes.Buffer
	big := make([]byte, transport.MaxFrameSize+1)
	if err := writeFrame(&buf, big); !errors.Is(err, transport.ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFramePartialThenEOF(t *testing.T) {
	var buf bytes.Buffer
	// 声明 100 字节但只给 10 字节。
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100)
	buf.Write(hdr[:])
	buf.Write(bytes.Repeat([]byte{1}, 10))

	if _, err := readFrame(&buf); err == nil {
		t.Fatal("truncated frame must error")
	}
}

// 粘包：多个帧连续写入必须能逐个正确取出。
func TestReadFrameConsecutive(t *testing.T) {
	var buf bytes.Buffer
	payloads := [][]byte{[]byte("first"), []byte("second"), []byte("third")}
	for _, p := range payloads {
		if err := writeFrame(&buf, p); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range payloads {
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d = %q, want %q", i, got, want)
		}
	}
	if _, err := readFrame(&buf); err != io.EOF {
		t.Fatalf("after last frame err = %v, want EOF", err)
	}
}

// 逐字节投递（模拟 TCP 分片）必须仍能正确解析。
type dripReader struct {
	data []byte
	pos  int
}

func (d *dripReader) Read(p []byte) (int, error) {
	if d.pos >= len(d.data) {
		return 0, io.EOF
	}
	p[0] = d.data[d.pos]
	d.pos++
	return 1, nil
}

func TestReadFrameByteByByte(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("split across many reads")
	if err := writeFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&dripReader{data: buf.Bytes()})
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("mismatch: %q", got)
	}
}

// --- 传输层契约 ---

// 守护解耦约束：lan 不得 import wire，但两者的帧上限必须一致。
// 不一致会导致静默截断——这是最难排查的一类 bug。
func TestMaxFrameSizeContract(t *testing.T) {
	if transport.MaxFrameSize != 1<<20 {
		t.Fatalf("transport.MaxFrameSize = %d, want 1 MiB (must match wire.MaxFrame)",
			transport.MaxFrameSize)
	}
}

func TestNewRequiresFingerprint(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("New without fingerprint must panic (rather than fabricate an identity)")
		}
	}()
	_ = New(Config{})
}

func TestSendRejectsOversizeFrame(t *testing.T) {
	tr := New(Config{Fingerprint: "AABB", ListenPort: 0})
	defer func() { _ = tr.Close() }()

	big := make([]byte, transport.MaxFrameSize+1)
	if err := tr.Send("somepeer", big); !errors.Is(err, transport.ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

func TestSendToUnknownPeer(t *testing.T) {
	tr := New(Config{Fingerprint: "AABB", ListenPort: 0})
	defer func() { _ = tr.Close() }()

	if err := tr.Send("nobody", []byte("x")); !errors.Is(err, transport.ErrPeerUnknown) {
		t.Fatalf("err = %v, want ErrPeerUnknown", err)
	}
}

// --- 真实进程内双实例互通（不依赖 mDNS，直接连接） ---

func TestTwoTransportsExchangeFrames(t *testing.T) {
	alice := New(Config{
		Fingerprint: "AAAA000000000000000000000000000000000000",
		ListenPort:  0,
	})
	if err := alice.Start(t.Context()); err != nil {
		t.Fatalf("alice start: %v", err)
	}
	defer func() { _ = alice.Close() }()

	bob := New(Config{
		Fingerprint: "BBBB111111111111111111111111111111111111",
		ListenPort:  0,
	})
	if err := bob.Start(t.Context()); err != nil {
		t.Fatalf("bob start: %v", err)
	}
	defer func() { _ = bob.Close() }()

	aliceAddr, ok := alice.LocalAddr().(*net.TCPAddr)
	if !ok {
		t.Fatal("alice has no TCP addr")
	}

	// 手工注入 Bob 的地址（绕过 mDNS：本用例只验证 TCP 通路）。
	alice.mu.Lock()
	alice.byAddr[aliceAddr.String()] = "bob"
	alice.mu.Unlock()

	bobID := transport.PeerID("bob")
	bob.mu.Lock()
	bob.peers[bobID] = &transport.PeerInfo{
		ID:          bobID,
		Fingerprint: string(bobID),
		Addrs:       []net.Addr{aliceAddr},
		LastSeen:    time.Now(),
	}
	bob.mu.Unlock()

	// Bob -> Alice
	payload := []byte("encrypted-frame-bytes")
	if err := bob.Send(bobID, payload); err != nil {
		t.Fatalf("bob send: %v", err)
	}

	// Alice 应收到 FrameReceived。
	// 之前可能先收到 ConnOpened（连接建立事件），需要跳过——
	// 这是正常的时序，不是错误。
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-alice.Events():
			switch e := ev.(type) {
			case transport.ConnOpened:
				continue // 连接建立事件，继续等帧
			case transport.FrameReceived:
				if !bytes.Equal(e.Frame, payload) {
					t.Fatalf("frame = %q, want %q", e.Frame, payload)
				}
				return // 成功
			default:
				continue
			}
		case <-deadline:
			t.Fatal("timeout waiting for frame")
		}
	}
}

func TestConcurrentSendsDoNotInterleave(t *testing.T) {
	a := New(Config{Fingerprint: "AAAA", ListenPort: 0})
	if err := a.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	b := New(Config{Fingerprint: "BBBB", ListenPort: 0})
	if err := b.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()

	addr := a.LocalAddr().(*net.TCPAddr)
	const peer = transport.PeerID("p")
	b.mu.Lock()
	b.peers[peer] = &transport.PeerInfo{ID: peer, Addrs: []net.Addr{addr}, LastSeen: time.Now()}
	b.mu.Unlock()

	// 先建立连接，再并发发送。
	//
	// 为什么要先握手式地发一帧：connFor 是**惰性**建连的，
	// 首个 Send 才触发 TCP 拨号。若直接并发五十个 Send，
	// 它们会同时争夺建连，部分调用会因"尚未连上"而失败——
	// 那是并发建连的竞态，与本用例要验证的"帧不分片交错"无关。
	if err := b.Send(peer, []byte("warmup")); err != nil {
		t.Fatalf("warmup send failed: %v", err)
	}
	// 等连接稳定（warmup 帧到达即证明）。
	//
	// ⚠️ 必须等到真正的 FrameReceived，而不是随便一个事件：
	// 连接建立会先产生 ConnOpened。若提前返回，
	// 后面会把 warmup 帧当成并发帧之一（表现为"帧损坏"误报）。
	warmupDeadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-a.Events():
			if fr, ok := ev.(transport.FrameReceived); ok {
				if string(fr.Frame) == "warmup" {
					goto established
				}
				continue
			}
		case <-warmupDeadline:
			t.Fatal("warmup frame never arrived; connection not established")
		}
	}
established:

	// 并发发送大量帧：若 len 前缀与载荷不是原子写入，
	// 接收侧会解析出损坏的帧。
	//
	// 注意：发送队列有界（DefaultSendQueue=64），队列满时 Send 返回错误
	// 而不是阻塞或静默丢弃——这是**有意的背压设计**。
	// 因此本用例统计"成功发送的帧数"，并验证收到的每一帧都完整未损坏。
	//
	// 并发度刻意小于队列长度，以尽量减少背压淘汰——
	// 本用例要验证的是**帧完整性**，不是背压行为（后者另有覆盖）。
	const n = 50
	var sent atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		body := bytes.Repeat([]byte{byte(i)}, 1000+i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := b.Send(peer, body); err == nil {
				sent.Add(1)
			}
		}()
	}
	wg.Wait()

	want := int(sent.Load())
	if want == 0 {
		t.Fatal("no frames were sent successfully")
	}
	t.Logf("accepted %d/%d frames (remainder rejected by backpressure, which is by design)", want, n)

	seen := 0
	deadline := time.After(20 * time.Second)
	for seen < want {
		select {
		case ev := <-a.Events():
			if fr, ok := ev.(transport.FrameReceived); ok {
				// 每帧必须是同一字节重复（验证无交错）。
				if len(fr.Frame) == 0 {
					t.Fatal("empty frame")
				}
				first := fr.Frame[0]
				for _, x := range fr.Frame {
					if x != first {
						t.Fatalf("frame corrupted (interleaved): first=%d found=%d", first, x)
					}
				}
				seen++
			}
		case <-deadline:
			t.Fatalf("timeout: got %d/%d frames (all received frames were intact)", seen, want)
		}
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	tr := New(Config{Fingerprint: "AAAA", ListenPort: 0})
	if err := tr.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := tr.Close(); err != nil && i == 0 {
			// 首次 Close 也不应报错。
			t.Fatalf("close %d: %v", i, err)
		}
	}
}

func TestSendAfterClose(t *testing.T) {
	tr := New(Config{Fingerprint: "AAAA", ListenPort: 0})
	if err := tr.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = tr.Close()
	if err := tr.Send("x", []byte("y")); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

// --- TXT 记录边界 ---

func TestAnnouncementLongTXTTruncated(t *testing.T) {
	fp := strings.Repeat("A", 300)
	pkt, err := announcement(makeServiceName("AAAA"), makeHostName("AAAA"), 1234,
		map[string]string{txtKeyFingerprint: fp}, mdnsTTL)
	if err != nil {
		t.Fatalf("announcement with very long TXT: %v", err)
	}
	// 不应 panic，且能解析出（被截断的）记录。
	recs, err := parseMDNS(pkt, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
}

// TestStripZone 验证 IPv6 zone 标识被正确剥离。
//
// 这是实测踩到的坑：Windows 上链路本地地址的 RemoteAddr() 形如
//
//	169.254.201.140%VMware Network Adapter VMnet8:62733
//
// 含空格与中文。它被当作 peerID（事件路由的键）后，
// 会导致帧收到了却无法归属到会话，表现为握手静默超时。
func TestStripZone(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// 无 zone：原样返回。
		{"192.168.1.8:8080", "192.168.1.8:8080"},
		{"[fe80::1]:5353", "[fe80::1]:5353"},
		// IPv6 + zone（简单接口名）。
		{"[fe80::1%eth0]:5353", "[fe80::1]:5353"},
		// Windows 接口名含空格——必须正确切分。
		{"169.254.201.140%VMware Network Adapter VMnet8:62733", "169.254.201.140:62733"},
		{"[fe80::a564:7fb4:89cf:2a9%vEthernet (Default Switch)]:61344", "[fe80::a564:7fb4:89cf:2a9]:61344"},
		// 只有 zone 没有端口。
		{"fe80::1%eth0", "fe80::1"},
	}
	for _, c := range cases {
		if got := stripZone(c.in); got != c.want {
			t.Errorf("stripZone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestIsIPv6Addr 验证地址族判断，确保拨号时能优先选 IPv4。
//
// 优先 IPv4 的理由：IPv6 链路本地地址需要 zone 才能路由，
// 且跨机器时容易与实际建立的那条 TCP 连接对不上（见实现笔记 §4.8）。
func TestIsIPv6Addr(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"192.168.1.8:8080", false},
		{"127.0.0.1:9000", false},
		{"169.254.38.107:1234", false}, // IPv4 链路本地仍是 IPv4
		{"[fe80::1]:5353", true},
		{"[fe80::1%eth0]:5353", true}, // 带 zone 也要认出来
		{"[2408:825c::1]:443", true},
		{"[::1]:80", true},
	}
	for _, c := range cases {
		addr := mustAddr(t, "tcp", c.in)
		if got := isIPv6Addr(addr); got != c.want {
			t.Errorf("isIPv6Addr(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func mustAddr(t *testing.T, network, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr(network, s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return a
}
