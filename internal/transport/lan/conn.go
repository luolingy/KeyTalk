// Package lan 实现基于 mDNS 发现 + TCP 的局域网传输层。
//
// 这是 transport.Transport 的首期实现。它只搬运不透明的帧，
// 不理解也不需要理解帧的内容（E2EE 在应用层完成）。
package lan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/exeliang/keytalk/internal/transport"
)

// 帧的传输层封装。
//
//	length(4B, big-endian) ‖ payload
//
// 这里的 length 是**载荷长度**，不含自身 4 字节。
//
// 与 wire 包的帧头（Type + SessionID + Epoch + Seq）不同：
// 传输层的 length 只是为了让 TCP 的字节流能切出消息边界。
// 传输层不理解载荷内容，也不应理解。
//
// 冗余但不冲突：wire 自己的 Encode 也带长度前缀，
// 因此线上是"传输层长度 + wire 帧"。这是有意的分层——
// 传输层必须能独立工作（例如未来换成 WebRTC DataChannel 时，
// 它自身有消息边界，这层封装就不再需要）。
const lengthPrefixSize = 4

// conn 是一条到对端的 TCP 连接。
//
// 每条连接有两个 goroutine：
//   - 读循环（readLoop）：解析长度前缀、读出完整帧、投递事件
//   - 写循环（writeLoop）：从队列取帧、写入 socket
//
// 拆成两个 goroutine 的理由：写入可能因对端不读而阻塞，
// 若与读取共用 goroutine，会导致本端也收不到数据（死锁）。
type conn struct {
	peerID transport.PeerID
	nc     net.Conn

	// send 是待发送帧队列。满时 Send 返回错误（背压），不无限缓冲。
	send chan []byte

	// closed 用于通知读写循环退出。
	closed  chan struct{}
	closeMu sync.Mutex
	isClose bool
}

func newConn(peerID transport.PeerID, nc net.Conn) *conn {
	return &conn{
		peerID: peerID,
		nc:     nc,
		send:   make(chan []byte, transport.DefaultSendQueue),
		closed: make(chan struct{}),
	}
}

// Close 关闭连接。幂等。
func (c *conn) Close() error {
	c.closeMu.Lock()
	if c.isClose {
		c.closeMu.Unlock()
		return nil
	}
	c.isClose = true
	close(c.closed)
	c.closeMu.Unlock()
	return c.nc.Close()
}

// isClosed 报告连接是否已关闭。
func (c *conn) isClosed() bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.isClose
}

// setPeerID 更新连接的对端标识。
//
// 仅在入站连接通过密码学握手确立了真实身份后调用
// （见 Transport.AdoptConnection）。之后该连接上报的事件
// 会使用已认证的身份，而非临时的 "inbound:<地址>"。
func (c *conn) setPeerID(id transport.PeerID) {
	c.closeMu.Lock()
	c.peerID = id
	c.closeMu.Unlock()
}

// currentPeerID 读取连接当前的（可能已更新的）对端标识。
//
// 读写循环必须用它而非捕获注册时的值：入站连接在握手后被
// AdoptConnection 改名，若沿用旧值，收编之后的事件仍带着临时 ID，
// 上层就查不到对应的会话。
func (c *conn) currentPeerID() transport.PeerID {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.peerID
}

// enqueue 把帧放入发送队列。
//
// 队列满时返回 transport.ErrNotConnected 语义的错误——这不是"连不上"，
// 而是对端消费不过来。上层应据此降低发送速率或提示用户，
// 而不是静默堆积到内存耗尽。
func (c *conn) enqueue(frame []byte) error {
	select {
	case <-c.closed:
		return transport.ErrNotConnected
	default:
	}

	select {
	case c.send <- frame:
		return nil
	case <-c.closed:
		return transport.ErrNotConnected
	default:
		// 队列满：明确报错而非阻塞，让背压可见。
		return fmt.Errorf("%w: send queue full for %s", transport.ErrNotConnected, c.peerID)
	}
}

// writeLoop 从队列取帧并写入连接。
//
// 使用 write deadline 避免对端不读时永久阻塞——
// 否则该 goroutine 会一直挂着，连接也无法被回收。
func (c *conn) writeLoop(onErr func(error)) {
	for {
		select {
		case <-c.closed:
			return
		case frame := <-c.send:
			if err := writeFrame(c.nc, frame); err != nil {
				onErr(err)
				_ = c.Close()
				return
			}
		}
	}
}

// writeFrame 写入一个带长度前缀的帧。
//
// 用 net.Buffers 让长度前缀与载荷在一次系统调用中写出，
// 避免 Nagle 算法把小包合并或产生额外往返。
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > transport.MaxFrameSize {
		return fmt.Errorf("%w: %d > %d", transport.ErrFrameTooLarge, len(payload), transport.MaxFrameSize)
	}
	var hdr [lengthPrefixSize]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))

	if nc, ok := w.(net.Conn); ok {
		// 设置写超时：对端不读时不能永久阻塞。
		_ = nc.SetWriteDeadline(time.Now().Add(transport.DefaultHeartbeatTimeout))
		bufs := net.Buffers{hdr[:], payload}
		_, err := bufs.WriteTo(nc)
		return err
	}

	// 测试用（非 net.Conn 的 writer）。
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame 读取一个带长度前缀的帧。
//
// 必须先校验长度再分配内存：恶意对端可声明 4 GiB 长度来耗尽本端内存
// （见 docs/threat-model.md 中的内存耗尽攻击）。
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [lengthPrefixSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > transport.MaxFrameSize {
		return nil, fmt.Errorf("%w: declared %d > %d", transport.ErrFrameTooLarge, n, transport.MaxFrameSize)
	}
	if n == 0 {
		return nil, errors.New("transport: zero-length frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// readLoop 持续读取帧并投递事件。
//
// 返回时通过 onErr 上报原因，由上层决定是否重连。
func (c *conn) readLoop(onFrame func([]byte), onErr func(error)) {
	for {
		if nc, ok := c.nc.(net.Conn); ok {
			// 读超时略长于心跳超时：正常心跳会不断刷新它。
			_ = nc.SetReadDeadline(time.Now().Add(transport.DefaultHeartbeatTimeout))
		}
		frame, err := readFrame(c.nc)
		if err != nil {
			if !c.isClosed() {
				onErr(err)
			}
			return
		}
		onFrame(frame)
	}
}
