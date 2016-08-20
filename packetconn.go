package ethernet

import (
	"fmt"
	"net"
	"sync"
	"time"
)

var _ net.PacketConn = &PacketConn{}

type PacketConn struct {
	c net.PacketConn

	mu   sync.RWMutex
	f    *Frame
	mode MarshalMode
}

func NewPacketConn(c net.PacketConn) *PacketConn {
	return &PacketConn{c: c}
}

type MarshalMode int

const (
	MarshalModeNormal MarshalMode = iota
	MarshalModeFCS
)

func (c *PacketConn) SetFrame(f *Frame, mode MarshalMode) error {
	switch mode {
	case MarshalModeNormal:
	case MarshalModeFCS:
	default:
		return fmt.Errorf("unknown MarshalMode: %d", mode)
	}

	c.mu.Lock()
	c.f = f
	c.mode = mode
	c.mu.Unlock()

	return nil
}

func (c *PacketConn) Close() error                       { return nil }
func (c *PacketConn) LocalAddr() net.Addr                { return nil }
func (c *PacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *PacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *PacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.c.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	f := new(Frame)
	if err := f.UnmarshalBinary(b); err != nil {
		return 0, nil, err
	}

	return n, addr, nil
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	dst, ok := addr.(*Addr)
	if !ok {
		return 0, fmt.Errorf("addr must be of type *ethernet.Addr, got %T", addr)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	f := *c.f
	f.Destination = dst.addr
	f.Payload = b

	var (
		fb  []byte
		err error
	)

	switch c.mode {
	case MarshalModeFCS:
		fb, err = f.MarshalFCS()
	case MarshalModeNormal:
		fb, err = f.MarshalBinary()
	}
	if err != nil {
		return 0, err
	}

	return c.c.WriteTo(fb, addr)
}

var _ net.Addr = &Addr{}

type Addr struct {
	addr net.HardwareAddr
}

func (a *Addr) Network() string { return "ethernet" }
func (a *Addr) String() string  { return a.addr.String() }
