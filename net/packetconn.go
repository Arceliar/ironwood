package net

import (
	"crypto/ed25519"
	"net"
	"time"
)

type PacketConn interface {
	net.PacketConn
	HandleConn(net.Conn) error
}

type packetConn struct {
	core *core
}

func NewPacketConn(secret ed25519.PrivateKey) (PacketConn, error) {
	c := new(core)
	c.pconn.core = c
	c.crypto.init(secret)
	c.tree.init(c)
	panic("TODO initialize core")
	return &c.pconn, nil
}

func (pc *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	panic("TODO implement ReadFrom")
	return
}

func (pc *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	panic("TODO implement WriteTo")
	return
}

func (pc *packetConn) Close() error {
	panic("TODO implement Close")
	return nil
}

func (pc *packetConn) LocalAddr() net.Addr {
	panic("TODO implemnet LocalAddr")
	return nil
}

func (pc *packetConn) SetDeadline(t time.Time) error {
	panic("TODO implement SetDeadline")
	return nil
}

func (pc *packetConn) SetReadDeadline(t time.Time) error {
	panic("TODO implement SetReadDeadline")
	return nil
}

func (pc *packetConn) SetWriteDeadline(t time.Time) error {
	panic("TODO implement SetWriteDeadline")
	return nil
}

func (pc *packetConn) HandleConn(conn net.Conn) error {
	// Note: This should block until we're done with the Conn, then return without closing it
	panic("TODO implement HandleConn")
	return nil
}
