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

type core struct {
	crypto crypto      // crypto info, e.g. pubkeys and sign/verify wrapper functions
	tree   tree        // spanning tree
	dht    interface{} // distributed hash table
	peers  interface{} // info about peers (from HandleConn), makes routing decisions and passes protocol traffic to relevant parts of the code
	router interface{} // handles traffic to/from the user's application code, contains the underlying logic for the exported net.PacketConn interface
}

func NewPacketConn(secret ed25519.PrivateKey) (PacketConn, error) {
	c := new(core)
	c.crypto.init(secret)
	c.tree.init(c)
	panic("TODO initialize core")
	return c, nil
}

func (c *core) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	panic("TODO implement ReadFrom")
	return
}

func (c *core) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	panic("TODO implement WriteTo")
	return
}

func (c *core) Close() error {
	panic("TODO implement Close")
	return nil
}

func (c *core) LocalAddr() net.Addr {
	panic("TODO implemnet LocalAddr")
	return nil
}

func (c *core) SetDeadline(t time.Time) error {
	panic("TODO implement SetDeadline")
	return nil
}

func (c *core) SetReadDeadline(t time.Time) error {
	panic("TODO implement SetReadDeadline")
	return nil
}

func (c *core) SetWriteDeadline(t time.Time) error {
	panic("TODO implement SetWriteDeadline")
	return nil
}

func (c *core) HandleConn(conn net.Conn) error {
	// Note: This should block until we're done with the Conn, then return without closing it
	panic("TODO implement HandleConn")
	return nil
}
