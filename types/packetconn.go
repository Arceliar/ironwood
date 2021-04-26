package types

import (
	"crypto/ed25519"
	"net"
)

type PacketConn interface {
	net.PacketConn
	// HandleConn expects a peer's public key as its first argument, and a net.Conn with TCP-like semantics (reliable ordered delivery) as its second argument.
	// This function blocks while the net.Conn is in use, and returns an error if any occurs.
	// This function returns (almost) immediately if PacketConn.Close() is called.
	// In all cases, the net.Conn is closed before returning.
	HandleConn(key ed25519.PublicKey, conn net.Conn) error
	// SetRecvCheck sets a function that is called on the destination key of any received packet.
	// If the function is not set, or set to nil, then packets are received (by calling ReadFrom) if and only if the destination key exactly matches this node's public key.
	// If the function is set, then packet are received any time the provided function returns true.
	// This is used to allow packets to be received if e.g. only a certain part of this connection's public key would be known by the sender.
	SetRecvCheck(isGood func(ed25519.PublicKey) bool) error
}
