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

	// SendOutOfBand sends some out-of-band data to a key.
	// The data will be forwarded towards the destination key as far as possible, and then handled by the out-of-band handler of the terminal node.
	// This could be used to do e.g. key discovery based on an incomplete key, or to implement application-specific helpers for debugging and analytics.
	SendOutOfBand(toKey ed25519.PublicKey, data []byte) error

	// SetOutOfBandHandler sets a function to handle out-of-band data.
	// This function will be called every time out-of-band data is received.
	// If no handler has been set, then any received out-of-band data is dropped.
	SetOutOfBandHandler(handler func(fromKey, toKey ed25519.PublicKey, data []byte)) error

	// IsClosed returns true if and only if the connection is closed.
	// This is to check if the PacketConn is closed without potentially being stuck on a blocking operation (e.g. a read or write).
	IsClosed() bool
}
