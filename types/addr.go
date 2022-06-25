package types

import (
	"crypto/ed25519"
	"encoding/hex"
	"net"
)

// ConvertibleAddr is for apps that want to implement a custom address behaviour
// but want to tell ironwood which public key to contact.
type ConvertibleAddr interface {
	IronwoodAddr() Addr
}

func ExtractAddrKey(a net.Addr) (addr Addr, ok bool) {
	var destKey Addr
	switch v := a.(type) {
	case Addr:
		destKey = v
	case ConvertibleAddr:
		destKey = v.IronwoodAddr()
	default:
		return nil, false
	}
	return destKey, true
}

// Addr implements the `net.Addr` interface for `ed25519.PublicKey` values.
type Addr ed25519.PublicKey

// Network returns "ed25519.PublicKey" as a string, but is otherwise unused.
func (a Addr) Network() string {
	return "ed25519.PublicKey"
}

// String returns the ed25519.PublicKey as a hexidecimal string, but is otherwise unused.
func (a Addr) String() string {
	return hex.EncodeToString(a)
}
