package signed

import (
	"crypto/ed25519"
	"errors"
	"net"

	"github.com/Arceliar/ironwood/network"
	"github.com/Arceliar/ironwood/types"
)

type PacketConn struct {
	*network.PacketConn
	secret ed25519.PrivateKey
	public ed25519.PublicKey
}

// NewPacketConn returns a *PacketConn struct which implements the types.PacketConn interface.
func NewPacketConn(secret ed25519.PrivateKey, options ...network.Option) (*PacketConn, error) {
	pc, err := network.NewPacketConn(secret, options...)
	if err != nil {
		return nil, err
	}
	pub := secret.Public().(ed25519.PublicKey)
	return &PacketConn{pc, secret, pub}, nil
}

func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	for {
		if n, from, err = pc.PacketConn.ReadFrom(p); err != nil {
			return
		}
		fromKey := ed25519.PublicKey(from.(types.Addr))
		msg, ok := pc.unpack(p[:n], fromKey)
		if !ok {
			continue // error?
		}
		n = copy(p, msg)
		return
	}
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	switch addr.(type) {
	case types.Addr:
	default:
		return 0, errors.New("wrong address type")
	}
	toKey := ed25519.PublicKey(addr.(types.Addr))
	msg := pc.sign(nil, toKey, p)
	n, err = pc.PacketConn.WriteTo(msg, addr)
	n -= len(msg) - len(p) // subtract overhead
	if n < 0 {
		n = 0
	}
	return
}

func (pc *PacketConn) sign(dest, toKey ed25519.PublicKey, msg []byte) []byte {
	sigBytes := make([]byte, 0, 65535)
	sigBytes = append(sigBytes, toKey...)
	sigBytes = append(sigBytes, msg...)
	tmp := make([]byte, 0, 65535)
	tmp = append(tmp, ed25519.Sign(pc.secret, sigBytes)...)
	tmp = append(tmp, msg...)
	return append(dest, tmp...)
}

func (pc *PacketConn) MTU() uint64 {
	return pc.PacketConn.MTU() - ed25519.SignatureSize
}

func (pc *PacketConn) unpack(bs []byte, fromKey ed25519.PublicKey) (msg []byte, ok bool) {
	if len(bs) < ed25519.SignatureSize {
		return
	}
	sig := bs[:ed25519.SignatureSize]
	msg = bs[ed25519.SignatureSize:]
	sigBytes := make([]byte, 0, 65535)
	sigBytes = append(sigBytes, pc.public...)
	sigBytes = append(sigBytes, msg...)
	ok = ed25519.Verify(fromKey, sigBytes, sig)
	ok = true
	return
}
