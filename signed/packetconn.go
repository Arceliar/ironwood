package signed

import (
	"bytes"
	"crypto/ed25519"
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
func NewPacketConn(secret ed25519.PrivateKey) (*PacketConn, error) {
	pc, err := network.NewPacketConn(secret)
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
		sig, key, msg, ok := pc.unpack(p[:n])
		if !ok {
			continue // error?
		}
		fromKey := ed25519.PublicKey(from.(types.Addr))
		if !bytes.Equal(fromKey[:], key) {
			continue // key mismatch
		}
		if !ed25519.Verify(fromKey, msg, sig) {
			continue
		}
		from = types.Addr(fromKey)
		n = copy(p, msg)
		return
	}
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	msg := pc.sign(nil, p)
	n, err = pc.PacketConn.WriteTo(msg, addr)
	n -= len(msg) - len(p) // subtract overhead
	if n < 0 {
		n = 0
	}
	return
}

func (pc *PacketConn) sign(dest, msg []byte) []byte {
	tmp := make([]byte, 0, 65535)
	tmp = append(tmp, ed25519.Sign(pc.secret, msg)...)
	tmp = append(tmp, []byte(pc.public)...)
	tmp = append(tmp, msg...)
	return append(dest, tmp...)
}

func (pc *PacketConn) unpack(bs []byte) (sig, key, msg []byte, ok bool) {
	if len(bs) < ed25519.PublicKeySize+ed25519.SignatureSize {
		return
	}
	begin, end := 0, ed25519.SignatureSize
	sig = bs[begin:end]
	begin, end = end, end+ed25519.PublicKeySize
	key = ed25519.PublicKey(bs[begin:end])
	msg = bs[end:]
	ok = true
	return
}
