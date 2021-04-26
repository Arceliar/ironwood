package signed

import (
	"bytes"
	"crypto/ed25519"
	"net"

	"github.com/Arceliar/ironwood/types"
)

type PacketConn struct {
	net.PacketConn
	secret    ed25519.PrivateKey
	public    ed25519.PublicKey
	pubToAddr func(ed25519.PublicKey) net.Addr
	addrToPub func(net.Addr) ed25519.PublicKey
}

func WrapPacketConn(pc net.PacketConn, secret ed25519.PrivateKey, pubToAddr func(ed25519.PublicKey) net.Addr, addrToPub func(net.Addr) ed25519.PublicKey) (*PacketConn, error) {
	pub := secret.Public().(ed25519.PublicKey)
	return &PacketConn{pc, secret, pub, pubToAddr, addrToPub}, nil
}

// NPC returns the underlying net.PacketConn.
func (pc *PacketConn) NPC() net.PacketConn {
	return pc.PacketConn
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
		fromAddr := from
		fromKey := pc.addrToPub(fromAddr)
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
	destKey := ed25519.PublicKey(addr.(types.Addr))
	destAddr := pc.pubToAddr(destKey)
	n, err = pc.PacketConn.WriteTo(msg, destAddr)
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
