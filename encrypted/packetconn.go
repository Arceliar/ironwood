package encrypted

import (
	"crypto/ed25519"
	"errors"
	"net"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/network"
	"github.com/Arceliar/ironwood/types"
)

type PacketConn struct {
	actor phony.Inbox
	*network.PacketConn
	secret   edPriv
	public   edPub
	sessions sessionManager
	network  netManager
}

// NewPacketConn returns a *PacketConn struct which implements the types.PacketConn interface.
func NewPacketConn(secret ed25519.PrivateKey) (*PacketConn, error) {
	npc, err := network.NewPacketConn(secret)
	if err != nil {
		return nil, err
	}
	pub := secret.Public().(ed25519.PublicKey)
	pc := &PacketConn{PacketConn: npc}
	copy(pc.secret[:], secret[:])
	copy(pc.public[:], pub[:])
	pc.sessions.init(pc)
	pc.network.init(pc)
	pc.SetOutOfBandHandler(nil)
	return pc, nil
}

func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	pc.network.read()
	info := <-pc.network.readCh
	if info.err != nil {
		err = info.err
		return
	}
	n, from = len(info.data), types.Addr(info.from.asKey())
	if n > len(p) {
		n = len(p)
	}
	copy(p, info.data[:n])
	return
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	destKey, ok := addr.(types.Addr)
	if !ok || len(destKey) != edPubSize {
		return 0, errors.New("bad destination address")
	}
	select {
	case <-pc.network.closed:
		return 0, errors.New("closed")
	default:
	}
	n = len(p)
	var dest edPub
	copy(dest[:], destKey)
	pc.sessions.writeTo(dest, append([]byte(nil), p...))
	return
}
