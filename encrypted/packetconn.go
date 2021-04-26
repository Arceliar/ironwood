package encrypted

import (
	"crypto/ed25519"

	"github.com/Arceliar/ironwood/network"
)

type PacketConn struct {
	*network.PacketConn
	secret edPriv
	public edPub
	mgr    sessionManager
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
	pc.mgr.init(pc)
	return pc, nil
}
