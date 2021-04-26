package network

import "crypto/ed25519"

type core struct {
	crypto crypto     // crypto info, e.g. pubkeys and sign/verify wrapper functions
	dhtree dhtree     // distributed hash table and spanning tree
	peers  peers      // info about peers (from HandleConn), makes routing decisions and passes protocol traffic to relevant parts of the code
	pconn  PacketConn // net.PacketConn-like interface
}

func (c *core) init(secret ed25519.PrivateKey) error {
	c.crypto.init(secret)
	c.dhtree.init(c)
	c.peers.init(c)
	c.pconn.init(c)
	return nil
}
