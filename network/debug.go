package network

import (
	"crypto/ed25519"
	"net"
	"time"

	"github.com/Arceliar/phony"
)

type Debug struct {
	c *core
}

func (d *Debug) init(c *core) {
	d.c = c
}

type DebugSelfInfo struct {
	Key            ed25519.PublicKey
	RoutingEntries uint64
}

type DebugPeerInfo struct {
	Key      ed25519.PublicKey
	Root     ed25519.PublicKey
	Port     uint64
	Priority uint8
	RX       uint64
	TX       uint64
	Updated  time.Time
	Conn     net.Conn
}

type DebugDHTInfo struct {
	Key      ed25519.PublicKey
	Parent   ed25519.PublicKey
	Sequence uint64
}

/*
type DebugPathInfo struct {
	Key      ed25519.PublicKey
	Sequence uint64
}
*/

func (d *Debug) GetSelf() (info DebugSelfInfo) {
	info.Key = append(info.Key[:0], d.c.crypto.publicKey[:]...)
	phony.Block(&d.c.router, func() {
		info.RoutingEntries = uint64(len(d.c.router.infos))
	})
	return
}

func (d *Debug) GetPeers() (infos []DebugPeerInfo) {
	phony.Block(&d.c.peers, func() {
		for port, peer := range d.c.peers.peers {
			var info DebugPeerInfo
			info.Port = uint64(port)
			info.Key = append(info.Key[:0], peer.key[:]...)
			info.Priority = peer.prio
			info.Conn = peer.conn
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetDHT() (infos []DebugDHTInfo) {
	phony.Block(&d.c.router, func() {
		for key, dinfo := range d.c.router.infos {
			var info DebugDHTInfo
			info.Key = append(info.Key[:0], key[:]...)
			info.Parent = append(info.Parent[:0], dinfo.parent[:]...)
			info.Sequence = dinfo.seq
			infos = append(infos, info)
		}
	})
	return
}

/*
func (d *Debug) GetPaths() (infos []DebugPathInfo) {
	return
}
*/
