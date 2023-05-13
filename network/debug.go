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

type DebugTreeInfo struct {
	Key      ed25519.PublicKey
	Parent   ed25519.PublicKey
	Sequence uint64
}

type DebugPathInfo struct {
	Key      ed25519.PublicKey
	Path     []uint64
	Sequence uint64
}

type DebugBloomInfo struct {
	Key  ed25519.PublicKey
	Send [bloomFilterU]uint64
	Recv [bloomFilterU]uint64
}

func (d *Debug) GetSelf() (info DebugSelfInfo) {
	info.Key = append(info.Key[:0], d.c.crypto.publicKey[:]...)
	phony.Block(&d.c.router, func() {
		info.RoutingEntries = uint64(len(d.c.router.infos))
	})
	return
}

func (d *Debug) GetPeers() (infos []DebugPeerInfo) {
	phony.Block(&d.c.peers, func() {
		for _, peers := range d.c.peers.peers {
			for peer := range peers {
				var info DebugPeerInfo
				info.Port = uint64(peer.port)
				info.Key = append(info.Key[:0], peer.key[:]...)
				info.Priority = peer.prio
				info.Conn = peer.conn
				infos = append(infos, info)
			}
		}
	})
	return
}

func (d *Debug) GetTree() (infos []DebugTreeInfo) {
	phony.Block(&d.c.router, func() {
		for key, dinfo := range d.c.router.infos {
			var info DebugTreeInfo
			info.Key = append(info.Key[:0], key[:]...)
			info.Parent = append(info.Parent[:0], dinfo.parent[:]...)
			info.Sequence = dinfo.seq
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetPaths() (infos []DebugPathInfo) {
	phony.Block(&d.c.router, func() {
		for key, pinfo := range d.c.router.pathfinder.paths {
			var info DebugPathInfo
			info.Key = append(info.Key[:0], key[:]...)
			info.Path = make([]uint64, 0, len(pinfo.path))
			for _, port := range pinfo.path {
				info.Path = append(info.Path, uint64(port))
			}
			info.Sequence = pinfo.seq
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetBlooms() (infos []DebugBloomInfo) {
	phony.Block(&d.c.router, func() {
		for key, binfo := range d.c.router.blooms.blooms {
			var info DebugBloomInfo
			info.Key = append(info.Key[:0], key[:]...)
			copy(info.Send[:], binfo.send.filter.BitSet().Bytes())
			copy(info.Recv[:], binfo.recv.filter.BitSet().Bytes())
			infos = append(infos, info)
		}
	})
	return
}
