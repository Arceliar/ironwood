package network

import (
	"crypto/ed25519"
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
	Key     ed25519.PublicKey
	Root    ed25519.PublicKey
	Coords  []uint64
	Updated time.Time
}

type DebugPeerInfo struct {
	Key     ed25519.PublicKey
	Root    ed25519.PublicKey
	Coords  []uint64
	Port    uint64
	Updated time.Time
}

type DebugDHTInfo struct {
	Key  ed25519.PublicKey
	Port uint64
	Next uint64
}

type DebugPathInfo struct {
	Key  ed25519.PublicKey
	Path []uint64
}

func (d *Debug) GetSelf() (info DebugSelfInfo) {
	phony.Block(&d.c.dhtree, func() {
		info.Key = append(info.Key, d.c.crypto.publicKey[:]...)
		info.Root = append(info.Root, d.c.dhtree.self.root[:]...)
		info.Coords = make([]uint64, 0)
		for _, hop := range d.c.dhtree.self.hops {
			info.Coords = append(info.Coords, uint64(hop.port))
		}
		info.Updated = d.c.dhtree.self.time
	})
	return
}

func (d *Debug) GetPeers() (infos []DebugPeerInfo) {
	phony.Block(&d.c.dhtree, func() {
		for p, tinfo := range d.c.dhtree.tinfos {
			var info DebugPeerInfo
			info.Key = append(info.Key, p.key[:]...)
			info.Root = append(info.Root, tinfo.root[:]...)
			info.Coords = make([]uint64, 0)
			for _, hop := range tinfo.hops {
				info.Coords = append(info.Coords, uint64(hop.port))
			}
			info.Coords = info.Coords[:len(info.Coords)-1] // Last hop is the port back to self
			info.Port = uint64(p.port)
			info.Updated = tinfo.time
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetDHT() (infos []DebugDHTInfo) {
	phony.Block(&d.c.dhtree, func() {
		for _, dinfo := range d.c.dhtree.dinfos {
			var info DebugDHTInfo
			info.Key = append(info.Key, dinfo.source[:]...)
			if dinfo.prev != nil {
				info.Port = uint64(dinfo.prev.port)
			}
			if dinfo.next != nil {
				info.Next = uint64(dinfo.next.port)
			}
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetPaths() (infos []DebugPathInfo) {
	phony.Block(&d.c.dhtree, func() {
		for key, pinfo := range d.c.dhtree.pathfinder.paths {
			var info DebugPathInfo
			info.Key = append(info.Key, key[:]...)
			info.Path = make([]uint64, 0)
			for _, port := range pinfo.path {
				info.Path = append(info.Path, uint64(port))
			}
			infos = append(infos, info)
		}
	})
	return
}
