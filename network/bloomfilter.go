package network

import (
	"encoding/binary"

	bfilter "github.com/bits-and-blooms/bloom/v3"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

const (
	bloomFilterM = 8192
	bloomFilterK = 22
	bloomFilterB = bloomFilterM / 8  // number of bytes in the backing array
	bloomFilterU = bloomFilterM / 64 // number of uint64s in the backing array
)

// bloom is an 8192 bit long bloom filter using 22 hash functions.
type bloom struct {
	seq    uint64
	filter *bfilter.BloomFilter
}

func newBloom(seq uint64) *bloom {
	return &bloom{
		seq:    seq,
		filter: bfilter.New(bloomFilterM, bloomFilterK),
	}
}

func (b *bloom) addKey(key publicKey) {
	b.filter.Add(key[:])
}

func (b *bloom) addFilter(f *bfilter.BloomFilter) {
	b.filter.Merge(f)
}

func (b *bloom) size() int {
	size := wireSizeUint(b.seq)
	size += bloomFilterB
	return size
}

func (b *bloom) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendUint(out, b.seq)
	us := b.filter.BitSet().Bytes()
	var buf [8]byte
	for _, u := range us {
		binary.BigEndian.PutUint64(buf[:], u)
		out = append(out, buf[:]...)
	}
	end := len(out)
	if end-start != b.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (b *bloom) decode(data []byte) error {
	var tmp bloom
	var usArray [bloomFilterU]uint64
	us := usArray[:0]
	if !wireChopUint(&tmp.seq, &data) {
		return types.ErrDecode
	}
	if len(data) != bloomFilterB {
		return types.ErrDecode
	}
	for len(data) != 0 {
		u := binary.BigEndian.Uint64(data[:8])
		us = append(us, u)
		data = data[8:]
	}

	tmp.filter = bfilter.From(us, bloomFilterK)
	*b = tmp
	return nil
}

/*****************************
 * router bloom filter stuff *
 *****************************/

// TODO only send blooms to peers that are on the tree, we can (and should) skip anything off-tree

type blooms struct {
	router *router
	blooms map[publicKey]bloomInfo
}

type bloomInfo struct {
	send bloom
	recv bloom
	// TODO add some kind of timeout and keepalive timer to force an update/send
}

func (bs *blooms) init(r *router) {
	bs.router = r
	bs.blooms = make(map[publicKey]bloomInfo)
}

func (bs *blooms) xKey(key publicKey) publicKey {
	k := key
	xfed := bs.router.core.config.bloomTransform(k.toEd())
	var xform publicKey
	copy(xform[:], xfed)
	return xform
}

func (bs *blooms) _addInfo(key publicKey) {
	bs.blooms[key] = bloomInfo{
		send: *newBloom(0),
		recv: *newBloom(0),
	}
}

func (bs *blooms) _removeInfo(key publicKey) {
	delete(bs.blooms, key)
	// At some later point (after we've finished cleaning things up), send blooms to everyone
	bs.router.Act(nil, bs._sendAllBlooms)
}

func (bs *blooms) handleBloom(fromPeer *peer, b *bloom) {
	bs.router.Act(fromPeer, func() {
		bs._handleBloom(fromPeer, b)
	})
}

func (bs blooms) _handleBloom(fromPeer *peer, b *bloom) {
	pbi, isIn := bs.blooms[fromPeer.key]
	if !isIn {
		return
	}
	if b.seq <= pbi.recv.seq {
		// This is old, we probably received it via a different link to the same peer
		return
	}
	doSend := !b.filter.Equal(pbi.recv.filter)
	pbi.recv = *b
	bs.blooms[fromPeer.key] = pbi
	if !doSend {
		return
	}
	// Our filter changed, so we need to send an update to all other peers
	for destKey, destPeers := range bs.router.peers {
		if destKey == fromPeer.key {
			continue
		}
		if send, isNew := bs._getBloomFor(destKey); isNew {
			for p := range destPeers {
				p.sendBloom(bs.router, send)
			}
		}
	}
}

func (bs *blooms) _getBloomFor(key publicKey) (*bloom, bool) {
	// getBloomFor increments the sequence number, even if we only send it to 1 peer
	// this means we may sometimes unnecessarily send a bloom when we get a new peer link to an existing peer node
	pbi, isIn := bs.blooms[key]
	if !isIn {
		panic("this should never happen")
	}
	b := newBloom(pbi.send.seq + 1)
	sKey := bs.router.core.crypto.publicKey
	sXform := bs.xKey(sKey)
	sInfo := bs.router.infos[sKey]
	b.addKey(sXform)
	for k, pbi := range bs.blooms {
		if k == key {
			continue
		}
		// Skip non-tree peers!
		if sInfo.parent != k {
			// This is not our parent
			if info := bs.router.infos[k]; info.parent != sKey {
				// This is not our child
				// So this is not a link used in the tree, we must not broadcast on it
				// TODO at the very least, we should set a flag or something, on the pbi, so we don't keep needing to check this
				continue
			}
		}
		b.addFilter(pbi.recv.filter)
	}
	isNew := true
	if b.filter.Equal(pbi.send.filter) {
		*b = pbi.send
		isNew = false
	} else {
		pbi.send = *b
		bs.blooms[key] = pbi
	}
	return b, isNew
}

func (bs *blooms) _sendBloom(p *peer) {
	// FIXME we should really just make it part of what router.addPeer does
	b, _ := bs._getBloomFor(p.key)
	p.sendBloom(bs.router, b)
}

func (bs *blooms) _sendAllBlooms() {
	// Called after e.g. a peer is removed, must update seq
	for k, ps := range bs.router.peers {
		if b, isNew := bs._getBloomFor(k); isNew {
			for p := range ps {
				p.sendBloom(bs.router, b)
			}
		}
	}
}

func (bs *blooms) sendMulticast(from phony.Actor, pType wirePacketType, data wireEncodeable, fromKey publicKey, toKey publicKey) {
	// TODO we need a way to detect duplicate packets from multiple links to the same peer, so we can drop them
	// I.e. we need to sequence number all multicast packets... This can maybe be part of the framing, along side the packet length, or something
	// For now, we just send to 1 peer (possibly at random)
	bs.router.Act(from, func() {
		bs._sendMulticast(pType, data, fromKey, toKey)
	})
}

func (bs *blooms) _sendMulticast(pType wirePacketType, data wireEncodeable, fromKey publicKey, toKey publicKey) {
	xform := bs.xKey(toKey)
	selfInfo := bs.router.infos[bs.router.core.crypto.publicKey]
	for k, pbi := range bs.blooms {
		if k == fromKey {
			// From this key, so don't send it back
			continue
		}
		if !pbi.recv.filter.Test(xform[:]) {
			// The bloom filter tells us this peer definitely doesn't carea bout this xformed toKey
			continue
		}
		// Skip non-tree peers!
		if selfInfo.parent != k {
			// This is not our parent
			if info := bs.router.infos[k]; info.parent != bs.router.core.crypto.publicKey {
				// This is not our child
				// So this is not a link used in the tree, we must not broadcast on it
				// TODO at the very least, we should set a flag or something, on the pbi, so we don't keep needing to check this
				continue
			}
		}
		// Send this broadcast packet to the peer
		var bestPeer *peer
		for p := range bs.router.peers[k] {
			if bestPeer == nil || p.prio < bestPeer.prio {
				bestPeer = p
			}
		}
		if bestPeer == nil {
			panic("this should never happen")
		}
		bestPeer.sendDirect(bs.router, pType, data)
	}
}
