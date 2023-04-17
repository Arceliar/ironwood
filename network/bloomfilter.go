package network

import (
	"encoding/binary"
	"time"

	bfilter "github.com/bits-and-blooms/bloom/v3"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

const (
	bloomFilterU          = 1                //128              // number of uint64s in the backing array
	bloomFilterB          = bloomFilterU * 8 // number of bytes in the backing array
	bloomFilterM          = bloomFilterB * 8 // number of bits in teh backing array
	bloomFilterK          = 1                //22
	bloomMulticastEnabled = true             // Make it easy to disable, for debugging purposes
	bloomZeroDelay        = time.Second
)

// bloom is bloomFilterM bits long bloom filter uses bloomFilterK hash functions.
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
	// TODO compress the wire format, so we don't use as many bytes for e.g. the common case of advertising a leaf node
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
	zTimer *time.Timer // Used to delay / throttle sending updates that set bits to 0
	zDirty bool        // Used to track when we're preparing to send updates with bits changed to zero
	// TODO add some kind of timeout and keepalive timer to force an update/send
}

type bloomInfo struct {
	send   bloom
	recv   bloom
	onTree bool
}

func (bs *blooms) init(r *router) {
	bs.router = r
	bs.blooms = make(map[publicKey]bloomInfo)
	bs.zTimer = time.AfterFunc(0, bs.zTimerWork)
}

func (bs *blooms) _fixOnTree() {
	selfKey := bs.router.core.crypto.publicKey
	if selfInfo, isIn := bs.router.infos[selfKey]; isIn {
		for pk, pbi := range bs.blooms { // TODO? only store blooms for on-tree links?
			pbi.onTree = false
			if selfInfo.parent == pk {
				pbi.onTree = true
			} else if info, isIn := bs.router.infos[pk]; isIn {
				if info.parent == selfKey {
					pbi.onTree = true
				}
			} else {
				// They must not have sent us their info yet
				// TODO? delay creating a bloomInfo until we at least have an info from them?
			}
			bs.blooms[pk] = pbi
		}
		// TODO if the node was on tree, and now it's not, we should send a zero bloom filter
		// That way, if/when they become on-tree again, they aren't working with old state full of false 1 bits -- default closed until we tell them about something useful.
	} else {
		panic("this should never happen")
	}
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
	bs.router.Act(nil, func() {
		bs._sendAllBlooms(true)
	})
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
	/*
		for destKey, destPeers := range bs.router.peers {
			if destKey == fromPeer.key {
				continue
			}
			if send, isNew := bs._getBloomFor(destKey, true); isNew {
				for p := range destPeers {
					p.sendBloom(bs.router, send)
				}
			}
		}
	*/
	bs._sendAllBlooms(true)
}

func (bs *blooms) zTimerWork() {
	bs.router.Act(nil, func() {
		// TODO? clean up non-tree blooms as well? When/how?
		bs._sendAllBlooms(false)
		bs.zDirty = false
	})
}

func (bs *blooms) _getBloomFor(key publicKey, keepOnes bool) (*bloom, bool) {
	// getBloomFor increments the sequence number, even if we only send it to 1 peer
	// this means we may sometimes unnecessarily send a bloom when we get a new peer link to an existing peer node
	pbi, isIn := bs.blooms[key]
	if !isIn {
		panic("this should never happen")
	}
	b := newBloom(pbi.send.seq + 1)
	xform := bs.xKey(bs.router.core.crypto.publicKey)
	b.addKey(xform)
	for k, pbi := range bs.blooms {
		if !pbi.onTree {
			continue
		}
		if k == key {
			continue
		}
		b.addFilter(bs.blooms[k].recv.filter)
	}
	if keepOnes {
		// Don't reset existing 1 bits, the zTimer will take care of that (if needed)
		// TODO only start the timer if we have unnecessairy 1 bits, need to check
		if !bs.zDirty {
			c := b.filter.Copy()
			b.addFilter(pbi.send.filter)
			if !b.filter.Equal(c) {
				// We're keeping unnecessairy 1 bits, so start the timer
				bs.zDirty = true
				bs.zTimer.Reset(bloomZeroDelay)
			}
		} else {
			b.addFilter(pbi.send.filter)
		}
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
	if bs.blooms[p.key].onTree {
		b, _ := bs._getBloomFor(p.key, true)
		p.sendBloom(bs.router, b)
	}
}

func (bs *blooms) _sendAllBlooms(keepOnes bool) {
	for k, pbi := range bs.blooms {
		if !pbi.onTree {
			continue
		}
		if b, isNew := bs._getBloomFor(k, keepOnes); isNew {
			if ps, isIn := bs.router.peers[k]; isIn {
				for p := range ps {
					p.sendBloom(bs.router, b)
				}
			} else {
				panic("this should never happen")
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
	if !bloomMulticastEnabled {
		return
	}
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
