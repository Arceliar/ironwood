package network

import (
	"encoding/binary"
	"time"

	bfilter "github.com/bits-and-blooms/bloom/v3"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

// FIXME we need to sequence number blooms, or otherwise handle races somehow
//  Currently, we just always use the latest received bloom
//  Imagine a node had two links, A and B, and sends blooms 1 and 2 over both links
//  We get A1, then A2 (over a fast link), then B1, then link B dies and we never receive B2
//  So we need to detect this and stick with / rever to A2...
//  But we also need to *not* get stuck never updating blooms if e.g. a node restarts faster than we close an existing connection to them (and delete the old blooms with, presumably, sequence numbers attached)
//  Note that we could just keep seqs if we detected node restarts in general and treated them as separate peers (e.g. index by a general peerID instead of publicKey, where peerID includes publicKey plus some random nonce generated on startup).
//    If we end up doing that anyway, then sequence numbering things is probably the right solution here too...
//  Can delayed zero sending help us at all here? Can we at least guarantee that we fail in a state with excess 1s if there's a race?
//    It would probably mean delaying zero sending to something much greater than peer timeout...
//    And I *think* would technically still race, it would just make the dropped B2 much less likely to fail closed unintentionally...
//  I guess forcing a resend periodically would also fix it (eventually), but that seems lazy and wrong...

const (
	bloomFilterF          = 16               // number of bytes used for flags in the wire format, should be bloomFilterU / 8, rounded up
	bloomFilterU          = bloomFilterF * 8 // number of uint64s in the backing array
	bloomFilterB          = bloomFilterU * 8 // number of bytes in the backing array
	bloomFilterM          = bloomFilterB * 8 // number of bits in teh backing array
	bloomFilterK          = 22
	bloomZeroDelay        = time.Second
	bloomMulticastEnabled = true // Make it easy to disable, for debugging purposes
)

// bloom is bloomFilterM bits long bloom filter uses bloomFilterK hash functions.
// TODO? just make this a bfilter.BloomFilter directly, no struct?
type bloom struct {
	filter *bfilter.BloomFilter
}

func newBloom() *bloom {
	return &bloom{
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
	size := bloomFilterF // Flags for chunks that are all 0 bits
	size += bloomFilterF // Flags for chunks that are all 1 bits
	us := b.filter.BitSet().Bytes()
	for _, u := range us {
		if u != 0 {
			size += 8
		}
	}
	return size
}

func (b *bloom) encode(out []byte) ([]byte, error) {
	start := len(out)
	var flags0, flags1 [bloomFilterF]byte
	keep := make([]uint64, 0, bloomFilterU)
	us := b.filter.BitSet().Bytes()
	for idx, u := range us {
		if u == 0 {
			flags0[idx/8] |= 0x80 >> (uint64(idx) % 8)
			continue
		}
		if u == ^uint64(0) {
			flags1[idx/8] |= 0x80 >> (uint64(idx) % 8)
			continue
		}
		keep = append(keep, u)
	}
	out = append(out, flags0[:]...)
	out = append(out, flags1[:]...)
	var buf [8]byte
	for _, u := range keep {
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
	var flags0, flags1 [bloomFilterF]byte
	if !wireChopSlice(flags0[:], &data) {
		return types.ErrDecode
	} else if !wireChopSlice(flags1[:], &data) {
		return types.ErrDecode
	}
	for idx := 0; idx < bloomFilterU; idx++ {
		flag0 := flags0[idx/8] & (0x80 >> (uint64(idx) % 8))
		flag1 := flags1[idx/8] & (0x80 >> (uint64(idx) % 8))
		if flag0 != 0 && flag1 != 0 {
			return types.ErrDecode
		} else if flag0 != 0 {
			us = append(us, 0)
		} else if flag1 != 0 {
			us = append(us, ^uint64(0))
		} else if len(data) >= 8 {
			u := binary.BigEndian.Uint64(data[:8])
			us = append(us, u)
			data = data[8:]
		} else {
			return types.ErrDecode
		}
	}
	if len(data) != 0 {
		return types.ErrDecode
	}
	tmp.filter = bfilter.From(us, bloomFilterK)
	*b = tmp
	return nil
}

/*****************************
 * router bloom filter stuff *
 *****************************/

// TODO? replace the global zTimer with one per peer?

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

func (bs *blooms) _isOnTree(key publicKey) bool {
	return bs.blooms[key].onTree //|| key == bs.router.core.crypto.publicKey
}

func (bs *blooms) _fixOnTree() {
	selfKey := bs.router.core.crypto.publicKey
	if selfInfo, isIn := bs.router.infos[selfKey]; isIn {
		for pk, pbi := range bs.blooms { // TODO? only store blooms for on-tree links?
			wasOn := pbi.onTree
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
			if wasOn && !pbi.onTree {
				// We dropped them from the tree, so we need to send a blank (but sequence numbered) update
				// That way, if the link returns to the tree, we don't start with false positives
				b := newBloom()
				pbi.send = *b
				for p := range bs.router.peers[pk] {
					p.sendBloom(bs.router, b)
				}
			}
			bs.blooms[pk] = pbi
		}
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
		send: *newBloom(),
		recv: *newBloom(),
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
	b := newBloom()
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
