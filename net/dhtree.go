package net

import (
	"bytes"

	"github.com/Arceliar/phony"
)

/********
 * tree *
 ********/

type dhtree struct {
	phony.Inbox
	core   *core
	tinfos map[string]*treeInfo // map[string(publicKey)]*treeInfo, key=peer
	dinfos map[string]*dhtInfo  // map[string(publicKey)]*dhtInfo, key=source
	self   *treeInfo            // self info
}

func (t *dhtree) init(c *core) {
	t.core = c
	t.tinfos = make(map[string]*treeInfo)
	t.dinfos = make(map[string]*dhtInfo)
	t.self = &treeInfo{root: t.core.crypto.publicKey}
}

func (t *dhtree) update(from phony.Actor, info *treeInfo) {
	t.Act(from, func() {
		// The tree info should have been checked before this point
		key := info.from()
		t.tinfos[string(key)] = info
		if bytes.Equal(key, t.self.from()) {
			t.self = nil
		}
		t._fix()
	})
}

func (t *dhtree) remove(from phony.Actor, info *treeInfo) {
	t.Act(from, func() {
		key := info.from()
		delete(t.tinfos, string(key))
		if bytes.Equal(key, t.self.from()) {
			t.self = nil
			t._fix()
		}
		for _, dinfo := range t.dinfos {
			if bytes.Equal(key, dinfo.prev) || bytes.Equal(key, dinfo.prev) {
				t._teardown(key, dinfo.source)
			}
		}
	})
}

func (t *dhtree) _fix() {
	oldSelf := t.self
	if t.self == nil || treeLess(t.self.root, t.core.crypto.publicKey) {
		t.self = &treeInfo{root: t.core.crypto.publicKey}
	}
	for _, info := range t.tinfos {
		switch {
		case !info.checkLoops():
			// This has a loop, e.g. it's from a child, so skip it
		case treeLess(t.self.root, info.root):
			// This is a better root
			t.self = info
		case treeLess(info.root, t.self.root):
			// This is a worse root, so don't do anything with it
		case len(info.hops) < len(t.self.hops):
			// This is a shorter path to the root
			t.self = info
		case len(info.hops) > len(t.self.hops):
			// This is a longer path to the root, so don't do anything with it
		case treeLess(t.self.from(), info.from()):
			// This peer has a higher key than our current parent
			t.self = info
		}
	}
	if t.self != oldSelf {
		t.core.peers.sendTree(t, t.self)
	}
}

func (t *dhtree) _treeLookup(dest *treeInfo) publicKey {
	best := t.self
	bestDist := best.dist(dest)
	for _, info := range t.tinfos {
		tmp := *info
		tmp.hops = tmp.hops[:len(tmp.hops)-1]
		dist := tmp.dist(dest)
		var isBetter bool
		switch {
		case dist < bestDist:
			isBetter = true
		case dist > bestDist:
		case treeLess(best.from(), info.from()):
			isBetter = true
		}
		if isBetter {
			best = info
			bestDist = dist
		}
	}
	if !bytes.Equal(best.root, dest.root) {
		// Dead end, so stay here
		return t.core.crypto.publicKey
	}
	return best.from()
}

func (t *dhtree) _dhtLookup(dest publicKey) publicKey {
	return t._keyspaceLookup(dest, false)
}

func (t *dhtree) _dhtBootstrapLookup(dest publicKey) publicKey {
	return t._keyspaceLookup(dest, true)
}

func (t *dhtree) _keyspaceLookup(dest publicKey, reverse bool) publicKey {
	// Initialize to self
	best := t.core.crypto.publicKey
	bestPeer := best
	// First check treeInfo
	if dhtOrdered(dest, t.self.root, best, reverse) {
		best = t.self.root
		bestPeer = t.self.from()
	}
	for _, hop := range t.self.hops {
		if dhtOrdered(dest, hop.next, best, reverse) {
			best = t.self.root
			bestPeer = t.self.from()
		}
	}
	// Next check peers
	for _, info := range t.tinfos {
		peer := info.from()
		if dhtOrdered(dest, peer, best, reverse) {
			best = peer
			bestPeer = peer
		}
	}
	// Finally check paths from the dht
	for _, info := range t.dinfos {
		if !reverse && dhtOrdered(dest, info.source, best, false) {
			best = info.source
			bestPeer = info.prev
		} else if reverse && dhtOrdered(dest, info.dest, best, true) {
			best = info.dest
			bestPeer = info.next
		} else if reverse && bytes.Equal(best, info.dest) && treeLess(bestPeer, info.next) {
			best = info.dest
			bestPeer = info.next
		}
	}
	return bestPeer
}

func (t *dhtree) newSetup(dest *treeInfo) *dhtSetup {
	setup := new(dhtSetup)
	setup.source = t.core.crypto.publicKey
	setup.dest = *dest
	setup.sig = t.core.crypto.privateKey.sign(setup.bytesForSig())
	return setup
}

func (t *dhtree) _handleSetup(prev publicKey, setup *dhtSetup) {
	if _, isIn := t.dinfos[string(setup.source)]; isIn {
		// TODO cancel the setup and tear down instead
		panic("TODO")
	}
	next := t._treeLookup(&setup.dest)
	dkey := setup.destKey()
	if bytes.Equal(t.core.crypto.publicKey, next) && !bytes.Equal(next, dkey) {
		// We're the next hop, but not the destination
		// TODO cancel the setup and tear down instead
		panic("TODO")
	}
	dinfo := new(dhtInfo)
	dinfo.source = setup.source
	dinfo.prev = prev
	dinfo.next = next
	dinfo.dest = dkey
	t.dinfos[string(dinfo.source)] = dinfo
	// TODO forward the setup to the next hop
	panic("TODO")
}

func (t *dhtree) _teardown(from, source publicKey) {
	if dinfo, isIn := t.dinfos[string(source)]; isIn {
		var next publicKey
		if bytes.Equal(from, dinfo.prev) {
			next = dinfo.next
		} else if bytes.Equal(from, dinfo.next) {
			next = dinfo.prev
		} else {
			panic("DEBUG teardown of nonexistant path")
		}
		delete(t.dinfos, string(source))
		// TODO forward teardown to next
		_ = next
	} else {
		panic("DEBUG teardown of nonexistant path")
	}
}

/************
 * treeInfo *
 ************/

type treeInfo struct {
	root publicKey
	hops []treeHop
}

type treeHop struct {
	next publicKey
	sig  signature
}

func (info *treeInfo) from() publicKey {
	key := info.root
	if len(info.hops) > 1 {
		// last hop is to this node, 2nd to last is to the previous hop, which is who this is from
		hop := info.hops[len(info.hops)-2]
		key = hop.next
	}
	return key
}

func (info *treeInfo) checkSigs() bool {
	if len(info.hops) == 0 {
		return false
	}
	var bs []byte
	key := info.root
	bs = append(bs, info.root...)
	for _, hop := range info.hops {
		bs = append(bs, hop.next...)
		if !key.verify(bs, hop.sig) {
			return false
		}
		key = hop.next
	}
	return true
}

func (info *treeInfo) checkLoops() bool {
	key := info.root
	keys := make(map[string]bool) // Used to avoid loops
	for _, hop := range info.hops {
		if keys[string(key)] {
			return false
		}
		keys[string(key)] = true
		key = hop.next
	}
	return !keys[string(key)]
}

func (info *treeInfo) add(priv privateKey, next publicKey) *treeInfo {
	newInfo := *info
	newInfo.hops = append([]treeHop(nil), info.hops...)
	var bs []byte
	bs = append(bs, info.root...)
	for _, hop := range info.hops {
		bs = append(bs, hop.next...)
	}
	bs = append(bs, next...)
	sig := priv.sign(bs)
	newInfo.hops = append(info.hops, treeHop{next: next, sig: sig})
	return &newInfo
}

func (info *treeInfo) dist(dest *treeInfo) int {
	if !bytes.Equal(info.root, dest.root) {
		return int(^(uint(0)) >> 1) // max int, but you should really check this first
	}
	a := info.hops
	b := dest.hops
	if len(b) < len(a) {
		a, b = b, a
	}
	lcaIdx := -1 // last common ancestor
	for idx := range a {
		if !bytes.Equal(a[idx].next, b[idx].next) {
			break
		}
		lcaIdx = idx
	}
	return len(a) + len(b) - 2*lcaIdx
}

func (info *treeInfo) MarshalBinary() (data []byte, err error) {
	data = append(data, info.root...)
	for _, hop := range info.hops {
		data = append(data, hop.next...)
		data = append(data, hop.sig...)
	}
	return
}

func (info *treeInfo) UnmarshalBinary(data []byte) error {
	nfo := treeInfo{}
	if !wireChopBytes((*[]byte)(&nfo.root), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	}
	for len(data) > 0 {
		hop := treeHop{}
		switch {
		case !wireChopBytes((*[]byte)(&hop.next), &data, publicKeySize):
			return wireUnmarshalBinaryError
		case !wireChopBytes((*[]byte)(&hop.sig), &data, signatureSize):
			return wireUnmarshalBinaryError
		}
		nfo.hops = append(nfo.hops, hop)
	}
	*info = nfo
	return nil
}

/***********
 * dhtInfo *
 ***********/

type dhtInfo struct {
	source publicKey
	prev   publicKey
	next   publicKey
	dest   publicKey
}

/************
 * dhtSetup *
 ************/

type dhtSetup struct {
	sig    signature
	source publicKey
	dest   treeInfo
}

func (s *dhtSetup) destKey() publicKey {
	key := s.dest.root
	if len(s.dest.hops) > 0 {
		key = s.dest.hops[len(s.dest.hops)-1].next
	}
	return key
}

func (s *dhtSetup) bytesForSig() []byte {
	var bs []byte
	bs = append(bs, s.source...)
	bs = append(bs, s.dest.root...)
	for _, hop := range s.dest.hops {
		bs = append(bs, hop.next...)
	}
	return bs
}

func (s *dhtSetup) check() bool {
	return s.dest.checkLoops() && s.source.verify(s.bytesForSig(), s.sig) && s.dest.checkSigs()
}

func (s *dhtSetup) MarshalBinary() (data []byte, err error) {
	var tmp []byte
	if tmp, err = s.dest.MarshalBinary(); err != nil {
		return
	}
	data = append(data, s.sig...)
	data = append(data, s.source...)
	data = append(data, tmp...)
	return
}

func (s *dhtSetup) UnmarshalBinary(data []byte) error {
	var tmp dhtSetup
	if !wireChopBytes((*[]byte)(&tmp.sig), &data, signatureSize) {
		return wireUnmarshalBinaryError
	} else if !wireChopBytes((*[]byte)(&tmp.source), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	} else if err := tmp.dest.UnmarshalBinary(data); err != nil {
		return err
	}
	*s = tmp
	return nil
}

/***************
 * dhtTeardown *
 ***************/

type dhtTeardown struct {
	source publicKey
}

/*********************
 * utility functions *
 *********************/

func treeLess(key1, key2 publicKey) bool {
	for idx := range key1 {
		switch {
		case key1[idx] < key2[idx]:
			return true
		case key1[idx] > key2[idx]:
			return false
		}
	}
	return false
}

func dhtOrdered(first, second, third publicKey, reverse bool) bool {
	if reverse {
		first, third = third, first
	}
	less12 := treeLess(first, second)
	less23 := treeLess(second, third)
	less31 := treeLess(third, first)
	switch {
	case less12 && less23:
		return true
	case less23 && less31:
		return true
	case less31 && less12:
		return true
	}
	return false
}
