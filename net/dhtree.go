package net

import (
	"encoding/binary"
	"time"

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
	pred   *dhtInfo             // predecessor in tree, they maintain a path to us
	succ   *dhtInfo             // successor in tree, who we maintain a path to
	seq    uint64               // updated whenever we send a new setup, technically it doesn't need to increase (it just needs to be different)
	timer  *time.Timer          // time.AfterFunc to send bootstrap packets
}

func (t *dhtree) init(c *core) {
	t.core = c
	t.tinfos = make(map[string]*treeInfo)
	t.dinfos = make(map[string]*dhtInfo)
	t.self = &treeInfo{root: t.core.crypto.publicKey}
	t.seq = uint64(time.Now().UnixNano())
	t.timer = time.AfterFunc(0, func() { t.Act(nil, t._doBootstrap) })
}

func (t *dhtree) update(from phony.Actor, info *treeInfo) {
	t.Act(from, func() {
		oldSelf := t.self
		// The tree info should have been checked before this point
		key := info.from()
		t.tinfos[string(key)] = info
		if key.equal(t.self.from()) {
			t.self = nil
		}
		t._fix()
		t._doBootstrap() // FIXME don't do this every time, only when we need to...
		println("DEBUG recv tree update:", time.Now().String(), t.core.crypto.publicKey.addr().String(), info.root.addr().String(), oldSelf.root.addr().String(), t.self.root.addr().String())
	})
}

func (t *dhtree) remove(from phony.Actor, info *treeInfo) {
	t.Act(from, func() {
		key := info.from()
		delete(t.tinfos, string(key))
		if key.equal(t.self.from()) {
			t.self = nil
			t._fix()
		}
		for _, dinfo := range t.dinfos {
			if key.equal(dinfo.prev) || key.equal(dinfo.prev) {
				t._teardown(key, dinfo.getTeardown())
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
	hasSelf := t.self != nil && t.self.root.equal(t.core.crypto.publicKey)
	for _, info := range t.tinfos {
		if treeLess(t.self.root, info.root) {
			println("DEBUG bad root:", t.core.crypto.publicKey.addr().String(), t.self.root.addr().String(), info.root.addr().String(), info.checkLoops())
			panic("DEBUG")
		}
		if t.self == info {
			hasSelf = true
		}
	}
	if !hasSelf {
		panic("inconsistent tree")
	}
	if t.self != oldSelf {
		t.core.peers.sendTree(t, t.self)
	}
}

func (t *dhtree) _treeLookup(dest *treeInfo) publicKey {
	if t.core.crypto.publicKey.equal(dest.dest()) {
		return t.core.crypto.publicKey
	}
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
	if !best.root.equal(dest.root) {
		// Dead end, so stay here
		println("DEBUG bad tree", t.core.crypto.publicKey.addr().String(), best.root.addr().String(), dest.root.addr().String())
		return t.core.crypto.publicKey
	}
	return best.from()
}

func (t *dhtree) _dhtLookup(dest publicKey) publicKey {
	best := t.core.crypto.publicKey
	bestPeer := t.core.crypto.publicKey
	for _, info := range t.dinfos {
		if info.source.equal(dest) || dhtOrdered(dest, info.source, best) {
			best = info.source
			bestPeer = info.prev
		}
	}
	// TODO use self/peer info, and share code with the below...
	return bestPeer
}

func (t *dhtree) _dhtBootstrapLookup(dest publicKey) publicKey {
	best := t.self.root
	bestPeer := t.self.from()
	for _, info := range t.tinfos {
		peer := info.from()
		if best.equal(dest) || dhtOrdered(best, peer, dest) {
			best = peer
			bestPeer = peer
		}
	}
	for _, info := range t.dinfos {
		if best.equal(dest) || dhtOrdered(best, info.dest, dest) {
			best = info.dest
			bestPeer = info.next
		}
	}
	// FIXME use all hops in self info, and share code with the above...
	return bestPeer
}

func (t *dhtree) _handleBootstrap(bootstrap *dhtBootstrap) {
	// FIXME we need better sanity checks before removing an existing successor
	//  e.g. test _treeLookup first
	source := bootstrap.info.dest()
	next := t._dhtBootstrapLookup(source)
	switch {
	case !t.core.crypto.publicKey.equal(next):
		t.core.peers.sendBootstrap(t, next, bootstrap)
		return
	case t.core.crypto.publicKey.equal(bootstrap.info.dest()):
		// This is our own bootstrap, but we failed to find a next hop
		println("DEBUG hb: 1")
		return
	case t.succ == nil:
		println("DEBUG hb: 2")
	case dhtOrdered(t.core.crypto.publicKey, source, t.succ.dest):
		println("DEBUG hb: 3")
	default:
		// We already have a better (FIXME? or equal) successor
		println("DEBUG hb: 4")
		println("DEBUG details:", t.core.crypto.publicKey.addr().String(), t.succ.dest.addr().String(), source.addr().String())
		return
	}
	if t.succ != nil {
		sinfo := t.dinfos[string(t.core.crypto.publicKey)]
		if sinfo == nil {
			panic("no dhtInfo for successor, this should never happen")
		}
		println("DEBUG removing old succ:", t.core.crypto.publicKey.addr().String(), sinfo.dest.addr().String(), source.addr().String())
		t._teardown(t.core.crypto.publicKey, sinfo.getTeardown())
		if t.succ != nil {
			panic("this should never happen")
		}
	}
	setup := t.newSetup(&bootstrap.info)
	t._handleSetup(t.core.crypto.publicKey, setup)
	if t.succ == nil {
		println("DEBUG hb: 5")
		//panic("this also should never happen")
		// FIXME this can happen if treeLookup fails to find a next hop...
		//  but then, we shouldn't be getting rid of our old successor...
	}
	println("DEBUG hb: 6")
}

func (t *dhtree) handleBootstrap(from phony.Actor, bootstrap *dhtBootstrap) {
	t.Act(from, func() {
		t._handleBootstrap(bootstrap)
	})
}

func (t *dhtree) newSetup(dest *treeInfo) *dhtSetup {
	t.seq++
	setup := new(dhtSetup)
	setup.seq = t.seq
	setup.source = t.core.crypto.publicKey
	setup.dest = *dest
	setup.sig = t.core.crypto.privateKey.sign(setup.bytesForSig())
	return setup
}

func (t *dhtree) _handleSetup(prev publicKey, setup *dhtSetup) {
	if dinfo, isIn := t.dinfos[string(setup.source)]; isIn {
		// Already have a path from this source
		// FIXME need to delete the old path too... anything else?
		if dinfo.seq != setup.seq {
			println("DEBUG duplicate setup", t.core.crypto.publicKey.addr().String(), prev.addr().String(), setup.source.addr().String(), setup.seq, dinfo.source.addr().String(), dinfo.seq)
			//panic("DEBUG duplicate setup")
			t.core.peers.sendTeardown(t, prev, setup.getTeardown())
		} else {
			println("DEBUG duplicate setup with same seq", t.core.crypto.publicKey.addr().String(), prev.addr().String(), setup.source.addr().String(), setup.seq, dinfo.source.addr().String(), dinfo.seq)
			t.core.peers.sendTeardown(t, prev, setup.getTeardown())
			//panic("this should never happen in testing")
		}
		return
	}
	next := t._treeLookup(&setup.dest)
	dest := setup.dest.dest()
	if t.core.crypto.publicKey.equal(next) && !next.equal(dest) {
		// FIXME this has problems if prev is self (from changes to tree state?)
		//panic("DEBUG dead end")
		if !prev.equal(t.core.crypto.publicKey) {
			println("DEBUG sending dead-end teardown", t.core.crypto.publicKey.addr().String(), prev.addr().String(), next.addr().String(), dest.addr().String())
			t.core.peers.sendTeardown(t, prev, setup.getTeardown())
		} else {
			// TODO? something?
			//println("DEBUG *not* sending dead-end teardown", t.core.crypto.publicKey.addr().String(), prev.addr().String(), next.addr().String(), dest.addr().String())
		}
		return
	}
	dinfo := new(dhtInfo)
	dinfo.seq = setup.seq
	dinfo.source = setup.source
	dinfo.prev = prev
	dinfo.next = next
	dinfo.dest = dest
	t.dinfos[string(dinfo.source)] = dinfo
	if prev.equal(t.core.crypto.publicKey) {
		// sanity checks, this should only happen when setting up our successor
		if !setup.source.equal(prev) {
			panic("wrong source")
		} else if setup.seq != t.seq {
			panic("wrong seq")
		} else if t.succ != nil {
			panic("already have a successor")
		}
		t.succ = dinfo
	}
	if !t.core.crypto.publicKey.equal(next) {
		t.core.peers.sendSetup(t, next, setup)
	} else {
		// TODO special case, this is our predecessor
		if t.pred != nil {
			println("DEBUG going to teardown old pred:", t.core.crypto.publicKey.addr().String(), t.pred.source.addr().String(), dinfo.source.addr().String())
			t._teardown(t.core.crypto.publicKey, t.pred.getTeardown())
		}
		t.pred = dinfo
	}
}

func (t *dhtree) handleSetup(from phony.Actor, prev publicKey, setup *dhtSetup) {
	t.Act(from, func() {
		t._handleSetup(prev, setup)
	})
}

func (t *dhtree) _teardown(from publicKey, teardown *dhtTeardown) {
	if dinfo, isIn := t.dinfos[string(teardown.source)]; isIn {
		if teardown.seq != dinfo.seq {
			return
		} else if !teardown.source.equal(dinfo.source) {
			panic("DEBUG this should never happen")
			return
		} else if !teardown.dest.equal(dinfo.dest) {
			panic("DEBUG if this happens then there's a design problem")
			return
		}
		var next publicKey
		if from.equal(dinfo.prev) {
			next = dinfo.next
		} else if from.equal(dinfo.next) {
			next = dinfo.prev
		} else {
			panic("DEBUG teardown of path from wrong node")
		}
		delete(t.dinfos, string(teardown.source))
		if !next.equal(t.core.crypto.publicKey) {
			//println("DEBUG going to send teardown:", t.core.crypto.publicKey.addr().String(), next.addr().String())
			t.core.peers.sendTeardown(t, next, teardown)
		}
		if t.pred == dinfo {
			println("Removed pred:", t.core.crypto.publicKey.addr().String(), dinfo.source.addr().String())
			t.pred = nil
			t._doBootstrap()
		}
		if t.succ == dinfo {
			println("Removed succ:", t.core.crypto.publicKey.addr().String(), dinfo.dest.addr().String())
			t.succ = nil
			//t._findSuccessor()
		}
	} else {
		//panic("DEBUG teardown of nonexistant path")
	}
}

func (t *dhtree) teardown(from phony.Actor, peerKey publicKey, teardown *dhtTeardown) {
	t.Act(from, func() {
		t._teardown(peerKey, teardown)
	})
}

func (t *dhtree) _doBootstrap() {
	if t.timer != nil && t.pred == nil {
		println("DEBUG findSuccessor:", t.core.crypto.publicKey.addr().String())
		t._handleBootstrap(&dhtBootstrap{info: *t.self})
		t.timer.Stop()
		t.timer = time.AfterFunc(time.Second, func() { t.Act(nil, t._doBootstrap) })
	}
}

func (t *dhtree) handleDHTTraffic(from phony.Actor, tr *dhtTraffic) {
	t.Act(from, func() {
		next := t._dhtLookup(tr.dest)
		if next.equal(t.core.crypto.publicKey) {
			t.core.pconn.handleTraffic(t, tr)
		} else {
			t.core.peers.sendDHTTraffic(t, next, tr)
		}
	})
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

func (info *treeInfo) dest() publicKey {
	key := info.root
	if len(info.hops) > 0 {
		key = info.hops[len(info.hops)-1].next
	}
	return key
}

func (info *treeInfo) from() publicKey {
	key := info.root
	if len(info.hops) > 1 {
		// last hop is to this node, 2nd to last is to the previous hop, which is who this is from
		key = info.hops[len(info.hops)-2].next
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
	newInfo.hops = nil
	newInfo.hops = append(newInfo.hops, info.hops...)
	newInfo.hops = append(newInfo.hops, treeHop{next: next, sig: sig})
	return &newInfo
}

func (info *treeInfo) dist(dest *treeInfo) int {
	if !info.root.equal(dest.root) {
		return int(^(uint(0)) >> 1) // max int, but you should really check this first
	}
	a := info.hops
	b := dest.hops
	if len(b) < len(a) {
		a, b = b, a
	}
	lcaIdx := -1 // last common ancestor
	for idx := range a {
		if !a[idx].next.equal(b[idx].next) {
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
	seq    uint64
	source publicKey
	prev   publicKey
	next   publicKey
	dest   publicKey
}

func (info *dhtInfo) getTeardown() *dhtTeardown {
	return &dhtTeardown{seq: info.seq, source: info.source, dest: info.dest}
}

/****************
 * dhtBootstrap *
 ****************/

type dhtBootstrap struct {
	info treeInfo
}

func (dbs *dhtBootstrap) check() bool {
	//FIXME checkSigs is broken if from the root, bootstrap probably needs its own format...
	//return dbs.info.checkLoops() && dbs.info.checkSigs()
	return true
}

func (dbs *dhtBootstrap) MarshalBinary() (data []byte, err error) {
	return dbs.info.MarshalBinary()
}

func (dbs *dhtBootstrap) UnmarshalBinary(data []byte) error {
	var tmp dhtBootstrap
	if err := tmp.info.UnmarshalBinary(data); err != nil {
		return err
	}
	*dbs = tmp
	return nil
}

/************
 * dhtSetup *
 ************/

// FIXME setup probably needs a path ID or something, to prevent races between setups and teardowns...

type dhtSetup struct {
	sig    signature
	source publicKey
	seq    uint64
	dest   treeInfo
}

func (s *dhtSetup) bytesForSig() []byte {
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, s.seq)
	bs = append(bs, s.source...)
	bs = append(bs, s.dest.root...)
	for _, hop := range s.dest.hops {
		bs = append(bs, hop.next...)
	}
	return bs
}

func (s *dhtSetup) check() bool {
	// FIXME checkSigs broken if from the root, same issue as with bootstrap packets...
	return true
	return s.dest.checkLoops() && s.source.verify(s.bytesForSig(), s.sig) && s.dest.checkSigs()
}

func (s *dhtSetup) getTeardown() *dhtTeardown {
	return &dhtTeardown{seq: s.seq, source: s.source, dest: s.dest.dest()}
}

func (s *dhtSetup) MarshalBinary() (data []byte, err error) {
	var tmp []byte
	if tmp, err = s.dest.MarshalBinary(); err != nil {
		return
	}
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, s.seq)
	data = append(data, s.sig...)
	data = append(data, s.source...)
	data = append(data, seq...)
	data = append(data, tmp...)
	return
}

func (s *dhtSetup) UnmarshalBinary(data []byte) error {
	var tmp dhtSetup
	if !wireChopBytes((*[]byte)(&tmp.sig), &data, signatureSize) {
		return wireUnmarshalBinaryError
	} else if !wireChopBytes((*[]byte)(&tmp.source), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	}
	if len(data) < 8 {
		return wireUnmarshalBinaryError
	}
	tmp.seq, data = binary.BigEndian.Uint64(data[:8]), data[8:]
	if err := tmp.dest.UnmarshalBinary(data); err != nil {
		return err
	}
	*s = tmp
	return nil
}

/***************
 * dhtTeardown *
 ***************/

type dhtTeardown struct {
	seq    uint64
	source publicKey
	dest   publicKey
}

func (t *dhtTeardown) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint64(data, t.seq)
	data = append(data, t.source...)
	data = append(data, t.dest...)
	return
}

func (t *dhtTeardown) UnmarshalBinary(data []byte) error {
	var tmp dhtTeardown
	if len(data) < 8 {
		return wireUnmarshalBinaryError
	}
	tmp.seq, data = binary.BigEndian.Uint64(data[:8]), data[8:]
	if !wireChopBytes((*[]byte)(&tmp.source), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	} else if !wireChopBytes((*[]byte)(&tmp.dest), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	} else if len(data) != 0 {
		return wireUnmarshalBinaryError
	}
	*t = tmp
	return nil
}

/**************
 * dhtTraffic *
 **************/

type dhtTraffic struct {
	source  publicKey
	dest    publicKey
	payload []byte
}

func (t *dhtTraffic) MarshalBinary() (data []byte, err error) {
	data = append(data, t.source...)
	data = append(data, t.dest...)
	data = append(data, t.payload...)
	return
}

func (t *dhtTraffic) UnmarshalBinary(data []byte) error {
	var tr dhtTraffic
	if !wireChopBytes((*[]byte)(&tr.source), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	} else if !wireChopBytes((*[]byte)(&tr.dest), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	} else if len(data) == 0 {
		return wireUnmarshalBinaryError
	}
	t.payload = append([]byte(nil), data...)
	*t = tr
	return nil
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

func dhtOrdered(first, second, third publicKey) bool {
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
