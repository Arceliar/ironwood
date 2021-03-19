package net

import (
	"crypto/rand"
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
	wait   bool                 // FIXME this is a hack to let bad news spread before changing parents
}

func (t *dhtree) init(c *core) {
	t.core = c
	t.tinfos = make(map[string]*treeInfo)
	t.dinfos = make(map[string]*dhtInfo)
	t.self = &treeInfo{root: t.core.crypto.publicKey}
	t.seq = uint64(time.Now().UnixNano())
	r := make([]byte, 8)
	if _, err := rand.Read(r); err != nil {
		panic(err)
	}
	for idx := range r {
		t.seq |= uint64(r[idx]) << 8 * uint64(idx)
	}
	t.timer = time.AfterFunc(0, func() { t.Act(nil, t._doBootstrap) })
}

// update adds a treeInfo to the spanning tree
// it then fixes the tree (selecting a new parent, if needed) and the dht (restarting the bootstrap process)
// if the info is from the current parent, then there's a delay before the tree/dht are fixed
//  that prevents a race where we immediately switch to a new parent, who tries to do the same with us
//  this avoids the tons of traffic generated when nodes race to use each other as parents
func (t *dhtree) update(from phony.Actor, info *treeInfo) {
	t.Act(from, func() {
		// The tree info should have been checked before this point
		key := info.from()
		oldInfo := t.tinfos[string(key)]
		t.tinfos[string(key)] = info
		if t.self == oldInfo {
			//t.self = nil
			t.self = &treeInfo{root: t.core.crypto.publicKey}
			t.core.peers.sendTree(t, t.self)
			if !t.wait {
				t.wait = true
				time.AfterFunc(time.Second, func() {
					t.Act(nil, func() {
						t.wait = false
						t._fix()
						t._doBootstrap()
					})
				})
			}
			return
		}
		if !t.wait {
			t._fix()
			t._doBootstrap() // FIXME don't do this every time, only when we need to...
		}
	})
}

// remove removes a peer from the tree, along with any paths through that peer in the dht
func (t *dhtree) remove(from phony.Actor, info *treeInfo) {
	t.Act(from, func() {
		key := info.from()
		oldInfo := t.tinfos[string(key)]
		delete(t.tinfos, string(key))
		if t.self == oldInfo {
			t.self = nil
			t._fix()
		}
		for _, dinfo := range t.dinfos {
			if key.equal(dinfo.prev) || key.equal(dinfo.next) {
				t._teardown(key, dinfo.getTeardown())
			}
		}
	})
}

// _fix selects the best parent (and is called in response to receiving a tree update)
// if this is not the same as our current parent, then it sends a tree update to our peers and resets our predecessor/successor in the dht
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
		// TODO? don't tear down every time thing change
		//  Strictly required whenever the root changes
		//  Ideally we probably want to tear down in at least some other case too
		//  Otherwise we would keep an old path forever after better ones appear
		//  Maybe in doBootstrap instead? That gets called after every tree update...
		if t.pred != nil {
			t._teardown(t.core.crypto.publicKey, t.pred.getTeardown())
		}
		if t.succ != nil {
			t._teardown(t.core.crypto.publicKey, t.succ.getTeardown())
		}
	}
}

// _treeLookup selects the best next hop (in treespace) for the destination
func (t *dhtree) _treeLookup(dest *treeInfo) publicKey {
	if t.core.crypto.publicKey.equal(dest.dest()) {
		return t.core.crypto.publicKey
	}
	best := t.self
	bestDist := best.dist(dest)
	bestPeer := t.core.crypto.publicKey
	for _, info := range t.tinfos {
		if !info.root.equal(dest.root) {
			continue
		}
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
			bestPeer = best.from()
		}
	}
	if !best.root.equal(dest.root) {
		// Dead end, so stay here
		return t.core.crypto.publicKey
	}
	return bestPeer
}

// _dhtLookup selects the next hop needed to route closer to the destination in dht keyspace
// this only uses the source direction of paths through the dht
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

// _dhtBootstrapLookup selects the next hop needed to route closer to the destination in dht keyspace
// this uses the destination direction of paths through the dht, so the node at the end of the line is the right one to repair a gap in the dht
// note that this also considers peers (this is what bootstraps the whole process)
// it also considers the root, to make sure that multiple split rings will converge back to one
func (t *dhtree) _dhtBootstrapLookup(dest publicKey) publicKey {
	best := t.core.crypto.publicKey
	bestPeer := t.core.crypto.publicKey
	if best.equal(dest) || dhtOrdered(best, t.self.root, dest) {
		best = t.self.root
		bestPeer = t.self.from()
	}
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

// _dhtAdd adds a dhtInfo to the dht and returns true
// it may return false if the path associated with the dhtInfo isn't allowed for some reason
//  e.g. we know a better successor/predecessor for one of the nodes in the path, which can happen if there's multiple split rings that haven't converged on their own yet
// as of writing, that never happens, it always adds and returns true
func (t *dhtree) _dhtAdd(info *dhtInfo) bool {
	for _, dinfo := range t.dinfos {
		break // FIXME this is broken for some reason
		if dhtOrdered(info.source, dinfo.source, info.dest) {
			return false // There's a better successor for this source
		}
	}
	for _, dinfo := range t.dinfos {
		break // TODO this or something like it
		if dinfo == t.pred || dinfo == t.succ {
			continue // Special cases, handled elsewhere
		}
		if dhtOrdered(dinfo.source, info.source, dinfo.dest) {
			t._teardown(dinfo.prev, dinfo.getTeardown())
			t._teardown(dinfo.next, dinfo.getTeardown())
		}
	}
	t.dinfos[string(info.source)] = info
	return true
}

// _handleBootstrap takes a bootstrap packet and checks if we know of a better predecessor for the source node
// if yes, then we forward to the next hop in the path towards that predecessor
// if no, then we decide whether or not this node is better than our current successor
// if yes, then we get rid of our current successor (if any) and start setting up a new path to the source of the bootstrap
// if no, then we drop the bootstrap without doing anything
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
		return
	case t.succ == nil:
	case dhtOrdered(t.core.crypto.publicKey, source, t.succ.dest):
	default:
		// We already have a better (FIXME? or equal) successor
		return
	}
	if t.succ != nil {
		sinfo := t.dinfos[string(t.core.crypto.publicKey)]
		if sinfo == nil {
			panic("no dhtInfo for successor, this should never happen")
		}
		t._teardown(t.core.crypto.publicKey, sinfo.getTeardown())
		if t.succ != nil {
			panic("this should never happen")
		}
	}
	setup := t.newSetup(&bootstrap.info)
	t._handleSetup(t.core.crypto.publicKey, setup)
	if t.succ == nil {
		// This can happen if the treeLookup in handleSetup fails
		// FIXME we should avoid letting this happen
		//  E.g. check that the lookup will succeed, or at least that the roots match
	}
}

// handleBootstrap is the externally callable actor behavior that sends a message to the dhtree that it should _handleBootstrap
func (t *dhtree) handleBootstrap(from phony.Actor, bootstrap *dhtBootstrap) {
	t.Act(from, func() {
		t._handleBootstrap(bootstrap)
	})
}

// newSetup returns a *dhtSetup for this node, with a new sequence number and signature
func (t *dhtree) newSetup(dest *treeInfo) *dhtSetup {
	t.seq++
	setup := new(dhtSetup)
	setup.seq = t.seq
	setup.source = t.core.crypto.publicKey
	setup.dest = *dest
	setup.sig = t.core.crypto.privateKey.sign(setup.bytesForSig())
	return setup
}

// _handleSetup checks if it's safe to add a path from the setup source to the setup destination
// if we can't add it (due to no next hop to forward it to, or if we're the destination but we already have a better predecessor, or if we already have a path from the same source node), then we send a teardown to remove the path from the network
// otherwise, we add the path to our table, and forward it (if we're not the destination) or set it as our predecessor path (if we are, tearing down our existing predecessor if one exists)
func (t *dhtree) _handleSetup(prev publicKey, setup *dhtSetup) {
	if _, isIn := t.dinfos[string(setup.source)]; isIn {
		// Already have a path from this source
		t.core.peers.sendTeardown(t, prev, setup.getTeardown())
		return
	}
	next := t._treeLookup(&setup.dest)
	dest := setup.dest.dest()
	if t.core.crypto.publicKey.equal(next) && !next.equal(dest) {
		// FIXME? this has problems if prev is self (from changes to tree state?)
		if !prev.equal(t.core.crypto.publicKey) {
			t.core.peers.sendTeardown(t, prev, setup.getTeardown())
		}
		return
	}
	dinfo := new(dhtInfo)
	dinfo.seq = setup.seq
	dinfo.source = setup.source
	dinfo.prev = prev
	dinfo.next = next
	dinfo.dest = dest
	if !t._dhtAdd(dinfo) {
		t.core.peers.sendTeardown(t, prev, setup.getTeardown())
	}
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
		var coords []string
		coords = append(coords, t.self.root.addr().String())
		for _, hop := range t.self.hops {
			coords = append(coords, hop.next.addr().String())
		}
		var dc []string
		dc = append(dc, setup.dest.root.addr().String())
		for _, hop := range setup.dest.hops {
			dc = append(dc, hop.next.addr().String())
		}
		var pcc [][]string
		for _, tinfo := range t.tinfos {
			var pc []string
			pc = append(pc, tinfo.root.addr().String())
			for _, hop := range tinfo.hops {
				pc = append(pc, hop.next.addr().String())
			}
			pcc = append(pcc, pc)
		}
		t.core.peers.sendSetup(t, next, setup)
	} else {
		if t.pred != nil {
			t._teardown(t.core.crypto.publicKey, t.pred.getTeardown())
		}
		t.pred = dinfo
	}
}

// handleSetup is the dhtree actor behavior that sends a message to _handleSetup
func (t *dhtree) handleSetup(from phony.Actor, prev publicKey, setup *dhtSetup) {
	t.Act(from, func() {
		t._handleSetup(prev, setup)
	})
}

// _teardown removes the path associated with the teardown from our dht and forwards it to the next hop along that path (or does nothing if the teardown doesn't match a known path)
func (t *dhtree) _teardown(from publicKey, teardown *dhtTeardown) {
	if dinfo, isIn := t.dinfos[string(teardown.source)]; isIn {
		if teardown.seq != dinfo.seq {
			return
		} else if !teardown.source.equal(dinfo.source) {
			panic("DEBUG this should never happen")
			// return
		} else if !teardown.dest.equal(dinfo.dest) {
			panic("DEBUG if this happens then there's a design problem")
			// return
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
			t.core.peers.sendTeardown(t, next, teardown)
		}
		if t.pred == dinfo {
			t.pred = nil
			t._doBootstrap()
		}
		if t.succ == dinfo {
			t.succ = nil
		}
	} else {
		//panic("DEBUG teardown of nonexistant path")
	}
}

// teardown is the dhtinfo actor behavior that sends a message to _teardown
func (t *dhtree) teardown(from phony.Actor, peerKey publicKey, teardown *dhtTeardown) {
	t.Act(from, func() {
		t._teardown(peerKey, teardown)
	})
}

// _doBootstrap decides whether or not to send a bootstrap packet
// if a bootstrap is sent, then it sets things up to attempt to send another bootstrap at a later point
func (t *dhtree) _doBootstrap() {
	//return // FIXME debug tree (root offline -> too much traffic to fix)
	if t.timer != nil && t.pred == nil {
		t._handleBootstrap(&dhtBootstrap{info: *t.self})
		t.timer.Stop()
		t.timer = time.AfterFunc(time.Second, func() { t.Act(nil, t._doBootstrap) })
	}
}

// handleDHTTraffic take a dht traffic packet (still marshaled as []bytes) and decides where to forward it to next to take it closer to its destination in keyspace
// if there's nowhere better to send it, then it hands it off to be read out from the local PacketConn interface
func (t *dhtree) handleDHTTraffic(from phony.Actor, trbs []byte) {
	t.Act(from, func() {
		var tr dhtTraffic
		if err := tr.UnmarshalBinaryInPlace(trbs); err != nil {
			return
		}
		next := t._dhtLookup(tr.dest)
		if next.equal(t.core.crypto.publicKey) {
			t.core.pconn.handleTraffic(trbs)
		} else {
			t.core.peers.sendDHTTraffic(t, next, trbs)
		}
	})
}

/************
 * treeInfo *
 ************/

type treeInfo struct {
	root publicKey
	seq  uint64
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
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, info.seq)
	bs = append(bs, seq...)
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
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, info.seq)
	bs = append(bs, seq...)
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
  seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, info.seq)
	data = append(data, seq...)
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
	if len(data) >= 8 {
    nfo.seq = binary.BigEndian.Uint64(data[:8])
    data = data[8:]
	} else {
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
	// return s.dest.checkLoops() && s.source.verify(s.bytesForSig(), s.sig) && s.dest.checkSigs()
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

func (t *dhtTraffic) MarshalBinaryTo(slice []byte) ([]byte, error) {
	slice = append(slice, t.source...)
	slice = append(slice, t.dest...)
	slice = append(slice, t.payload...)
	if len(slice) > 65535 {
		return slice, wireMarshalBinaryError
	}
	return slice, nil
}

func (t *dhtTraffic) UnmarshalBinaryInPlace(data []byte) error {
	if len(data) < 2*publicKeySize {
		return wireUnmarshalBinaryError
	}
	t.source = data[:publicKeySize]
	t.dest = data[publicKeySize : 2*publicKeySize]
	t.payload = data[2*publicKeySize:]
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
