package net

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/Arceliar/phony"
)

const (
	treeTIMEOUT  = 60 * time.Second
	treeANNOUNCE = treeTIMEOUT / 2
	treeTHROTTLE = treeANNOUNCE / 2 // TODO use this to limit how fast seqs can update
)

/********
 * tree *
 ********/

type dhtree struct {
	phony.Inbox
	core    *core
	expired map[string]uint64       // map[string(publicKey)](treeInfo.seq) of expired infos per root pubkey (highest seq)
	tinfos  map[string]*treeInfo    // map[string(publicKey)]*treeInfo, key=peer
	dinfos  map[dhtInfoKey]*dhtInfo //
	self    *treeInfo               // self info
	pred    *dhtInfo                // predecessor in tree, they maintain a path to us
	succ    *dhtInfo                // successor in tree, who we maintain a path to
	seq     uint64                  // updated whenever we send a new setup, technically it doesn't need to increase (it just needs to be different)
	timer   *time.Timer             // time.AfterFunc to send bootstrap packets
	wait    bool                    // FIXME this is a hack to let bad news spread before changing parents
}

func (t *dhtree) init(c *core) {
	t.core = c
	t.expired = make(map[string]uint64)
	t.tinfos = make(map[string]*treeInfo)
	t.dinfos = make(map[dhtInfoKey]*dhtInfo) // TODO clean these up after some timeout
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
		if t.self == oldInfo { // TODO also check root/seq stuff, no need to wait if that's updating
			// FIXME this is wrong now that roots send seq updates
			//  We should only wait if the root and seq number are both still the same?
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
		// Note that seq needs to be non-decreasing for the node to function as a root
		//  a timestamp it used to partly mitigate rollbacks from restarting
		t.self = &treeInfo{root: t.core.crypto.publicKey, seq: uint64(time.Now().Unix())}
	}
	for _, info := range t.tinfos {
		if oldSeq, isIn := t.expired[string(info.root)]; isIn {
			if info.seq <= oldSeq {
				continue // skip expired sequence numbers
			}
		}
		switch {
		case !info.checkLoops():
			// This has a loop, e.g. it's from a child, so skip it
		case treeLess(t.self.root, info.root):
			// This is a better root
			t.self = info
		case treeLess(info.root, t.self.root):
			// This is a worse root, so don't do anything with it
		case info.seq > t.self.seq:
			// This is a newer sequence number, so update parent
			t.self = info
		case info.seq < t.self.seq:
			// This is an older sequnce number, so ignore it
		case info.time.Before(t.self.time):
			// This info has been around for longer (e.g. the path is more stable)
			t.self = info
		case info.time.After(t.self.time):
			// This info has been around for less time (e.g. the path is less stable)
			// Note that everything after this is extremely unlikely to be reached...
		case len(info.hops) < len(t.self.hops):
			// This is a shorter path to the root
			t.self = info
		case len(info.hops) > len(t.self.hops):
			// This is a longer path to the root, so don't do anything
		case treeLess(t.self.from(), info.from()):
			// This peer has a higher key than our current parent
			t.self = info
		}
	}
	if t.self != oldSelf {
		if oldSelf == nil || !oldSelf.root.equal(t.self.root) || oldSelf.seq == t.self.seq {
			// We've used an announcement from this root/seq before, so no need to start a timer
		} else {
			// Start a timer to make t.self.seq expire at some point
			self := t.self
			time.AfterFunc(treeTIMEOUT, func() {
				if oldSeq, isIn := t.expired[string(t.self.root)]; !isIn || oldSeq < self.seq {
					t.expired[string(t.self.root)] = self.seq
					if t.self == self {
						t.self = nil
						t._fix()
						t._doBootstrap()
					}
				}
			})
		}
		t.core.peers.sendTree(t, t.self)
		if oldSelf == nil || !oldSelf.root.equal(t.self.root) || oldSelf.seq != t.self.seq {
			// TODO? merge this cleanly with the closely related conditions on the above if statement
			// Strictly required whenever the root changes
			//  Ideally we probably want to tear down in at least some other case too
			//  Otherwise we would keep an old path forever after better ones appear
			//  For now, also tear down any time the root seq updates
			// TODO don't tear down, keep multiple paths and let the old seq paths expire...
			if t.pred != nil {
				// Changed: Keep the old predecessor until we hear about a new one
				//  We'll start sending bootstraps due to the mismatch in root/seq
				//t._teardown(t.core.crypto.publicKey, t.pred.getTeardown())
			}
			if t.succ != nil {
				// Changed: Don't tear down the successor immediately, just set to nil
				//  That way we'll respond to bootstraps
				//  The destination side can tear down the old path when they get a new predecessor
				//t._teardown(t.core.crypto.publicKey, t.succ.getTeardown())
				t.succ = nil
			}
		}
		if t.self.root.equal(t.core.crypto.publicKey) {
			// We're the root, so schedule a timestamp update to happen later
			self := t.self
			time.AfterFunc(treeANNOUNCE, func() {
				// TODO? save this timer and cancel it if needed?
				t.Act(nil, func() {
					if t.self == self {
						t.self = nil
						t._fix()
						t._doBootstrap()
					}
				})
			})
		}
		// Clean up t.expired
		for skey := range t.expired {
			key := publicKey(skey)
			if key.equal(t.self.root) || treeLess(key, t.self.root) {
				delete(t.expired, skey)
			}
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
		if !info.root.equal(dest.root) || info.seq != dest.seq {
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
	if !best.root.equal(dest.root) || best.seq != dest.seq { // TODO? check self, not next/dest?
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
	var bestInfo *dhtInfo
	for _, info := range t.dinfos {
		if info.source.equal(dest) || dhtOrdered(dest, info.source, best) {
			best = info.source
			bestPeer = info.prev
			bestInfo = info
		}
		if bestInfo != nil && info.source.equal(bestInfo.source) && info.rootSeq > bestInfo.rootSeq {
			// Favor new paths
			best = info.source
			bestPeer = info.prev
			bestInfo = info
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
	var bestInfo *dhtInfo
	for _, info := range t.dinfos {
		if best.equal(dest) || dhtOrdered(best, info.dest, dest) {
			best = info.dest
			bestPeer = info.next
			bestInfo = info
		}
		if bestInfo != nil && info.dest.equal(bestInfo.dest) && info.rootSeq > bestInfo.rootSeq {
			// Favor new paths
			best = info.dest
			bestPeer = info.next
			bestInfo = info
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
	t.dinfos[info.getKey()] = info
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
	case !bootstrap.info.root.equal(t.self.root):
		// We have a different root, so tree lookups would fail
		return
	case bootstrap.info.seq != t.self.seq:
		// This bootstrap is too old, so path setup would fail
		return
	case t.succ == nil:
	case dhtOrdered(t.core.crypto.publicKey, source, t.succ.dest):
		// This bootstrap is from a better successor than our current one
	case !t.succ.root.equal(t.self.root) || t.succ.rootSeq != t.self.seq:
		// The curent successor needs replacing (old tree info)
	default:
		// We already have a better (FIXME? or equal) successor
		return
	}
	t.succ = nil
	for _, dinfo := range t.dinfos {
		// Former successors need to be notified that we're no longer a predecessor
		// The only way to signal that is by tearing down the path
		// We may have multiple former successor paths
		//  From t.succ = nil when the tree changes, but kept around to bootstrap
		// So loop over paths and close any going to a *different* node than the current successor
		// The current successor can close the old path from the predecessor side after setup
		if dinfo.source.equal(t.core.crypto.publicKey) && !dinfo.dest.equal(source) {
			t._teardown(t.core.crypto.publicKey, dinfo.getTeardown())
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
	dinfo.root = setup.dest.root
	dinfo.rootSeq = setup.dest.seq
	if !dinfo.root.equal(t.self.root) || dinfo.rootSeq != t.self.seq {
		// Wrong root or mismatched seq
		t.core.peers.sendTeardown(t, prev, setup.getTeardown())
		return
	}
	if _, isIn := t.dinfos[dinfo.getKey()]; isIn {
		// Already have a path from this source
		t.core.peers.sendTeardown(t, prev, setup.getTeardown())
		return
	}
	if !t._dhtAdd(dinfo) {
		t.core.peers.sendTeardown(t, prev, setup.getTeardown())
	}
	dinfo.timer = time.AfterFunc(2*treeTIMEOUT, func() {
		t.Act(nil, func() {
			// Clean up path if it has timed out
			// TODO save this timer, cancel if removing the path prior to this
			if info, isIn := t.dinfos[dinfo.getKey()]; isIn {
				if !info.prev.equal(t.core.crypto.publicKey) {
					t.core.peers.sendTeardown(t, info.prev, info.getTeardown())
				}
				t._teardown(info.prev, info.getTeardown())
			}
		})
	})
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
	if !next.equal(t.core.crypto.publicKey) {
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
			// TODO get this right!
			//  We need to replace the old predecessor in most cases
			//  The exceptions are when:
			//    1. The dinfo's root/seq don't match our current root/seq
			//    2. The dinfo matches, but so does t.pred, and t.pred is better
			//  What happens when the dinfo matches, t.pred does not, but t.pred is still better?...
			//  Just doing something for now (replace pred) but not sure that's right...
			doUpdate := true
			if !dinfo.root.equal(t.self.root) || dinfo.rootSeq != t.self.seq {
				doUpdate = false
			} else if !t.pred.root.equal(t.self.root) || t.pred.rootSeq != t.self.seq {
				// The old pred is old enough to be replaced
			} else if dhtOrdered(dinfo.source, t.pred.source, t.core.crypto.publicKey) {
				// Both dinfo and t.pred match our root/seq, but dinfo is actually worse as a predecessor
				doUpdate = false
			}
			if doUpdate {
				t._teardown(t.core.crypto.publicKey, t.pred.getTeardown())
				t.pred = dinfo
			} else {
				t._teardown(t.core.crypto.publicKey, dinfo.getTeardown())
			}
		} else {
			t.pred = dinfo
		}
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
	if dinfo, isIn := t.dinfos[teardown.getKey()]; isIn {
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
		dinfo.timer.Stop()
		delete(t.dinfos, teardown.getKey())
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
	if t.timer != nil {
		if t.pred != nil && t.pred.root.equal(t.self.root) && t.pred.rootSeq == t.self.seq {
			return
		}
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
	time time.Time // Note: *NOT* serialized
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
	nfo.time = time.Now()
	*info = nfo
	return nil
}

/***********
 * dhtInfo *
 ***********/

type dhtInfo struct {
	seq     uint64
	source  publicKey
	prev    publicKey
	next    publicKey
	dest    publicKey
	root    publicKey
	rootSeq uint64
	timer   *time.Timer // time.AfterFunc to clean up after timeout, stop this on teardown
}

func (info *dhtInfo) getTeardown() *dhtTeardown {
	return &dhtTeardown{seq: info.seq, source: info.source, dest: info.dest, root: info.root, rootSeq: info.rootSeq}
}

type dhtInfoKey struct {
	source  string // publicKey
	root    string // publicKey
	rootSeq uint64
}

func (info *dhtInfo) getKey() dhtInfoKey {
	return dhtInfoKey{string(info.source), string(info.root), info.rootSeq}
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
	return &dhtTeardown{seq: s.seq, source: s.source, dest: s.dest.dest(), root: s.dest.root, rootSeq: s.dest.seq}
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
	seq     uint64
	source  publicKey
	dest    publicKey
	root    publicKey
	rootSeq uint64
}

func (t *dhtTeardown) getKey() dhtInfoKey {
	return dhtInfoKey{string(t.source), string(t.root), t.rootSeq}
}

func (t *dhtTeardown) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint64(data, t.seq)
	data = append(data, t.source...)
	data = append(data, t.dest...)
	data = append(data, t.root...)
	rseq := make([]byte, 8)
	binary.BigEndian.PutUint64(rseq, t.rootSeq)
	data = append(data, rseq...)
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
	} else if !wireChopBytes((*[]byte)(&tmp.root), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	} else if len(data) != 8 {
		return wireUnmarshalBinaryError
	}
	tmp.rootSeq = binary.BigEndian.Uint64(data)
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
