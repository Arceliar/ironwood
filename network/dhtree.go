package network

import (
	"crypto/rand"
	"encoding/binary"
	//"fmt"
	"time"

	"github.com/Arceliar/phony"
)

const (
	treeTIMEOUT  = time.Hour // TODO figure out what makes sense
	treeANNOUNCE = treeTIMEOUT / 2
	treeTHROTTLE = treeANNOUNCE / 2 // TODO use this to limit how fast seqs can update
	dhtWAIT      = time.Second      // Should be less than dhtANNOUNCE
	dhtANNOUNCE  = 2 * time.Second
	dhtTIMEOUT   = 2*dhtANNOUNCE + time.Second
)

/**********
 * dhtree *
 **********/

type dhtree struct {
	phony.Inbox
	core       *core
	pathfinder pathfinder
	expired    map[publicKey]treeExpiredInfo // stores root highest seq and when it expires
	tinfos     map[*peer]*treeInfo
	dinfos     map[dhtMapKey]map[uint64]*dhtInfo
	self       *treeInfo   // self info
	parent     *peer       // peer that sent t.self to us
	seq        uint64      // updated whenever we send a new setup, technically it doesn't need to increase (it just needs to be different)
	btimer     *time.Timer // time.AfterFunc to send bootstrap packets
	stimer     *time.Timer // time.AfterFunc for self/parent expiration
	wait       bool        // FIXME this shouldn't be needed
	hseq       uint64      // used to track the order treeInfo updates are handled
	bwait      bool        // wait before sending another bootstrap
}

type treeExpiredInfo struct {
	seq  uint64    // sequence number that expires
	time time.Time // Time when it expires
}

func (t *dhtree) init(c *core) {
	t.core = c
	t.expired = make(map[publicKey]treeExpiredInfo)
	t.tinfos = make(map[*peer]*treeInfo)
	t.dinfos = make(map[dhtMapKey]map[uint64]*dhtInfo)
	t.seq = uint64(time.Now().UnixNano())
	r := make([]byte, 8)
	if _, err := rand.Read(r); err != nil {
		panic(err)
	}
	for idx := range r {
		t.seq |= uint64(r[idx]) << 8 * uint64(idx)
	}
	t.btimer = time.AfterFunc(0, func() {}) // non-nil until closed
	t.stimer = time.AfterFunc(0, func() {}) // non-nil until closed
	t._fix()                                // Initialize t.self and start announce and timeout timers
	t.pathfinder.init(t)
}

func (t *dhtree) _sendTree() {
	for p := range t.tinfos {
		p.sendTree(t, t.self)
	}
}

// update adds a treeInfo to the spanning tree
// it then fixes the tree (selecting a new parent, if needed) and the dht (restarting the bootstrap process)
// if the info is from the current parent, then there's a delay before the tree/dht are fixed
//  that prevents a race where we immediately switch to a new parent, who tries to do the same with us
//  this avoids the tons of traffic generated when nodes race to use each other as parents
func (t *dhtree) update(from phony.Actor, info *treeInfo, p *peer) {
	t.Act(from, func() {
		// The tree info should have been checked before this point
		info.time = time.Now() // Order by processing time, not receiving time...
		t.hseq++
		info.hseq = t.hseq // Used to track order without comparing timestamps, since some platforms have *horrible* time resolution
		if exp, isIn := t.expired[info.root]; !isIn || exp.seq < info.seq {
			t.expired[info.root] = treeExpiredInfo{seq: info.seq, time: info.time}
		}
		if t.tinfos[p] == nil {
			// The peer may have missed an update due to a race between creating the peer and now
			// The easiest way to fix the problem is to just send it another update right now
			p.sendTree(t, t.self)
		}
		t.tinfos[p] = info
		if p == t.parent {
			if t.wait {
				panic("this should never happen")
			}
			var doWait bool
			if treeLess(t.self.root, info.root) {
				doWait = true // worse root
			} else if info.root.equal(t.self.root) && info.seq <= t.self.seq {
				doWait = true // same root and seq
			}
			t.self, t.parent = nil, nil // The old self/parent are now invalid
			if doWait {
				// FIXME this is a hack
				//  We seem to busyloop if we process parent updates immediately
				//  E.g. we get bad news and immediately switch to a different peer
				//  Then we get more bad news and switch again, etc...
				// Set self to root, send, then process things correctly 1 second later
				t.wait = true
				t.self = &treeInfo{root: t.core.crypto.publicKey}
				t._sendTree() // send bad news immediately
				time.AfterFunc(time.Second, func() {
					t.Act(nil, func() {
						t.wait = false
						t.self, t.parent = nil, nil
						t._fix()
						t._doBootstrap(true)
					})
				})
			}
		}
		if !t.wait {
			t._fix()
			t._doBootstrap(true)
		}
	})
}

// remove removes a peer from the tree, along with any paths through that peer in the dht
func (t *dhtree) remove(from phony.Actor, p *peer) {
	t.Act(from, func() {
		oldInfo := t.tinfos[p]
		delete(t.tinfos, p)
		if t.self == oldInfo {
			t.self = nil
			t.parent = nil
			t._fix()
		}
		for mk, dinfos := range t.dinfos {
			for s, dinfo := range dinfos {
				if dinfo.peer == p {
					//dinfo.peer = nil
					//continue
					//t._teardown(p, dinfo.getTeardown())
					dinfo.timer.Stop()
					delete(dinfos, s)
				}
			}
			//continue
			if len(dinfos) == 0 {
				delete(t.dinfos, mk)
			}
		}
		t.pathfinder._remove(p)
	})
}

// _fix selects the best parent (and is called in response to receiving a tree update)
// if this is not the same as our current parent, then it sends a tree update to our peers and resets our prev/next in the dht
func (t *dhtree) _fix() {
	if t.stimer == nil {
		return // closed
	}
	oldSelf := t.self
	if t.self == nil || treeLess(t.core.crypto.publicKey, t.self.root) {
		// Note that seq needs to be non-decreasing for the node to function as a root
		//  a timestamp it used to partly mitigate rollbacks from restarting
		t.self = &treeInfo{
			root: t.core.crypto.publicKey,
			seq:  uint64(time.Now().Unix()),
			time: time.Now(),
		}
		t.parent = nil
	}
	for _, info := range t.tinfos {
		// Refill expired to include non-root nodes (in case we're replacing an expired
		if exp, isIn := t.expired[info.root]; !isIn || exp.seq < info.seq || exp.seq == info.seq && info.time.Before(exp.time) {
			// Fill expired as we
			t.expired[info.root] = treeExpiredInfo{seq: info.seq, time: info.time}
		}
	}
	for p, info := range t.tinfos {
		if exp, isIn := t.expired[info.root]; isIn {
			if info.seq < exp.seq {
				continue // skip old sequence numbers
			} else if info.seq == exp.seq && time.Since(exp.time) > treeTIMEOUT {
				continue // skip expired sequence numbers
			}
		}
		switch {
		case !info.checkLoops():
			// This has a loop, e.g. it's from a child, so skip it
		case treeLess(info.root, t.self.root):
			// This is a better root
			t.self, t.parent = info, p
		case treeLess(t.self.root, info.root):
			// This is a worse root, so don't do anything with it
		case info.seq > t.self.seq:
			// This is a newer sequence number, so update parent
			t.self, t.parent = info, p
		case info.seq < t.self.seq:
			// This is an older sequnce number, so ignore it
		case info.hseq < t.self.hseq:
			// This info has been around for longer (e.g. the path is more stable)
			t.self, t.parent = info, p
		}
	}
	if t.self != oldSelf {
		// Reset a timer to make t.self expire at some point
		t.stimer.Stop()
		self := t.self
		var delay time.Duration
		if t.self.root.equal(t.core.crypto.publicKey) {
			// We are the root, so we need to expire after treeANNOUNCE to update seq
			delay = treeANNOUNCE
		} else {
			// Figure out when the root needs to time out
			stopTime := t.expired[t.self.root].time.Add(treeTIMEOUT)
			delay = time.Until(stopTime)
		}
		t.stimer = time.AfterFunc(delay, func() {
			t.Act(nil, func() {
				if t.self == self {
					t.self = nil
					t.parent = nil
					t._fix()
					t._doBootstrap(true)
				}
			})
		})
		t._sendTree() // Send the tree update to our peers
	}
	// Clean up t.expired (remove anything worse than the current root)
	for skey := range t.expired {
		key := publicKey(skey)
		if key.equal(t.self.root) || treeLess(t.self.root, key) {
			delete(t.expired, skey)
		}
	}
}

// _treeLookup selects the best next hop (in treespace) for the destination
func (t *dhtree) _treeLookup(dest *treeLabel) *peer {
	if t.core.crypto.publicKey.equal(dest.key) {
		return nil
	}
	best := t.self
	bestDist := best.dist(dest)
	var bestPeer *peer
	for p, info := range t.tinfos {
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
		case treeLess(info.from(), best.from()):
			isBetter = true
		}
		if isBetter {
			best = info
			bestDist = dist
			bestPeer = p
		}
	}
	if !best.root.equal(dest.root) || best.seq != dest.seq { // TODO? check self, not next/dest?
		// Dead end, so stay here
		return nil
	}
	return bestPeer
}

// _dhtLookup selects the next hop needed to route closer to the destination in dht keyspace
// this only uses the source direction of paths through the dht
// bootstraps use slightly different logic, since they need to stop short of the destination key
func (t *dhtree) _dhtLookup(dest publicKey, isBootstrap bool, mark *dhtWatermark) *peer {
	// Start by defining variables and helper functions
	best := t.core.crypto.publicKey
	var bestPeer *peer
	var bestInfo *dhtInfo
	// doUpdate is just to make sure we don't forget to update something
	doUpdate := func(key publicKey, p *peer, d *dhtInfo) {
		best, bestPeer, bestInfo = key, p, d
	}
	// doCheckedUpdate checks if the provided key is better than the current best, and updates if so
	doCheckedUpdate := func(key publicKey, p *peer, d *dhtInfo) {
		switch {
		case !isBootstrap && key.equal(dest) && !best.equal(dest):
			fallthrough
		case dhtOrdered(best, key, dest):
			doUpdate(key, p, d)
		}
	}
	// doAncestry updates based on the ancestry information in a treeInfo
	doAncestry := func(info *treeInfo, p *peer) {
		doCheckedUpdate(info.root, p, nil) // updates if the root is better
		if isBootstrap {
			// TODO: don't count nodes that aren't the root or from a DHT path
			// There are DoS / security reasons to avoid them
			// This is temporarily disabled for testing
			//return
		}
		for _, hop := range info.hops {
			doCheckedUpdate(hop.next, p, nil) // updates if this hop is better
			tinfo := t.tinfos[bestPeer]       // may be nil if we're in the middle of a remove
			if tinfo != nil && best.equal(hop.next) && info.hseq < tinfo.hseq {
				// This ancestor matches our current next hop, but this peer's treeInfo is better, so switch to it
				doUpdate(hop.next, p, nil)
			}
		}
	}
	// doDHT updates best based on a DHT path
	doDHT := func(info *dhtInfo) {
		//if !info.isActive {
		//	return
		//}
		if mark != nil {
			if treeLess(info.key, mark.key) || (info.key.equal(mark.key) && info.seq < mark.seq) {
				return
			}
		}
		if isBootstrap && !(info.root.equal(t.self.root) && info.rootSeq == t.self.seq) {
			return
		}
		doCheckedUpdate(info.key, info.peer, info) // updates if the source is better
		if bestInfo != nil && info.key.equal(bestInfo.key) {
			if treeLess(info.root, bestInfo.root) {
				doUpdate(info.key, info.peer, info) // same source, but the root is better
			} else if info.root.equal(bestInfo.root) && info.rootSeq > bestInfo.rootSeq {
				doUpdate(info.key, info.peer, info) // same source, same root, but the rootSeq is newer
			} else if !info.root.equal(bestInfo.root) || info.rootSeq != bestInfo.rootSeq {
				// skip any non-matches
			} else if info.seq > bestInfo.seq {
				doUpdate(info.key, info.peer, info) // same source/root/rootSeq, but newer seq
			}
		}
		/*
					if mark != nil && bestInfo == info {
						mark.key = info.key
						mark.seq = info.seq
					}
					if mark != nil && mark.seq != 0 {
			      panic(mark.seq)
					}
		*/
	}
	// Update the best key and peer
	// First check if the current best (ourself) is an invalid next hop
	if (isBootstrap && best.equal(dest)) || dhtOrdered(t.self.root, dest, best) {
		// We're the current best, and we're already too far through keyspace
		// That means we need to default to heading towards the root
		doUpdate(t.self.root, t.parent, nil)
	}
	// Update based on the ancestry of our own treeInfo
	doAncestry(t.self, t.parent)
	// Update based on the ancestry of our peers
	for p, info := range t.tinfos {
		doAncestry(info, p)
	}
	// Check peers
	for p := range t.tinfos {
		if best.equal(p.key) {
			// The best next hop is one of our peers
			// We may have stumbled upon them too early, as the ancestor of another peer
			// Switch to using the direct route to this peer, just in case
			doUpdate(p.key, p, nil)
		}
	}
	// Update based on pathfinder paths
	/*
		if mark != nil {
			for key, pinfo := range t.pathfinder.paths {
				if pinfo.peer == nil {
					continue
				}
				if !treeLess(mark.prev, key) {
					// Not strictly better than the lower threshold mark, so ignore
					continue
				}
				if treeLess(key, mark.next) {
					// Strictly worse than the best path found so far
					continue
				}
				if dhtOrdered(best, key, dest) {
					doUpdate(key, pinfo.peer, nil)
				}
			}
			// Update the high water mark
			if treeLess(mark.next, best) {
				// New best path
				mark.next = best
			}
			if treeLess(best, mark.next) {
				// We hit a dead end or otherwise went backwards in keyspace
				// Update the prev mark to prevent us from looping
				// TODO do this better, I'm pretty sure we can still get a single loop cycle before things are updated
				mark.prev = mark.next
			}
		}
	*/
	// Update based on our DHT infos
	for _, dinfos := range t.dinfos {
		for _, dinfo := range dinfos {
			doDHT(dinfo)
		}
	}
	if mark != nil {
		if bestInfo != nil {
			mark.key = bestInfo.key
			mark.seq = bestInfo.seq
		}
		if treeLess(best, mark.key) || (bestInfo != nil && bestInfo.seq < mark.seq) {
			// The best isn't good enough
			bestPeer = nil
		}
	}
	return bestPeer
}

// _dhtAdd adds a dhtInfo to the dht and returns true
// it may return false if the path associated with the dhtInfo isn't allowed for some reason
//  e.g. we know a better prev/next for one of the nodes in the path, which can happen if there's multiple split rings that haven't converged on their own yet
// as of writing, that never happens, it always adds and returns true
func (t *dhtree) _dhtAdd(info *dhtInfo) bool {
	// TODO? check existing paths, don't allow this one if the source/dest pair makes no sense
	if dinfos, isIn := t.dinfos[info.getMapKey()]; isIn {
		if _, isIn = dinfos[info.seq]; isIn {
			return false
		}
		for _, oldInfo := range dinfos {
			//if oldInfo.dhtPathState != info.dhtPathState {
			//	continue
			//}
			if oldInfo.seq < info.seq {
				// This path is newer than the old one, so tear down the old one (so we can replace it)
				/*
					if oldInfo.peer != nil {
						oldInfo.peer.sendTeardown(t, oldInfo.getTeardown())
					}
					t._teardown(oldInfo.peer, oldInfo.getTeardown())
				*/
			} else {
				// We already have a path that's either the same seq or better, so ignore this one
				// TODO? keep the path, but don't forward it anywhere
				// This is very delicate (needed for anycast to not break the network, etc)
				return false
			}
		}
	}
	if _, isIn := t.dinfos[info.getMapKey()]; !isIn {
		t.dinfos[info.getMapKey()] = make(map[uint64]*dhtInfo)
	}
	dinfos := t.dinfos[info.getMapKey()]
	dinfos[info.seq] = info
	return true
	/*
		for _, oldInfo := range dinfos {
			if info.dhtPathState == oldInfo.dhtPathState {
				// FIXME TODO? allow replacement if our seq is better?
				// Or jut always replace?
				// Currently, we don't ever replace, but that may not be the right action
				if oldInfo.seq < info.seq {
					if oldInfo.peer != nil {
						oldInfo.peer.sendTeardown(t, oldInfo.getTeardown())
					}
					t._teardown(oldInfo.peer, oldInfo.getTeardown())
					break //continue
				}
				return false
			}
		}
		if _, isIn := t.dinfos[info.getMapKey()]; !isIn {
			t.dinfos[info.getMapKey()] = make(map[uint64]*dhtInfo)
		}
		dinfos := t.dinfos[info.getMapKey()]
		if _, isIn := dinfos[info.seq]; isIn {
			return false
		}
		dinfos[info.seq] = info
		return true
	*/
}

// _newBootstrap returns a *dhtBootstrap for this node, using t.self, with a signature
func (t *dhtree) _newBootstrap() *dhtBootstrap {
	t.seq++
	dbs := &dhtBootstrap{
		key:     t.core.crypto.publicKey,
		root:    t.self.root,
		rootSeq: t.self.seq,
		seq:     t.seq,
	}
	dbs.sig = t.core.crypto.privateKey.sign(dbs.bytesForSig())
	return dbs
}

func (t *dhtree) _addBootstrapPath(bootstrap *dhtBootstrap, prev *peer) *dhtInfo {
	if !bootstrap.root.equal(t.self.root) || bootstrap.rootSeq != t.self.seq {
		// Wrong root or rootSeq
		return nil
	}
	/* This is now checked by the peer actor instead
	if !bootstrap.check() {
		// Signature check failed... TODO do this at peer level instead
		return nil
	}
	source := bootstrap.key
	next := t._dhtLookup(source, true, &bootstrap.mark)
	if prev == nil && next == nil {
		// This is our own bootstrap and we don't have anywhere to send it
		return nil
	}
	*/
	dinfo := &dhtInfo{
		dhtBootstrap: *bootstrap,
		//key:     source,
		//seq:     bootstrap.seq, // TODO add a seq to bootstraps (like setups)
		//root:    bootstrap.root,
		//rootSeq: bootstrap.rootSeq,
		peer: prev,
		//rest: next,
	}
	for _, s := range bootstrap.bhs {
		if prev != nil && dinfo.peer != prev {
			break
		}
		// TODO something faster than this inner loop
		for p := range t.tinfos {
			if p.key.equal(s.key) {
				dinfo.peer = p
				break
			}
		}
	}
	dinfo.dhtBootstrap.bhs = nil
	//dinfo.isActive = true // FIXME DEBUG, this should start false and switch to true when acked (or after some timeout)
	//dinfo.isBootstrap = true
	if dinfos, isIn := t.dinfos[dinfo.getMapKey()]; isIn {
		if dfo, isIn := dinfos[dinfo.seq]; isIn {
			//return nil // TODO FIXME debug this
			// The path looped, so we have two options here:
			//  1. Tear down the new path, and let the source try again
			//  2. Stitch the old path and the new path together, and remove the loop
			// This is an attempt at option 2
			/*
				if dfo.rest != nil {
					dfo.rest.sendTeardown(t, dfo.getTeardown())
				}
				dfo.rest = dinfo.rest
				if t.prev == dfo {
					// TODO figure out if this is really safe
					t.prev = nil
				}
			*/
			_ = dfo
			return nil //dfo
		}
		/*
			if altInfo, isIn := dinfos[dinfo.dhtPathState]; isIn && altInfo.seq < dinfo.seq {
				// A path in the same state already exists
				// TODO? in some circumstances, tear down that path and keep this one instead?
				if altInfo.peer != nil {
					altInfo.peer.sendTeardown(t, altInfo.getTeardown())
				}
				t._teardown(altInfo.peer, altInfo.getTeardown())
				//return nil
			}
		*/
	}
	if dinfo.peer == nil {
		// We're about to replace our current prev
		// Lets tear down any old prevs, except the current one, to clean up
		// Then we'll let the current prev stick around while we set up a new one
		if !dinfo.key.equal(t.core.crypto.publicKey) {
			panic("this should never happen")
		}
		//t._cleanupOldPrevs()
	}
	if !t._dhtAdd(dinfo) {
		// We failed to add the dinfo to the DHT for some reason
		return nil
	}
	// Setup timer for cleanup
	dinfo.timer = time.AfterFunc(dhtTIMEOUT, func() {
		t.Act(nil, func() {
			// Clean up path if it has timed out
			if dinfos, isIn := t.dinfos[dinfo.getMapKey()]; isIn {
				if info := dinfos[dinfo.seq]; info == dinfo {
					delete(dinfos, dinfo.seq)
					if len(dinfos) == 0 {
						delete(t.dinfos, dinfo.getMapKey())
					}
					/*
						if info.peer != nil {
							info.peer.sendTeardown(t, info.getTeardown())
						}
						t._teardown(info.peer, info.getTeardown())
					*/
				}
			}
		})
	})
	return dinfo
}

/*
func (t *dhtree) _replaceNext(dinfo *dhtInfo) bool {
	if t.next != nil {
		// TODO get this right!
		//  We need to replace the old next in most cases
		//  The exceptions are when:
		//    1. The dinfo's root/seq don't match our current root/seq
		//    2. The dinfo matches, but so does t.next, and t.next is better
		//  What happens when the dinfo matches, t.next does not, but t.next is still better?...
		//  Just doing something for now (replace next) but not sure that's right...
		var doUpdate bool
		if !dinfo.root.equal(t.self.root) || dinfo.rootSeq != t.self.seq {
			// The root/seq is bad, so don't update
		} else if dinfo.key.equal(t.next.key) {
			// It's an update from the current next
			doUpdate = true
		} else if dhtOrdered(t.core.crypto.publicKey, dinfo.key, t.next.key) {
			// It's an update from a better next
			doUpdate = true
		}
		// TODO? this is a newer update, but from a worse node? which should win?
		if doUpdate {
			// TODO use a dhtExtension instead of tearing down the old path
			ext := &dhtExtension{
				bootstrap: t.next.dhtBootstrap,
				extKey:    t.next.key,
				extSeq:    t.next.seq,
			}
			_ = ext
			//t._extend(nil, ext) // FIXME TODO get this working
			t._teardown(nil, t.next.getTeardown())
			t.next = dinfo
			return true
		} else {
			t._teardown(nil, dinfo.getTeardown())
			return false
		}
	} else {
		t.next = dinfo
		return true
	}
}
*/

// _getNexts returns a set of all next hops that would route to exactly the given key.
func (t *dhtree) _getNexts(key publicKey) map[*peer]struct{} {
	nexts := make(map[*peer]struct{})
	for p, tinfo := range t.tinfos {
		break // TODO? forward over the tree if it makes sense to do so?
		if tinfo.root.equal(key) {
			nexts[p] = struct{}{}
			continue
		}
		for _, hop := range tinfo.hops {
			if hop.next.equal(key) {
				nexts[p] = struct{}{}
				break
			}
		}
	}
	mk := dhtMapKey{
		key:     key,
		root:    t.self.root,
		rootSeq: t.self.seq,
	}
	dinfos := t.dinfos[mk]
	for _, dinfo := range dinfos {
		if dinfo.peer != nil {
			nexts[dinfo.peer] = struct{}{}
		}
	}
	return nexts
}

// _handleBootstrap takes a bootstrap packet and checks if we know of a better prev for the source node
// if yes, then we forward to the next hop in the path towards that prev
// if no, then we reply with a dhtBootstrapAck (unless sanity checks fail)
func (t *dhtree) _handleBootstrap(prev *peer, bootstrap *dhtBootstrap) {
	if dinfo := t._addBootstrapPath(bootstrap, prev); dinfo != nil {
		if dinfo.peer == nil {
			// sanity checks, this should only happen when setting up our prev
			if !bootstrap.key.equal(t.core.crypto.publicKey) {
				panic("wrong key")
			} else if bootstrap.seq != t.seq {
				panic("wrong seq")
			} /*else if t.prev != nil {
				if t.prev.root.equal(t.self.root) && t.prev.rootSeq == t.self.seq {
					panic("already have an equivalent prev")
				} else {
					// TODO only tear down if the prev is from a bootstrap
					t._teardown(nil, t.prev.getTeardown())
				}
			}*/
			/*
				if t.ptimer == nil {
					// TODO? something other than an arbitrary 1 minute timeout
					t.ptimer = time.AfterFunc(time.Minute, func() {
						t.Act(nil, func() {
							if t.ptimer == nil {
								return
							}
							t.ptimer.Stop()
							t.ptimer = nil
							//if false && t.prev != nil && !t.prev.isActive {
							//	act := &dhtActivate{*bootstrap.getTeardown()}
							//	t._handleActivate(prev, act)
							//	t._cleanupOldPrevs()
							//}
							//t._cleanupOldPrevs()
						})
					})
				}
				t.prev = dinfo
				//t.dkeys[dinfo] = dest // N/A for bootstrap paths...
			*/
		}
		// TODO remove this, debugging code
		/*
		   act := &dhtActivate{*bootstrap.getTeardown()}
		   t._handleActivate(prev, act)
		*/
		// End TODO
		/*
			if dinfo.rest != nil {
				dinfo.rest.sendBootstrap(t, bootstrap)
				return
			}
		*/
		bhs := bootstrap.bhs
		bootstrap.bhs = bootstrap.bhs[:0]
		for _, s := range bhs {
			if dinfo.peer == nil || dinfo.peer.key != s.key {
				continue
			}
			bootstrap.bhs = append(bootstrap.bhs, s)
			break
		}
		var s bootstrapHopSig
		s.key = t.core.crypto.publicKey
		s.sig = t.core.crypto.privateKey.sign(bootstrap.bytesForSig())
		bootstrap.bhs = append(bootstrap.bhs, s)
		oldMark := bootstrap.mark
		if next := t._dhtLookup(bootstrap.key, true, &bootstrap.mark); next != nil || oldMark != bootstrap.mark {
			next.sendBootstrap(t, bootstrap)
			for p := range t._getNexts(bootstrap.mark.key) {
				if p == prev || p == next {
					continue
				}
				p.sendBootstrap(t, bootstrap)
			}
		}
		/*
			if t._replaceNext(dinfo) {
				ack := new(dhtBootstrapAck)
				ack.bootstrap = *bootstrap
				ack.response = *t._getToken(bootstrap.key)
				t._handleBootstrapAck(ack) // TODO FIXME enable this
			}
		*/
	} else if prev != nil {
		//prev.sendTeardown(t, bootstrap.getTeardown())
	}
	/*
		source := bootstrap.label.key
		if next := t._dhtLookup(source, true); next != nil {
			next.sendBootstrap(t, bootstrap)
			return
		} else if source.equal(t.core.crypto.publicKey) {
			return
		} else if !bootstrap.check() {
			return
		}
		ack := new(dhtBootstrapAck)
		ack.bootstrap = *bootstrap
		ack.response = *t._getToken(source)
		t._handleBootstrapAck(ack)
	*/
}

// handleBootstrap is the externally callable actor behavior that sends a message to the dhtree that it should _handleBootstrap
func (t *dhtree) handleBootstrap(from phony.Actor, prev *peer, bootstrap *dhtBootstrap) {
	t.Act(from, func() {
		t._handleBootstrap(prev, bootstrap)
	})
}

// _doBootstrap decides whether or not to send a bootstrap packet
// if a bootstrap is sent, then it sets things up to attempt to send another bootstrap at a later point
func (t *dhtree) _doBootstrap(prompt bool) {
	if t.btimer == nil {
		return
	}
	if !t.bwait {
		//if t.prev != nil && t.prev.root.equal(t.self.root) && t.prev.rootSeq == t.self.seq {
		//	return
		//}
		waitTime := dhtANNOUNCE
		if t.parent != nil {
			t._handleBootstrap(nil, t._newBootstrap())
			// Don't immediately send more bootstraps if called again too quickly
			// This helps prevent traffic spikes in some mobility scenarios
			if prompt {
				waitTime = dhtWAIT
			}
			t.bwait = prompt
		}
		t.btimer.Stop()
		t.btimer = time.AfterFunc(waitTime, func() {
			t.Act(nil, func() {
				t.bwait = false
				t._doBootstrap(false)
			})
		})
	}
}

// handleDHTTraffic take a dht traffic packet (still marshaled as []bytes) and decides where to forward it to next to take it closer to its destination in keyspace
// if there's nowhere better to send it, then it hands it off to be read out from the local PacketConn interface
func (t *dhtree) handleDHTTraffic(from phony.Actor, tr *dhtTraffic, doNotify bool) {
	t.Act(from, func() {
		next := t._dhtLookup(tr.dest, false, &tr.mark)
		if next == nil {
			if false && tr.dest.equal(t.core.crypto.publicKey) {
				dest := tr.source
				t.pathfinder._doNotify(dest, !doNotify)
				/*
					if !doNotify {
						println("success!")
						//panic("DEBUG success!")
					} else {
						println("fail :(")
					}
				*/
			}
			t.core.pconn.handleTraffic(tr)
		} else {
			next.sendDHTTraffic(t, tr)
		}
	})
}

func (t *dhtree) sendTraffic(from phony.Actor, tr *dhtTraffic) {
	t.Act(from, func() {
		if peer := t.pathfinder._getPathPeer(tr.dest); peer != nil {
			//pt := new(pathTraffic)
			//pt.path = path
			//pt.dt = *tr
			//t.core.peers.handlePathTraffic(t, pt)
			pt := &pathTraffic{
				baseTraffic: tr.baseTraffic,
			}
			peer.sendPathTraffic(t, pt)
			//panic("DEBUG found peer")
		} else {
			t.handleDHTTraffic(nil, tr, false)
		}
	})
}

func (t *dhtree) _getLabel() *treeLabel {
	// TODO do this once when t.self changes and save it somewhere
	//  (to avoid repeated signing every time we call this)
	// Fill easy fields of label
	label := new(treeLabel)
	label.key = t.core.crypto.publicKey
	label.root = t.self.root
	label.seq = t.self.seq
	for _, hop := range t.self.hops {
		label.path = append(label.path, hop.port)
	}
	label.sig = t.core.crypto.privateKey.sign(label.bytesForSig())
	return label
}

// TODO get rid of this, it's currently reused by the pathfinder
func (t *dhtree) _getToken(source publicKey) *dhtSetupToken {
	token := new(dhtSetupToken)
	token.source = source
	token.dest = *t._getLabel()
	token.sig = t.core.crypto.privateKey.sign(token.bytesForSig())
	return token
}

/************
 * treeInfo *
 ************/

type treeInfo struct {
	time time.Time // Note: *NOT* serialized
	hseq uint64    // Note: *NOT* serialized, set when handling the update
	root publicKey
	seq  uint64
	hops []treeHop
}

type treeHop struct {
	next publicKey
	port peerPort
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
	bs = append(bs, info.root[:]...)
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, info.seq)
	bs = append(bs, seq...)
	for _, hop := range info.hops {
		bs = append(bs, hop.next[:]...)
		bs = wireEncodeUint(bs, uint64(hop.port))
		if !key.verify(bs, &hop.sig) {
			return false
		}
		key = hop.next
	}
	return true
}

func (info *treeInfo) checkLoops() bool {
	key := info.root
	keys := make(map[publicKey]bool) // Used to avoid loops
	for _, hop := range info.hops {
		if keys[key] {
			return false
		}
		keys[key] = true
		key = hop.next
	}
	return !keys[key]
}

func (info *treeInfo) add(priv privateKey, next *peer) *treeInfo {
	var bs []byte
	bs = append(bs, info.root[:]...)
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, info.seq)
	bs = append(bs, seq...)
	for _, hop := range info.hops {
		bs = append(bs, hop.next[:]...)
		bs = wireEncodeUint(bs, uint64(hop.port))
	}
	bs = append(bs, next.key[:]...)
	bs = wireEncodeUint(bs, uint64(next.port))
	sig := priv.sign(bs)
	hop := treeHop{next: next.key, port: next.port, sig: sig}
	newInfo := *info
	newInfo.hops = nil
	newInfo.hops = append(newInfo.hops, info.hops...)
	newInfo.hops = append(newInfo.hops, hop)
	return &newInfo
}

func (info *treeInfo) dist(dest *treeLabel) int {
	if !info.root.equal(dest.root) {
		// TODO? also check the root sequence number?
		return int(^(uint(0)) >> 1) // max int, but you should really check this first
	}
	a, b := len(info.hops), len(dest.path)
	if b < a {
		a, b = b, a // make 'a' be the smaller value
	}
	lcaIdx := -1 // last common ancestor
	for idx := 0; idx < a; idx++ {
		if info.hops[idx].port != dest.path[idx] {
			break
		}
		lcaIdx = idx
	}
	return a + b - 2*(lcaIdx+1)
}

func (info *treeInfo) encode(out []byte) ([]byte, error) {
	out = append(out, info.root[:]...)
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, info.seq)
	out = append(out, seq...)
	for _, hop := range info.hops {
		out = append(out, hop.next[:]...)
		out = wireEncodeUint(out, uint64(hop.port))
		out = append(out, hop.sig[:]...)
	}
	return out, nil
}

func (info *treeInfo) decode(data []byte) error {
	nfo := treeInfo{}
	if !wireChopSlice(nfo.root[:], &data) {
		return wireDecodeError
	}
	if len(data) >= 8 {
		nfo.seq = binary.BigEndian.Uint64(data[:8])
		data = data[8:]
	} else {
		return wireDecodeError
	}
	for len(data) > 0 {
		hop := treeHop{}
		switch {
		case !wireChopSlice(hop.next[:], &data):
			return wireDecodeError
		case !wireChopUint((*uint64)(&hop.port), &data):
			return wireDecodeError
		case !wireChopSlice(hop.sig[:], &data):
			return wireDecodeError
		}
		nfo.hops = append(nfo.hops, hop)
	}
	//nfo.time = time.Now() // Set by the dhtree in update
	*info = nfo
	return nil
}

/*************
 * treeLabel *
 *************/

type treeLabel struct {
	sig  signature
	key  publicKey
	root publicKey
	seq  uint64
	path []peerPort
}

func (l *treeLabel) bytesForSig() []byte {
	var bs []byte
	bs = append(bs, l.root[:]...)
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, l.seq)
	bs = append(bs, seq...)
	bs = wireEncodePath(bs, l.path)
	return bs
}

func (l *treeLabel) check() bool {
	bs := l.bytesForSig()
	return l.key.verify(bs, &l.sig)
}

func (l *treeLabel) encode(out []byte) ([]byte, error) {
	out = append(out, l.sig[:]...)
	out = append(out, l.key[:]...)
	out = append(out, l.root[:]...)
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, l.seq)
	out = append(out, seq...)
	out = wireEncodePath(out, l.path)
	return out, nil
}

func (l *treeLabel) decode(data []byte) error {
	var tmp treeLabel
	if !wireChopSlice(tmp.sig[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.key[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.root[:], &data) {
		return wireDecodeError
	} else if len(data) < 8 {
		return wireDecodeError
	} else {
		tmp.seq = binary.BigEndian.Uint64(data[:8])
		data = data[8:]
	}
	if !wireChopPath(&tmp.path, &data) {
		return wireDecodeError
	} else if len(data) != 0 {
		return wireDecodeError
	}
	*l = tmp
	return nil
}

/***********
 * dhtInfo *
 ***********/

type dhtInfo struct {
	dhtBootstrap
	//seq     uint64
	//key     publicKey
	peer *peer
	//rest *peer
	//root    publicKey
	//rootSeq uint64
	timer *time.Timer // time.AfterFunc to clean up after timeout, stop this on teardown
	//dhtPathState
}

/*
type dhtPathState struct {
	isActive    bool // Path has been acknowledged from the remote side, or reached some activation timeout
	isOrphaned  bool // Path has been torn down from the "rest" direction
	isBootstrap bool // Path is a bootstrap
}
*/

/*
func (info *dhtInfo) getTeardown() *dhtTeardown {
	return &dhtTeardown{
		seq:     info.seq,
		key:     info.key,
		root:    info.root,
		rootSeq: info.rootSeq,
	}
}
*/

type dhtMapKey struct {
	key     publicKey
	root    publicKey
	rootSeq uint64
}

func (info *dhtInfo) getMapKey() dhtMapKey {
	return dhtMapKey{
		key:     info.key,
		root:    info.root,
		rootSeq: info.rootSeq,
	}
}

/****************
 * dhtBootstrap *
 ****************/

type dhtBootstrap struct {
	sig     signature
	key     publicKey
	root    publicKey
	rootSeq uint64
	seq     uint64
	mark    dhtWatermark
	bhs     []bootstrapHopSig
}

type bootstrapHopSig struct {
	key publicKey
	sig signature
}

func (dbs *dhtBootstrap) bytesForSig() []byte {
	const size = len(dbs.key) + len(dbs.root) + 8 + 8
	bs := make([]byte, 0, size)
	bs = append(bs, dbs.key[:]...)
	bs = append(bs, dbs.root[:]...)
	bs = bs[:size]
	binary.BigEndian.PutUint64(bs[len(bs)-16:len(bs)-8], dbs.rootSeq)
	binary.BigEndian.PutUint64(bs[len(bs)-8:], dbs.seq)
	return bs
}

func (dbs *dhtBootstrap) check() bool {
	if len(dbs.bhs) > 2 {
		return false
	}
	bs := dbs.bytesForSig()
	for _, s := range dbs.bhs {
		if !s.key.verify(bs, &s.sig) {
			return false
		}
	}
	return dbs.key.verify(bs, &dbs.sig)
}

func (dbs *dhtBootstrap) checkFrom(from publicKey) bool {
	if len(dbs.bhs) < 1 || !from.equal(dbs.bhs[len(dbs.bhs)-1].key) {
		return false
	}
	return dbs.check()
}

/*
func (dbs *dhtBootstrap) getTeardown() *dhtTeardown {
	return &dhtTeardown{
		seq:     dbs.seq,
		key:     dbs.key,
		root:    dbs.root,
		rootSeq: dbs.rootSeq,
	}
}
*/

func (dbs *dhtBootstrap) encode(out []byte) ([]byte, error) {
	out = append(out, dbs.sig[:]...)
	out = append(out, dbs.bytesForSig()...)
	var err error
	if out, err = dbs.mark.encode(out); err != nil {
		return nil, err
	}
	for _, s := range dbs.bhs {
		out = append(out, s.key[:]...)
		out = append(out, s.sig[:]...)
	}
	return out, nil
}

func (dbs *dhtBootstrap) decode(data []byte) error {
	var tmp dhtBootstrap
	if !wireChopSlice(tmp.sig[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.key[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.root[:], &data) {
		return wireDecodeError
	} else if len(data) < 16 { // TODO? < 16, in case it's embedded in something?
		return wireDecodeError
	}
	tmp.rootSeq = binary.BigEndian.Uint64(data[:8])
	tmp.seq = binary.BigEndian.Uint64(data[8:16])
	data = data[16:]
	if !tmp.mark.chop(&data) {
		return wireDecodeError
	}
	for len(data) > 0 {
		var s bootstrapHopSig
		if !wireChopSlice(s.key[:], &data) {
			return wireDecodeError
		} else if !wireChopSlice(s.sig[:], &data) {
			return wireDecodeError
		}
		tmp.bhs = append(tmp.bhs, s)
	}
	*dbs = tmp
	return nil
}

/*
type dhtBootstrap struct {
	label treeLabel
}

func (dbs *dhtBootstrap) check() bool {
	return dbs.label.check()
}

func (dbs *dhtBootstrap) encode(out []byte) ([]byte, error) {
	return dbs.label.encode(out)
}

func (dbs *dhtBootstrap) decode(data []byte) error {
	var tmp dhtBootstrap
	if err := tmp.label.decode(data); err != nil {
		return err
	}
	*dbs = tmp
	return nil
}
*/

/*****************
 * dhtSetupToken *
 *****************/

// When you send a bootstrap, this is the thing you're trying to get back in a response.
// It's what lets you open a path to a keyspace neighbor.

// TODO? change the token format? The dest part contains a redundant sig inside of the treeLabel... technically we could reuse it, but that seems weird?
// Maybe remove the sig from treeLabel, put that in a signedTreeLabel?

type dhtSetupToken struct {
	sig    signature // Signed by dest
	source publicKey // Who the dest permits a path from
	dest   treeLabel // Path to dest
}

func (st *dhtSetupToken) bytesForSig() []byte {
	var bs []byte
	bs = append(bs, st.source[:]...)
	var err error
	if bs, err = st.dest.encode(bs); err != nil {
		panic("this should never happen")
	}
	return bs
}

// TODO? remove the redundant sig and check? both from same node, one should be a superset of the other...

func (st *dhtSetupToken) check() bool {
	bs := st.bytesForSig()
	return st.dest.key.verify(bs, &st.sig) && st.dest.check()
}

func (st *dhtSetupToken) encode(out []byte) ([]byte, error) {
	out = append(out, st.sig[:]...)
	out = append(out, st.source[:]...)
	return st.dest.encode(out)
}

func (st *dhtSetupToken) decode(data []byte) error {
	if !wireChopSlice(st.sig[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(st.source[:], &data) {
		return wireDecodeError
	}
	return st.dest.decode(data)
}

/**************
 * dhtTraffic *
 **************/

type dhtWatermark struct {
	key publicKey
	seq uint64
}

func (m *dhtWatermark) encode(out []byte) ([]byte, error) {
	out = append(out, m.key[:]...)
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, m.seq)
	out = append(out, seq...)
	return out, nil
}

func (m *dhtWatermark) decode(data []byte) error {
	var tmp dhtWatermark
	if !wireChopSlice(tmp.key[:], &data) {
		return wireDecodeError
	}
	if len(data) < 8 {
		return wireDecodeError
	}
	tmp.seq = binary.BigEndian.Uint64(data[:8])
	data = data[8:]
	*m = tmp
	return nil
}

func (m *dhtWatermark) chop(ptr *[]byte) bool {
	if ptr == nil {
		return false
	}
	if err := m.decode(*ptr); err != nil {
		return false
	}
	*ptr = (*ptr)[len(m.key)+8:]
	return true
}

type baseTraffic struct {
	source  publicKey
	dest    publicKey
	kind    byte // in-band vs out-of-band, TODO? separate type?
	payload []byte
}

func (t *baseTraffic) encode(out []byte) ([]byte, error) {
	out = append(out, t.source[:]...)
	out = append(out, t.dest[:]...)
	out = append(out, t.kind)
	out = append(out, t.payload...)
	return out, nil
}

func (t *baseTraffic) decode(data []byte) error {
	var tmp baseTraffic
	if !wireChopSlice(tmp.source[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.dest[:], &data) {
		return wireDecodeError
	} else if len(data) < 1 {
		return wireDecodeError
	}
	tmp.kind, data = data[0], data[1:]
	tmp.payload = append(tmp.payload[:0], data...)
	*t = tmp
	return nil
}

type dhtTraffic struct {
	mark dhtWatermark
	baseTraffic
}

func (t *dhtTraffic) encode(out []byte) ([]byte, error) {
	out = append(out, t.mark.key[:]...)
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, t.mark.seq)
	out = append(out, seq...)
	return t.baseTraffic.encode(out)
}

func (t *dhtTraffic) decode(data []byte) error {
	var tmp dhtTraffic
	if !tmp.mark.chop(&data) {
		return wireDecodeError
	} else if err := tmp.baseTraffic.decode(data); err != nil {
		return err
	}
	*t = tmp
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
	return treeLess(first, second) && treeLess(second, third)
}
