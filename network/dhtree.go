package network

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/Arceliar/phony"
)

const (
	treeTIMEOUT  = time.Hour // TODO figure out what makes sense
	treeANNOUNCE = treeTIMEOUT / 2
	treeTHROTTLE = treeANNOUNCE / 2 // TODO use this to limit how fast seqs can update
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
	dinfos     map[dhtMapKey]*dhtInfo
	self       *treeInfo              // self info
	parent     *peer                  // peer that sent t.self to us
	pred       *dhtInfo               // predecessor in dht, who we maintain a path to
	succ       *dhtInfo               // successor in dht, they maintain a path to us
	dkeys      map[*dhtInfo]publicKey // map of *dhtInfo->destKey for current and past predecessors
	seq        uint64                 // updated whenever we send a new setup, technically it doesn't need to increase (it just needs to be different)
	btimer     *time.Timer            // time.AfterFunc to send bootstrap packets
	stimer     *time.Timer            // time.AfterFunc for self/parent expiration
	wait       bool                   // FIXME this is a hack to let bad news spread before changing parents
}

type treeExpiredInfo struct {
	seq  uint64    // sequence number that expires
	time time.Time // Time when it expires
}

func (t *dhtree) init(c *core) {
	t.core = c
	t.expired = make(map[publicKey]treeExpiredInfo)
	t.tinfos = make(map[*peer]*treeInfo)
	t.dinfos = make(map[dhtMapKey]*dhtInfo)
	t.dkeys = make(map[*dhtInfo]publicKey)
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
		if exp, isIn := t.expired[info.root]; !isIn || exp.seq < info.seq {
			t.expired[info.root] = treeExpiredInfo{seq: info.seq, time: info.time}
		}
		oldInfo := t.tinfos[p]
		t.tinfos[p] = info
		var doWait bool
		if t.self != oldInfo {
			// Not our parent, don't update
		} else if !info.root.equal(t.self.root) {
			doWait = true // FIXME make this safe if the new root is better
		} else if info.seq == t.self.seq {
			// Same root and same seq, so something changed -> unstable path
			doWait = true
		}
		if doWait {
			// This is bad news about our path to the root
			// We don't want to switch to a new path to aggressively, since our other
			//  peers could also be handling bad news right now, and that tends to
			//  busyloop until all possible paths to the root have been exhausted.
			// So send some bad news and wait before trying to select a new parent
			t.self = &treeInfo{root: t.core.crypto.publicKey} // WARNING: no timer was set
			t.parent = nil
			t._sendTree() //t.core.peers.sendTree(t, t.self)
			if !t.wait {
				t.wait = true
				time.AfterFunc(time.Second, func() {
					// FIXME until this timer fires, we potentially have no path to the root
					// That messes with the DHT
					// Adjust DHT lookups to tolerate this (if peers are OK...)
					t.Act(nil, func() {
						t.wait = false
						t.self = nil // So fix can reset things / start a proper timer
						t.parent = nil
						t._fix()
						t._doBootstrap()
					})
				})
			}
			return
		}
		if !t.wait {
			// TODO? something special if we're in the unsafe t.self state with no timer?
			t._fix()
			t._doBootstrap() // FIXME don't do this every time, only when we need to...
		}
		if oldInfo == nil {
			// The peer may have missed an update due to a race between creating the peer and now
			// The easiest way to fix the problem is to just send it another update right now
			p.sendTree(t, t.self)
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
		for _, dinfo := range t.dinfos {
			if dinfo.prev == p || dinfo.next == p {
				t._teardown(p, dinfo.getTeardown())
			}
		}
	})
}

// _fix selects the best parent (and is called in response to receiving a tree update)
// if this is not the same as our current parent, then it sends a tree update to our peers and resets our successor/predecessor in the dht
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
		case info.time.Before(t.self.time):
			// This info has been around for longer (e.g. the path is more stable)
			t.self, t.parent = info, p
		case info.time.After(t.self.time):
			// This info has been around for less time (e.g. the path is less stable)
			// Note that everything after this is extremely unlikely to be reached...
		case len(info.hops) < len(t.self.hops):
			// This is a shorter path to the root
			t.self, t.parent = info, p
		case len(info.hops) > len(t.self.hops):
			// This is a longer path to the root, so don't do anything
		case treeLess(info.from(), t.self.from()):
			// This peer has a higher key than our current parent
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
					t._doBootstrap()
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
func (t *dhtree) _dhtLookup(dest publicKey, isBootstrap bool) *peer {
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
			doUpdate(key, p, nil)
		}
	}
	// doAncestry updates based on the ancestry information in a treeInfo
	doAncestry := func(info *treeInfo, p *peer) {
		doCheckedUpdate(info.root, p, nil) // updates if the root is better
		for _, hop := range info.hops {
			doCheckedUpdate(hop.next, p, nil) // updates if this hop is better
			if bestPeer != nil && best.equal(hop.next) && info.time.Before(t.tinfos[bestPeer].time) {
				// This ancestor matches our current next hop, but this peer's treeInfo is better, so switch to it
				doUpdate(hop.next, p, nil)
			}
		}
	}
	// doDHT updates best based on a DHT path
	doDHT := func(info *dhtInfo) {
		doCheckedUpdate(info.key, info.prev, info) // updates if the source is better
		if bestInfo != nil && info.key.equal(bestInfo.key) {
			if treeLess(info.root, bestInfo.root) {
				doUpdate(info.key, info.prev, info) // same source, but the root is better
			} else if info.root.equal(bestInfo.root) && info.rootSeq > bestInfo.rootSeq {
				doUpdate(info.key, info.prev, info) // same source, same root, but the rootSeq is newer
			}
		}
	}
	// Update the best key and peer
	if (isBootstrap && best.equal(dest)) || dhtOrdered(t.self.root, dest, best) {
		// We're the current best, and we're already too far through keyspace
		// That means we need to default to heading towards the root
		doUpdate(t.self.root, t.parent, nil)
	}
	// Update based on our root
	doAncestry(t.self, t.parent)
	// Update based on our peers
	for p, info := range t.tinfos {
		doAncestry(info, p)
	}
	// Replace best (from an ancestor) if it happens to be a direct peer
	for p := range t.tinfos {
		if best.equal(p.key) {
			doUpdate(p.key, p, nil)
		}
	}
	// Update based on our DHT infos
	for _, info := range t.dinfos {
		doDHT(info)
	}
	return bestPeer
}

// _dhtAdd adds a dhtInfo to the dht and returns true
// it may return false if the path associated with the dhtInfo isn't allowed for some reason
//  e.g. we know a better predecessor/successor for one of the nodes in the path, which can happen if there's multiple split rings that haven't converged on their own yet
// as of writing, that never happens, it always adds and returns true
func (t *dhtree) _dhtAdd(info *dhtInfo) bool {
	// TODO? check existing paths, don't allow this one if the source/dest pair makes no sense
	t.dinfos[info.getMapKey()] = info
	return true
}

// _newBootstrap returns a *dhtBootstrap for this node, using t.self, with a signature
func (t *dhtree) _newBootstrap() *dhtBootstrap {
	dbs := new(dhtBootstrap)
	dbs.label = *t._getLabel()
	return dbs
}

// _handleBootstrap takes a bootstrap packet and checks if we know of a better predecessor for the source node
// if yes, then we forward to the next hop in the path towards that predecessor
// if no, then we reply with a dhtBootstrapAck (unless sanity checks fail)
func (t *dhtree) _handleBootstrap(bootstrap *dhtBootstrap) {
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
}

// handleBootstrap is the externally callable actor behavior that sends a message to the dhtree that it should _handleBootstrap
func (t *dhtree) handleBootstrap(from phony.Actor, bootstrap *dhtBootstrap) {
	t.Act(from, func() {
		t._handleBootstrap(bootstrap)
	})
}

// _handleBootstrapAck takes an ack packet and checks if we know a next hop on the tree
// if yes, then we forward to the next hop
// if no, then we decide whether or not this node is better than our current predecessor
// if yes, then we get rid of our current predecessor (if any) and start setting up a new path to the response node in the ack
// if no, then we drop the bootstrap acknowledgement without doing anything
func (t *dhtree) _handleBootstrapAck(ack *dhtBootstrapAck) {
	source := ack.response.dest.key
	next := t._treeLookup(&ack.bootstrap.label)
	switch {
	case next != nil:
		next.sendBootstrapAck(t, ack)
		return
	case t.core.crypto.publicKey.equal(source):
		// This is our own ack, but we failed to find a next hop
		return
	case !t.core.crypto.publicKey.equal(ack.bootstrap.label.key):
		// This isn't an ack of our own bootstrap
		return
	case !t.core.crypto.publicKey.equal(ack.response.source):
		// This is an ack of or own bootstrap, but the token isn't for us
		return
	case !ack.response.dest.root.equal(t.self.root):
		// We have a different root, so tree lookups would fail
		return
	case ack.response.dest.seq != t.self.seq:
		// This response is too old, so path setup would fail
		return
	case t.pred == nil:
		// We have no predecessor, so anything matching the above is good enough
	case dhtOrdered(t.dkeys[t.pred], source, t.core.crypto.publicKey):
		// This is from a better predecessor than our current one
	case !source.equal(t.dkeys[t.pred]):
		// This isn't from the current predecessor or better, so ignore it
		return
	case !t.pred.root.equal(t.self.root) || t.pred.rootSeq != t.self.seq:
		// The curent predecessor needs replacing (old tree info)
	default:
		// We already have a better (FIXME? or equal) predecessor
		return
	}
	if !ack.response.check() {
		// Final thing to check, if the signatures are bad then ignore it
		return
	}
	t.pred = nil
	for _, dinfo := range t.dinfos {
		// Former predecessors need to be notified that we're no longer a successor
		// The only way to signal that is by tearing down the path
		// We may have multiple former predecessor paths
		//  From t.pred = nil when the tree changes, but kept around to bootstrap
		// So loop over paths and close any going to a *different* node than the current predecessor
		// The current predecessor can close the old path from that side after setup
		if dest, isIn := t.dkeys[dinfo]; isIn && !dest.equal(source) {
			t._teardown(nil, dinfo.getTeardown())
		}
	}
	setup := t._newSetup(&ack.response)
	t._handleSetup(nil, setup)
	if t.pred == nil {
		// This can happen if the treeLookup in handleSetup fails
		// FIXME we should avoid letting this happen
		//  E.g. check that the lookup will predeed, or at least that the roots match
	}
}

// handleBootstrapAck is the externally callable actor behavior that sends a message to the dhtree that it should _handleBootstrapAck
func (t *dhtree) handleBootstrapAck(from phony.Actor, ack *dhtBootstrapAck) {
	t.Act(from, func() {
		t._handleBootstrapAck(ack)
	})
}

// _newSetup returns a *dhtSetup for this node, with a new sequence number and signature
func (t *dhtree) _newSetup(token *dhtSetupToken) *dhtSetup {
	t.seq++
	setup := new(dhtSetup)
	setup.seq = t.seq
	setup.token = *token
	setup.sig = t.core.crypto.privateKey.sign(setup.bytesForSig())
	return setup
}

// _handleSetup checks if it's safe to add a path from the setup source to the setup destination
// if we can't add it (due to no next hop to forward it to, or if we're the destination but we already have a better successor, or if we already have a path from the same source node), then we send a teardown to remove the path from the network
// otherwise, we add the path to our table, and forward it (if we're not the destination) or set it as our successor path (if we are, tearing down our existing successor if one exists)
func (t *dhtree) _handleSetup(prev *peer, setup *dhtSetup) {
	next := t._treeLookup(&setup.token.dest)
	dest := setup.token.dest.key
	if next == nil && !dest.equal(t.core.crypto.publicKey) {
		// FIXME? this has problems if prev is self (from changes to tree state?)
		if prev != nil {
			prev.sendTeardown(t, setup.getTeardown())
		}
		return
	}
	dinfo := new(dhtInfo)
	dinfo.seq = setup.seq
	dinfo.key = setup.token.source
	dinfo.prev = prev
	dinfo.next = next
	dinfo.root = setup.token.dest.root
	dinfo.rootSeq = setup.token.dest.seq
	if !dinfo.root.equal(t.self.root) || dinfo.rootSeq != t.self.seq {
		// Wrong root or mismatched seq
		if prev != nil {
			prev.sendTeardown(t, setup.getTeardown())
		}
		return
	}
	if _, isIn := t.dinfos[dinfo.getMapKey()]; isIn {
		// Already have a path from this source
		if prev != nil {
			prev.sendTeardown(t, setup.getTeardown())
		}
		return
	}
	if !t._dhtAdd(dinfo) {
		if prev != nil {
			prev.sendTeardown(t, setup.getTeardown())
		}
	}
	dinfo.timer = time.AfterFunc(2*treeTIMEOUT, func() {
		t.Act(nil, func() {
			// Clean up path if it has timed out
			if info, isIn := t.dinfos[dinfo.getMapKey()]; isIn {
				if info.prev != nil {
					info.prev.sendTeardown(t, info.getTeardown())
				}
				t._teardown(info.prev, info.getTeardown())
			}
		})
	})
	if prev == nil {
		// sanity checks, this should only happen when setting up our predecessor
		if !setup.token.source.equal(t.core.crypto.publicKey) {
			panic("wrong source")
		} else if setup.seq != t.seq {
			panic("wrong seq")
		} else if t.pred != nil {
			panic("already have a predecessor")
		}
		t.pred = dinfo
		t.dkeys[dinfo] = dest
	}
	if next != nil {
		next.sendSetup(t, setup)
	} else {
		if t.succ != nil {
			// TODO get this right!
			//  We need to replace the old successor in most cases
			//  The exceptions are when:
			//    1. The dinfo's root/seq don't match our current root/seq
			//    2. The dinfo matches, but so does t.succ, and t.succ is better
			//  What happens when the dinfo matches, t.succ does not, but t.succ is still better?...
			//  Just doing something for now (replace succ) but not sure that's right...
			var doUpdate bool
			if !dinfo.root.equal(t.self.root) || dinfo.rootSeq != t.self.seq {
				// The root/seq is bad, so don't update
			} else if dinfo.key.equal(t.succ.key) {
				// It's an update from the current successor
				doUpdate = true
			} else if dhtOrdered(t.core.crypto.publicKey, dinfo.key, t.succ.key) {
				// It's an update from a better successor
				doUpdate = true
			}
			if doUpdate {
				t._teardown(nil, t.succ.getTeardown())
				t.succ = dinfo
			} else {
				t._teardown(nil, dinfo.getTeardown())
			}
		} else {
			t.succ = dinfo
		}
	}
}

// handleSetup is the dhtree actor behavior that sends a message to _handleSetup
func (t *dhtree) handleSetup(from phony.Actor, prev *peer, setup *dhtSetup) {
	t.Act(from, func() {
		t._handleSetup(prev, setup)
	})
}

// _teardown removes the path associated with the teardown from our dht and forwards it to the next hop along that path (or does nothing if the teardown doesn't match a known path)
func (t *dhtree) _teardown(from *peer, teardown *dhtTeardown) {
	if dinfo, isIn := t.dinfos[teardown.getMapKey()]; isIn {
		if teardown.seq != dinfo.seq {
			return
		} else if !teardown.key.equal(dinfo.key) {
			panic("this should never happen")
		}
		var next *peer
		if from == dinfo.prev {
			next = dinfo.next
		} else if from == dinfo.next {
			next = dinfo.prev
		} else {
			return //panic("DEBUG teardown of path from wrong node")
		}
		dinfo.timer.Stop()
		delete(t.dkeys, dinfo)
		delete(t.dinfos, teardown.getMapKey())
		if next != nil {
			next.sendTeardown(t, teardown)
		}
		if t.succ == dinfo {
			t.succ = nil
		}
		if t.pred == dinfo {
			t.pred = nil
			t._doBootstrap()
		}
	}
}

// teardown is the dhtinfo actor behavior that sends a message to _teardown
func (t *dhtree) teardown(from phony.Actor, p *peer, teardown *dhtTeardown) {
	t.Act(from, func() {
		t._teardown(p, teardown)
	})
}

// _doBootstrap decides whether or not to send a bootstrap packet
// if a bootstrap is sent, then it sets things up to attempt to send another bootstrap at a later point
func (t *dhtree) _doBootstrap() {
	//return // FIXME debug tree (root offline -> too much traffic to fix)
	if t.btimer != nil {
		if t.pred != nil && t.pred.root.equal(t.self.root) && t.pred.rootSeq == t.self.seq {
			return
		}
		t._handleBootstrap(t._newBootstrap())
		t.btimer.Stop()
		t.btimer = time.AfterFunc(time.Second, func() { t.Act(nil, t._doBootstrap) })
	}
}

// handleDHTTraffic take a dht traffic packet (still marshaled as []bytes) and decides where to forward it to next to take it closer to its destination in keyspace
// if there's nowhere better to send it, then it hands it off to be read out from the local PacketConn interface
func (t *dhtree) handleDHTTraffic(from phony.Actor, tr *dhtTraffic, doNotify bool) {
	t.Act(from, func() {
		next := t._dhtLookup(tr.dest, false)
		if next == nil {
			if tr.dest.equal(t.core.crypto.publicKey) {
				dest := tr.source
				t.pathfinder._doNotify(dest, !doNotify)
			}
			t.core.pconn.handleTraffic(tr)
		} else {
			next.sendDHTTraffic(t, tr)
		}
	})
}

func (t *dhtree) sendTraffic(from phony.Actor, tr *dhtTraffic) {
	t.Act(from, func() {
		if path := t.pathfinder._getPath(tr.dest); path != nil {
			pt := new(pathTraffic)
			pt.path = path
			pt.dt = *tr
			t.core.peers.handlePathTraffic(t, pt)
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
	return a + b - 2*lcaIdx
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
	seq     uint64
	key     publicKey
	prev    *peer
	next    *peer
	root    publicKey
	rootSeq uint64
	timer   *time.Timer // time.AfterFunc to clean up after timeout, stop this on teardown
}

func (info *dhtInfo) getTeardown() *dhtTeardown {
	return &dhtTeardown{seq: info.seq, key: info.key, root: info.root, rootSeq: info.rootSeq}
}

type dhtMapKey struct {
	key     publicKey
	root    publicKey
	rootSeq uint64
}

func (info *dhtInfo) getMapKey() dhtMapKey {
	return dhtMapKey{info.key, info.root, info.rootSeq}
}

/****************
 * dhtBootstrap *
 ****************/

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

/*******************
 * dhtBootstrapAck *
 *******************/

type dhtBootstrapAck struct {
	bootstrap dhtBootstrap
	response  dhtSetupToken
}

func (ack *dhtBootstrapAck) check() bool {
	return ack.bootstrap.check() && ack.response.check()
}

func (ack *dhtBootstrapAck) encode(out []byte) ([]byte, error) {
	var bootBytes, resBytes []byte // TODO get rid of these
	var err error
	if bootBytes, err = ack.bootstrap.encode(nil); err != nil {
		return nil, err
	} else if resBytes, err = ack.response.encode(nil); err != nil {
		return nil, err
	}
	out = wireEncodeUint(out, uint64(len(bootBytes)))
	out = append(out, bootBytes...)
	out = append(out, resBytes...)
	return out, nil
}

func (ack *dhtBootstrapAck) decode(data []byte) error {
	bootLen, begin := wireDecodeUint(data)
	end := begin + int(bootLen)
	var tmp dhtBootstrapAck
	if end > len(data) {
		return wireDecodeError
	} else if err := tmp.bootstrap.decode(data[begin:end]); err != nil {
		return err
	} else if err := tmp.response.decode(data[end:]); err != nil {
		return err
	}
	*ack = tmp
	return nil
}

/************
 * dhtSetup *
 ************/

type dhtSetup struct {
	sig   signature
	seq   uint64
	token dhtSetupToken
}

func (s *dhtSetup) bytesForSig() []byte {
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, s.seq)
	var err error
	if bs, err = s.token.encode(bs); err != nil {
		panic("this should never happen")
	}
	return bs
}

func (s *dhtSetup) check() bool {
	if !s.token.check() {
		return false
	}
	bs := s.bytesForSig()
	return s.token.source.verify(bs, &s.sig)
}

func (s *dhtSetup) getTeardown() *dhtTeardown {
	return &dhtTeardown{
		seq:     s.seq,
		key:     s.token.source,
		root:    s.token.dest.root,
		rootSeq: s.token.dest.seq,
	}
}

func (s *dhtSetup) encode(out []byte) ([]byte, error) {
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, s.seq)
	out = append(out, s.sig[:]...)
	out = append(out, seq...)
	return s.token.encode(out)
}

func (s *dhtSetup) decode(data []byte) error {
	var tmp dhtSetup
	if !wireChopSlice(tmp.sig[:], &data) {
		return wireDecodeError
	}
	if len(data) < 8 {
		return wireDecodeError
	}
	tmp.seq, data = binary.BigEndian.Uint64(data[:8]), data[8:]
	if err := tmp.token.decode(data); err != nil {
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
	key     publicKey
	root    publicKey
	rootSeq uint64
}

func (t *dhtTeardown) getMapKey() dhtMapKey {
	return dhtMapKey{t.key, t.root, t.rootSeq}
}

func (t *dhtTeardown) encode(out []byte) ([]byte, error) {
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, t.seq)
	out = append(out, seq...)
	out = append(out, t.key[:]...)
	out = append(out, t.root[:]...)
	rseq := make([]byte, 8)
	binary.BigEndian.PutUint64(rseq, t.rootSeq)
	out = append(out, rseq...)
	return out, nil
}

func (t *dhtTeardown) decode(data []byte) error {
	var tmp dhtTeardown
	if len(data) < 8 {
		return wireDecodeError
	}
	tmp.seq, data = binary.BigEndian.Uint64(data[:8]), data[8:]
	if !wireChopSlice(tmp.key[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.root[:], &data) {
		return wireDecodeError
	} else if len(data) != 8 {
		return wireDecodeError
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
	kind    byte // in-band vs out-of-band, TODO? separate type?
	payload []byte
}

func (t *dhtTraffic) encode(out []byte) ([]byte, error) {
	out = append(out, t.source[:]...)
	out = append(out, t.dest[:]...)
	out = append(out, t.kind)
	out = append(out, t.payload...)
	return out, nil
}

func (t *dhtTraffic) decode(data []byte) error {
	var tmp dhtTraffic
	if !wireChopSlice(tmp.source[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.dest[:], &data) {
		return wireDecodeError
	}
	if len(data) < 1 {
		return wireDecodeError
	}
	tmp.kind, data = data[0], data[1:]
	tmp.payload = append(tmp.payload[:0], data...)
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
