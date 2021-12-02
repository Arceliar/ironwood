package network

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/Arceliar/phony"
)

// TODO everything dht-routed (except possibly bootstraps) needs a DHT high water mark...
// To avoid transient loops when paths time out
// That includes dhtTraffic (separate from the pathfinder path watermarks), and pathfinder notify/request packets

const (
	treeTIMEOUT  = time.Hour // TODO figure out what makes sense
	treeANNOUNCE = treeTIMEOUT / 2
	treeTHROTTLE = treeANNOUNCE / 2 // TODO use this to limit how fast seqs can update
)

const (
	dhtDELAY_MIN       = 3
	dhtDELAY_MAX       = 3
	dhtDELAY_TOLERANCE = 2
	dhtDELAY_COUNT     = 6
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
	dinfos     map[publicKey]*dhtInfo // map of key onto info
	self       *treeInfo              // self info
	parent     *peer                  // peer that sent t.self to us
	seq        uint64                 // updated whenever we send a new setup, technically it doesn't need to increase (it just needs to be different)
	btimer     *time.Timer            // time.AfterFunc to send bootstrap packets
	stimer     *time.Timer            // time.AfterFunc for self/parent expiration
	wait       bool                   // FIXME this shouldn't be needed
	hseq       uint64                 // used to track the order treeInfo updates are handled
	bwait      bool                   // wait before sending another bootstrap
	delay      uint8                  // delay between sending bootstraps
	dcount     uint8                  // counter, used it delay scaling
}

type treeExpiredInfo struct {
	seq  uint64    // sequence number that expires
	time time.Time // Time when it expires
}

func (t *dhtree) init(c *core) {
	t.core = c
	t.expired = make(map[publicKey]treeExpiredInfo)
	t.tinfos = make(map[*peer]*treeInfo)
	t.dinfos = make(map[publicKey]*dhtInfo)
	t.seq = uint64(time.Now().Unix())
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
	t._resetBootstrapState()
	t.Act(nil, t._doBootstrap) // Start the bootstrap loop
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
		//defer t._redirectPaths()
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
				//t._resetBootstrapState()
				t._sendTree() // send bad news immediately
				time.AfterFunc(time.Second, func() {
					t.Act(nil, func() {
						t.wait = false
						t.self, t.parent = nil, nil
						t._fix()
						//t._doBootstrap()
					})
				})
			}
		}
		if !t.wait {
			t._fix()
			//t._doBootstrap()
		}
	})
}

// remove removes a peer from the tree, along with any paths through that peer in the dht
func (t *dhtree) remove(from phony.Actor, p *peer) {
	t.Act(from, func() {
		//defer t._redirectPaths()
		for _, dinfo := range t.dinfos {
			//if dinfo.peer == p || dinfo.rest == p {
			//	dinfo.peer = nil
			//	/* TODO remove completely? That seems to loop in the DHT...
			//	dinfo.timer.Stop()
			//	delete(t.dinfos, dinfo.key)
			//	*/
			//}
			if dinfo.peer == p {
				dinfo.peer = nil
				dinfo.isExpired = true // Well no, but actually yes
			}
			if dinfo.rest == p {
				dinfo.rest = nil
			}
		}
		var reboot bool
		if dinfo, isIn := t.dinfos[t.core.crypto.publicKey]; isIn && dinfo.rest == p {
			reboot = true
		}
		oldInfo := t.tinfos[p]
		delete(t.tinfos, p)
		if t.self == oldInfo {
			t.self = nil
			t.parent = nil
			t._fix()
			reboot = true
		}
		t.pathfinder._remove(p)
		if reboot {
			t._resetBootstrapState()
			t._doBootstrap()
		}
	})
}

// _fix selects the best parent (and is called in response to receiving a tree update)
// if this is not the same as our current parent, then it sends a tree update to our peers and resets our prev/next in the dht
func (t *dhtree) _fix() {
	if t.stimer == nil {
		return // closed
	}
	oldSelf := t.self
	oldParent := t.parent
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
					//t._doBootstrap()
				}
			})
		})
		t._sendTree() // Send the tree update to our peers
		// Delete obsolete stuff
		if oldSelf == nil || !t.self.root.equal(oldSelf.root) || t.self.seq != oldSelf.seq {
			for key, dinfo := range t.dinfos {
				break // FIXME DEBUG, just never delete any old paths
				// If we delete a path, then change root again (mobility), we may hear about that same path again from a node that hasn't expired it yet
				// Routing loops actually happen in the lab tests, and I *think* this is why
				// So a different root/seq is not sufficient cause to delete the old paths...
				// Same root and higher seq is probably good enough
				// The question is what to do when the root is different... when is it safe to delete the path?
				if dinfo.isExpired {
					delete(t.dinfos, key)
				}
			}
		}
		if oldSelf == nil || t.parent != oldParent || !t.self.root.equal(oldSelf.root) {
			// We updated t.self, and it's not just a seq update from the same parent
			t._resetBootstrapState()
			t._doBootstrap()
		}
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
func (t *dhtree) _dhtLookup(dest publicKey, isBootstrap bool, mark *dhtWatermark) (*peer, publicKey) {
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
		if isBootstrap && !(info.root.equal(t.self.root) || info.rootSeq != t.self.seq) {
			//return
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
	// Update tree watermark before checking paths
	/*
		if mark != nil {
			if treeLess(mark.tree, best) {
				mark.dht = best
			} else if treeLess(best, mark.tree) {
				bestPeer = nil
			}
		}
	*/
	// Update based on pathfinder paths
	if false && mark != nil {
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
	// Update based on our DHT infos
	for _, dinfo := range t.dinfos {
		if dinfo.isExpired {
			continue
		}
		doDHT(dinfo)
	}
	// Update DHT watermark
	/*
		if mark != nil && bestInfo != nil {
			if treeLess(mark.dht, bestInfo.key) {
				mark.dht = bestInfo.key
			} else if treeLess(bestInfo.key, mark.dht) {
				bestPeer = nil
			}
		}
	*/
	if mark != nil {
		fmt.Println("DEBUG1", best, bestPeer != nil, bestInfo != nil, mark.dht)
		if treeLess(mark.dht, best) {
			mark.dht = best
		} else if treeLess(best, mark.dht) {
			bestPeer = nil
		}
		fmt.Println("DEBUG2", best, bestPeer != nil, bestInfo != nil, mark.dht)
	}
	return bestPeer, best
}

// _dhtAdd adds a dhtInfo to the dht and returns true
// it may return false if the path associated with the dhtInfo isn't allowed for some reason
//  e.g. we know a better prev/next for one of the nodes in the path, which can happen if there's multiple split rings that haven't converged on their own yet
// as of writing, that never happens, it always adds and returns true
func (t *dhtree) _dhtAdd(info *dhtInfo) bool {
	// TODO? check existing paths, don't allow this one if the source/dest pair makes no sense
	if oldInfo, isIn := t.dinfos[info.key]; isIn {
		if oldInfo.seq >= info.seq {
			return false
		}
		oldInfo.timer.Stop()
		// TODO FIXME we need to tear down the old path, unless it's some edge case where we don't...
	}
	t.dinfos[info.key] = info
	return true
}

// _newBootstrap returns a *dhtBootstrap for this node, using t.self, with a signature
func (t *dhtree) _newBootstrap() *dhtBootstrap {
	t.seq++
	dbs := &dhtBootstrap{
		key:     t.core.crypto.publicKey,
		root:    t.self.root,
		rootSeq: t.self.seq,
		seq:     t.seq,
		delay:   t._getBootstrapDelay(),
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
	*/
	next, target := t._dhtLookup(bootstrap.key, true, nil)
	if next == prev {
		// This would loop for some reason, e.g. it's our own bootstrap and we don't have anywhere to send it
		return nil
	}
	dinfo := &dhtInfo{
		dhtBootstrap: *bootstrap,
		//key:     source,
		//seq:     bootstrap.seq, // TODO add a seq to bootstraps (like setups)
		//root:    bootstrap.root,
		//rootSeq: bootstrap.rootSeq,
		peer:   prev,
		rest:   next,   // TODO either don't keep this, or monitor when it goes offline and try to send again?
		target: target, // Key we are trying to route towards
		time:   time.Now(),
	}
	if !t._dhtAdd(dinfo) {
		// We failed to add the dinfo to the DHT for some reason
		return nil
	}
	// TODO re-evaluate existing dhtInfos
	// Would dinfo be a better next hop for anything we've already forwarded before?
	// If so, we should probably do that now... Plugs keyspace holes faster than waiting for more bootstraps
	// Setup timer for cleanup
	delay := bootstrap.delay
	if delay < dhtDELAY_MIN {
		delay = dhtDELAY_MIN
	}
	if delay > dhtDELAY_MAX {
		delay = dhtDELAY_MAX
	}
	dinfo.timer = time.AfterFunc(time.Duration(delay+dhtDELAY_TOLERANCE)*time.Second, func() {
		//return // TODO actual cleanup
		t.Act(nil, func() {
			// Clean up path if it has timed out
			if info := t.dinfos[dinfo.key]; info == dinfo {
				// TODO either delete the path, or mark it as bad
				//delete(t.dinfos, dinfo.key)
				dinfo.isExpired = true
			} else {
				return
			}
			for _, dfo := range t.dinfos {
				break // FIXME this leads to huge traffic spikes, possibly loops?
				if dfo.rest != dinfo.peer {
					continue
				}
				if dfo.target != dinfo.key {
					continue
				}
				next, target := t._dhtLookup(dfo.key, true, nil)
				if next != dfo.rest {
					dfo.rest = next
					dfo.target = target
					if dfo.rest != nil {
						dfo.rest.sendBootstrap(t, &dfo.dhtBootstrap)
					}
				}
			}
			t._redirectPaths()
		})
	})
	return dinfo
}

func (t *dhtree) _redirectPaths() {
	// TODO do something efficient, this scales O(n**2)
	for _, dinfo := range t.dinfos {
		if dinfo.isExpired {
			continue
		}
		t._redirectPath(dinfo)
	}
}

func (t *dhtree) _redirectPath(dinfo *dhtInfo) {
	if next, target := t._dhtLookup(dinfo.key, true, nil); next != nil && next != dinfo.rest && next != dinfo.peer {
		// TODO next != dinfo.peer isn't sufficient to prevent all possible loops, if nodes delete paths
		// Need to e.g. hold on to paths until it's "safe" to delete them, whatever that means
		// A newer timestamp from the same root would probably be sufficient...
		// A *different* root is generally probably not...
		dinfo.rest = next
		dinfo.target = target
		dinfo.rest.sendBootstrap(t, &dinfo.dhtBootstrap)
	}
}

// _handleBootstrap takes a bootstrap packet and checks if we know of a better prev for the source node
// if yes, then we forward to the next hop in the path towards that prev
// if no, then we reply with a dhtBootstrapAck (unless sanity checks fail)
func (t *dhtree) _handleBootstrap(prev *peer, bootstrap *dhtBootstrap) {
	if dinfo := t._addBootstrapPath(bootstrap, prev); dinfo != nil {
		if dinfo.rest != nil {
			dinfo.rest.sendBootstrap(t, bootstrap)
		}
		if dinfo.peer != nil {
			for _, dfo := range t.dinfos {
				break // FIXME this leads to traffic spikes
				if dfo.peer == dinfo.peer || dfo.rest == dinfo.peer {
					continue
				}
				if dfo.target == dinfo.key || dhtOrdered(dfo.target, dinfo.key, dfo.key) {
					// If we had known about dinfo earlier, then we should have sent dfo towards dinfo.peer
					// Better late than never
					dfo.rest = dinfo.peer
					dfo.target = dinfo.key
					dinfo.peer.sendBootstrap(t, &dfo.dhtBootstrap)
				}
			}
		}
		t._redirectPaths()
	}
}

// handleBootstrap is the externally callable actor behavior that sends a message to the dhtree that it should _handleBootstrap
func (t *dhtree) handleBootstrap(from phony.Actor, prev *peer, bootstrap *dhtBootstrap) {
	t.Act(from, func() {
		t._handleBootstrap(prev, bootstrap)
	})
}

// _doBootstrap decides whether or not to send a bootstrap packet
// if a bootstrap is sent, then it sets things up to attempt to send another bootstrap at a later point
func (t *dhtree) _doBootstrap() {
	if t.btimer != nil {
		delay := t._getBootstrapDelay()
		if t.parent != nil {
			// Adjust delay for future bootstraps
			t.dcount++
			if t.dcount > dhtDELAY_COUNT {
				t.dcount = 0
				t.delay++
				if t.delay > dhtDELAY_MAX {
					t.delay = dhtDELAY_MAX
				}
			}
			t._handleBootstrap(nil, t._newBootstrap())
		}
		t.btimer.Stop()
		t.btimer = time.AfterFunc(time.Duration(delay)*time.Second, func() {
			t.Act(nil, t._doBootstrap)
		})
	}
}

func (t *dhtree) _getBootstrapDelay() uint8 {
	return t.delay
}

func (t *dhtree) _resetBootstrapState() {
	if t.btimer != nil {
		t.btimer.Stop()
	}
	t.delay = dhtDELAY_MIN
	t.dcount = 0
}

// handleDHTTraffic take a dht traffic packet (still marshaled as []bytes) and decides where to forward it to next to take it closer to its destination in keyspace
// if there's nowhere better to send it, then it hands it off to be read out from the local PacketConn interface
func (t *dhtree) handleDHTTraffic(from phony.Actor, tr *dhtTraffic, doNotify bool) {
	t.Act(from, func() {
		next, _ := t._dhtLookup(tr.dest, false, &tr.mark)
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
	peer   *peer
	rest   *peer
	target publicKey
	//root    publicKey
	//rootSeq uint64
	timer     *time.Timer // time.AfterFunc to clean up after timeout, stop this on teardown
	time      time.Time   // time when this info was added
	isExpired bool
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
	delay   uint8
}

func (dbs *dhtBootstrap) bytesForSig() []byte {
	const size = len(dbs.key) + len(dbs.root) + 8 + 8
	bs := make([]byte, 0, size)
	bs = append(bs, dbs.key[:]...)
	bs = append(bs, dbs.root[:]...)
	bs = bs[:size]
	binary.BigEndian.PutUint64(bs[len(bs)-16:len(bs)-8], dbs.rootSeq)
	binary.BigEndian.PutUint64(bs[len(bs)-8:], dbs.seq)
	bs = append(bs, dbs.delay)
	return bs
}

func (dbs *dhtBootstrap) check() bool {
	bs := dbs.bytesForSig()
	return dbs.key.verify(bs, &dbs.sig)
}

func (dbs *dhtBootstrap) encode(out []byte) ([]byte, error) {
	out = append(out, dbs.sig[:]...)
	out = append(out, dbs.bytesForSig()...)
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
	} else if len(data) != 17 { // TODO? < 16, in case it's embedded in something?
		return wireDecodeError
	}
	tmp.rootSeq = binary.BigEndian.Uint64(data[:8])
	tmp.seq = binary.BigEndian.Uint64(data[8:16])
	tmp.delay = data[16]
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

/**************
 * baseTraffic *
 **************/

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

/**************
 * dhtTraffic *
 **************/

type dhtWatermark struct {
	tree publicKey
	dht  publicKey
	prev publicKey
	next publicKey
}

type dhtTraffic struct {
	mark dhtWatermark
	baseTraffic
}

func (t *dhtTraffic) encode(out []byte) ([]byte, error) {
	out = append(out, t.mark.tree[:]...)
	out = append(out, t.mark.dht[:]...)
	out = append(out, t.mark.prev[:]...)
	out = append(out, t.mark.next[:]...)
	return t.baseTraffic.encode(out)
}

func (t *dhtTraffic) decode(data []byte) error {
	var tmp dhtTraffic
	if !wireChopSlice(tmp.mark.tree[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.mark.dht[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.mark.prev[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.mark.next[:], &data) {
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
