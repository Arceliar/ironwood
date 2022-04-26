package network

import (
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/Arceliar/phony"
)

const (
	treeTIMEOUT  = time.Hour // TODO figure out what makes sense
	treeANNOUNCE = treeTIMEOUT / 2
	treeTHROTTLE = treeANNOUNCE / 2 // TODO use this to limit how fast seqs can update
	dhtANNOUNCE  = 3 * time.Second
	dhtTIMEOUT   = 2*dhtANNOUNCE + time.Second
	dhtCLEANUP   = dhtANNOUNCE + dhtTIMEOUT + time.Second
)

/**********
 * dhtree *
 **********/

type dhtree struct {
	phony.Inbox
	core       *core
	pathfinder pathfinder
	peers      map[*peer]struct{}
	expired    map[publicKey]treeExpiredInfo // stores root highest seq and when it expires
	tinfos     map[*peer]*treeInfo
	dinfos     map[publicKey]*dhtInfo
	self       *treeInfo   // self info
	parent     *peer       // peer that sent t.self to us
	btimer     *time.Timer // time.AfterFunc to send bootstrap packets
	stimer     *time.Timer // time.AfterFunc for self/parent expiration
	wait       bool        // FIXME this shouldn't be needed
	hseq       uint64      // used to track the order treeInfo updates are handled
}

type treeExpiredInfo struct {
	seq  uint64    // sequence number that expires
	time time.Time // Time when it expires
}

func (t *dhtree) init(c *core) {
	t.core = c
	t.peers = make(map[*peer]struct{})
	t.expired = make(map[publicKey]treeExpiredInfo)
	t.tinfos = make(map[*peer]*treeInfo)
	t.dinfos = make(map[publicKey]*dhtInfo)
	t.btimer = time.AfterFunc(0, func() {}) // non-nil until closed
	t.stimer = time.AfterFunc(0, func() {}) // non-nil until closed
	t._fix()                                // Initialize t.self and start announce and timeout timers
	t.Act(nil, t._doBootstrap)
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
					})
				})
			}
		}
		if !t.wait {
			t._fix()
		}
	})
}

func (t *dhtree) addPeer(from phony.Actor, p *peer) {
	t.Act(from, func() {
		t.peers[p] = struct{}{}
	})
}

// remove removes a peer from the tree, along with any paths through that peer in the dht
func (t *dhtree) remove(from phony.Actor, p *peer) {
	t.Act(from, func() {
		delete(t.peers, p)
		oldInfo := t.tinfos[p]
		delete(t.tinfos, p)
		if t.self == oldInfo {
			t.self = nil
			t.parent = nil
			t._fix()
		}
		for k, dinfo := range t.dinfos {
			if dinfo.peer == p {
				//dinfo.peer = nil
				//continue
				//t._teardown(p, dinfo.getTeardown())
				dinfo.timer.Stop()
				delete(t.dinfos, k)
			}
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
	distCut := bestDist
	var bestPeer *peer
	for p, info := range t.tinfos {
		if !info.root.equal(dest.root) || info.seq != dest.rootSeq {
			continue
		}
		tmp := *info
		tmp.hops = tmp.hops[:len(tmp.hops)-1]
		dist := tmp.dist(dest)
		var isBetter bool
		switch {
		case dist >= distCut:
		case dist < bestDist:
			isBetter = true
		case dist > bestDist:
		case info.time.Before(best.time):
			isBetter = true
		case best.time.Before(info.time):
		case treeLess(info.from(), best.from()): // Matters on platforms where time resolution is bad
			isBetter = true
		}
		if isBetter {
			best = info
			bestDist = dist
			bestPeer = p
		}
	}
	if !best.root.equal(dest.root) || best.seq != dest.rootSeq { // TODO? check self, not next/dest?
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
	var best publicKey
	var bestPeer *peer
	var bestInfo *dhtInfo
	var firstInfo *dhtInfo
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
	// doDHT updates best based on a DHT path
	doDHT := func(info *dhtInfo) {
		if isBootstrap && time.Since(info.time) > dhtTIMEOUT {
			return
		}
		doCheckedUpdate(info.key, info.peer, info) // updates if the source is better
		if firstInfo == nil || treeLess(info.key, firstInfo.key) {
			firstInfo = info
		}
	}
	// Update based on our DHT infos
	for _, dinfo := range t.dinfos {
		// Note that this includes the self dht entry, so no special logic is needed if we're the destination
		doDHT(dinfo)
	}
	// Escape hatch:
	// If the target is even lower than the lowest known key, forward towards that key
	// This is just to make the DHT complete (otherwise, keys lower than the lowest known key would route to nowhere)
	if bestPeer == nil && firstInfo != nil && treeLess(dest, firstInfo.key) {
		doUpdate(firstInfo.key, firstInfo.peer, firstInfo)
	}
	// Check high water mark (loop avoidance)
	if mark != nil {
		if treeLess(best, mark.key) || (bestInfo != nil && best.equal(mark.key) && bestInfo.seq < mark.seq) {
			// The best isn't good enough
			bestPeer = nil
		} else if bestInfo != nil {
			// Update the watermark
			mark.key = bestInfo.key
			mark.seq = bestInfo.seq
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
	if dinfo, isIn := t.dinfos[info.key]; isIn {
		if dinfo.seq < info.seq {
			dinfo.timer.Stop()
			delete(t.dinfos, dinfo.key)
		} else {
			// We already have a path that's either the same seq or better, so ignore this one
			// TODO? keep the path, but don't forward it anywhere
			// This is very delicate (needed for anycast to not break the network, etc)
			return false
		}
	}
	t.dinfos[info.key] = info
	// Setup timer for cleanup
	info.timer = time.AfterFunc(dhtCLEANUP, func() {
		t.Act(nil, func() {
			// Clean up path if it has timed out
			if nfo := t.dinfos[info.key]; nfo == info {
				delete(t.dinfos, nfo.key)
			}
		})
	})
	return true
}

// _newBootstrap returns a *dhtBootstrap for this node, using t.self, with a signature
func (t *dhtree) _newBootstrap() *dhtBootstrap {
	dbs := &dhtBootstrap{
		key: t.core.crypto.publicKey,
		seq: uint64(time.Now().Unix()),
	}
	dbs.sig = t.core.crypto.privateKey.sign(dbs.bytesForSig())
	return dbs
}

func (t *dhtree) _addBootstrapPath(bootstrap *dhtBootstrap, prev *peer) *dhtInfo {
	dinfo := &dhtInfo{
		dhtBootstrap: *bootstrap,
		peer:         prev,
		time:         time.Now(),
	}
	// Possibly set peer to something != prev, if it's better
	for _, s := range bootstrap.bhs {
		if prev != nil && dinfo.peer != prev {
			// We already found something better than prev, so break the outer loop
			break
		}
		// TODO something faster than this inner loop
		for p := range t.peers {
			if p.key.equal(s.key) {
				dinfo.peer = p
				break
			}
		}
	}
	dinfo.dhtBootstrap.bhs = nil
	if dinfo.peer == nil {
		if !dinfo.key.equal(t.core.crypto.publicKey) {
			panic("this should never happen")
		}
	}
	if !t._dhtAdd(dinfo) {
		// We failed to add the dinfo to the DHT for some reason
		return nil
	}

	return dinfo
}

func (t *dhtree) _isBroadcast(bootstrap *dhtBootstrap) bool {
	for k, dinfo := range t.dinfos {
		if time.Since(dinfo.time) > dhtTIMEOUT {
			continue
		}
		if treeLess(k, bootstrap.key) {
			return false
		}
	}
	return true
}

// _handleBootstrap takes a bootstrap packet and checks if we know of a better prev for the source node
// if yes, then we forward to the next hop in the path towards that prev
// if no, then we reply with a dhtBootstrapAck (unless sanity checks fail)
func (t *dhtree) _handleBootstrap(prev *peer, bootstrap *dhtBootstrap) {
	if dinfo := t._addBootstrapPath(bootstrap, prev); dinfo != nil {
		if dinfo.peer == nil {
			// sanity checks, this should only happen when setting up our own path
			if !bootstrap.key.equal(t.core.crypto.publicKey) {
				panic("wrong key")
			}
		}
		// Get the next hop(s)
		sendTo := make(map[*peer]struct{})
		// Check if this needs to be broadcast, and fix some things if so
		if t._isBroadcast(bootstrap) {
			//dinfo.peer = prev // In case it was set to something from bhs
			for p := range t.peers {
				sendTo[p] = struct{}{}
			}
		} else if next := t._dhtLookup(bootstrap.key, true, nil); next != nil {
			sendTo[next] = struct{}{}
		}
		// Fix the bootstrap hop sigs before sending
		bhs := bootstrap.bhs
		bootstrap.bhs = bootstrap.bhs[:0]
		for _, s := range bhs {
			if dfo, isIn := t.dinfos[s.key]; isIn {
				// This node has already seen it, so make sure we don't send it to them
				delete(sendTo, dfo.peer)
			}
			if dinfo.peer == nil || dinfo.peer.key != s.key {
				continue
			}
			bootstrap.bhs = append(bootstrap.bhs, s)
		}
		var s bootstrapHopSig
		s.key = t.core.crypto.publicKey
		s.sig = t.core.crypto.privateKey.sign(bootstrap.bytesForSig())
		bootstrap.bhs = append(bootstrap.bhs, s)
		// Send to peers
		for p := range sendTo {
			p.sendBootstrap(t, bootstrap)
		}
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
	if t.btimer == nil {
		return
	}
	t._handleBootstrap(nil, t._newBootstrap())
	t.btimer.Stop()
	waitTime := dhtANNOUNCE - 250*time.Millisecond + time.Duration(rand.Intn(500))*time.Millisecond
	t.btimer = time.AfterFunc(waitTime, func() {
		t.Act(nil, t._doBootstrap)
	})
}

// handleDHTTraffic take a dht traffic packet (still marshaled as []bytes) and decides where to forward it to next to take it closer to its destination in keyspace
// if there's nowhere better to send it, then it hands it off to be read out from the local PacketConn interface
func (t *dhtree) handleDHTTraffic(from phony.Actor, tr *dhtTraffic, doNotify bool) {
	t.Act(from, func() {
		next := t._dhtLookup(tr.dest, false, &tr.mark)
		if next == nil {
			if tr.dest.equal(t.core.crypto.publicKey) {
				dest := tr.source
				if doNotify {
					t.pathfinder._doNotify(dest)
				}
			}
			t.core.pconn.handleTraffic(tr)
		} else {
			next.sendDHTTraffic(t, tr)
		}
	})
}

// sendTraffic sends a dhtTraffic packet to the destination, possibly by wrapping it in a pathfinder packet.
func (t *dhtree) sendTraffic(from phony.Actor, tr *dhtTraffic) {
	t.Act(from, func() {
		if path := t.pathfinder._getPath(tr.dest); path != nil {
			pt := &pathTraffic{
				path:        path,
				baseTraffic: tr.baseTraffic,
			}
			t.pathfinder.handlePathTraffic(nil, pt)
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
	label.rootSeq = t.self.seq
	label.destSeq = uint64(time.Now().Unix())
	for _, hop := range t.self.hops {
		label.path = append(label.path, hop.port)
	}
	label.path = append(label.path, 0)
	label.sig = t.core.crypto.privateKey.sign(label.bytesForSig())
	return label
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
	sig     signature
	key     publicKey
	root    publicKey
	rootSeq uint64
	destSeq uint64
	path    []peerPort
}

func (l *treeLabel) bytesForSig() []byte {
	var bs []byte
	bs = append(bs, l.root[:]...)
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, l.rootSeq)
	bs = append(bs, seq...)
	binary.BigEndian.PutUint64(seq, l.destSeq)
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
	out = append(out, l.bytesForSig()...)
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
		tmp.rootSeq = binary.BigEndian.Uint64(data[:8])
		data = data[8:]
	}
	if len(data) < 8 {
		return wireDecodeError
	} else {
		tmp.destSeq = binary.BigEndian.Uint64(data[:8])
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
	peer  *peer
	time  time.Time
	timer *time.Timer // time.AfterFunc to clean up after timeout, stop this on teardown
}

/****************
 * dhtBootstrap *
 ****************/

type dhtBootstrap struct {
	sig signature
	key publicKey
	seq uint64
	bhs []bootstrapHopSig
}

type bootstrapHopSig struct {
	key publicKey
	sig signature
}

func (dbs *dhtBootstrap) bytesForSig() []byte {
	const size = len(dbs.key) + 8
	bs := make([]byte, 0, size)
	bs = append(bs, dbs.key[:]...)
	bs = bs[:size]
	binary.BigEndian.PutUint64(bs[len(bs)-8:], dbs.seq)
	return bs
}

func (dbs *dhtBootstrap) check() bool {
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

func (dbs *dhtBootstrap) encode(out []byte) ([]byte, error) {
	out = append(out, dbs.sig[:]...)
	out = append(out, dbs.bytesForSig()...)
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
	} else if len(data) < 8 { // TODO? < 16, in case it's embedded in something?
		return wireDecodeError
	}
	tmp.seq = binary.BigEndian.Uint64(data[:8])
	data = data[8:]
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
