package network

import (
	crand "crypto/rand"
	"encoding/binary"
	"time"

	//"fmt"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

/***********
 * router *
 ***********/

/*

TODO: Testing
  The merkle tree logic hasn't been very thoroughly tested yet.
    In particular, when responding to a request, we skip over parts of the tree with only 1 non-empty child node.
    That logic is a bit delicate... some fuzz testing would probably be nice.
  Also need to test how expired node infos are handled.
    We mark an info as expired, and ignore it in lookups etc., after it times out.
    We don't delete the info until after 2 timeout periods.
    The intent is that this gives us some time to let all nodes mark the info as timed out, so we stop sending it as part of the merkle tree updates.
    Otherwise, info could hit a live-lock scenario where nothing ever expired in a dynamic enough network.
    However, that leads to issues with nodes disconnecting/reconnecting, and retting their sequence number.
    To combat this, if we decline an update but see that our local info is expired (and not equivalent to the update we saw), then we send back an announce for it.
    The intent is for this announce to travel back to the corresponding node, so they can quickly update their seq (if needed).
    Sending back an announce is a delicate matter -- if nodes disagree on what announcement is "better", then they can infinitely spam eachother.
    This means we need to be very sure the CRDT conflict resolution logic is eventually consistent.
  The max network size logic could use some futher testing.

TODO: Mostly ignore the above
  In the middle of rewriting things to not keep a full view of the network.
  Need to:
    Store a merkle tree per peer
    Fill the tree with our nodes ancestry + the peer's ancestry
    Don't store info that isn't needed for either
      Slightly subtle, we receive things from the merkle trees in no particular order, so it may not be clear that it's ancestry info for some node until much later.
      So we need to be careful about when we *delete* info, though if we don't (and just let it time out) then this doesn't really break anything, it's just a waste / opens the door to OOM issues (if a node spams irrelevant info -- though at least we don't forward it if they do).
      If we *did* delete things immediately when they're not seen to be important, then we would at least learn the peer's info when we sync merkle trees. Then the peer's parent. Then the parent's parent, etc., so it would finish eventually, it's just wasteful. But that suggets we could set a short timeout for anything not important (e.g. 1 minute) or delete a random not-important thing if the store becomes too full.
    Sync merkle trees with peers... somehow.
      Sending a request and our own root whenever we change anything at all would, technically, be sufficient I think... just wasteful.
      FIXME: yes, it spams like crazy because new info launches another merkle tree sync in paralllel with the existing one(s)

OK, now most of the above is irrelevant anyway, we're just using soft state and tracking what we've already sent to reduce spamming

TODO: we need a way to detect if a peer changes the coords they advertise to us, we should require that they stay fixed (disconnect the peer if it happens?)

TODO: we do need to bring back some way to limit memory use... we don't forward things that aren't important, but we'd happily accept everything until we OOM, so that's not great for public nodes (we should either stop accepting anything until traffic things time out, TOFU, drop "worst", or something...)

TODO: when our path to the root flaps, we should try to switch to a more stable path
  Consider the whole path, not just the parent
  We probably need to track peer ancestry and record when they change. "When" meaning we sequence number it.

FIXME Potential showstopping issue:
  Greedy routing using coords is fundamentally insecure.
    Nothing prevents a node from advertising the same port number to two different children.
    Everything downstream of the attacker is at risk of random blackholes etc.
    This costs the attacker essentially nothing.
  Workaround: use full keys.
    That obviously won't work for normal traffic -- it's too much info.
    It *may* work for protocol traffic, so we can use it for pathfinding.
    We could then e.g. build a source route along the way, and use the source route... if we can do that securely...
    Added benefit, we do expect source routing to be more stable in the face of tree flapping...
  Obvious issues with ygg v0.4 style source routing... alternatives?
    Detect if we've visited the same node before so we can drop traffic? How?
      Bloom filter would work, except for the issue of false positives...
      If we store a reverse route, we could send back an error, so the sender can resize the bloom filter... Seems messy...

*/

type router struct {
	phony.Inbox
	core       *core
	pathfinder pathfinder                           // see pathfinder.go
	blooms     blooms                               // see bloomfilter.go
	peers      map[publicKey]map[*peer]struct{}     // True if we're allowed to send a mirror to this peer (but have not done so already)
	sent       map[publicKey]map[publicKey]struct{} // tracks which info we've sent to our peer
	ports      map[peerPort]publicKey               // used in tree lookups
	infos      map[publicKey]routerInfo
	timers     map[publicKey]*time.Timer
	ancs       map[publicKey][]publicKey // Peer ancestry info
	ancSeqs    map[publicKey]uint64
	ancSeqCtr  uint64
	cache      map[publicKey][]peerPort // Cache path slice for each peer
	requests   map[publicKey]routerSigReq
	responses  map[publicKey]routerSigRes
	resSeqs    map[publicKey]uint64
	resSeqCtr  uint64
	refresh    bool
	doRoot1    bool
	doRoot2    bool
	mainTimer  *time.Timer
}

func (r *router) init(c *core) {
	r.core = c
	r.pathfinder.init(r)
	r.blooms.init(r)
	r.peers = make(map[publicKey]map[*peer]struct{})
	r.sent = make(map[publicKey]map[publicKey]struct{})
	r.ports = make(map[peerPort]publicKey)
	r.infos = make(map[publicKey]routerInfo)
	r.timers = make(map[publicKey]*time.Timer)
	r.ancs = make(map[publicKey][]publicKey)
	r.ancSeqs = make(map[publicKey]uint64)
	r.cache = make(map[publicKey][]peerPort)
	r.requests = make(map[publicKey]routerSigReq)
	r.responses = make(map[publicKey]routerSigRes)
	r.resSeqs = make(map[publicKey]uint64)
	// Kick off actor to do initial work / become root
	r.mainTimer = time.AfterFunc(time.Second, func() {
		r.Act(nil, r._doMaintenance)
	})
	r.doRoot2 = true
	r.Act(nil, r._doMaintenance)
}

func (r *router) _doMaintenance() {
	if r.mainTimer == nil {
		return
	}
	r.doRoot2 = r.doRoot2 || r.doRoot1
	r._resetCache() // Resets path caches, since that info may no longer be good, TODO don't wait for maintenance to do this
	r._updateAncestries()
	r._fix()           // Selects new parent, if needed
	r._sendAnnounces() // Sends announcements to peers, if needed
	r.blooms._doMaintenance()
	r.mainTimer.Reset(time.Second)
}

func (r *router) _shutdown() {
	if r.mainTimer != nil {
		r.mainTimer.Stop()
		r.mainTimer = nil
	}
	// TODO clean up pathfinder etc...
	//  There's a lot more to do here
}

func (r *router) _resetCache() {
	for k := range r.cache {
		delete(r.cache, k)
	}
}

func (r *router) addPeer(from phony.Actor, p *peer) {
	r.Act(from, func() {
		//r._resetCache()
		if _, isIn := r.peers[p.key]; !isIn {
			r.peers[p.key] = make(map[*peer]struct{})
			r.sent[p.key] = make(map[publicKey]struct{})
			r.ports[p.port] = p.key
			r.ancSeqs[p.key] = r.ancSeqCtr
			r.blooms._addInfo(p.key)
		} else {
			// Send anything we've already sent over previous peer connections to this node
			for k := range r.sent[p.key] {
				if info, isIn := r.infos[k]; isIn {
					p.sendAnnounce(r, info.getAnnounce(k))
				} else {
					panic("this should never happen")
				}
			}
		}
		r.peers[p.key][p] = struct{}{}
		if _, isIn := r.responses[p.key]; !isIn {
			if _, isIn := r.requests[p.key]; !isIn {
				r.requests[p.key] = *r._newReq()
			}
			req := r.requests[p.key]
			p.sendSigReq(r, &req)
		}
		r.blooms._sendBloom(p)
	})
}

func (r *router) removePeer(from phony.Actor, p *peer) {
	r.Act(from, func() {
		//r._resetCache()
		ps := r.peers[p.key]
		delete(ps, p)
		if len(ps) == 0 {
			delete(r.peers, p.key)
			delete(r.sent, p.key)
			delete(r.ports, p.port)
			delete(r.requests, p.key)
			delete(r.responses, p.key)
			delete(r.resSeqs, p.key)
			delete(r.ancs, p.key)
			delete(r.ancSeqs, p.key)
			delete(r.cache, p.key)
			r.blooms._removeInfo(p.key)
			//r._fix()
		} else {
			// The bloom the remote node is tracking could be wrong due to a race
			// TODO? don't send it immediately, reset the "sent" state to blank so we'll resend next maintenance period
			for p := range ps {
				r.blooms._sendBloom(p)
			}
		}
	})
}

func (r *router) _clearReqs() {
	for k := range r.requests {
		delete(r.requests, k)
	}
	for k := range r.responses {
		delete(r.responses, k)
	}
	for k := range r.resSeqs {
		delete(r.resSeqs, k)
	}
	r.resSeqCtr = 0
}

func (r *router) _sendReqs() {
	r._clearReqs()
	for pk, ps := range r.peers {
		req := r._newReq()
		r.requests[pk] = *req
		for p := range ps {
			p.sendSigReq(r, req)
		}
	}
}

func (r *router) _updateAncestries() {
	r.ancSeqCtr++
	for pkey := range r.peers {
		anc := r._getAncestry(pkey)
		old := r.ancs[pkey]
		var diff bool
		if len(anc) != len(old) {
			diff = true
		} else {
			for idx := range anc {
				if anc[idx] != old[idx] {
					diff = true
					break
				}
			}
		}
		if diff {
			r.ancs[pkey] = anc
			r.ancSeqs[pkey] = r.ancSeqCtr
		}
	}
}

func (r *router) _fix() {
	bestRoot := r.core.crypto.publicKey
	bestParent := r.core.crypto.publicKey
	self := r.infos[r.core.crypto.publicKey]
	// Check if our current parent leads to a better root than ourself
	if _, isIn := r.peers[self.parent]; isIn {
		root, _ := r._getRootAndDists(r.core.crypto.publicKey)
		if root.less(bestRoot) {
			bestRoot, bestParent = root, self.parent
		}
	}
	// Check if we know a better root/parent
	for pk := range r.responses {
		if _, isIn := r.infos[pk]; !isIn {
			// We don't know where this peer is
			continue
		}
		pRoot, pDists := r._getRootAndDists(pk)
		if _, isIn := pDists[r.core.crypto.publicKey]; isIn {
			// This would loop through us already
			continue
		}
		if pRoot.less(bestRoot) {
			bestRoot, bestParent = pRoot, pk
		} else if pRoot != bestRoot {
			continue // wrong root
		}
		if r.ancSeqs[pk] < r.ancSeqs[bestParent] {
			// This node is advertising a more stable path, so we should probably switch to it...
			bestRoot, bestParent = pRoot, pk
		} else if r.ancSeqs[pk] != r.ancSeqs[bestParent] {
			continue // less stable path
		}
		// TODO? Update parents even if the old one works, if the new one is "better"
		//  But it has to be by a lot, stability is high priority (affects all downstream nodes)
		//  For now, if we're forced to select a new parent, then choose the "best" one
		//  Otherwise, just always keep the current parent if possible
		if /* r.refresh  || */ bestParent != self.parent {
			if pRoot == bestRoot && r.resSeqs[pk] < r.resSeqs[bestParent] {
				bestRoot, bestParent = pRoot, pk
			}
		}
	}
	if r.refresh || r.doRoot1 || r.doRoot2 || self.parent != bestParent {
		res, isIn := r.responses[bestParent]
		switch {
		case isIn && bestRoot != r.core.crypto.publicKey: // && t._useResponse(bestParent, &res):
			// Somebody else should be root
			if !r._useResponse(bestParent, &res) {
				panic("this should never happen")
			}
			r.refresh = false
			r.doRoot1 = false
			r.doRoot2 = false // TODO panic to check that this was already false
			r._sendReqs()
		case r.doRoot2:
			// Become root
			if !r._becomeRoot() {
				panic("this should never happen")
			}
			/*
				self = r.infos[r.core.crypto.publicKey]
				ann := self.getAnnounce(r.core.crypto.publicKey)
				for _, ps := range r.peers {
					for p := range ps {
						p.sendAnnounce(r, ann)
					}
				}
			*/
			r.refresh = false
			r.doRoot1 = false
			r.doRoot2 = false
			r._sendReqs()
		case !r.doRoot1:
			r.doRoot1 = true
			// No need to sendReqs in this case
			//  either we already have a req, or we've already requested one
			//  so resetting and re-requesting is just a waste of bandwidth
		default:
			// We need to self-root, but we already started a timer to do that later
			// So this is a no-op
		}
	}
}

func (r *router) _sendAnnounces() {
	// This is insanely delicate, lots of correctness is implicit across how nodes behave
	// Change nothing here.
	selfAnc := r._getAncestry(r.core.crypto.publicKey)
	var toSend []publicKey
	var anns []*routerAnnounce

	for peerKey, sent := range r.sent {
		// Initial setup stuff
		toSend = toSend[:0]
		anns = anns[:0]
		peerAnc := r._getAncestry(peerKey)

		// Get whatever we haven't sent from selfAnc
		for _, k := range selfAnc {
			if _, isIn := sent[k]; !isIn {
				toSend = append(toSend, k)
				sent[k] = struct{}{}
			}
		}

		// Get whatever we haven't sent from peerAnc
		for _, k := range peerAnc {
			if _, isIn := sent[k]; !isIn {
				toSend = append(toSend, k)
				sent[k] = struct{}{}
			}
		}

		/*
			// Reset sent so it only contains the ancestry info
			for k := range sent {
				delete(sent, k)
			}
			for _, k := range selfAnc {
				sent[k] = struct{}{}
			}
			for _, k := range peerAnc {
				sent[k] = struct{}{}
			}
		*/

		// Now prepare announcements
		for _, k := range toSend {
			if info, isIn := r.infos[k]; isIn {
				anns = append(anns, info.getAnnounce(k))
			} else {
				panic("this should never happen")
			}
		}

		// Send announcements
		for p := range r.peers[peerKey] {
			for _, ann := range anns {
				p.sendAnnounce(r, ann)
			}
		}
	}
}

func (r *router) _newReq() *routerSigReq {
	var req routerSigReq
	nonce := make([]byte, 8)
	crand.Read(nonce) // If there's an error, there's not much to do...
	req.nonce = binary.BigEndian.Uint64(nonce)
	req.seq = r.infos[r.core.crypto.publicKey].seq + 1
	return &req
}

func (r *router) _becomeRoot() bool {
	req := r._newReq()
	res := routerSigRes{
		routerSigReq: *req,
		port:         0, // TODO? something sane?
	}
	res.psig = r.core.crypto.privateKey.sign(res.bytesForSig(r.core.crypto.publicKey, r.core.crypto.publicKey))
	ann := routerAnnounce{
		key:          r.core.crypto.publicKey,
		parent:       r.core.crypto.publicKey,
		routerSigRes: res,
		sig:          res.psig,
	}
	if !ann.check() {
		panic("this should never happen")
	}
	return r._update(&ann)
}

func (r *router) _handleRequest(p *peer, req *routerSigReq) {
	res := routerSigRes{
		routerSigReq: *req,
		port:         p.port,
	}
	res.psig = r.core.crypto.privateKey.sign(res.bytesForSig(p.key, r.core.crypto.publicKey))
	p.sendSigRes(r, &res)
}

func (r *router) handleRequest(from phony.Actor, p *peer, req *routerSigReq) {
	r.Act(from, func() {
		r._handleRequest(p, req)
	})
}

func (r *router) _handleResponse(p *peer, res *routerSigRes) {
	if _, isIn := r.responses[p.key]; !isIn && r.requests[p.key] == res.routerSigReq {
		r.resSeqCtr++
		r.resSeqs[p.key] = r.resSeqCtr
		r.responses[p.key] = *res
		//r._fix() // This could become our new parent
	}
}

func (r *router) _useResponse(peerKey publicKey, res *routerSigRes) bool {
	bs := res.bytesForSig(r.core.crypto.publicKey, peerKey)
	info := routerInfo{
		parent:       peerKey,
		routerSigRes: *res,
		sig:          r.core.crypto.privateKey.sign(bs),
	}
	ann := info.getAnnounce(r.core.crypto.publicKey)
	if r._update(ann) {
		/*
			for _, ps := range r.peers {
				for p := range ps {
					p.sendAnnounce(r, ann)
				}
			}
		*/
		return true
	}
	return false
}

func (r *router) handleResponse(from phony.Actor, p *peer, res *routerSigRes) {
	r.Act(from, func() {
		r._handleResponse(p, res)
	})
}

func (r *router) _update(ann *routerAnnounce) bool {
	if info, isIn := r.infos[ann.key]; isIn {
		switch {
		// Note: This logic *must* be the same on every node
		// If that's not true, then peers can infinitely spam announcements at each other for expired infos
		/*********************************
		 * XXX *** DO NOT CHANGE *** XXX *
		 *********************************/
		case info.seq > ann.seq:
			// This is an old seq, so exit
			return false
		case info.seq < ann.seq:
			// This is a newer seq, so don't exit
		case info.parent.less(ann.parent):
			// same seq, worse (higher) parent
			return false
		case ann.parent.less(info.parent):
			// same seq, better (lower) parent, so don't exit
		case ann.nonce < info.nonce:
			// same seq and parent, lower nonce, so don't exit
		default:
			// same seq and parent, same or worse nonce, so exit
			return false
		}
	}
	// Clean up sent info and cache
	for _, sent := range r.sent {
		delete(sent, ann.key)
	}
	r._resetCache()
	// Save info
	info := routerInfo{
		parent:       ann.parent,
		routerSigRes: ann.routerSigRes,
		sig:          ann.sig,
	}
	key := ann.key
	var timer *time.Timer
	if key == r.core.crypto.publicKey {
		delay := r.core.config.routerRefresh // TODO? slightly randomize
		timer = time.AfterFunc(delay, func() {
			r.Act(nil, func() {
				if r.timers[key] == timer {
					r.refresh = true
					//r._fix()
				}
			})
		})
	} else {
		timer = time.AfterFunc(r.core.config.routerTimeout, func() {
			r.Act(nil, func() {
				if r.timers[key] == timer {
					timer.Stop() // Shouldn't matter, but just to be safe...
					delete(r.infos, key)
					delete(r.timers, key)
					for _, sent := range r.sent {
						delete(sent, key)
					}
					r._resetCache()
					//r._fix()
				}
			})
		})
	}
	if oldTimer, isIn := r.timers[key]; isIn {
		oldTimer.Stop()
	}
	r.timers[ann.key] = timer
	r.infos[ann.key] = info
	return true
}

func (r *router) _handleAnnounce(p *peer, ann *routerAnnounce) {
	if r._update(ann) {
		if ann.key == r.core.crypto.publicKey {
			// We just updated our own info from a message we received by a peer
			// That suggests we went offline, so our seq reset when we came back
			// The info they sent us could have been expired (see below in this function)
			// So we need to set that an update is required, as if our refresh timer has passed
			r.refresh = true
		}
		//r._fix() // This could require us to change parents
	} else {
		// We didn't accept the info, because we alerady know it or something better
		// TODO we didn't accept the ann, why did they send it?
		// Do we need to do anything to make sure we're consistent?
		info := routerInfo{
			parent:       ann.parent,
			routerSigRes: ann.routerSigRes,
			sig:          ann.sig,
		}
		if oldInfo := r.infos[ann.key]; info != oldInfo {
			// They sent something, but it was worse
			// We should tell them what we know
			// Only to the p that sent it, since we'll spam the rest as messages arrive
			p.sendAnnounce(r, oldInfo.getAnnounce(ann.key))
		}
	}
}

func (r *router) handleAnnounce(from phony.Actor, p *peer, ann *routerAnnounce) {
	r.Act(from, func() {
		r._handleAnnounce(p, ann)
	})
}

func (r *router) sendTraffic(tr *traffic) {
	// This must be non-blocking, to prevent deadlocks between read/write paths in the encrypted package
	// Basically, WriteTo and ReadFrom can't be allowed to block each other, but they could if we allowed backpressure here
	// There may be a better way to handle this, but it practice it probably won't be an issue (we'll throw the packet in a queue somewhere, or drop it)
	r.Act(nil, func() {
		r.pathfinder._handleTraffic(tr)
	})
}

func (r *router) handleTraffic(from phony.Actor, tr *traffic) {
	r.Act(from, func() {
		if p := r._lookup(tr); p != nil {
			p.sendTraffic(r, tr)
		} else if tr.dest == r.core.crypto.publicKey {
			r.core.pconn.handleTraffic(r, tr)
		} else {
			// Not addressed to us, and we don't know a next hop.
			// The path is broken, so do something about that.
			r.pathfinder._doBroken(tr)
		}
	})
}

func (r *router) _keyLookup(dest publicKey) publicKey {
	// Returns the key that's the closest match to the destination publicKey
	if _, isIn := r.infos[dest]; !isIn {
		// Switch dest to the closest known key, so out-of-band stuff works
		// This would be a hack to make the example code run without modification
		// Long term, TODO remove out-of-band stuff, provide a function to simply look up the closest known node for a given key
		var lowest *publicKey
		var best *publicKey
		for key := range r.infos {
			if lowest == nil || key.less(*lowest) {
				k := key
				lowest = &k
			}
			if best == nil && key.less(dest) {
				k := key
				best = &k
			}
			if key.less(dest) && best.less(key) {
				k := key
				best = &k
			}
		}
		if best == nil {
			best = lowest
		}
		if best == nil {
			//return nil
		} else {
			dest = *best
		}
	}
	return dest
}

func (r *router) _getRootAndDists(dest publicKey) (publicKey, map[publicKey]uint64) {
	// This returns the distances from the destination's root for the destination and each of its ancestors
	// Note that we skip any expired infos
	dists := make(map[publicKey]uint64)
	next := dest
	var root publicKey
	var dist uint64
	for {
		if _, isIn := dists[next]; isIn {
			break
		}
		if info, isIn := r.infos[next]; isIn {
			root = next
			dists[next] = dist
			dist++
			next = info.parent
		} else {
			break
		}
	}
	return root, dists
}

func (r *router) _getRootAndPath(dest publicKey) (publicKey, []peerPort) {
	var ports []peerPort
	visited := make(map[publicKey]struct{})
	var root publicKey
	next := dest
	for {
		if _, isIn := visited[next]; isIn {
			// We hit a loop
			return dest, nil
		}
		if info, isIn := r.infos[next]; isIn {
			root = next
			visited[next] = struct{}{}
			if next == info.parent {
				// We reached a root, don't append the self port (it should be zero anyway)
				break
			}
			ports = append(ports, info.port)
			next = info.parent
		} else {
			// We hit a dead end
			return dest, nil
		}
	}
	// Reverse order, since we built this from the node to the root
	for left, right := 0, len(ports)-1; left < right; left, right = left+1, right-1 {
		ports[left], ports[right] = ports[right], ports[left]
	}
	return root, ports
}

func (r *router) _getDist(destPath []peerPort, key publicKey) uint64 {
	// We cache the keyPath to avoid allocating slices for every lookup
	var keyPath []peerPort
	if cached, isIn := r.cache[key]; isIn {
		keyPath = cached
	} else {
		_, keyPath = r._getRootAndPath(key)
		r.cache[key] = keyPath
	}
	end := len(destPath)
	if len(keyPath) < end {
		end = len(keyPath)
	}
	dist := uint64(len(keyPath) + len(destPath))
	for idx := 0; idx < end; idx++ {
		if keyPath[idx] == destPath[idx] {
			dist -= 2
		} else {
			break
		}
	}
	return dist
}

func (r *router) _lookup(tr *traffic) *peer {
	// Look up the next hop (in treespace) towards the destination
	var bestPeer *peer
	bestDist := ^uint64(0)
	if dist := r._getDist(tr.path, r.core.crypto.publicKey); dist < tr.watermark {
		bestDist = dist // Self dist, so other nodes must be strictly better by distance
		tr.watermark = dist
	} else {
		return nil
	}
	for k, ps := range r.peers {
		if dist := r._getDist(tr.path, k); dist < bestDist {
			for p := range ps {
				switch {
				case bestPeer != nil && p.prio > bestPeer.prio:
					// Skip worse priority links
					continue
				case bestPeer != nil && p.time.After(bestPeer.time):
					// Skip links that have been up for less time
					continue
				default:
					bestPeer = p
				}
			}
			bestDist = dist
		}
	}

	return bestPeer
}

func (r *router) _getAncestry(key publicKey) []publicKey {
	// Returns the ancestry starting with the root side, ordering is important for how we send over the network / GC info...
	anc := r._backwardsAncestry(key)
	for left, right := 0, len(anc)-1; left < right; left, right = left+1, right-1 {
		anc[left], anc[right] = anc[right], anc[left]
	}
	return anc
}

func (r *router) _backwardsAncestry(key publicKey) []publicKey {
	// Return an ordered list of node ancestry, starting with the given key and ending at the root (or the end of the line)
	var anc []publicKey
	here := key
	for {
		// TODO? use a map or something to check visited nodes faster?
		for _, k := range anc {
			if k == here {
				return anc
			}
		}
		if info, isIn := r.infos[here]; isIn {
			anc = append(anc, here)
			here = info.parent
			continue
		}
		// Dead end
		return anc
	}
}

/*****************
 * routerSigReq *
 *****************/

type routerSigReq struct {
	seq   uint64
	nonce uint64
}

func (req *routerSigReq) bytesForSig(node, parent publicKey) []byte {
	out := make([]byte, 0, publicKeySize*2+8+8)
	out = append(out, node[:]...)
	out = append(out, parent[:]...)
	out, _ = req.encode(out)
	return out
}

func (req *routerSigReq) size() int {
	size := wireSizeUint(req.seq)
	size += wireSizeUint(req.nonce)
	return size
}

func (req *routerSigReq) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendUint(out, req.seq)
	out = wireAppendUint(out, req.nonce)
	end := len(out)
	if end-start != req.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (req *routerSigReq) chop(data *[]byte) error {
	var tmp routerSigReq
	orig := *data
	if !wireChopUint(&tmp.seq, &orig) {
		return types.ErrDecode
	} else if !wireChopUint(&tmp.nonce, &orig) {
		return types.ErrDecode
	}
	*req = tmp
	*data = orig
	return nil
}

func (req *routerSigReq) decode(data []byte) error {
	var tmp routerSigReq
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return types.ErrDecode
	}
	*req = tmp
	return nil
}

/*****************
 * routerSigRes *
 *****************/

type routerSigRes struct {
	routerSigReq
	port peerPort
	psig signature
}

func (res *routerSigRes) check(node, parent publicKey) bool {
	bs := res.bytesForSig(node, parent)
	return parent.verify(bs, &res.psig)
}

func (res *routerSigRes) bytesForSig(node, parent publicKey) []byte {
	bs := res.routerSigReq.bytesForSig(node, parent)
	bs = wireAppendUint(bs, uint64(res.port))
	return bs
}

func (res *routerSigRes) size() int {
	size := res.routerSigReq.size()
	size += wireSizeUint(uint64(res.port))
	size += len(res.psig)
	return size
}

func (res *routerSigRes) encode(out []byte) ([]byte, error) {
	start := len(out)
	var err error
	out, err = res.routerSigReq.encode(out)
	if err != nil {
		return nil, err
	}
	out = wireAppendUint(out, uint64(res.port))
	out = append(out, res.psig[:]...)
	end := len(out)
	if end-start != res.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (res *routerSigRes) chop(data *[]byte) error {
	orig := *data
	var tmp routerSigRes
	if err := tmp.routerSigReq.chop(&orig); err != nil {
		return err
	} else if !wireChopUint((*uint64)(&tmp.port), &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.psig[:], &orig) {
		return types.ErrDecode
	}
	*res = tmp
	*data = orig
	return nil
}

func (res *routerSigRes) decode(data []byte) error {
	var tmp routerSigRes
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return types.ErrDecode
	}
	*res = tmp
	return nil
}

/*******************
 * routerAnnounce *
 *******************/

type routerAnnounce struct {
	key    publicKey
	parent publicKey
	routerSigRes
	sig signature
}

func (ann *routerAnnounce) check() bool {
	if ann.port == 0 && ann.key != ann.parent {
		return false
	}
	bs := ann.bytesForSig(ann.key, ann.parent)
	return ann.key.verify(bs, &ann.sig) && ann.parent.verify(bs, &ann.psig)
}

func (ann *routerAnnounce) size() int {
	size := len(ann.key)
	size += len(ann.parent)
	size += ann.routerSigRes.size()
	size += len(ann.sig)
	return size
}

func (ann *routerAnnounce) encode(out []byte) ([]byte, error) {
	start := len(out)
	var err error
	out = append(out, ann.key[:]...)
	out = append(out, ann.parent[:]...)
	out, err = ann.routerSigRes.encode(out)
	if err != nil {
		return nil, err
	}
	out = append(out, ann.sig[:]...)
	end := len(out)
	if end-start != ann.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (ann *routerAnnounce) decode(data []byte) error {
	var tmp routerAnnounce
	if !wireChopSlice(tmp.key[:], &data) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.parent[:], &data) {
		return types.ErrDecode
	} else if err := tmp.routerSigRes.chop(&data); err != nil {
		return err
	} else if !wireChopSlice(tmp.sig[:], &data) {
		return types.ErrDecode
	} else if len(data) != 0 {
		return types.ErrDecode
	}
	*ann = tmp
	return nil
}

/***************
 * routerInfo *
 ***************/

// This is the value stored in a key,value map

type routerInfo struct {
	parent publicKey
	routerSigRes
	sig signature
}

func (info *routerInfo) getAnnounce(key publicKey) *routerAnnounce {
	return &routerAnnounce{
		key:          key,
		parent:       info.parent,
		routerSigRes: info.routerSigRes,
		sig:          info.sig,
	}
}

/****************
 * routerForget *
 ****************/

type routerForget struct {
	routerAnnounce
}
