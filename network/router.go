package network

import (
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"time"

	//"fmt"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/network/internal/merkletree"
)

/***********
 * router *
 ***********/

// TODO if we stay soft state and no DHT, then implement some kind of fisheye update logic? No need to immediately send info that we can prove won't affect other node's next-hop calculations (and isn't needed to avoid timeouts)
//  We really do need something like the above
//  Then we send updates relatively frequently, and let the fisheye logic throttle things
//  Since watermarks prevent routing loops, we can do a few things:
//    1. Forward updates from our ancestry immediately (but maybe not from our descendants)
//      Nodes will know their own location in the tree, and that of their peers, with relatively good accuracy
//      Other info doesn't need to be perfectly accurate for routing to (usually) work
//    2. Don't send any info upon peer connection, only in response to receiving an update
//      We'll learn our local neighborhood quickly, due to fisheye logic, and learn remote nodes at some later point
//      Not ideal, but it means it's useful for local stuff (almost) immediately at least...
//      This prevents outdated info from being kept alive indefinitely in a highly dynamic network
//    3. Set timeouts independently per node info, based on how often we expect to hear updates
//  This begs the question of what the fisheye logic should look like...
//    Note: only forwarding updates along parent/child relationships gives us causal messaging (in stable networks at least), simplifies some things...
//    E.g. we could forward along the tree, and only forward every 2nd update for non-ancestor updates...
//    May run into some bootstrap problems?... Can't join the tree if we don't already have a parent... can't pick a parent without knowing the tree...

// TODO alternatively, we don't fisheye things:
//  1. Send a full view when needed, and just live with things potentially hanging around the network indefinitely in highly dynamic networks
//  2. Don't proactively send a full view, let the remote side ask for a merkel tree root (or proactively send just that much) and navigate the tree to find differences
//  On the plus side, merkel tree logic is needed if/when we switch to hard state, so it would be useful to have anyway...

// In place of the above, we now request a mirror of the remote node's network, and they could decline to respond if they wanted to
//  TODO: come up with some logic to determine when we should request
//  TODO Also, it probably makes sense to export some logic to make requsts denyable on a per peer object (network link) basis, to e.g. only do a full mirror over ethernet and wifi, never over data (don't request or reply to requests on forbidden links)

// TODO allow for some kind of application-configurable limit on the number of nodes we keep track of, for OOM/DoS mitigation
//  Only keep track of the X closest nodes to you (in the tree), or something like that
//    Not as easy as it sounds, naively doing this leads to nodes infinitely spamming updates at each other
//  Probably give exceptional priority to ancestors and the ancestry of your peers, so you can still route locally
//    Or don't, and make you pick the best root from the split part of the network?...
//  This is just a temporary stopgap to prevent OOM from node flooding attacks, until a good DHT can be designed and implemented
//  A very dumb TOFU version of this is currently in place, but it's probably not a good solution for real world usage
//  EDIT: not anymore, now we keep track of the lowest keys (plus ourself), so it's at least deterministic...

type routerCacheInfo struct {
	peer *peer
	dist uint64
}

type router struct {
	phony.Inbox
	core      *core
	merk      merkletree.Tree
	peers     map[publicKey]map[*peer]struct{} // True if we're allowed to send a mirror to this peer (but have not done so already)
	infos     map[publicKey]routerInfo
	timers    map[publicKey]*time.Timer
	cache     map[publicKey]routerCacheInfo // Cache of next hop for each destination
	requests  map[publicKey]routerSigReq
	responses map[publicKey]routerSigRes
	resSeqs   map[publicKey]uint64
	resSeqCtr uint64
	refresh   bool
	doRoot1   bool
	doRoot2   bool
	fixTimer  *time.Timer
}

func (r *router) init(c *core) {
	r.core = c
	r.peers = make(map[publicKey]map[*peer]struct{})
	r.infos = make(map[publicKey]routerInfo)
	r.timers = make(map[publicKey]*time.Timer)
	r.cache = make(map[publicKey]routerCacheInfo)
	r.requests = make(map[publicKey]routerSigReq)
	r.responses = make(map[publicKey]routerSigRes)
	r.resSeqs = make(map[publicKey]uint64)
	r.fixTimer = time.AfterFunc(0, func() {})
	// Kick off actor to do initial work / become root
	r.Act(nil, r._fix)
}

func (r *router) _shutdown() {} // TODO cleanup (stop any timers etc)

func (r *router) _resetCache() {
	for k := range r.cache {
		delete(r.cache, k)
	}
}

func (r *router) addPeer(from phony.Actor, p *peer) {
	r.Act(from, func() {
		r._resetCache()
		if _, isIn := r.peers[p.key]; !isIn {
			r.peers[p.key] = make(map[*peer]struct{})
		}
		// TODO? In some cases, should this be false? Depending on the link type maybe?
		r.peers[p.key][p] = struct{}{}
		if _, isIn := r.responses[p.key]; !isIn {
			if _, isIn := r.requests[p.key]; !isIn {
				r.requests[p.key] = *r._newReq()
			}
			req := r.requests[p.key]
			p.sendSigReq(r, &req)
		}
		p.sendMerkleReq(r, new(routerMerkleReq))
	})
}

func (r *router) removePeer(from phony.Actor, p *peer) {
	r.Act(from, func() {
		r._resetCache()
		ps := r.peers[p.key]
		delete(ps, p)
		if len(ps) == 0 {
			delete(r.peers, p.key)
			delete(r.requests, p.key)
			delete(r.responses, p.key)
			delete(r.resSeqs, p.key)
			r._fix()
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
		}
		// TODO? switch to another parent (to the same root) if they're "better", at least sometimes
		if r.refresh || bestParent != self.parent {
			if pRoot == bestRoot && r.resSeqs[pk] < r.resSeqs[bestParent] {
				bestRoot, bestParent = pRoot, pk
			}
		}
	}
	if r.refresh || r.doRoot1 || r.doRoot2 || self.parent != bestParent {
		res, isIn := r.responses[bestParent] // FIXME only use if bestParent isIn t.responses!
		switch {
		case isIn && bestRoot != r.core.crypto.publicKey: // && t._useResponse(bestParent, &res):
			// Somebody else should be root
			if !r._useResponse(bestParent, &res) {
				panic("this should never happen")
			}
			r.fixTimer.Stop()
			r.refresh = false
			r.doRoot1 = false
			r.doRoot2 = false // TODO panic to check that this was already false
			r._sendReqs()
		case r.doRoot2:
			// Become root
			if !r._becomeRoot() {
				panic("this should never happen")
			}
			self = r.infos[r.core.crypto.publicKey]
			ann := self.getAnnounce(r.core.crypto.publicKey)
			for _, ps := range r.peers {
				for p := range ps {
					p.sendAnnounce(r, ann)
				}
			}
			r.refresh = false
			r.doRoot1 = false
			r.doRoot2 = false
			r.fixTimer.Stop()
			r._sendReqs()
		case !r.doRoot1:
			r.fixTimer = time.AfterFunc(time.Second, func() {
				r.Act(nil, func() {
					if r.doRoot1 {
						r.doRoot2 = true
						r._fix()
					}
				})
			})
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
	bs := req.bytesForSig(r.core.crypto.publicKey, r.core.crypto.publicKey)
	sig := r.core.crypto.privateKey.sign(bs)
	res := routerSigRes{*req, sig}
	ann := routerAnnounce{
		key:          r.core.crypto.publicKey,
		parent:       r.core.crypto.publicKey,
		routerSigRes: res,
		sig:          sig,
	}
	if !ann.check() {
		panic("this should never happen")
	}
	return r._update(&ann)
}

func (r *router) _handleRequest(p *peer, req *routerSigReq) {
	bs := req.bytesForSig(p.key, r.core.crypto.publicKey)
	sig := r.core.crypto.privateKey.sign(bs)
	res := routerSigRes{*req, sig}
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
		r._fix() // This could become our new parent
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
		for _, ps := range r.peers {
			for p := range ps {
				p.sendAnnounce(r, ann)
			}
		}
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
	r._resetCache()
	info := routerInfo{
		parent:       ann.parent,
		routerSigRes: ann.routerSigRes,
		sig:          ann.sig,
	}
	key := ann.key
	var timer *time.Timer
	if key == r.core.crypto.publicKey {
		delay := r.core.config.routerRefresh + time.Millisecond*time.Duration(mrand.Intn(1024))
		timer = time.AfterFunc(delay, func() {
			r.Act(nil, func() {
				if r.timers[key] == timer {
					r.refresh = true
					r._fix()
				}
			})
		})
	} else {
		timer = time.AfterFunc(r.core.config.routerTimeout, func() {
			r.Act(nil, func() {
				if r.timers[key] == timer {
					timer.Stop() // Shouldn't matter, but just to be safe...
					r.merk.Remove(merkletree.Key(key))
					delete(r.infos, key)
					delete(r.timers, key)
					r._resetCache()
					r._fix()
				}
			})
		})
	}
	if oldTimer, isIn := r.timers[key]; isIn {
		oldTimer.Stop()
	}
	bs, _ := ann.encode(nil)
	digest := merkletree.GetDigest(bs)
	r.merk.Add(merkletree.Key(key), digest)
	r.infos[key] = info
	r.timers[key] = timer
	return true
}

func (r *router) _handleAnnounce(sender *peer, ann *routerAnnounce) {
	var doUpdate bool
	var worst publicKey
	var found bool
	if len(r.infos) < int(r.core.config.routerMaxInfos) {
		// We're not at max capacity yet, so we have room to add more
		doUpdate = true
	} else if _, isIn := r.infos[ann.key]; isIn {
		// We're at capacity (or, somehow, above) but we alread know about this
		// Therefore, there's no harm in accepting the update (we can't force anything else out)
		// If this was or last check, then this is basically TOFU for the network
		doUpdate = true
	} else {
		// We're at or above capacity, and this is a new node
		// It may be "better" than something we already know about
		// We define better to mean lower key (so e.g. we all know the root)
		// We also special case or own info, to avoid timer problems
		for k := range r.infos {
			if k == r.core.crypto.publicKey {
				// Skip self
				continue
			}
			if !found || worst.less(k) {
				// This is the worst (non-self) node we've seen so far
				worst = k
				found = true
			}
		}
		if ann.key.less(worst) {
			// This means ann.key is better than some node we already know
			// We will try to _update, and remove the worst node if we do
			doUpdate = true
		}
	}
	if doUpdate && r._update(ann) {
		for _, ps := range r.peers {
			for p := range ps {
				if p == sender {
					continue
				}
				p.sendAnnounce(r, ann)
			}
		}
		if found {
			// Cleanup worst
			r.timers[worst].Stop()
			r.merk.Remove(merkletree.Key(worst))
			delete(r.infos, worst)
			delete(r.timers, worst)
			r._resetCache()
		}
		r._fix() // This could require us to change parents
	}
}

func (r *router) handleAnnounce(from phony.Actor, p *peer, ann *routerAnnounce) {
	r.Act(from, func() {
		r._handleAnnounce(p, ann)
	})
}

func (r *router) handleMerkleReq(from phony.Actor, p *peer, req *routerMerkleReq) {
	r.Act(from, func() {
		// TODO naviage futher if there's only 1 child, to speed things up, requires merkletree updates...
		// TODO send announcement if we're at the end and there's nothing left to look up...
		/*
			if digest := r.merk.Lookup(merkletree.Key(req.prefix), int(req.prefixLen)); digest != merkletree.Empty() {
				res := routerMerkleRes{*req, digest}
				p.sendMerkleRes(r, &res)
			}
		*/
		node, plen := r.merk.NodeFor(merkletree.Key(req.prefix), int(req.prefixLen))
		if uint64(plen) != req.prefixLen {
			// We don't know anyone from the part of the network we were asked about, so we can't respond in any useful way
			return
		}
		if true {
			// This is the "foolproof" but extra inefficient version of things
			res := new(routerMerkleRes)
			res.prefixLen = req.prefixLen
			res.prefix = req.prefix
			res.digest = node.Digest
			p.sendMerkleRes(r, res)
			if res.prefixLen == merkletree.KeyBits {
				if info, isIn := r.infos[res.prefix]; isIn {
					p.sendAnnounce(r, info.getAnnounce(res.prefix))
				} else {
					panic("this should never happen")
				}
			}
			return
		}
		// This is the slightly less inefficient but very delicate version of things
		// FIXME here be dragons
		prefixLen := req.prefixLen
		prefix := req.prefix
		for {
			if node.Left != nil && node.Right != nil {
				res := new(routerMerkleRes)
				res.prefixLen = prefixLen
				res.prefix = prefix
				res.digest = node.Digest
				p.sendMerkleRes(r, res)
			} else if node.Left != nil {
				offset := int(prefixLen)
				prefixLen += 1
				k := merkletree.Key(prefix)
				k.SetBit(false, offset)
				prefix = publicKey(k)
				node = node.Left
				continue
			} else if node.Right != nil {
				offset := int(prefixLen)
				prefixLen += 1
				k := merkletree.Key(prefix)
				k.SetBit(true, offset)
				prefix = publicKey(k)
				node = node.Right
				continue
			} else {
				if prefixLen != merkletree.KeyBits {
					panic("this should never happen")
				}
				if info, isIn := r.infos[prefix]; isIn {
					p.sendAnnounce(r, info.getAnnounce(prefix))
				} else {
					panic("this should never happen")
				}
			}
			break
		}
	})
}

func (r *router) handleMerkleRes(from phony.Actor, p *peer, res *routerMerkleRes) {
	r.Act(from, func() {
		if res.prefixLen == merkletree.KeyBits {
			// This is a response to a full key, we can't ask for children, and there's nothing useful to do with it right now.
			return
		}
		if digest := r.merk.Lookup(merkletree.Key(res.prefix), int(res.prefixLen)); digest != res.digest {
			// We disagree, so ask about the left and right children
			left := routerMerkleReq{
				prefixLen: res.prefixLen + 1,
				prefix:    publicKey(merkletree.GetLeft(merkletree.Key(res.prefix), int(res.prefixLen))),
			}
			if !left.check() {
				panic("this should never happen")
			}
			p.sendMerkleReq(r, &left)
			right := routerMerkleReq{
				prefixLen: res.prefixLen + 1,
				prefix:    publicKey(merkletree.GetRight(merkletree.Key(res.prefix), int(res.prefixLen))),
			}
			if !right.check() {
				panic("this should never happen")
			}
			p.sendMerkleReq(r, &right)
		}
	})
}

func (r *router) sendTraffic(tr *traffic) {
	// This must be non-blocking, to prevent deadlocks between read/write paths in the encrypted package
	// Basically, WriteTo and ReadFrom can't be allowed to block each other, but they could if we allowed backpressure here
	// There may be a better way to handle this, but it practice it probably won't be an issue (we'll throw the packet in a queue somewhere, or drop it)
	r.handleTraffic(nil, tr)
}

func (r *router) handleTraffic(from phony.Actor, tr *traffic) {
	r.Act(from, func() {
		if p := r._lookup(tr); p != nil {
			p.sendTraffic(r, tr)
		} else {
			r.core.pconn.handleTraffic(r, tr)
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

func (r *router) _getDist(dists map[publicKey]uint64, key publicKey) (uint64, bool) {
	var dist uint64
	visited := make(map[publicKey]struct{})
	visited[publicKey{}] = struct{}{}
	here := key
	for {
		if _, isIn := visited[here]; isIn {
			return 0, false
		}
		if d, isIn := dists[here]; isIn {
			return dist + d, true
		}
		dist++
		visited[here] = struct{}{}
		here = r.infos[here].parent
	}
}

func (r *router) _lookup(tr *traffic) *peer {
	if info, isIn := r.cache[tr.dest]; isIn {
		if info.dist < tr.watermark {
			tr.watermark = info.dist
			return info.peer
		} else {
			return nil
		}
	}
	if _, isIn := r.infos[tr.dest]; !isIn {
		return nil // If we want to restore DHT-like logic, it's mostly copy/paste from _keyLookup
	}
	// Look up the next hop (in treespace) towards the destination
	_, dists := r._getRootAndDists(tr.dest)
	var bestPeer *peer
	bestDist := ^uint64(0)
	if dist, ok := r._getDist(dists, r.core.crypto.publicKey); ok && dist < tr.watermark {
		bestDist = dist // Self dist, so other nodes must be strictly better by distance
		tr.watermark = dist
	} else {
		return nil
	}
	for k, ps := range r.peers {
		dist, ok := r._getDist(dists, k)
		if !ok {
			continue
		}
		if dist < bestDist {
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

	r.cache[tr.dest] = routerCacheInfo{bestPeer, tr.watermark}
	return bestPeer
}

func (r *router) _getRootAndDists(dest publicKey) (publicKey, map[publicKey]uint64) {
	// This returns the distances from the destination's root for the destination and each of its ancestors
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
	var tmp [10]byte
	size := binary.PutUvarint(tmp[:], req.seq)
	size += binary.PutUvarint(tmp[:], req.nonce)
	return size
}

func (req *routerSigReq) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = binary.AppendUvarint(out, req.seq)
	out = binary.AppendUvarint(out, req.nonce)
	end := len(out)
	if end-start != req.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (req *routerSigReq) chop(data *[]byte) error {
	var tmp routerSigReq
	orig := *data
	if !wireChopUvarint(&tmp.seq, &orig) {
		return DecodeError{}
	} else if !wireChopUvarint(&tmp.nonce, &orig) {
		return DecodeError{}
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
		return DecodeError{}
	}
	*req = tmp
	return nil
}

/*****************
 * routerSigRes *
 *****************/

type routerSigRes struct {
	routerSigReq
	psig signature
}

func (res *routerSigRes) check(node, parent publicKey) bool {
	bs := res.bytesForSig(node, parent)
	return parent.verify(bs, &res.psig)
}

func (res *routerSigRes) size() int {
	size := res.routerSigReq.size()
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
	} else if !wireChopSlice(tmp.psig[:], &orig) {
		return DecodeError{}
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
		return DecodeError{}
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
	// TODO clean this up, give "chop" versions of decode to the embedded structs?
	var tmp routerAnnounce
	if !wireChopSlice(tmp.key[:], &data) {
		return DecodeError{}
	} else if !wireChopSlice(tmp.parent[:], &data) {
		return DecodeError{}
	} else if err := tmp.routerSigRes.chop(&data); err != nil {
		return err
	} else if !wireChopSlice(tmp.sig[:], &data) {
		return DecodeError{}
	} else if len(data) != 0 {
		return DecodeError{}
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

/*******************
 * routerMerkleReq *
 *******************/

type routerMerkleReq struct {
	prefixLen uint64
	prefix    publicKey
}

func (req *routerMerkleReq) check() bool {
	return req.prefixLen <= merkletree.KeyBits
}

func (req *routerMerkleReq) size() int {
	var tmp [10]byte
	size := binary.PutUvarint(tmp[:], req.prefixLen)
	size += len(req.prefix)
	return size
}

func (req *routerMerkleReq) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = binary.AppendUvarint(out, req.prefixLen)
	out = append(out, req.prefix[:]...)
	end := len(out)
	if end-start != req.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (req *routerMerkleReq) chop(data *[]byte) error {
	var tmp routerMerkleReq
	orig := *data
	if !wireChopUvarint(&tmp.prefixLen, &orig) {
		return DecodeError{}
	} else if !wireChopSlice(tmp.prefix[:], &orig) {
		return DecodeError{}
	}
	*req = tmp
	*data = orig
	return nil
}

func (req *routerMerkleReq) decode(data []byte) error {
	var tmp routerMerkleReq
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return DecodeError{}
	}
	*req = tmp
	return nil
}

/*******************
* routerMerkleRes *
*******************/

type routerMerkleRes struct {
	routerMerkleReq
	digest merkletree.Digest
}

func (res *routerMerkleRes) size() int {
	size := res.routerMerkleReq.size()
	size += len(res.digest)
	return size
}

func (res *routerMerkleRes) encode(out []byte) ([]byte, error) {
	start := len(out)
	var err error
	if out, err = res.routerMerkleReq.encode(out); err != nil {
		return nil, err
	}
	out = append(out, res.digest[:]...)
	end := len(out)
	if end-start != res.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (res *routerMerkleRes) chop(data *[]byte) error {
	var tmp routerMerkleRes
	orig := *data
	if err := tmp.routerMerkleReq.chop(&orig); err != nil {
		return err
	} else if !wireChopSlice(tmp.digest[:], &orig) {
		return DecodeError{}
	}
	*res = tmp
	*data = orig
	return nil
}

func (res *routerMerkleRes) decode(data []byte) error {
	var tmp routerMerkleRes
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return DecodeError{}
	}
	*res = tmp
	return nil
}
