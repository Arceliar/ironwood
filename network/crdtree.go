package network

import (
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"time"

	//"fmt"

	"github.com/Arceliar/phony"
)

/***********
 * crdtree *
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

const (
	crdtreeRefresh  = 23 * time.Hour //time.Minute
	crdtreeTimeout  = 24 * time.Hour //crdtreeRefresh + 10*time.Second
	crdtreeMaxInfos = 65535          // TODO make configurable at init time, use more intelligently
)

type crdtreeCacheInfo struct {
	peer *peer
	dist uint64
}

type crdtree struct {
	phony.Inbox
	core      *core
	peers     map[publicKey]map[*peer]bool // True if we're allowed to send a mirror to this peer (but have not done so already)
	infos     map[publicKey]crdtreeInfo
	cache     map[publicKey]crdtreeCacheInfo // Cache of next hop for each destination
	requests  map[publicKey]crdtreeSigReq
	responses map[publicKey]crdtreeSigRes
	resSeqs   map[publicKey]uint64
	resSeqCtr uint64
	refresh   bool
	doRoot1   bool
	doRoot2   bool
	fixTimer  *time.Timer
}

func (t *crdtree) init(c *core) {
	t.core = c
	t.peers = make(map[publicKey]map[*peer]bool)
	t.infos = make(map[publicKey]crdtreeInfo)
	t.cache = make(map[publicKey]crdtreeCacheInfo)
	t.requests = make(map[publicKey]crdtreeSigReq)
	t.responses = make(map[publicKey]crdtreeSigRes)
	t.resSeqs = make(map[publicKey]uint64)
	t.fixTimer = time.AfterFunc(0, func() {})
	// Kick off actor to do initial work / become root
	t.Act(nil, t._fix)
}

func (t *crdtree) _shutdown() {} // TODO cleanup (stop any timers etc)

func (t *crdtree) _resetCache() {
	for k := range t.cache {
		delete(t.cache, k)
	}
}

func (t *crdtree) addPeer(from phony.Actor, p *peer) {
	t.Act(from, func() {
		t._resetCache()
		if _, isIn := t.peers[p.key]; !isIn {
			t.peers[p.key] = make(map[*peer]bool)
		}
		// TODO? In some cases, should this be false? Depending on the link type maybe?
		t.peers[p.key][p] = true
		if _, isIn := t.responses[p.key]; !isIn {
			if _, isIn := t.requests[p.key]; !isIn {
				t.requests[p.key] = *t._newReq()
			}
			req := t.requests[p.key]
			p.sendSigReq(t, &req)
		}
		// TODO don't unconditionally ask for peers, at least not immediately?
		//p.sendMirrorReq(t)
		var doReq bool
		if _, isIn := t.infos[p.key]; !isIn {
			// If we don't know about a peer, this is probably sufficient cause to ask for their network
			// It suggests we were in different connected components until now
			// But it's probably not the only case where we should request it...
			doReq = true
		}
		if !doReq {
			selfRoot, _ := t._getRootAndDists(t.core.crypto.publicKey)
			peerRoot, _ := t._getRootAndDists(p.key)
			if peerRoot != selfRoot {
				// We were in different connected components
				// This only fixes the situation for one of the two nodes...
				// Still, probably better than nothing
				doReq = true
			}
		}
		if doReq {
			p.sendMirrorReq(t)
		}
	})
}

func (t *crdtree) removePeer(from phony.Actor, p *peer) {
	t.Act(from, func() {
		t._resetCache()
		ps := t.peers[p.key]
		delete(ps, p)
		if len(ps) == 0 {
			delete(t.peers, p.key)
			delete(t.requests, p.key)
			delete(t.responses, p.key)
			delete(t.resSeqs, p.key)
			t._fix()
		}
	})
}

func (t *crdtree) _clearReqs() {
	for k := range t.requests {
		delete(t.requests, k)
	}
	for k := range t.responses {
		delete(t.responses, k)
	}
	for k := range t.resSeqs {
		delete(t.resSeqs, k)
	}
	t.resSeqCtr = 0
}

func (t *crdtree) _sendReqs() {
	t._clearReqs()
	for pk, ps := range t.peers {
		req := t._newReq()
		t.requests[pk] = *req
		for p := range ps {
			p.sendSigReq(t, req)
		}
	}
}

func (t *crdtree) _fix() {
	bestRoot := t.core.crypto.publicKey
	bestParent := t.core.crypto.publicKey
	self := t.infos[t.core.crypto.publicKey]
	// Check if our current parent leads to a better root than ourself
	if _, isIn := t.peers[self.parent]; isIn {
		root, _ := t._getRootAndDists(t.core.crypto.publicKey)
		if root.less(bestRoot) {
			bestRoot, bestParent = root, self.parent
		}
	}
	// Check if we know a better root/parent
	for pk := range t.responses {
		if _, isIn := t.infos[pk]; !isIn {
			// We don't know where this peer is
			continue
		}
		pRoot, pDists := t._getRootAndDists(pk)
		if _, isIn := pDists[t.core.crypto.publicKey]; isIn {
			// This would loop through us already
			continue
		}
		if pRoot.less(bestRoot) {
			bestRoot, bestParent = pRoot, pk
		}
		// TODO? switch to another parent (to the same root) if they're "better", at least sometimes
		if t.refresh || bestParent != self.parent {
			if pRoot == bestRoot && t.resSeqs[pk] < t.resSeqs[bestParent] {
				bestRoot, bestParent = pRoot, pk
			}
		}
	}
	if t.refresh || t.doRoot1 || t.doRoot2 || self.parent != bestParent {
		res, isIn := t.responses[bestParent] // FIXME only use if bestParent isIn t.responses!
		switch {
		case isIn && bestRoot != t.core.crypto.publicKey: // && t._useResponse(bestParent, &res):
			// Somebody else should be root
			if !t._useResponse(bestParent, &res) {
				panic("this should never happen")
			}
			t.fixTimer.Stop()
			t.refresh = false
			t.doRoot1 = false
			t.doRoot2 = false // TODO panic to check that this was already false
			t._sendReqs()
		case t.doRoot2:
			// Become root
			if !t._becomeRoot() {
				panic("this should never happen")
			}
			self = t.infos[t.core.crypto.publicKey]
			ann := self.getAnnounce(t.core.crypto.publicKey)
			for _, ps := range t.peers {
				for p := range ps {
					p.sendAnnounce(t, ann)
				}
			}
			t.refresh = false
			t.doRoot1 = false
			t.doRoot2 = false
			t.fixTimer.Stop()
			t._sendReqs()
		case !t.doRoot1:
			t.fixTimer = time.AfterFunc(time.Second, func() {
				t.Act(nil, func() {
					if t.doRoot1 {
						t.doRoot2 = true
						t._fix()
					}
				})
			})
			t.doRoot1 = true
			// No need to sendReqs in this case
			//  either we already have a req, or we've already requested one
			//  so resetting and re-requesting is just a waste of bandwidth
		default:
			// We need to self-root, but we already started a timer to do that later
			// So this is a no-op
		}
	}
}

func (t *crdtree) _newReq() *crdtreeSigReq {
	var req crdtreeSigReq
	nonce := make([]byte, 8)
	crand.Read(nonce) // If there's an error, there's not much to do...
	req.nonce = binary.BigEndian.Uint64(nonce)
	req.seq = t.infos[t.core.crypto.publicKey].seq + 1
	return &req
}

func (t *crdtree) _becomeRoot() bool {
	req := t._newReq()
	bs := req.bytesForSig(t.core.crypto.publicKey, t.core.crypto.publicKey)
	sig := t.core.crypto.privateKey.sign(bs)
	res := crdtreeSigRes{*req, sig}
	ann := crdtreeAnnounce{
		key:           t.core.crypto.publicKey,
		parent:        t.core.crypto.publicKey,
		crdtreeSigRes: res,
		sig:           sig,
	}
	if !ann.check() {
		panic("this should never happen")
	}
	return t._update(&ann)
}

func (t *crdtree) _handleRequest(p *peer, req *crdtreeSigReq) {
	bs := req.bytesForSig(p.key, t.core.crypto.publicKey)
	sig := t.core.crypto.privateKey.sign(bs)
	res := crdtreeSigRes{*req, sig}
	p.sendSigRes(t, &res)
}

func (t *crdtree) handleRequest(from phony.Actor, p *peer, req *crdtreeSigReq) {
	t.Act(from, func() {
		t._handleRequest(p, req)
	})
}

func (t *crdtree) _handleResponse(p *peer, res *crdtreeSigRes) {
	if _, isIn := t.responses[p.key]; !isIn && t.requests[p.key] == res.crdtreeSigReq {
		t.resSeqCtr++
		t.resSeqs[p.key] = t.resSeqCtr
		t.responses[p.key] = *res
		t._fix() // This could become our new parent
	}
}

func (t *crdtree) _useResponse(peerKey publicKey, res *crdtreeSigRes) bool {
	bs := res.bytesForSig(t.core.crypto.publicKey, peerKey)
	info := crdtreeInfo{
		parent:        peerKey,
		crdtreeSigRes: *res,
		sig:           t.core.crypto.privateKey.sign(bs),
	}
	ann := info.getAnnounce(t.core.crypto.publicKey)
	if t._update(ann) {
		for _, ps := range t.peers {
			for p := range ps {
				p.sendAnnounce(t, ann)
			}
		}
		return true
	}
	return false
}

func (t *crdtree) handleResponse(from phony.Actor, p *peer, res *crdtreeSigRes) {
	t.Act(from, func() {
		t._handleResponse(p, res)
	})
}

func (t *crdtree) _update(ann *crdtreeAnnounce) bool {
	if info, isIn := t.infos[ann.key]; isIn {
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
	t._resetCache()
	info := crdtreeInfo{
		parent:        ann.parent,
		crdtreeSigRes: ann.crdtreeSigRes,
		sig:           ann.sig,
	}
	key := ann.key
	if key == t.core.crypto.publicKey {
		delay := crdtreeRefresh + time.Millisecond*time.Duration(mrand.Intn(1024))
		info.timer = time.AfterFunc(delay, func() {
			t.Act(nil, func() {
				if t.infos[key] == info {
					t.refresh = true
					t._fix()
				}
			})
		})
	} else {
		info.timer = time.AfterFunc(crdtreeTimeout, func() {
			t.Act(nil, func() {
				if t.infos[key] == info {
					delete(t.infos, key)
					t._resetCache()
					t._fix()
				}
			})
		})
	}
	if oldInfo, isIn := t.infos[key]; isIn {
		oldInfo.timer.Stop()
	}
	t.infos[key] = info
	return true
}

func (t *crdtree) _handleAnnounce(sender *peer, ann *crdtreeAnnounce) {
	var doUpdate bool
	var worst publicKey
	var found bool
	if len(t.infos) < crdtreeMaxInfos {
		// We're not at max capacity yet, so we have room to add more
		doUpdate = true
	} else if _, isIn := t.infos[ann.key]; isIn {
		// We're at capacity (or, somehow, above) but we alread know about this
		// Therefore, there's no harm in accepting the update (we can't force anything else out)
		// If this was or last check, then this is basically TOFU for the network
		doUpdate = true
	} else {
		// We're at or above capacity, and this is a new node
		// It may be "better" than something we already know about
		// We define better to mean lower key (so e.g. we all know the root)
		// We also special case or own info, to avoid timer problems
		for k := range t.infos {
			if k == t.core.crypto.publicKey {
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
	if doUpdate && t._update(ann) {
		for _, ps := range t.peers {
			for p := range ps {
				if p == sender {
					continue
				}
				p.sendAnnounce(t, ann)
			}
		}
		if found {
			// Cleanup worst
			t.infos[worst].timer.Stop()
			delete(t.infos, worst)
			t._resetCache()
		}
		t._fix() // This could require us to change parents
	}
}

func (t *crdtree) handleAnnounce(from phony.Actor, p *peer, ann *crdtreeAnnounce) {
	t.Act(from, func() {
		t._handleAnnounce(p, ann)
	})
}

func (t *crdtree) handleMirrorReq(from phony.Actor, p *peer) {
	t.Act(from, func() {
		if t.peers[p.key][p] {
			t.peers[p.key][p] = false
			p.sendMirrorReq(t) // Synchronize in both directions, if possible (done first, so they don't needlessly send us back everything we send them)
			for key, info := range t.infos {
				p.sendAnnounce(t, info.getAnnounce(key))
			}
		}
	})
}

func (t *crdtree) sendTraffic(tr *traffic) {
	// This must be non-blocking, to prevent deadlocks between read/write paths in the encrypted package
	// Basically, WriteTo and ReadFrom can't be allowed to block each other, but they could if we allowed backpressure here
	// There may be a better way to handle this, but it practice it probably won't be an issue (we'll throw the packet in a queue somewhere, or drop it)
	t.handleTraffic(nil, tr)
}

func (t *crdtree) handleTraffic(from phony.Actor, tr *traffic) {
	t.Act(from, func() {
		if p := t._lookup(tr); p != nil {
			p.sendTraffic(t, tr)
		} else {
			t.core.pconn.handleTraffic(t, tr)
		}
	})
}

func (t *crdtree) _keyLookup(dest publicKey) publicKey {
	// Returns the key that's the closest match to the destination publicKey
	if _, isIn := t.infos[dest]; !isIn {
		// Switch dest to the closest known key, so out-of-band stuff works
		// This would be a hack to make the example code run without modification
		// Long term, TODO remove out-of-band stuff, provide a function to simply look up the closest known node for a given key
		var lowest *publicKey
		var best *publicKey
		for key := range t.infos {
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

func (t *crdtree) _getDist(dists map[publicKey]uint64, key publicKey) (uint64, bool) {
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
		here = t.infos[here].parent
	}
}

func (t *crdtree) _lookup(tr *traffic) *peer {
	if info, isIn := t.cache[tr.dest]; isIn {
		if info.dist < tr.watermark {
			tr.watermark = info.dist
			return info.peer
		} else {
			return nil
		}
	}
	if _, isIn := t.infos[tr.dest]; !isIn {
		return nil // If we want to restore DHT-like logic, it's mostly copy/paste from _keyLookup
	}
	// Look up the next hop (in treespace) towards the destination
	_, dists := t._getRootAndDists(tr.dest)
	var bestPeer *peer
	bestDist := ^uint64(0)
	if dist, ok := t._getDist(dists, t.core.crypto.publicKey); ok && dist < tr.watermark {
		bestDist = dist // Self dist, so other nodes must be strictly better by distance
		tr.watermark = dist
	} else {
		return nil
	}
	for k, ps := range t.peers {
		dist, ok := t._getDist(dists, k)
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

	t.cache[tr.dest] = crdtreeCacheInfo{bestPeer, tr.watermark}
	return bestPeer
}

func (t *crdtree) _getRootAndDists(dest publicKey) (publicKey, map[publicKey]uint64) {
	// This returns the distances from the destination's root for the destination and each of its ancestors
	dists := make(map[publicKey]uint64)
	next := dest
	var root publicKey
	var dist uint64
	for {
		if _, isIn := dists[next]; isIn {
			break
		}
		if info, isIn := t.infos[next]; isIn { // && !info.expired {
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
 * crdtreeSigReq *
 *****************/

type crdtreeSigReq struct {
	seq   uint64
	nonce uint64
}

func (req *crdtreeSigReq) bytesForSig(node, parent publicKey) []byte {
	out := make([]byte, 0, publicKeySize*2+8+8)
	out = append(out, node[:]...)
	out = append(out, parent[:]...)
	out, _ = req.encode(out)
	return out
}

func (req *crdtreeSigReq) encode(out []byte) ([]byte, error) {
	out = binary.AppendUvarint(out, req.seq)
	out = binary.AppendUvarint(out, req.nonce)
	return out, nil
}

func (req *crdtreeSigReq) chop(data *[]byte) error {
	var tmp crdtreeSigReq
	orig := *data
	if !wireChopUvarint(&tmp.seq, &orig) {
		return wireDecodeError
	} else if !wireChopUvarint(&tmp.nonce, &orig) {
		return wireDecodeError
	}
	*req = tmp
	*data = orig
	return nil
}

func (req *crdtreeSigReq) decode(data []byte) error {
	var tmp crdtreeSigReq
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return wireDecodeError
	}
	*req = tmp
	return nil
}

/*****************
 * crdtreeSigRes *
 *****************/

type crdtreeSigRes struct {
	crdtreeSigReq
	psig signature
}

func (res *crdtreeSigRes) check(node, parent publicKey) bool {
	bs := res.bytesForSig(node, parent)
	return parent.verify(bs, &res.psig)
}

func (res *crdtreeSigRes) encode(out []byte) ([]byte, error) {
	var err error
	out, err = res.crdtreeSigReq.encode(out)
	if err != nil {
		return nil, err
	}
	out = append(out, res.psig[:]...)
	return out, nil
}

func (res *crdtreeSigRes) chop(data *[]byte) error {
	orig := *data
	var tmp crdtreeSigRes
	if err := tmp.crdtreeSigReq.chop(&orig); err != nil {
		return err
	} else if !wireChopSlice(tmp.psig[:], &orig) {
		return wireDecodeError
	}
	*res = tmp
	*data = orig
	return nil
}

func (res *crdtreeSigRes) decode(data []byte) error {
	var tmp crdtreeSigRes
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return wireDecodeError
	}
	*res = tmp
	return nil
}

/*******************
 * crdtreeAnnounce *
 *******************/

type crdtreeAnnounce struct {
	key    publicKey
	parent publicKey
	crdtreeSigRes
	sig signature
}

func (ann *crdtreeAnnounce) check() bool {
	bs := ann.bytesForSig(ann.key, ann.parent)
	return ann.key.verify(bs, &ann.sig) && ann.parent.verify(bs, &ann.psig)
}

func (ann *crdtreeAnnounce) encode(out []byte) ([]byte, error) {
	var err error
	out = append(out, ann.key[:]...)
	out = append(out, ann.parent[:]...)
	out, err = ann.crdtreeSigRes.encode(out)
	if err != nil {
		return nil, err
	}
	out = append(out, ann.sig[:]...)
	return out, nil
}

func (ann *crdtreeAnnounce) decode(data []byte) error {
	// TODO clean this up, give "chop" versions of decode to the embedded structs?
	var tmp crdtreeAnnounce
	if !wireChopSlice(tmp.key[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.parent[:], &data) {
		return wireDecodeError
	} else if err := tmp.crdtreeSigRes.chop(&data); err != nil {
		return err
	} else if !wireChopSlice(tmp.sig[:], &data) {
		return wireDecodeError
	} else if len(data) != 0 {
		return wireDecodeError
	}
	*ann = tmp
	return nil
}

/***************
 * crdtreeInfo *
 ***************/

// This is the value stored in a key,value map

type crdtreeInfo struct {
	parent publicKey
	crdtreeSigRes
	sig   signature
	timer *time.Timer
}

func (info *crdtreeInfo) getAnnounce(key publicKey) *crdtreeAnnounce {
	return &crdtreeAnnounce{
		key:           key,
		parent:        info.parent,
		crdtreeSigRes: info.crdtreeSigRes,
		sig:           info.sig,
	}
}
