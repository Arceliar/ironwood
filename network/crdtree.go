package network

import (
	"crypto/rand"
	"encoding/binary"
	"time"
	//"fmt"

	"github.com/Arceliar/phony"
)

/***********
 * crdtree *
 ***********/

// TODO have some way to gc / expire unused data eventually... soft state?

type crdtree struct {
	phony.Inbox
	core      *core
	peers     map[publicKey]map[*peer]struct{}
	infos     map[publicKey]crdtreeInfo
	requests  map[publicKey]crdtreeSigReq
	responses map[publicKey]crdtreeSigRes
}

func (t *crdtree) init(c *core) {
	t.core = c
	t.peers = make(map[publicKey]map[*peer]struct{})
	t.infos = make(map[publicKey]crdtreeInfo)
	t.requests = make(map[publicKey]crdtreeSigReq)
	t.responses = make(map[publicKey]crdtreeSigRes)
	// Kick off actor to do initial work / become root
	t.Act(nil, func() { t._fix(true) })
}

func (t *crdtree) _shutdown() {} // TODO cleanup (stop any timers etc)

func (t *crdtree) addPeer(from phony.Actor, p *peer) {
	t.Act(from, func() {
		if _, isIn := t.peers[p.key]; !isIn {
			t.peers[p.key] = make(map[*peer]struct{})
		}
		t.peers[p.key][p] = struct{}{}
		if _, isIn := t.responses[p.key]; !isIn {
			if _, isIn := t.requests[p.key]; !isIn {
				t.requests[p.key] = *t._newReq()
			}
			req := t.requests[p.key]
			p.sendSigReq(t, &req)
		}
		//req := t._newReq()
		//p.sendSigReq(t, req)
		for key, info := range t.infos {
			p.sendAnnounce(t, info.getAnnounce(key))
		}
	})
}

func (t *crdtree) removePeer(from phony.Actor, p *peer) {
	t.Act(from, func() {
		ps := t.peers[p.key]
		delete(ps, p)
		if len(ps) == 0 {
			delete(t.peers, p.key)
			delete(t.requests, p.key)
			delete(t.responses, p.key)
			if t.infos[t.core.crypto.publicKey].parent == p.key {
				if !t._becomeRoot() {
					panic("this should never happen")
				}
				//delete(t.infos, t.core.crypto.publicKey)
				t._fix(true)
			}
		}
	})
}

// TODO all the actual work:
//  something (fix?) needs to root ourself
//  something (fix?) needs to send a request when it makes sense to do so
//  lookups need to work
//  we need to handle traffic
//  we need to do something to support IP->key lookups, e.g. a way to return the closest key and let the caller check if it's a match
//  we need to remove unreachable nodes from the network (somehow) -- though technically speaking, we can save that for last

func (t *crdtree) _fix(force bool) {
	if _, isIn := t.infos[t.core.crypto.publicKey]; !isIn && !t._becomeRoot() {
		panic("this should never happen")
	}
	self := t.infos[t.core.crypto.publicKey]
	// TODO dheck if we know a better parent for ourself, if so, switch to it... or rather, send a request so we can switch later?
	myRoot := t._getRootFor(t.core.crypto.publicKey)
	bestRoot := myRoot
	bestParent := self.parent
	for pk := range t.responses {
		// TODO have them pre-sign an announcement, which we store in a map somewhere
		peerRoot := t._getRootFor(pk)
		if crdtreeLess(peerRoot, bestRoot) {
			bestRoot = peerRoot
			bestParent = pk
		}
		// TODO tie break, right now it's selecting a basically random peer
	}
	if bestRoot != myRoot {
		// TODO switch to this peer as our new parent
		// This really requires having a signed update from the peers already on hand...
		res, isIn := t.responses[bestParent]
		if !isIn {
			panic("this should never happen")
		}
		if t._useResponse(bestParent, &res) {
			for pk := range t.requests {
				delete(t.requests, pk)
			}
			for pk := range t.responses {
				delete(t.responses, pk)
			}
			for pk, ps := range t.peers {
				// TODO track which req was sent to which peer, only accept ones we actually sent...
				req := t._newReq()
				t.requests[pk] = *req
				for p := range ps {
					p.sendSigReq(t, req)
				}
			}
			return
		} else {
			// TODO DEBUG THIS!
			//panic("this should never happen")
			if !t._becomeRoot() {
				panic("this also should never happen")
			}
			force = true
		}
	}
	if force {
		// TODO send announcement
		ann := self.getAnnounce(t.core.crypto.publicKey)
		for _, ps := range t.peers {
			for p := range ps {
				p.sendAnnounce(t, ann)
			}
		}
		for pk := range t.requests {
			delete(t.requests, pk)
		}
		for pk := range t.responses {
			delete(t.responses, pk)
		}
		for pk, ps := range t.peers {
			// TODO track which req was sent to which peer, only accept ones we actually sent...
			req := t._newReq()
			t.requests[pk] = *req
			for p := range ps {
				p.sendSigReq(t, req)
			}
		}
	}
}

func (t *crdtree) _getRootFor(key publicKey) publicKey {
	visited := make(map[publicKey]struct{})
	visited[publicKey{}] = struct{}{}
	here := key
	for {
		if _, isIn := visited[here]; isIn {
			return here
		}
		visited[here] = struct{}{}
		here = t.infos[here].parent
	}
}

func (t *crdtree) _newReq() *crdtreeSigReq {
	var req crdtreeSigReq
	nonce := make([]byte, 8)
	rand.Read(nonce) // If there's an error, there's not much to do...
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
	// TODO sanity check that this wouldn't loop, only sign/respond if it's safe
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
	// TODO check that we actually sent this request / that it's our most recent to this peer
	// Ignore it if not, it could be old or they could be spewing grabage
	// This is the entire point of having a nonce...
	if t.requests[p.key] == res.crdtreeSigReq {
		t.responses[p.key] = *res
		t._fix(false) // This could become our new parent
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
			//fmt.Println("DEBUG1")
			return false
		case info.seq < ann.seq:
			// This is a newer seq, so don't exit
		case info.parent.less(ann.parent):
			// same seq, worse (higher) parent
			//fmt.Println(info.parent, info.seq, ann.parent, ann.seq)
			//fmt.Println("DEBUG2")
			return false
		case ann.parent.less(info.parent):
			// same seq, better (lower) parent, so don't exit
		case ann.nonce < info.nonce:
			// same seq and parent, lower nonce, so don't exit
		default:
			// same seq and parent, same or worse nonce, so exit
			//fmt.Println("DEBUG3")
			return false
		}
	}
	info := crdtreeInfo{
		parent:        ann.parent,
		crdtreeSigRes: ann.crdtreeSigRes,
		sig:           ann.sig,
		time:          time.Now(),
	}
	t.infos[ann.key] = info
	return true
}

func (t *crdtree) _handleAnnounce(p *peer, ann *crdtreeAnnounce) {
	if t._update(ann) {
		for _, ps := range t.peers {
			for p := range ps {
				p.sendAnnounce(t, ann)
			}
		}
		t._fix(false) // This could require us to change parents
	}
}

func (t *crdtree) handleAnnounce(from phony.Actor, p *peer, ann *crdtreeAnnounce) {
	t.Act(from, func() {
		t._handleAnnounce(p, ann)
	})
}

func (t *crdtree) sendTraffic(from phony.Actor, tr *traffic) {
	// TODO any sort of additional sanity checks (in an Act)
	t.handleTraffic(from, tr)
}

func (t *crdtree) handleTraffic(from phony.Actor, tr *traffic) {
	t.Act(from, func() {
		if p := t._lookup(tr.dest); p != nil {
			p.sendTraffic(t, tr)
		} else {
			t.core.pconn.handleTraffic(tr)
		}
	})
}

func (t *crdtree) _lookup(dest publicKey) *peer {
	_, isIn := t.infos[dest]
	if !isIn {
		//return nil
		// TODO switch dest to the closest known key, so out-of-band stuff works
		// This would be a hack to make the example code run without modification
		// Long term, TODO remove out-of-band stuff, provide a function to simply look up the closest known node for a given key
		var lowest *publicKey
		var best *publicKey
		for key := range t.infos {
			if lowest == nil || crdtreeLess(key, *lowest) {
				k := key
				lowest = &k
			}
			if best == nil && crdtreeLess(key, dest) {
				k := key
				best = &k
			}
			if crdtreeLess(key, dest) && crdtreeLess(*best, key) {
				k := key
				best = &k
			}
		}
		if best == nil {
			best = lowest
		}
		if best == nil {
			return nil
		}
		dest = *best
	}
	dists := t._getDists(dest)
	getDist := func(key publicKey) (uint64, bool) {
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
	var bestPeer *peer
	bestDist := ^uint64(0)
	if dist, ok := getDist(t.core.crypto.publicKey); ok {
		bestDist = dist // Self dist, so other nodes must be strictly better by distance
	}
	for k, ps := range t.peers {
		dist, ok := getDist(k)
		if !ok {
			continue
		}
		if dist < bestDist {
			for p := range ps {
				// TODO decide which peer is best
				bestPeer = p
				break
			}
			bestDist = dist
		}
	}
	return bestPeer
}

func (t *crdtree) _getDists(dest publicKey) map[publicKey]uint64 {
	// This returns the distances from the destination's root for the destination and each of its ancestors
	dists := make(map[publicKey]uint64)
	next := dest
	var dist uint64
	for {
		if _, isIn := dists[next]; isIn {
			break
		}
		if info, isIn := t.infos[next]; isIn {
			dists[next] = dist
			dist++
			next = info.parent
		} else {
			break
		}
	}
	return dists
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
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], req.seq)
	out = append(out, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], req.nonce)
	out = append(out, tmp[:]...)
	return out, nil
}

func (req *crdtreeSigReq) decode(data []byte) error {
	var tmp crdtreeSigReq
	if len(data) != 16 {
		return wireDecodeError
	}
	tmp.seq, data = binary.BigEndian.Uint64(data[:8]), data[8:]
	tmp.nonce, data = binary.BigEndian.Uint64(data[:8]), data[8:]
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

func (res *crdtreeSigRes) decode(data []byte) error {
	var tmp crdtreeSigRes
	if err := tmp.crdtreeSigReq.decode(data[:16]); err != nil {
		return err
	}
	data = data[16:]
	if !wireChopSlice(tmp.psig[:], &data) {
		return wireDecodeError
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
	} else if err := tmp.crdtreeSigRes.decode(data[:16+64]); err != nil {
		return err
	}
	data = data[16+64:]
	if !wireChopSlice(tmp.sig[:], &data) {
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
	sig  signature
	time time.Time // This part not serialized
}

func (info *crdtreeInfo) getAnnounce(key publicKey) *crdtreeAnnounce {
	return &crdtreeAnnounce{
		key:           key,
		parent:        info.parent,
		crdtreeSigRes: info.crdtreeSigRes,
		sig:           info.sig,
	}
}

/******************
 * util functions *
 ******************/

func crdtreeLess(key1, key2 publicKey) bool {
	for idx := range key1 {
		if key1[idx] < key2[idx] {
			return true
		} else if key1[idx] > key2[idx] {
			return false
		}
	}
	return false
}
