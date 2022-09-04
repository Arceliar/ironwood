package network

import (
	"encoding/binary"
	"time"

	"github.com/Arceliar/phony"
)

/***********
 * crdtree *
 ***********/

// TODO have some way to gc / expire unused data eventually... soft state?

type crdtree struct {
	phony.Inbox
	core  *core
	peers map[publicKey]map[*peer]struct{}
	infos map[publicKey]crdtreeInfo
}

func (t *crdtree) init(c *core) {
	t.core = c
	t.peers = make(map[publicKey]map[*peer]struct{})
	t.infos = make(map[publicKey]crdtreeInfo)
	// Kick off actor to do initial work / become root
	t.Act(nil, t._fix)
}

func (t *crdtree) _shutdown() {} // TODO cleanup (stop any timers etc)

func (t *crdtree) addPeer(from phony.Actor, p *peer) {
	t.Act(from, func() {
		if _, isIn := t.peers[p.key]; !isIn {
			t.peers[p.key] = make(map[*peer]struct{})
		}
		t.peers[p.key][p] = struct{}{}
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

func (t *crdtree) _fix() {}

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
	if false {
		// TODO decide if we should actually switch to this as our announcement
		return
	}
	bs := res.bytesForSig(t.core.crypto.publicKey, p.key)
	info := crdtreeInfo{
		parent:        p.key,
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
	}
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
		for k, ps := range t.peers {
			if k.equal(p.key) {
				continue
			}
			for p := range ps {
				p.sendAnnounce(t, ann)
			}
		}
	}
}

func (t *crdtree) handleAnnounce(from phony.Actor, p *peer, ann *crdtreeAnnounce) {
	t.Act(from, func() {
		t._handleAnnounce(p, ann)
	})
}

func (t *crdtree) sendTraffic(from phony.Actor, tr *traffic) {}

func (t *crdtree) handleTraffic(from phony.Actor, tr *traffic) {
	t.Act(from, func() {
		if p := t._lookup(tr.dest); p != nil {
			p.sendTraffic(t, tr)
		} else {
			// TODO handle traffic
			panic("TODO")
		}
	})
}

func (t *crdtree) _lookup(dest publicKey) *peer {
	_, isIn := t.infos[dest]
	if !isIn {
		return nil
	}
	/* TODO
	ancDists := t._getDists(dest)
	var bestPeer publicKey
	var bestDist uint64
	var found bool
	for k := range t.peers {
	  // TODO something more efficient
	  pDists := t._getDists(k)
	  for k, pd := pDists {
	    if ad, isIn := ancDists[k]; isIn {
	      dist := ad+pd
	      if !found || dist < bestDist {

	      }
	    }
	  }
	}
	*/
	return nil
}

func (t *crdtree) _getDists(dest publicKey) map[publicKey]uint64 {
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
