package network

import (
	"encoding/binary"
	//"time"

	"github.com/Arceliar/phony"
)

/***********
 * crdtree *
 **********/

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

func (t *crdtree) addPeer(from phony.Actor, p *peer) {}

func (t *crdtree) removePeer(from phony.Actor, p *peer) {}

// TODO all the actual work

func (t *crdtree) _fix() {}

func (t *crdtree) _handleRequest(p *peer, req *crdtreeSigReq) {}

func (t *crdtree) handleRequest(from phony.Actor, p *peer, req *crdtreeSigReq) {
	t.Act(from, func() {
		t._handleRequest(p, req)
	})
}

func (t *crdtree) _handleResponse(p *peer, res *crdtreeSigRes) {}

func (t *crdtree) handleResponse(from phony.Actor, p *peer, res *crdtreeSigRes) {
	t.Act(from, func() {
		t._handleResponse(p, res)
	})
}

func (t *crdtree) _handleAnnounce(p *peer, ann *crdtreeAnnounce) {}

func (t *crdtree) handleAnnounce(from phony.Actor, p *peer, ann *crdtreeAnnounce) {
	t.Act(from, func() {
		t._handleAnnounce(p, ann)
	})
}

func (t *crdtree) sendTraffic(from phony.Actor, tr *traffic) {}

func (t *crdtree) handleTraffic(from phony.Actor, tr *traffic) {}

// TODO lookup/forward traffic

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

func (res *crdtreeSigRes) check() bool {
	return true // TODO
}

/*******************
 * crdtreeAnnounce *
 *******************/

// This is the wire format for the treeInfo, treeInfo is the subset stored in a map

type crdtreeAnnounce struct {
	key publicKey
	crdtreeInfo
}

func (ann *crdtreeAnnounce) check() bool {
	return true // TODO
}

/***************
 * crdtreeInfo *
 ***************/

// This is the value stored in a key,value map

type crdtreeInfo struct {
	parent publicKey
	crdtreeSigRes
	sig signature
}
