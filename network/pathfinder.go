package network

import (
	"time"

	"github.com/Arceliar/phony"
)

// WARNING The pathfinder should only be used from within the router's actor, it's not threadsafe
type pathfinder struct {
	router *router
	paths  map[publicKey]*pathInfo
}

func (pf *pathfinder) init(r *router) {
	pf.router = r
	pf.paths = make(map[publicKey]*pathInfo)
}

// TODO everything, these are just placeholders

func (pf *pathfinder) _lookup(dest publicKey) *pathInfo { return nil }

func (pf *pathfinder) _sendRequest(dest publicKey) {}

func (pf *pathfinder) handleReq(from phony.Actor, req *pathRequest) {}

func (pf *pathfinder) handleRes(from phony.Actor, res *pathResponse) {}

func (pf *pathfinder) _sendLookup(target publicKey) {
	// TODO the real thing
	// For now, this is just a hack to send a notify to... whoever
	// Note that the target is already transformed
	for k := range pf.router.infos {
		xformEd := pf.router.core.config.pathTransform(k.toEd())
		var xform publicKey
		copy(xform[:], xformEd)
		if xform == target {
			pf.router.core.config.pathNotify(k.toEd())
		}
	}
}

func (pf *pathfinder) _handleTraffic(tr *traffic) {
	// TODO the real thing
	// For now, this is just a hack, grab the info from the router
	_, tr.path = pf.router._getRootAndPath(tr.dest)
	pf.router.handleTraffic(nil, tr)
}

/************
 * pathInfo *
 ************/

type pathInfo struct {
	path    []peerPort // *not* zero terminated (and must be free of zeros)
	seq     uint64
	reqTime time.Time   // Time a request was last sent (to prevent spamming)
	timer   *time.Timer // time.AfterFunc(cleanup...), reset whenever this is used
}

/***************
 * pathRequest *
 ***************/

type pathRequest struct {
	source publicKey
	target publicKey // may be different from destiantion address
	seq    uint64    // set by requester, used to recognize which response is which
	sig    signature
}

/****************
 * pathResponse *
 ****************/

type pathResponse struct {
	source publicKey  // who sent the response, not who resquested it
	dest   publicKey  // exact key we are sending response to
	seq    uint64     // sequence number from the original request
	root   publicKey  // Who is the source's root. TODO? omit this?
	path   []peerPort // Path from root to source, aka coords, zero-terminated
	sig    signature  // signed by source
}
