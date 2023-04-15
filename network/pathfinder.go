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

/************
 * pathInfo *
 ************/

type pathInfo struct {
	path    []peerPort
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
