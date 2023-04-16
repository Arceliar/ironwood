package network

import (
	"time"

	"github.com/Arceliar/phony"
)

// WARNING The pathfinder should only be used from within the router's actor, it's not threadsafe
type pathfinder struct {
	router *router
	paths  map[publicKey]pathInfo
	rumors map[publicKey]pathRumor
	seq    uint64
}

type pathRumor struct {
	traffic *traffic
	timer   *time.Timer
}

func (pf *pathfinder) init(r *router) {
	pf.router = r
	pf.paths = make(map[publicKey]pathInfo)
	pf.rumors = make(map[publicKey]pathRumor)
}

// TODO everything, these are just placeholders

func (pf *pathfinder) _sendRequest(target publicKey) {
	pf.seq++
	req := pathRequest{
		source: pf.router.core.crypto.publicKey,
		target: target,
		seq:    pf.seq,
		// TODO sig
	}

	// Now skip to the end and just pretend we got a response from the network
	for k := range pf.router.infos {
		xform := pf.xKey(k)
		if xform == req.target {
			root, path := pf.router._getRootAndPath(k)
			res := pathResponse{
				source: k,
				dest:   req.source,
				seq:    req.seq,
				root:   root,
				path:   path,
				// TODO sig
			}
			pf.handleRes(nil, &res)
		}
	}
}

func (pf *pathfinder) handleReq(from phony.Actor, req *pathRequest) {}

func (pf *pathfinder) handleRes(from phony.Actor, res *pathResponse) {
	pf.router.Act(from, func() {
		if res.seq > pf.seq {
			// Too new, we need to just ignore it
			// TODO? something better? could be important for anycast/multicast to work some day...
			return
		}
		var info pathInfo
		var isIn bool
		if info, isIn = pf.paths[res.source]; isIn {
			if res.seq <= info.seq {
				// This isn't newer than the last seq we received, so drop it
				return
			}
			info.timer.Reset(pf.router.core.config.pathTimeout)
			info.path = res.path
			info.seq = res.seq
		} else {
			xform := pf.xKey(res.source)
			if _, isIn := pf.rumors[xform]; !isIn {
				return
			}
			key := res.source
			var timer *time.Timer
			timer = time.AfterFunc(pf.router.core.config.pathTimeout, func() {
				pf.router.Act(nil, func() {
					if pf.paths[key].timer == timer {
						timer.Stop()
						delete(pf.paths, key)
					}
				})
			})
			info = pathInfo{
				reqTime: time.Now(),
				timer:   timer,
			}
			if rumor := pf.rumors[xform]; rumor.traffic != nil && rumor.traffic.dest == res.source {
				tr := rumor.traffic
				rumor.traffic = nil
				defer pf._handleTraffic(tr)
			}
		}
		info.path = res.path
		info.seq = res.seq
		pf.paths[res.source] = info
		pf.router.core.config.pathNotify(res.source.toEd())
	})
}

func (pf *pathfinder) _sendLookup(dest publicKey) {
	// TODO the real thing
	xform := pf.xKey(dest)
	if rumor, isIn := pf.rumors[xform]; isIn {
		rumor.timer.Reset(pf.router.core.config.pathTimeout)
	} else {
		var timer *time.Timer
		x := xform
		timer = time.AfterFunc(pf.router.core.config.pathTimeout, func() {
			pf.router.Act(nil, func() {
				if rumor := pf.rumors[x]; rumor.timer == timer {
					delete(pf.rumors, x)
					timer.Stop()
					if rumor.traffic != nil {
						freeTraffic(rumor.traffic)
					}
				}
			})
		})
		pf.rumors[x] = pathRumor{
			timer: timer,
		}
	}
	pf._sendRequest(xform)
}

func (pf *pathfinder) _handleTraffic(tr *traffic) {
	if info, isIn := pf.paths[tr.dest]; isIn {
		tr.path = append(tr.path[:0], info.path...)
		pf.router.handleTraffic(nil, tr)
	} else {
		pf._sendLookup(tr.dest)
		xform := pf.xKey(tr.dest)
		if rumor, isIn := pf.rumors[xform]; isIn {
			if rumor.traffic != nil {
				freeTraffic(rumor.traffic)
			}
			rumor.traffic = tr
			pf.rumors[xform] = rumor
		} else {
			panic("this should never happen")
		}
	}
}

func (pf *pathfinder) xKey(key publicKey) publicKey {
	k := key
	xfed := pf.router.core.config.pathTransform(k.toEd())
	var xform publicKey
	copy(xform[:], xfed)
	return xform
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
