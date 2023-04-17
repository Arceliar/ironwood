package network

import (
	"time"

	"github.com/Arceliar/ironwood/types"
)

// WARNING The pathfinder should only be used from within the router's actor, it's not threadsafe
type pathfinder struct {
	router *router
	paths  map[publicKey]pathInfo
	rumors map[publicKey]pathRumor
	seq    uint64
}

func (pf *pathfinder) init(r *router) {
	pf.router = r
	pf.paths = make(map[publicKey]pathInfo)
	pf.rumors = make(map[publicKey]pathRumor)
}

// TODO everything, these are just placeholders

func (pf *pathfinder) _sendRequest(dest publicKey) {
	if info, isIn := pf.paths[dest]; isIn {
		if time.Since(info.reqTime) < pf.router.core.config.pathThrottle {
			// Don't flood with request, wait a bit
			return
		}
	}
	pf.seq++
	req := pathRequest{
		source: pf.router.core.crypto.publicKey,
		dest:   dest,
		seq:    pf.seq,
		// TODO sig
	}
	if bloomMulticastEnabled {
		// This is what we should actually do
		pf._handleReq(req.source, &req)
	} else {
		// Now skip to the end and just pretend we got a response from the network
		target := pf.router.blooms.xKey(dest)
		for k := range pf.router.infos {
			xform := pf.router.blooms.xKey(k)
			if xform == target {
				root, path := pf.router._getRootAndPath(k)
				res := pathResponse{
					source: k,
					dest:   req.source,
					seq:    req.seq,
					root:   root,
					path:   path,
					// TODO sig
				}
				// Queue this up for later, so we can e.g. cache rumor packets first
				pf.router.Act(nil, func() {
					pf._handleRes(req.dest, &res)
				})
			}
		}
	}
}

func (pf *pathfinder) handleReq(p *peer, req *pathRequest) {
	pf.router.Act(p, func() {
		if !pf.router.blooms._isOnTree(p.key) {
			return
		}
		pf._handleReq(p.key, req)
	})
}

func (pf *pathfinder) _handleReq(fromKey publicKey, req *pathRequest) {
	// Continue the multicast
	pf.router.blooms._sendMulticast(wireProtoPathReq, req, fromKey, req.dest)
	// Check if we should send a response too
	dx := pf.router.blooms.xKey(req.dest)
	sx := pf.router.blooms.xKey(pf.router.core.crypto.publicKey)
	if dx == sx {
		// We match, send a response
		// TODO throttle this
		root, path := pf.router._getRootAndPath(pf.router.core.crypto.publicKey)
		res := pathResponse{
			source: pf.router.core.crypto.publicKey,
			dest:   req.source,
			seq:    req.seq,
			root:   root,
			path:   path,
			// TODO sig
		}
		pf._handleRes(res.source, &res)
	}
}

func (pf *pathfinder) handleRes(p *peer, res *pathResponse) {
	pf.router.Act(p, func() {
		if !pf.router.blooms._isOnTree(p.key) {
			return
		}
		pf._handleRes(p.key, res)
	})
}

func (pf *pathfinder) _handleRes(fromKey publicKey, res *pathResponse) {
	// Continue the multicast
	pf.router.blooms._sendMulticast(wireProtoPathRes, res, fromKey, res.dest)
	// Check if we should accept this response
	if res.dest != pf.router.core.crypto.publicKey {
		return
	}
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
		if info.traffic != nil {
			panic("DEBUG1")
		}
	} else {
		xform := pf.router.blooms.xKey(res.source)
		if _, isIn := pf.rumors[xform]; !isIn {
			return
		}
		key := res.source
		var timer *time.Timer
		timer = time.AfterFunc(pf.router.core.config.pathTimeout, func() {
			pf.router.Act(nil, func() {
				if info := pf.paths[key]; info.timer == timer {
					timer.Stop()
					delete(pf.paths, key)
					if info.traffic != nil {
						freeTraffic(info.traffic)
					}
				}
			})
		})
		info = pathInfo{
			reqTime: time.Now(),
			timer:   timer,
		}
		if rumor := pf.rumors[xform]; rumor.traffic != nil && rumor.traffic.dest == res.source {
			info.traffic = rumor.traffic
			rumor.traffic = nil
			pf.rumors[xform] = rumor
		}
	}
	info.path = res.path
	info.seq = res.seq
	if info.traffic != nil {
		tr := info.traffic
		info.traffic = nil
		defer pf._handleTraffic(tr, false)
		panic("DEBUG2, why isn't this happening in meshnet-lab tests?")
	}
	pf.paths[res.source] = info
	pf.router.core.config.pathNotify(res.source.toEd())
}

func (pf *pathfinder) _sendLookup(dest publicKey) {
	// TODO the real thing
	xform := pf.router.blooms.xKey(dest)
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
	pf._sendRequest(dest)
}

func (pf *pathfinder) _handleTraffic(tr *traffic, cache bool) {
	if !bloomMulticastEnabled {
		_, path := pf.router._getRootAndPath(tr.dest)
		tr.path = append(tr.path[:0], path...)
		pf.router.handleTraffic(nil, tr)
		return
	}
	if info, isIn := pf.paths[tr.dest]; isIn {
		tr.path = append(tr.path[:0], info.path...)
		if cache {
			if info.traffic != nil {
				panic("DEBUG3")
				freeTraffic(info.traffic)
			}
			info.traffic = allocTraffic()
			info.traffic.copyFrom(tr)
		}
		pf.router.handleTraffic(nil, tr)
	} else {
		pf._sendLookup(tr.dest)
		if cache {
			xform := pf.router.blooms.xKey(tr.dest)
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
}

func (pf *pathfinder) handleBroken(p *peer, pb *pathBroken) {
	pf.router.Act(p, func() {
		if !pf.router.blooms._isOnTree(p.key) {
			return
		}
		pf._handleBroken(p.key, pb)
	})
}

func (pf *pathfinder) _handleBroken(fromKey publicKey, pb *pathBroken) {
	// Continue the multicast
	pf.router.blooms._sendMulticast(wireProtoPathBroken, pb, fromKey, pb.dest)
	// Check if this is for us
	if pb.dest != pf.router.core.crypto.publicKey {
		return
	}
	if _, isIn := pf.paths[pb.broken]; !isIn {
		return
	}
	// The throttle logic happens inside sendRequest
	pf._sendRequest(pb.broken)
}

func (pf *pathfinder) _sendPathBroken(tr *traffic) {
	pb := pathBroken{
		dest:   tr.source,
		broken: tr.dest,
	}
	pf._handleBroken(pf.router.core.crypto.publicKey, &pb)
}

/************
 * pathInfo *
 ************/

type pathInfo struct {
	path    []peerPort // *not* zero terminated (and must be free of zeros)
	seq     uint64
	reqTime time.Time   // Time a request was last sent (to prevent spamming)
	timer   *time.Timer // time.AfterFunc(cleanup...), reset whenever this is used
	traffic *traffic
}

/*************
 * pathRumor *
 *************/

type pathRumor struct {
	traffic *traffic // TODO use this better, and/or add a similar buffer to pathInfo... quickly resend 1 dropped packet after we get a pathRes
	timer   *time.Timer
}

/***************
 * pathRequest *
 ***************/

type pathRequest struct {
	source publicKey
	dest   publicKey
	seq    uint64 // set by requester, used to recognize which response is which
	sig    signature
}

func (req *pathRequest) check() bool {
	return true // TODO
}

func (req *pathRequest) size() int {
	size := len(req.source)
	size += len(req.dest)
	size += wireSizeUint(req.seq)
	size += len(req.sig)
	return size
}

func (req *pathRequest) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = append(out, req.source[:]...)
	out = append(out, req.dest[:]...)
	out = wireAppendUint(out, req.seq)
	out = append(out, req.sig[:]...)
	end := len(out)
	if end-start != req.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (req *pathRequest) decode(data []byte) error {
	var tmp pathRequest
	orig := data
	if !wireChopSlice(tmp.source[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.dest[:], &orig) {
		return types.ErrDecode
	} else if !wireChopUint(&tmp.seq, &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.sig[:], &orig) {
		return types.ErrDecode
	} else if len(orig) != 0 {
		return types.ErrDecode
	}
	*req = tmp
	return nil
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

func (res *pathResponse) check() bool {
	return true // TODO, sig and also verify there aren't zeros in the path, though I guess that would make decoding fail anyway
}

func (res *pathResponse) size() int {
	size := len(res.source)
	size += len(res.dest)
	size += wireSizeUint(res.seq)
	size += len(res.root)
	size += wireSizePath(res.path)
	size += len(res.sig)
	return size
}

func (res *pathResponse) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = append(out, res.source[:]...)
	out = append(out, res.dest[:]...)
	out = wireAppendUint(out, res.seq)
	out = append(out, res.root[:]...)
	out = wireAppendPath(out, res.path)
	out = append(out, res.sig[:]...)
	end := len(out)
	if end-start != res.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (res *pathResponse) decode(data []byte) error {
	var tmp pathResponse
	orig := data
	if !wireChopSlice(tmp.source[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.dest[:], &orig) {
		return types.ErrDecode
	} else if !wireChopUint(&tmp.seq, &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.root[:], &orig) {
		return types.ErrDecode
	} else if !wireChopPath(&tmp.path, &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.sig[:], &orig) {
		return types.ErrDecode
	} else if len(orig) != 0 {
		return types.ErrDecode
	}
	*res = tmp
	return nil
}

/**************
 * pathBroken *
 **************/

// Sent when a traffic packet hits a dead-end that is not the intended destination

type pathBroken struct {
	dest   publicKey // the sender of the dropped packet
	broken publicKey // the dest of the dropped packet
}

func (pb *pathBroken) size() int {
	return len(pb.dest) + len(pb.broken)
}

func (pb *pathBroken) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = append(out, pb.dest[:]...)
	out = append(out, pb.broken[:]...)
	end := len(out)
	if end-start != pb.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (pb *pathBroken) decode(data []byte) error {
	var tmp pathBroken
	orig := data
	if !wireChopSlice(tmp.dest[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.broken[:], &orig) {
		return types.ErrDecode
	} else if len(orig) != 0 {
		return types.ErrDecode
	}
	*pb = tmp
	return nil
}
