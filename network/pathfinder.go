package network

import (
	"time"

	"github.com/Arceliar/ironwood/types"
)

// TODO we should make infos delay timeout as long as they keep *receiving* traffic, not sending
//  We want a node that restarts (and resets seq) to be reachable again after the timeout

// TODO we shouldn't have request and response both be multicast.
//  It probably makes sense for traffic and requests to both include the source's path
//  Then the response could be greedy routed as unicast traffic

// TODO? fix asymmetry in request/response
//  Requests are unsigned (by necessity) and smaller than responses
//  This means it can be used for traffic amplification -- the response traffic is bigger by at least a sig
//  We could sort-of fix that by foricng request traffic to include padding for a sig (and maybe an extra copy of the source path, to approximately match dest path size)
//  Need to think about how much of a vulnerability this really is (the extra is probably small compared to E.G. TCP/IP overheads on the underlying link layer traffic

const pathfinderTrafficCache = true

// WARNING The pathfinder should only be used from within the router's actor, it's not threadsafe
type pathfinder struct {
	router *router
	info   pathResponseInfo
	paths  map[publicKey]pathInfo
	rumors map[publicKey]pathRumor
}

func (pf *pathfinder) init(r *router) {
	pf.router = r
	pf.info.sign(pf.router.core.crypto.privateKey)
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
	req := pathRequest{
		source: pf.router.core.crypto.publicKey,
		dest:   dest,
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
				_, path := pf.router._getRootAndPath(k)
				pf.info.seq++
				res := pathResponse{
					source: k,
					dest:   req.source,
					info: pathResponseInfo{
						seq:  pf.info.seq,
						path: path,
					},
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
		// TODO? throttle this per dest that we're sending a response to?
		_, path := pf.router._getRootAndPath(pf.router.core.crypto.publicKey)
		res := pathResponse{
			source: pf.router.core.crypto.publicKey,
			dest:   req.source,
			info: pathResponseInfo{
				seq:  pf.info.seq,
				path: path,
			},
		}
		if !pf.info.equal(res.info) {
			res.info.seq++
			res.info.sign(pf.router.core.crypto.privateKey)
			pf.info = res.info
		} else {
			res.info = pf.info
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
	var info pathInfo
	var isIn bool
	// Note that we need to res.check() in every case (as soon as success is otherwise inevitable)
	if info, isIn = pf.paths[res.source]; isIn {
		if res.info.seq <= info.seq {
			// This isn't newer than the last seq we received, so drop it
			return
		}
		nfo := res.info
		nfo.path = info.path
		if nfo.equal(res.info) {
			// This doesn't actually add anything new, so skip it
			return
		}
		if !res.check() {
			return
		}
		info.timer.Reset(pf.router.core.config.pathTimeout)
		info.path = res.info.path
		info.seq = res.info.seq
	} else {
		xform := pf.router.blooms.xKey(res.source)
		if _, isIn := pf.rumors[xform]; !isIn {
			return
		}
		if !res.check() {
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
	info.path = res.info.path
	info.seq = res.info.seq
	if info.traffic != nil {
		tr := info.traffic
		info.traffic = nil
		// We defer so it happens after we've store the updated info in the map
		defer pf._handleTraffic(tr)
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

func (pf *pathfinder) _handleTraffic(tr *traffic) {
	const cache = pathfinderTrafficCache // TODO make this unconditional, this is just to easily toggle the cache on/off for now
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
				freeTraffic(info.traffic)
			}
			info.traffic = allocTraffic()
			info.traffic.copyFrom(tr)
			pf.paths[tr.dest] = info
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

func (pf *pathfinder) _doBroken(tr *traffic) {
	req := pathRequest{
		source: tr.source,
		dest:   tr.dest,
	}
	pf.router.blooms._sendMulticast(wireProtoPathReq, &req, pf.router.core.crypto.publicKey, req.dest)
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
}

func (req *pathRequest) size() int {
	size := len(req.source)
	size += len(req.dest)
	return size
}

func (req *pathRequest) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = append(out, req.source[:]...)
	out = append(out, req.dest[:]...)
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
	} else if len(orig) != 0 {
		return types.ErrDecode
	}
	*req = tmp
	return nil
}

/********************
 * pathResponseInfo *
 ********************/

type pathResponseInfo struct {
	seq  uint64     // sequence number for this update, TODO only keep this, instead of the seq in the pathfinder itself?
	path []peerPort // Path from root to source, aka coords, zero-terminated
	sig  signature  // signature from the source key
}

// equal returns true if the pathResponseInfos are equal, inspecting the contents of the path and ignoring the sig
func (info *pathResponseInfo) equal(cmp pathResponseInfo) bool {
	if info.seq != cmp.seq {
		return false
	} else if len(info.path) != len(cmp.path) {
		return false
	}
	for idx := range info.path {
		if info.path[idx] != cmp.path[idx] {
			return false
		}
	}
	return true
}

func (info *pathResponseInfo) bytesForSig() []byte {
	var out []byte
	out = wireAppendUint(out, info.seq)
	out = wireAppendPath(out, info.path)
	return out
}

func (info *pathResponseInfo) sign(key privateKey) {
	info.sig = key.sign(info.bytesForSig())
}

func (info *pathResponseInfo) size() int {
	size := wireSizeUint(info.seq)
	size += wireSizePath(info.path)
	size += len(info.sig)
	return size
}

func (info *pathResponseInfo) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendUint(out, info.seq)
	out = wireAppendPath(out, info.path)
	out = append(out, info.sig[:]...)
	end := len(out)
	if end-start != info.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (info *pathResponseInfo) decode(data []byte) error {
	var tmp pathResponseInfo
	orig := data
	if !wireChopUint(&tmp.seq, &orig) {
		return types.ErrDecode
	} else if !wireChopPath(&tmp.path, &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.sig[:], &orig) {
		return types.ErrDecode
	} else if len(orig) != 0 {
		return types.ErrDecode
	}
	*info = tmp
	return nil
}

/****************
 * pathResponse *
 ****************/

type pathResponse struct {
	source publicKey // who sent the response, not who resquested it
	dest   publicKey // exact key we are sending response to
	info   pathResponseInfo
}

func (res *pathResponse) check() bool {
	if !bloomMulticastEnabled {
		return true
	}
	return res.source.verify(res.info.bytesForSig(), &res.info.sig)
}

func (res *pathResponse) size() int {
	size := len(res.source)
	size += len(res.dest)
	size += res.info.size()
	return size
}

func (res *pathResponse) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = append(out, res.source[:]...)
	out = append(out, res.dest[:]...)
	var err error
	if out, err = res.info.encode(out); err != nil {
		return nil, err
	}
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
	} else if err := tmp.info.decode(orig); err != nil {
		return err
	}
	*res = tmp
	return nil
}
