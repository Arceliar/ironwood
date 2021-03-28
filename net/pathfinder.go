package net

import (
	"time"
)

const (
	pathfinderTIMEOUT  = time.Minute
	pathfinderTHROTTLE = time.Second
)

// WARNING The pathfinder should only be used from within the dhtree's actor, it's not threadsafe
type pathfinder struct {
	dhtree *dhtree
	paths  map[string]*pathInfo
}

func (pf *pathfinder) init(t *dhtree) {
	pf.dhtree = t
	pf.paths = make(map[string]*pathInfo)
}

func (pf *pathfinder) newNotify(dest publicKey) *pathNotify {
	n := new(pathNotify)
	n.info = pf.dhtree.self
	n.dest = dest
	ibytes, err := n.info.MarshalBinary()
	if err != nil {
		panic("this should never happen")
	}
	var bs []byte
	bs = append(bs, dest...)
	bs = append(bs, ibytes...)
	n.sig = pf.dhtree.core.crypto.privateKey.sign(bs)
	if info, isIn := pf.paths[string(dest)]; isIn {
		info.ntime = time.Now()
	}
	return n
}

func (pf *pathfinder) getLookup(n *pathNotify) *pathLookup {
	if info, isIn := pf.paths[string(n.info.dest())]; isIn {
		if time.Since(info.ltime) < pathfinderTHROTTLE {
			return nil
		}
		l := new(pathLookup)
		l.notify = *n
		info.ltime = time.Now()
		return l
	}
	return nil
}

func (pf *pathfinder) getLookupResponse(l *pathLookup) *pathLookupResponse {
	// Check if lookup comes from us
	dest := l.notify.info.dest()
	if !dest.equal(pf.dhtree.core.crypto.publicKey) || !l.notify.check() {
		// TODO? skip l.notify.check()? only check the last hop?
		return nil
	}
	r := new(pathLookupResponse)
	r.from = pf.dhtree.core.crypto.publicKey
	r.path = l.rpath
	return r
}

func (pf *pathfinder) getPath(dest publicKey) []peerPort {
	var info *pathInfo
	if nfo, isIn := pf.paths[string(dest)]; isIn {
		info = nfo
		info.timer.Stop()
		// TODO? Check info.ntime and possibly send a notify?
	} else {
		info = new(pathInfo)
		info.ltime = time.Now().Add(-pathfinderTHROTTLE)
		info.ntime = time.Now().Add(-pathfinderTHROTTLE)
	}
	info.timer = time.AfterFunc(pathfinderTIMEOUT, func() {
		pf.dhtree.Act(nil, func() {
			if pf.paths[string(dest)] == info {
				delete(pf.paths, string(dest))
			}
		})
	})
	return info.path
}

/* TODO actually bother to run this
The basic logic is:
  0. Add a placeholder to pathfinder.paths for nodes we care about (make sure nil path is handled)
  1. Send a pathNotify whenever we receive a non-source-routed packet
  2. Possibly send a pathLookup when we receive a pathNotify
    Check that we care about the path (pathInfo exists)
    Check that we haven't sent a lookup too recently (e.g. within the last second)
  3. Reply to pathLookup with pathLookupResponse
  4. If we receive a pathLookupResponse from a node we care about, save the path to pathfinder.paths
*/

/************
 * pathInfo *
 ************/

type pathInfo struct {
	path  []peerPort
	timer *time.Timer // time.AfterFunc(cleanup...), reset whenever this is used
	ltime time.Time   // Time a lookup was last sent
	ntime time.Time   // Time a notify was last sent (to periodically try to optimize paths)
}

/**************
 * pathNotify *
 **************/

type pathNotify struct {
	sig  signature
	dest publicKey // Who to send the notify to
	info *treeInfo
}

func (pn *pathNotify) check() bool {
	if len(pn.info.hops) > 0 {
		if !pn.info.checkLoops() || !pn.info.checkSigs() {
			return false
		}
	}
	ibytes, err := pn.info.MarshalBinary()
	if err != nil {
		return false
	}
	var bs []byte
	bs = append(bs, pn.dest...)
	bs = append(bs, ibytes...)
	dest := pn.info.dest()
	return dest.verify(bs, pn.sig)
}

/**************
 * pathLookup *
 **************/

type pathLookup struct {
	notify pathNotify
	rpath  []peerPort
}

// TODO logic to forward this towards pathLookup.notify.info via the tree
//   Append a port number back to the previous hop to path along the way

/**********************
 * pathLookupResponse *
 **********************/

type pathLookupResponse struct {
	// TODO? a sig or something? Since we can't sign the rpath, which is the part we care about...
	from  publicKey
	path  []peerPort
	rpath []peerPort
}

// TODO a counter or something to skip hops of path? Otherwise we'll need to truncate along the way...

/***************
 * pathTraffic *
 ***************/

// TODO source routed packet format
//  Should contain a full dhtTraffic packet to fall back to if source routing fails

type pathTraffic struct {
	path []peerPort
	dt   dhtTraffic
}
