package network

import (
	"time"

	"github.com/Arceliar/phony"
)

const (
	pathfinderTIMEOUT  = time.Minute
	pathfinderTHROTTLE = time.Second
)

// WARNING The pathfinder should only be used from within the dhtree's actor, it's not threadsafe
type pathfinder struct {
	dhtree *dhtree
	paths  map[publicKey]*pathInfo
}

func (pf *pathfinder) init(t *dhtree) {
	pf.dhtree = t
	pf.paths = make(map[publicKey]*pathInfo)
}

func (pf *pathfinder) handlePathTraffic(from phony.Actor, pt *pathTraffic) {
	pf.dhtree.Act(from, func() {
		// TODO save path back to res.req.source in a local path cache
		// If a path already exists, replace it if (and only if) this is higher res.seq
		var label treeLabel
		label.root = pf.dhtree.self.root
		label.rootSeq = pf.dhtree.self.seq
		label.path = pt.path
		label.key = pt.dest
		if next := pf.dhtree._treeLookup(&label); next != nil {
			next.sendPathTraffic(pf.dhtree, pt)
			//panic("DEBUG sent path traffic")
		} else {
			dt := &dhtTraffic{
				baseTraffic: pt.baseTraffic,
			}
			pf.dhtree.handleDHTTraffic(nil, dt, false)
			//panic("DEBUG fallback to DHT")
		}
	})
}

func (pf *pathfinder) _getNotify(dest publicKey) *pathNotify {
	if info, isIn := pf.paths[dest]; isIn && time.Since(info.ntime) > pathfinderTHROTTLE {
		n := &pathNotify{
			dest:  dest,
			label: pf.dhtree._getLabel(),
		}
		info.ntime = time.Now()
		return n
	}
	return nil
}

func (pf *pathfinder) _getPathInfo(dest publicKey) *pathInfo {
	var info *pathInfo
	if nfo, isIn := pf.paths[dest]; isIn {
		info = nfo
	} else {
		info = new(pathInfo)
		info.ntime = time.Now().Add(-pathfinderTHROTTLE)
		pf._updateTimer(dest, info)
		pf.paths[dest] = info
	}
	return info
}

func (pf *pathfinder) _updateTimer(dest publicKey, info *pathInfo) {
	if info.timer != nil {
		info.timer.Stop()
	}
	info.timer = time.AfterFunc(pathfinderTIMEOUT, func() {
		pf.dhtree.Act(nil, func() {
			if pf.paths[dest] == info {
				info.timer.Stop()
				delete(pf.paths, dest)
			}
		})
	})
}

func (pf *pathfinder) _getPath(dest publicKey) []peerPort {
	info := pf._getPathInfo(dest)
	pf._updateTimer(dest, info)
	var path []peerPort
	if info.path != nil {
		path = append(path, info.path...)
		path = append(path, 0)
	}
	return path
}

func (pf *pathfinder) handleNotify(from phony.Actor, n *pathNotify) {
	pf.dhtree.Act(from, func() {
		if next := pf.dhtree._dhtLookup(n.dest, false, nil); next != nil {
			next.sendPathNotify(pf.dhtree, n)
			return
		}
		if !n.dest.equal(pf.dhtree.core.crypto.publicKey) {
			return
		}
		// TODO check seq (and if we even have a pinfo)
		if pinfo, isIn := pf.paths[n.label.key]; isIn {
			if n.label.destSeq > pinfo.seq && n.check() {
				pinfo.path = n.label.path
				pinfo.seq = n.label.destSeq
			}
		}
	})
}

func (pf *pathfinder) _doNotify(dest publicKey) {
	if n := pf._getNotify(dest); n != nil {
		pf.handleNotify(nil, n) // TODO pf._handleNotify
	}
}

/* TODO actually bother to run this
The basic logic is:
  0. Add a placeholder to pathfinder.paths for nodes we care about (make sure nil path is handled)
  1. Send a pathNotify whenever we receive a non-source-routed packet
  2. Possibly send a pathRequest when we receive a pathNotify
    Check that we care about the path (pathInfo exists)
    Check that we haven't sent a lookup too recently (e.g. within the last second)
  3. Reply to pathRequest with pathResponse
  4. If we receive a pathResponse from a node we care about, save the path to pathfinder.paths
*/

/************
 * pathInfo *
 ************/

type pathInfo struct {
	path  []peerPort
	seq   uint64
	timer *time.Timer // time.AfterFunc(cleanup...), reset whenever this is used
	ntime time.Time   // Time a notify was last sent (to prevent spamming)
}

/**************
 * pathNotify *
 **************/

type pathNotify struct {
	dest  publicKey // Who to send the notify to
	label *treeLabel
}

func (pn *pathNotify) check() bool {
	return pn.label.check()
}

func (pn *pathNotify) encode(out []byte) ([]byte, error) {
	if pn.label == nil {
		return nil, wireEncodeError
	}
	var bs []byte
	var err error
	if bs, err = pn.label.encode(nil); err != nil { // TODO non-nil
		return out, err
	}
	out = append(out, pn.dest[:]...)
	out = append(out, bs...)
	return out, nil
}

func (pn *pathNotify) decode(data []byte) error {
	var tmp pathNotify
	tmp.label = new(treeLabel)
	if !wireChopSlice(tmp.dest[:], &data) {
		return wireDecodeError
	} else if err := tmp.label.decode(data); err != nil {
		return err
	}
	*pn = tmp
	return nil
}

/***************
 * pathTraffic *
 ***************/

type pathTraffic struct {
	path []peerPort
	baseTraffic
}

func (pt *pathTraffic) encode(out []byte) ([]byte, error) {
	out = wireEncodePath(out, pt.path)
	return pt.baseTraffic.encode(out)
}

func (pt *pathTraffic) decode(data []byte) error {
	var tmp pathTraffic
	if !wireChopPath(&tmp.path, &data) {
		return wireDecodeError
	} else if err := tmp.baseTraffic.decode(data); err != nil {
		return err
	}
	*pt = tmp
	return nil
}
