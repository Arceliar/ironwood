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

func (pf *pathfinder) _getNotify(dest publicKey, keepAlive bool) *pathNotify {
	throttle := pathfinderTHROTTLE
	if keepAlive {
		throttle = pathfinderTIMEOUT
	}
	if info, isIn := pf.paths[dest]; isIn && time.Since(info.ntime) > throttle {
		n := new(pathNotify)
		n.label = pf.dhtree._getLabel()
		n.dest = dest
		ibytes, err := n.label.encode(nil) // TODO non-nil
		if err != nil {
			panic("this should never happen")
		}
		var bs []byte
		bs = append(bs, dest[:]...)
		bs = append(bs, ibytes...)
		n.sig = pf.dhtree.core.crypto.privateKey.sign(bs)
		info.ntime = time.Now()
		return n
	}
	return nil
}

func (pf *pathfinder) _getPath(dest publicKey) []peerPort {
	var info *pathInfo
	if nfo, isIn := pf.paths[dest]; isIn {
		info = nfo
		info.timer.Stop()
		// TODO? Check info.ntime and possibly send a notify?
	} else {
		info = new(pathInfo)
		info.ltime = time.Now().Add(-pathfinderTHROTTLE)
		info.ntime = time.Now().Add(-pathfinderTHROTTLE)
		pf.paths[dest] = info
	}
	info.timer = time.AfterFunc(pathfinderTIMEOUT, func() {
		pf.dhtree.Act(nil, func() {
			if pf.paths[dest] == info {
				info.timer.Stop()
				delete(pf.paths, dest)
			}
		})
	})
	return info.path
}

func (pf *pathfinder) handleNotify(from phony.Actor, n *pathNotify) {
	pf.dhtree.Act(from, func() {
		if next := pf.dhtree._dhtLookup(n.dest, false); next != nil {
			next.sendPathNotify(pf.dhtree, n)
		} else if info, isIn := pf.paths[n.label.key]; isIn {
			info.path = append(info.path[:0], n.label.path...)
			info.path = append(info.path, 0)
		}
	})
}

func (pf *pathfinder) _doNotify(dest publicKey, keepAlive bool) {
	if n := pf._getNotify(dest, keepAlive); n != nil {
		pf.handleNotify(nil, n) // TODO pf._handleNotify
	}
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
	sig   signature // TODO? remove this? is it really useful for anything?...
	dest  publicKey // Who to send the notify to
	label *treeLabel
}

func (pn *pathNotify) check() bool {
	if !pn.label.check() {
		return false
	}
	ibytes, err := pn.label.encode(nil) // TODO non-nil
	if err != nil {
		return false
	}
	var bs []byte
	bs = append(bs, pn.dest[:]...)
	bs = append(bs, ibytes...)
	dest := pn.label.key
	return dest.verify(bs, &pn.sig)
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
	out = append(out, pn.sig[:]...)
	out = append(out, pn.dest[:]...)
	out = append(out, bs...)
	return out, nil
}

func (pn *pathNotify) decode(data []byte) error {
	var tmp pathNotify
	tmp.label = new(treeLabel)
	if !wireChopSlice(tmp.sig[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.dest[:], &data) {
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
	dt   dhtTraffic
}

func (t *pathTraffic) encode(out []byte) ([]byte, error) {
	out = wireEncodePath(out, t.path)
	return t.dt.encode(out)
}

func (t *pathTraffic) decode(data []byte) error {
	var tmp pathTraffic
	if !wireChopPath(&tmp.path, &data) {
		return wireDecodeError
	} else if err := tmp.dt.decode(data); err != nil {
		return err
	}
	*t = tmp
	return nil
}

func pathPopFirstHop(data []byte) (peerPort, []byte) {
	u, l := wireDecodeUint(data)
	copy(data, data[l:]) // Shift data forward, because we pool []byte
	return peerPort(u), data[:len(data)-l]
}
