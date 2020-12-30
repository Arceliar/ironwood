package net

import (
	"github.com/Arceliar/phony"
)

/*******
 * dht *
 *******/

type dht struct {
	phony.Inbox
	core  *core
	infos map[string]*dhtInfo  // map[string(publicKey)]*dhtInfo, key=source
	peers map[string]*treeInfo // TODO actually keep track of / use this info
}

func (t *dht) init(c *core) {
	t.core = c
	t.infos = make(map[string]*dhtInfo)
	t.peers = make(map[string]*treeInfo)
}

func (t *dht) _lookup(dest publicKey) publicKey {
	best := t.core.crypto.publicKey
	bestPeer := best
	for _, info := range t.infos {
		if dhtOrdered(info.source, dest, best) {
			best = info.source
			bestPeer = info.prev
		}
	}
	// TODO check peers and tree for something better
	return bestPeer
}

/***********
 * dhtInfo *
 ***********/

type dhtInfo struct {
	source publicKey
	prev   publicKey
	next   publicKey
	dest   publicKey
}

/*********************
 * utility functions *
 *********************/

func dhtOrdered(first, second, third publicKey) bool {
	less12 := treeLess(first, second)
	less23 := treeLess(second, third)
	less31 := treeLess(third, first)
	switch {
	case less12 && less23:
		return true
	case less23 && less31:
		return true
	case less31 && less12:
		return true
	}
	return false
}
