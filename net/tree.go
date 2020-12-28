package net

import "bytes"

/********
 * tree *
 ********/

type tree struct {
	core  *core
	infos map[string]*treeInfo // map[string(publicKey)]*treeInfo
	self  *treeInfo            // self info
}

func (t *tree) init(c *core) {
	t.core = c
	t.infos = make(map[string]*treeInfo)
	t.self = &treeInfo{root: t.core.crypto.publicKey}
}

func (t *tree) update(info *treeInfo) {
	// The tree info should have been checked before this point
	key := info.from()
	t.infos[string(key)] = info
	if bytes.Equal(key, t.self.from()) {
		t.self = nil
	}
	t.fix()
}

func (t *tree) remove(info *treeInfo) {
	key := info.from()
	delete(t.infos, string(key))
	if bytes.Equal(key, t.self.from()) {
		t.self = nil
		t.fix()
	}
}

func (t *tree) fix() {
	if t.self == nil || treeLess(t.self.root, t.core.crypto.publicKey) {
		t.self = &treeInfo{root: t.core.crypto.publicKey}
	}
	for _, info := range t.infos {
		switch {
		case treeLess(t.self.root, info.root):
			// This is a better root
			t.self = info
		case treeLess(info.root, t.self.root):
			// This is a worse root, so don't do anything with it
		case len(info.hops) < len(t.self.hops):
			// This is a shorter path to the root
			t.self = info
		case len(info.hops) > len(t.self.hops):
			// This is a longer path to the root, so don't do anything with it
		case treeLess(t.self.from(), info.from()):
			// This peer has a higher key than our current parent
			t.self = info
		}
	}
	panic("TODO fix, send changes")
}

/************
 * treeInfo *
 ************/

type treeInfo struct {
	root publicKey
	hops []treeHop
}

type treeHop struct {
	next publicKey
	sig  signature
}

func (info *treeInfo) from() publicKey {
	key := info.root
	if len(info.hops) > 1 {
		// last hop is to this node, 2nd to last is to the previous hop, which is who this is from
		hop := info.hops[len(info.hops)-2]
		key = hop.next
	}
	return key
}

func (info *treeInfo) check() bool {
	var bs []byte
	key := info.root
	keys := make(map[string]bool) // Used to avoid loops
	bs = append(bs, info.root...)
	for _, hop := range info.hops {
		if keys[string(key)] {
			return false
		}
		keys[string(key)] = true
		bs = append(bs, hop.next...)
		if !key.verify(bs, hop.sig) {
			return false
		}
		key = hop.next
	}
	return true
}

func (info *treeInfo) add(priv privateKey, next publicKey) *treeInfo {
	newInfo := *info
	newInfo.hops = append([]treeHop(nil), info.hops...)
	var bs []byte
	bs = append(bs, info.root...)
	for _, hop := range info.hops {
		bs = append(bs, hop.next...)
	}
	bs = append(bs, next...)
	sig := priv.sign(bs)
	newInfo.hops = append(info.hops, treeHop{next: next, sig: sig})
	return &newInfo
}

func (info *treeInfo) MarshalBinary() (data []byte, err error) {
	data = append(data, info.root...)
	for _, hop := range info.hops {
		data = append(data, hop.next...)
		data = append(data, hop.sig...)
	}
	return
}

func (info *treeInfo) UnmarshalBinary(data []byte) error {
	nfo := treeInfo{}
	if !wireChopBytes((*[]byte)(&nfo.root), &data, publicKeySize) {
		return wireUnmarshalBinaryError
	}
	for len(data) > 0 {
		hop := treeHop{}
		switch {
		case !wireChopBytes((*[]byte)(&hop.next), &data, publicKeySize):
			return wireUnmarshalBinaryError
		case !wireChopBytes((*[]byte)(&hop.sig), &data, signatureSize):
			return wireUnmarshalBinaryError
		}
		nfo.hops = append(nfo.hops, hop)
	}
	*info = nfo
	return nil
}

/*********************
 * utility functions *
 *********************/

func treeLess(key1, key2 publicKey) bool {
	for idx := range key1 {
		switch {
		case key1[idx] < key2[idx]:
			return true
		case key1[idx] > key2[idx]:
			return false
		}
	}
	return false
}
