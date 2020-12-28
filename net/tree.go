package net

/********
 * tree *
 ********/

type tree struct {
	core  *core
	infos map[string]*treeInfo // map[string(publicKey)]*treeInfo
	self  *treeInfo            // self coords, parent, etc
}

func (t *tree) init(c *core) {
	t.core = c
	t.infos = make(map[string]*treeInfo)
	t.self = &treeInfo{root: t.core.crypto.publicKey}
}

func (t *tree) handleInfo(info *treeInfo) {
	panic("TODO handleInfo")
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

func (t *treeInfo) check() bool {
	panic("TODO: check, prepare bytes and validate")
	return true
}

func (t *treeInfo) add(next publicKey) *treeInfo {
	info := *t
	info.hops = append([]treeHop(nil), info.hops...)
	var sig signature
	panic("TODO add, prepare bytes and sign")
	info.hops = append(info.hops, treeHop{next: next, sig: sig})
	return &info
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
