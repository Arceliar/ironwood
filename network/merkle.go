package network

import (
	"github.com/Arceliar/ironwood/network/internal/merkletree"
	"github.com/Arceliar/ironwood/types"
)

// TODO make all this stuff reply over all peer links for a given node, not just the one that happened to send the message

type merkle struct {
	router *router
	merks  map[publicKey]merkletree.Tree
	reqs   map[publicKey][]merkleReq // Note that we rely on having a fixed ordering of messages
}

func (m *merkle) init(r *router) {
	m.router = r
	m.merks = make(map[publicKey]merkletree.Tree)
	m.reqs = make(map[publicKey][]merkleReq)
}

func (m *merkle) _add(key publicKey) {
	m.merks[key] = merkletree.Tree{}
}

func (m *merkle) _remove(key publicKey) {
	delete(m.merks, key)
	delete(m.reqs, key)
}

func (m *merkle) _flush(p *peer) {
	for _, req := range m.reqs[p.key] {
		request := req
		p.sendMerkleReq(m.router, &request)
	}
}

func (m *merkle) _fixMerks() {
	// FIXME this is pretty bad
	//  We shouldn't recreate the merkle tree from scratch to compare with the existing root hash
	//  We should just update the existing tree as-needed (minimize hashing)
	var merk merkletree.Tree
	var selfDists map[publicKey]uint64
	if !bloomMulticastEnabled {
		for k, info := range m.router.infos {
			ann := info.getAnnounce(k)
			bs, err := ann.encode(nil)
			if err != nil {
				panic("this should never happen")
			}
			digest := merkletree.GetDigest(bs)
			merk.Add(merkletree.Key(k), digest)
		}
	} else {
		_, selfDists = m.router._getRootAndDists(m.router.core.crypto.publicKey)
	}
	for k, orig := range m.merks {
		if _, isIn := m.reqs[k]; isIn {
			// We're already syncing with this node, so skip it for now
			continue
		}
		if !bloomMulticastEnabled {
			// Merk is already in the right state, don't touch it
		} else {
			merk = merkletree.Tree{}
			_, peerDists := m.router._getRootAndDists(k)
			for k := range selfDists {
				if info, isIn := m.router.infos[k]; isIn {
					ann := info.getAnnounce(k)
					bs, err := ann.encode(nil)
					if err != nil {
						panic("this should never happen")
					}
					digest := merkletree.GetDigest(bs)
					merk.Add(merkletree.Key(k), digest)
				} else {
					panic("this should never happen")
				}
			}
			for k := range peerDists {
				if _, isIn := selfDists[k]; isIn {
					continue
				}
				if info, isIn := m.router.infos[k]; isIn {
					ann := info.getAnnounce(k)
					bs, err := ann.encode(nil)
					if err != nil {
						panic("this should never happen")
					}
					digest := merkletree.GetDigest(bs)
					merk.Add(merkletree.Key(k), digest)
				} else {
					panic("this should never happen")
				}
			}
		}
		if merk.Root.Digest == orig.Root.Digest {
			continue
		}
		m.merks[k] = merk
		var notify merkleNotify
		for p := range m.router.peers[k] {
			p.sendMerkleNotify(m.router, &notify)
		}
		m._handleNotify(k, &notify)
	}
}

func (m *merkle) handleNotify(p *peer, notify *merkleNotify) {
	m.router.Act(p, func() {
		m._handleNotify(p.key, notify)
	})
}

func (m *merkle) _handleNotify(peerKey publicKey, notify *merkleNotify) {
	reqs, isIn := m.reqs[peerKey]
	if isIn {
		// There's already a sync ongoing, so skip it
		return
	}
	var req merkleReq
	reqs = append(reqs, req)
	m.reqs[peerKey] = reqs
	for p := range m.router.peers[peerKey] {
		p.sendMerkleReq(m.router, &req)
	}
}

func (m *merkle) handleReq(p *peer, req *merkleReq) {
	m.router.Act(p, func() {
		merk := m.merks[p.key]
		node, plen := merk.NodeFor(merkletree.Key(req.prefix), int(req.prefixLen))
		if uint64(plen) != req.prefixLen {
			// We don't know anyone from the part of the network we were asked about, so we can't respond in any useful way
			end := merkleEnd{*req}
			p.sendMerkleEnd(m.router, &end)
			return
		}
		/*
			// This is the "safe" but extra inefficient version of things
			res := new(routerMerkleRes)
			res.prefixLen = req.prefixLen
			res.prefix = req.prefix
			res.digest = node.Digest
			p.sendMerkleRes(r, res)
			if res.prefixLen == merkletree.KeyBits {
				if info, isIn := r.infos[res.prefix]; isIn {
					p.sendAnnounce(r, info.getAnnounce(res.prefix))
				} else {
					panic("this should never happen")
				}
			}
			return
		*/
		// This is the slightly less inefficient but very delicate version of things
		// Basically, if we get to a node that only has 1 child, follow it until we have 2 (or reach the end, to send a node announcement instead)
		// TODO we need to test this thoroughly
		prefixLen := req.prefixLen
		prefix := req.prefix
		for {
			if node.Left != nil && node.Right != nil {
				res := new(merkleRes)
				res.prefixLen = prefixLen
				res.prefix = prefix
				res.digest = node.Digest
				res.end = merkleEnd{*req}
				p.sendMerkleRes(m.router, res)
			} else if node.Left != nil {
				offset := int(prefixLen)
				prefixLen += 1
				k := merkletree.Key(prefix)
				k.SetBit(false, offset)
				prefix = publicKey(k)
				node = node.Left
				continue
			} else if node.Right != nil {
				offset := int(prefixLen)
				prefixLen += 1
				k := merkletree.Key(prefix)
				k.SetBit(true, offset)
				prefix = publicKey(k)
				node = node.Right
				continue
			} else {
				if prefixLen != merkletree.KeyBits {
					panic("this should never happen")
				}
				if info, isIn := m.router.infos[prefix]; isIn {
					p.sendAnnounce(m.router, info.getAnnounce(prefix))
					end := merkleEnd{*req}
					p.sendMerkleEnd(m.router, &end)
				} else {
					panic("this should never happen")
				}
			}
			break
		}
	})
}

func (m *merkle) handleRes(p *peer, res *merkleRes) {
	m.router.Act(p, func() {
		reqs := m.reqs[p.key]
		if len(reqs) == 0 || reqs[0] != res.end.merkleReq {
			// This is not the response we're looking for
			return
		}
		defer m._handleEnd(p, &res.end)
		if res.prefixLen == merkletree.KeyBits {
			// This is a response to a full key, we can't ask for children, and there's nothing useful to do with it right now.
			return
		}
		merk := m.merks[p.key]
		if digest, ok := merk.Lookup(merkletree.Key(res.prefix), int(res.prefixLen)); !ok || digest != res.digest {
			// We disagree, so ask about the left and right children
			left := merkleReq{
				prefixLen: res.prefixLen + 1,
				prefix:    publicKey(merkletree.GetLeft(merkletree.Key(res.prefix), int(res.prefixLen))),
			}
			if !left.check() {
				panic("this should never happen")
			}
			p.sendMerkleReq(m.router, &left)
			right := merkleReq{
				prefixLen: res.prefixLen + 1,
				prefix:    publicKey(merkletree.GetRight(merkletree.Key(res.prefix), int(res.prefixLen))),
			}
			if !right.check() {
				panic("this should never happen")
			}
			p.sendMerkleReq(m.router, &right)
			// Save that we sent these, in order
			reqs = append(reqs, left)
			reqs = append(reqs, right)
			m.reqs[p.key] = reqs
		}
	})
}

func (m *merkle) handleEnd(p *peer, end *merkleEnd) {
	m.router.Act(p, func() {
		m._handleEnd(p, end)
	})
}

func (m *merkle) _handleEnd(p *peer, end *merkleEnd) {
	if reqs := m.reqs[p.key]; len(reqs) > 0 && reqs[0] == end.merkleReq {
		reqs = reqs[1:]
		if len(reqs) > 0 {
			m.reqs[p.key] = reqs
		} else {
			delete(m.reqs, p.key)
			m._fixMerks()
		}
	}
}

/****************
 * merkleNotify *
 ****************/

type merkleNotify struct{}

func (n *merkleNotify) size() int {
	return 0
}

func (n *merkleNotify) encode(out []byte) ([]byte, error) {
	return out, nil
}

func (n *merkleNotify) decode(data []byte) error {
	if len(data) != 0 {
		return types.ErrDecode
	}
	return nil
}

/*******************
 * merkleReq *
 *******************/

type merkleReq struct {
	prefixLen uint64
	prefix    publicKey
}

func (req *merkleReq) check() bool {
	return req.prefixLen <= merkletree.KeyBits
}

func (req *merkleReq) size() int {
	size := wireSizeUint(req.prefixLen)
	size += len(req.prefix)
	return size
}

func (req *merkleReq) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendUint(out, req.prefixLen)
	out = append(out, req.prefix[:]...)
	end := len(out)
	if end-start != req.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (req *merkleReq) chop(data *[]byte) error {
	var tmp merkleReq
	orig := *data
	if !wireChopUint(&tmp.prefixLen, &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.prefix[:], &orig) {
		return types.ErrDecode
	}
	*req = tmp
	*data = orig
	return nil
}

func (req *merkleReq) decode(data []byte) error {
	var tmp merkleReq
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return types.ErrDecode
	}
	*req = tmp
	return nil
}

/*******************
* merkleRes *
*******************/

type merkleRes struct {
	merkleReq
	digest merkletree.Digest
	end    merkleEnd // TODO update methods to use this below
}

func (res *merkleRes) size() int {
	size := res.merkleReq.size()
	size += len(res.digest)
	size += res.end.size()
	return size
}

func (res *merkleRes) encode(out []byte) ([]byte, error) {
	start := len(out)
	var err error
	if out, err = res.merkleReq.encode(out); err != nil {
		return nil, err
	}
	out = append(out, res.digest[:]...)
	if out, err = res.end.encode(out); err != nil {
		return nil, err
	}
	end := len(out)
	if end-start != res.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (res *merkleRes) chop(data *[]byte) error {
	var tmp merkleRes
	orig := *data
	if err := tmp.merkleReq.chop(&orig); err != nil {
		return err
	} else if !wireChopSlice(tmp.digest[:], &orig) {
		return types.ErrDecode
	} else if err := tmp.end.chop(&orig); err != nil {
		return err
	}
	*res = tmp
	*data = orig
	return nil
}

func (res *merkleRes) decode(data []byte) error {
	var tmp merkleRes
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return types.ErrDecode
	}
	*res = tmp
	return nil
}

/*******************
 * merkleEnd *
 *******************/

type merkleEnd struct {
	merkleReq
}
