package merkletree

import "crypto/sha512"

const (
	KeyBytes    = KeyBits / 8
	KeyBits     = 256
	DigestBytes = sha512.Size
)

type Key [KeyBytes]byte

type Tree struct {
	Root Node
}

type Node struct {
	Digest Digest
	Left   *Node
	Right  *Node
}

func (n *Node) fix() {
	var nothing Node
	if n.Left != nil && *n.Left == nothing {
		n.Left = nil
	}
	if n.Right != nil && *n.Right == nothing {
		n.Right = nil
	}
	if n.Left != nil && n.Right != nil {
		bs := make([]byte, 0, 2*DigestBytes)
		bs = append(bs, n.Left.Digest[:]...)
		bs = append(bs, n.Right.Digest[:]...)
		n.Digest = GetDigest(bs)
	} else if n.Left != nil {
		n.Digest = n.Left.Digest
	} else if n.Right != nil {
		n.Digest = n.Right.Digest
	} else {
		*n = Node{}
	}
}

type Digest [DigestBytes]byte

func GetDigest(data []byte) Digest {
	return sha512.Sum512(data)
}

func (t *Tree) Add(key Key, digest Digest) {
	var path []*Node
	here := &t.Root
	for idx := 0; idx < KeyBits; idx++ {
		path = append(path, here)
		kByte := key[idx/8]
		kBit := kByte & (0x80 >> (idx % 8))
		var next *Node
		if kBit == 0 {
			if here.Left == nil {
				here.Left = new(Node)
			}
			next = here.Left
		} else {
			if here.Right == nil {
				here.Right = new(Node)
			}
			next = here.Right
		}
		here = next
	}
	here.Digest = digest
	for idx := len(path) - 1; idx >= 0; idx-- {
		here = path[idx]
		here.fix()
	}
}

func (t *Tree) Remove(key Key) {
	// FIXME if key is not found, this allocates nodes and then resets them to 0, we should just exit early instead... or error out in some way...
	var path []*Node
	here := &t.Root
	for idx := 0; idx < KeyBits; idx++ {
		path = append(path, here)
		kByte := key[idx/8]
		kBit := kByte & (0x80 >> (idx % 8))
		var next *Node
		if kBit == 0 {
			if here.Left == nil {
				here.Left = new(Node)
			}
			next = here.Left
		} else {
			if here.Right == nil {
				here.Right = new(Node)
			}
			next = here.Right
		}
		here = next
	}
	empty := Empty()
	here.Digest = empty
	// TODO detect / delete empty digests...
	for idx := len(path) - 1; idx >= 0; idx-- {
		here = path[idx]
		here.fix()
	}
}

func (t *Tree) NodeFor(start Key, prefixLen int) (*Node, int) {
	here := &t.Root
	for idx := 0; idx < prefixLen; idx++ {
		kByte := start[idx/8]
		kBit := kByte & (0x80 >> (idx % 8))
		var next *Node
		if kBit == 0 {
			next = here.Left
		} else {
			next = here.Right
		}
		if next == nil {
			return here, idx
		}
		here = next
	}
	return here, prefixLen
}

// Lookup returns the digest assocated with the subtree indexed by start, and matching the leading prefixLen bits. A prefixLen of 0 implies the root of the tree.
func (t *Tree) Lookup(start Key, prefixLen int) Digest {
	n, i := t.NodeFor(start, prefixLen)
	if i == prefixLen {
		return n.Digest
	}
	return Empty()
}

// Empty returns a zero-valued Digest, which is used in any empty part of the tree (instead of hashing empty slices or layers of hashes thereof).
func Empty() Digest {
	return Digest{}
}

func (k *Key) SetBit(value bool, offset int) {
	if offset >= KeyBits {
		panic("TOO LONG")
		return
	}
	byteIdx := offset / 8
	var bitmask uint8
	bitmask = 0x80 >> (uint64(offset) % 8)
	if value {
		k[byteIdx] = k[byteIdx] | bitmask
	} else {
		k[byteIdx] = k[byteIdx] & ^bitmask
	}
}

func GetBitmask(length int) Key {
	if length > KeyBits {
		panic("TOO LONG")
	}
	var key Key
	// TODO set whole bytes first, only set individual bits for the last byte
	for idx := 0; idx < length; idx++ {
		key.SetBit(true, idx)
	}
	return key
}

func GetLeft(key Key, prefixLen int) Key {
	mask := GetBitmask(prefixLen)
	for idx := range key {
		key[idx] &= mask[idx]
	}
	// Child of prefixLen, so set bit at prefixLen (easy to make an off-by-1 error here)
	key.SetBit(false, prefixLen)
	return key
}

func GetRight(key Key, prefixLen int) Key {
	mask := GetBitmask(prefixLen)
	for idx := range key {
		key[idx] &= mask[idx]
	}
	key.SetBit(true, prefixLen)
	return key
}
