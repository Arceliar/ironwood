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
		kBit := kByte & (0x80 >> idx % 8)
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
	empty := Empty()
	for idx := len(path) - 1; idx >= 0; idx-- {
		bs := make([]byte, 0, 2*DigestBytes)
		here = path[idx]
		if here.Left != nil {
			bs = append(bs, here.Left.Digest[:]...)
		} else {
			bs = append(bs, empty[:]...)
		}
		if here.Right != nil {
			bs = append(bs, here.Right.Digest[:]...)
		} else {
			bs = append(bs, empty[:]...)
		}
		here.Digest = GetDigest(bs)
	}
}

func (t *Tree) Remove(key Key) {
	// FIXME if key is not found, this allocates nodes and then resets them to 0, we should just exit early instead... or error out in some way...
	var path []*Node
	here := &t.Root
	for idx := 0; idx < KeyBits; idx++ {
		path = append(path, here)
		kByte := key[idx/8]
		kBit := kByte & (0x80 >> idx % 8)
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
		bs := make([]byte, 0, 2*DigestBytes)
		here = path[idx]
		if here.Left != nil && here.Left.Digest == Empty() {
			here.Left = nil
		}
		if here.Right != nil && here.Right.Digest == Empty() {
			here.Right = nil
		}
		if here.Left == nil && here.Right == nil {
			here.Digest = Empty()
			continue
		}
		if here.Left != nil {
			bs = append(bs, here.Left.Digest[:]...)
		} else {
			bs = append(bs, empty[:]...)
		}
		if here.Right != nil {
			bs = append(bs, here.Right.Digest[:]...)
		} else {
			bs = append(bs, empty[:]...)
		}
		here.Digest = GetDigest(bs)
	}
}

// Lookup returns the digest assocated with the subtree indexed by start, and matching the leading prefixLen bits. A prefixLen of 0 implies the root of the tree.
func (t *Tree) Lookup(start Key, prefixLen int) Digest {
	here := &t.Root
	for idx := 0; idx < prefixLen; idx++ {
		kByte := start[idx/8]
		kBit := kByte & (0x80 >> idx % 8)
		var next *Node
		if kBit == 0 {
			next = here.Left
		} else {
			next = here.Right
		}
		if next == nil {
			return Empty()
		}
		here = next
	}
	return here.Digest
}

// Empty returns a zero-valued Digest, which is used in any empty part of the tree (instead of hashing empty slices or layers of hashes thereof).
func Empty() Digest {
	return Digest{}
}

func GetLeft(key Key, prefixLen int) Key {
	panic("TODO")
	return Key{}
}

func GetRight(key Key, prefixLen int) Key {
	panic("TODO")
}
