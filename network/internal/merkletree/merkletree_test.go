package merkletree

import "testing"

func TestTree(t *testing.T) {
	var tree Tree
	var key Key
	for idx := 0; idx < 256; idx++ {
		key[0] = uint8(idx)
		tree.Add(key, GetDigest(key[:]))
	}
	for idx := 0; idx < 256; idx++ {
		key[0] = uint8(idx)
		if tree.Lookup(key, KeyBits) != GetDigest(key[:]) {
			panic("lookup failed")
		}
	}
	for idx := 0; idx < 256; idx++ {
		key[0] = uint8(idx)
		tree.Remove(key)
	}
	var blank Tree
	if tree != blank {
		panic("unclean")
	}
}
