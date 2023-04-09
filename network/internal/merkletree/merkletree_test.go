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
		if digest, ok := tree.Lookup(key, KeyBits); !ok || digest != GetDigest(key[:]) {
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
	// Try to delete everything again, make sure nothing crashes
	for idx := 0; idx < 256; idx++ {
		key[0] = uint8(idx)
		tree.Remove(key)
	}
}
