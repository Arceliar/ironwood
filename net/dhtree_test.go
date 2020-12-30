package net

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestTreeInfo(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	info := new(treeInfo)
	info.root = publicKey(pub)
	for idx := 0; idx < 10; idx++ {
		newPub, newPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		info = info.add(privateKey(priv), publicKey(newPub))
		if !info.checkSigs() {
			panic("checkSigs failed")
		} else if !info.checkLoops() {
			panic("checkLoops failed")
		}
		pub, priv = newPub, newPriv
	}
	bs, err := info.MarshalBinary()
	if err != nil {
		panic(err)
	}
	newInfo := new(treeInfo)
	err = newInfo.UnmarshalBinary(bs)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(info.root, newInfo.root) {
		panic("unequal roots")
	}
	if len(newInfo.hops) != len(info.hops) {
		panic("unequal number of hops")
	}
	for idx := range newInfo.hops {
		newHop := newInfo.hops[idx]
		hop := info.hops[idx]
		if !bytes.Equal(newHop.next, hop.next) {
			panic("unequal next")
		}
		if !bytes.Equal(newHop.sig, hop.sig) {
			panic("unequal sig")
		}
	}
	if !newInfo.checkSigs() {
		panic("new checkSigs failed")
	} else if !newInfo.checkLoops() {
		panic("new checkLoops failed")
	}
}
