package net

import (
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
		if !info.check() {
			panic("check failed")
		}
		pub, priv = newPub, newPriv
	}
}
