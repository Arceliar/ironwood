package network

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestMarshalTreeInfo(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	var sk privateKey
	copy(sk[:], priv)
	info := new(treeInfo)
	copy(info.root[:], pub)
	for idx := 0; idx < 10; idx++ {
		newPub, newPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		var pk publicKey
		copy(pk[:], newPub)
		info = info.add(sk, &peer{key: pk})
		if !info.checkSigs() {
			t.Log(len(info.hops))
			t.Log(info.hops[len(info.hops)-1].sig)
			panic("checkSigs failed")
		} else if !info.checkLoops() {
			panic("checkLoops failed")
		}
		copy(sk[:], newPriv)
	}
	bs, err := info.encode(nil)
	if err != nil {
		panic(err)
	}
	newInfo := new(treeInfo)
	err = newInfo.decode(bs)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(info.root[:], newInfo.root[:]) {
		panic("unequal roots")
	}
	if len(newInfo.hops) != len(info.hops) {
		panic("unequal number of hops")
	}
	for idx := range newInfo.hops {
		newHop := newInfo.hops[idx]
		hop := info.hops[idx]
		if !bytes.Equal(newHop.next[:], hop.next[:]) {
			panic("unequal next")
		}
		if !bytes.Equal(newHop.sig[:], hop.sig[:]) {
			panic("unequal sig")
		}
	}
	if !newInfo.checkSigs() {
		panic("new checkSigs failed")
	} else if !newInfo.checkLoops() {
		panic("new checkLoops failed")
	}
}

func TestMarshalDHTBootstrap(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	var sk privateKey
	copy(sk[:], priv)
	info := new(treeInfo)
	copy(info.root[:], pub)
	for idx := 0; idx < 10; idx++ {
		newPub, newPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		var pk publicKey
		copy(pk[:], newPub)
		info = info.add(sk, &peer{key: pk, port: 1})
		if !info.checkSigs() {
			panic("checkSigs failed")
		} else if !info.checkLoops() {
			panic("checkLoops failed")
		}
		copy(sk[:], newPriv)
	}
	c := new(core)
	_ = c.init(priv)
	c.dhtree.self = info
	bootstrap := new(dhtBootstrap)
	bootstrap.label = *c.dhtree._getLabel()
	if !bootstrap.check() {
		panic("failed to check bootstrap")
	}
	bs, err := bootstrap.encode(nil)
	if err != nil {
		panic(err)
	}
	newBootstrap := new(dhtBootstrap)
	err = newBootstrap.decode(bs)
	if err != nil {
		panic(err)
	}
	if !newBootstrap.check() {
		panic("failed to check new bootstrap")
	}
}

func TestMarshalDHTSetup(t *testing.T) {
	_, destPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	sourcePub, sourcePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	dpc, _ := NewPacketConn(destPriv)
	spc, _ := NewPacketConn(sourcePriv)
	var pk publicKey
	copy(pk[:], sourcePub)
	token := dpc.core.dhtree._getToken(pk)
	setup := spc.core.dhtree._newSetup(token)
	if !setup.check() {
		panic("initial check failed")
	}
	bs, err := setup.encode(nil)
	if err != nil {
		panic(err)
	}
	newSetup := new(dhtSetup)
	if err = newSetup.decode(bs); err != nil {
		panic(err)
	}
	if !newSetup.check() {
		panic("final check failed")
	}
}
