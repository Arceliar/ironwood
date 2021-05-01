package encrypted

import (
	"crypto/ed25519"
	"testing"
)

func TestEdX25519(t *testing.T) {
	bsPub, bsPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("key generation failed")
	}
	var ePub edPub
	var ePriv edPriv
	copy(ePub[:], bsPub)
	copy(ePriv[:], bsPriv)
	pub1, _ := ePub.toBox()
	priv1 := ePriv.toBox()
	pub2, priv2 := newBoxKeys()
	var encShared, decShared boxShared
	getShared(&encShared, pub1, &priv2)
	getShared(&decShared, &pub2, priv1)
	if encShared != decShared {
		panic("shared secret mismatch")
	}
}
