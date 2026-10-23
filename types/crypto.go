package types

import (
	"bytes"

	"filippo.io/edwards25519"
)

var identityPoint = edwards25519.NewIdentityPoint()

func IsPublicKeyValid[T ~[32]byte](key T) bool {
	var point edwards25519.Point
	if _, err := point.SetBytes(key[:]); err != nil || !bytes.Equal(point.Bytes(), key[:]) {
		return false
	}
	if point.MultByCofactor(&point).Equal(identityPoint) == 1 {
		return false
	}
	return true
}
