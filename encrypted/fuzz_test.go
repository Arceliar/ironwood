package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// FuzzSessionInitDecrypt feeds random buffers into sessionInit.decrypt
// to confirm that no input shape causes a panic before the length and
// decryption checks reject it.
func FuzzSessionInitDecrypt(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Skip(err)
	}
	var ePriv edPriv
	copy(ePriv[:], priv)
	bPriv := ePriv.toBox()
	var ePub edPub
	copy(ePub[:], pub)

	f.Add(make([]byte, sessionInitSize))
	f.Add(bytes.Repeat([]byte{0xAB}, sessionInitSize-1))
	f.Add(bytes.Repeat([]byte{0xCD}, sessionInitSize+8))

	f.Fuzz(func(t *testing.T, data []byte) {
		var init sessionInit
		_ = init.decrypt(bPriv, &ePub, data, groupAuth{})
	})
}
