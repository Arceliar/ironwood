package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

/********
 * util *
 ********/

func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

/******
 * ed *
 ******/

const (
	edPubSize  = 32
	edPrivSize = 64
	edSigSize  = 64
)

type edPub [edPubSize]byte
type edPriv [edPrivSize]byte
type edSig [edSigSize]byte

func edSign(msg []byte, priv *edPriv) *edSig {
	var sig edSig
	copy(sig[:], ed25519.Sign(priv[:], msg))
	return &sig
}

func edCheck(msg []byte, sig *edSig, pub *edPub) bool {
	return ed25519.Verify(pub[:], msg, sig[:])
}

/*******
 * box *
 *******/

const (
	boxPubSize    = 32
	boxPrivSize   = 32
	boxSharedSize = 32
	boxNonceSize  = 24
)

type boxPub [boxPubSize]byte
type boxPriv [boxPrivSize]byte
type boxShared [boxSharedSize]byte
type boxNonce [boxNonceSize]byte

func newBoxKeys() (pub *boxPub, priv *boxPriv) {
	bpub, bpriv, err := box.GenerateKey(nil)
	if err != nil {
		panic("failed to generate keys")
	}
	pub, priv = (*boxPub)(bpub), (*boxPriv)(bpriv)
	return
}

func getShared(out *boxShared, pub *boxPub, priv *boxPriv) {
	box.Precompute((*[32]byte)(out), (*[32]byte)(pub), (*[32]byte)(priv))
}

func boxOpen(out, boxed []byte, nonce *boxNonce, shared *boxShared) ([]byte, bool) {
	return box.OpenAfterPrecomputation(out, boxed, (*[24]byte)(nonce), (*[32]byte)(shared))
}

func boxSeal(out, msg []byte, nonce *boxNonce, shared *boxShared) []byte {
	return box.SealAfterPrecomputation(out, msg, (*[24]byte)(nonce), (*[32]byte)(shared))
}

func (n *boxNonce) inc() {
	panic("TODO test this")
	for _, e := range n {
		e++
		if e != 0 {
			break // continue only if we roll over
		}
	}
}
