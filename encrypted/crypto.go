package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/nacl/box"

	"github.com/Arceliar/ironwood/encrypted/internal/e2c"
)

/********
 * util *
 ********/

func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func bytesPush(dest, source []byte, offset int) (newOffset int) {
	copy(dest[offset:], source)
	return offset + len(source)
}

func bytesPop(dest, source []byte, offset int) (newOffset int) {
	copy(dest[:], source[offset:])
	return offset + len(dest)
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

func edSign(msg []byte, priv *edPriv, preimage []byte) *edSig {
	var sig edSig
	if len(preimage) > 0 {
		copy(sig[:], ed25519.Sign(priv[:], append(preimage, msg...)))
	} else {
		copy(sig[:], ed25519.Sign(priv[:], msg))
	}
	return &sig
}

func edCheck(msg []byte, sig *edSig, pub *edPub, preimage []byte) bool {
	if len(preimage) > 0 {
		return ed25519.Verify(pub[:], append(preimage, msg...), sig[:])
	} else {
		return ed25519.Verify(pub[:], msg, sig[:])
	}
}

func (pub *edPub) asKey() ed25519.PublicKey {
	return ed25519.PublicKey(pub[:])
}

func (pub *edPub) toBox() (*boxPub, error) {
	var c boxPub
	e := e2c.Ed25519PublicKeyToCurve25519(pub.asKey())
	copy(c[:], e)
	return &c, nil
}

func (priv *edPriv) toBox() *boxPriv {
	var c boxPriv
	e := e2c.Ed25519PrivateKeyToCurve25519(ed25519.PrivateKey(priv[:]))
	copy(c[:], e)
	return &c
}

func (priv *edPriv) pub() *edPub {
	pk := ed25519.PrivateKey(priv[:]).Public().(ed25519.PublicKey)
	pub := new(edPub)
	copy(pub[:], pk[:])
	return pub
}

/*******
 * box *
 *******/

const (
	boxPubSize    = 32
	boxPrivSize   = 32
	boxSharedSize = 32
	boxNonceSize  = 24
	boxOverhead   = box.Overhead
)

type boxPub [boxPubSize]byte
type boxPriv [boxPrivSize]byte
type boxShared [boxSharedSize]byte
type boxNonce [boxNonceSize]byte

func newBoxKeys() (pub boxPub, priv boxPriv) {
	bpub, bpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic("failed to generate keys")
	}
	pub, priv = boxPub(*bpub), boxPriv(*bpriv)
	return
}

func getShared(out *boxShared, pub *boxPub, priv *boxPriv) {
	box.Precompute((*[32]byte)(out), (*[32]byte)(pub), (*[32]byte)(priv))
}

func boxOpen(out, boxed []byte, nonce uint64, shared *boxShared) ([]byte, bool) {
	n := nonceForUint64(nonce)
	return box.OpenAfterPrecomputation(out, boxed, (*[24]byte)(&n), (*[32]byte)(shared))
}

func boxSeal(out, msg []byte, nonce uint64, shared *boxShared) []byte {
	n := nonceForUint64(nonce)
	return box.SealAfterPrecomputation(out, msg, (*[24]byte)(&n), (*[32]byte)(shared))
}

// TODO we need to catch if nonce hits its max value and force a rekey
//  To that end, maybe we can use a smaller nonce size? or a vuint and reset on uint64 max?

func nonceForUint64(u64 uint64) boxNonce {
	var nonce boxNonce
	slice := nonce[boxNonceSize-8:]
	binary.BigEndian.PutUint64(slice, u64)
	return nonce
}

/*********
 * group *
 *********/

type groupAuth struct {
	enabled bool
	secret  [32]byte
}

func newGroupAuth(password string) groupAuth {
	if password == "" {
		return groupAuth{}
	}
	return groupAuth{
		enabled: true,
		secret:  sha256.Sum256(append([]byte("ironwood/encrypted\x00"), []byte(password)...)),
	}
}

func (auth groupAuth) preimage() []byte {
	if auth.enabled {
		return auth.secret[:]
	}
	return nil
}
