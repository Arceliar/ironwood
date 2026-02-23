package encrypted

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

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
	edPubSize  = ed25519.PublicKeySize
	edPrivSize = ed25519.PrivateKeySize
	edSigSize  = ed25519.SignatureSize
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
	boxPubSize    = 32 // X25519 public key bytes
	boxPrivSize   = 32 // X25519 private key bytes
	boxSharedSize = chacha20poly1305.KeySize
	boxNonceSize  = chacha20poly1305.NonceSize
	boxOverhead   = chacha20poly1305.Overhead

	pqPubSize = mlkem.EncapsulationKeySize768

	// MLKEM768X25519 HPKE values
	hpkeEncSize  = mlkem.CiphertextSize768 + boxPubSize
	hpkeTagSize  = 16
	hpkeOverhead = hpkeEncSize + hpkeTagSize

	ratchetSecretSize = mlkem.SharedKeySize
)

var kdf = hpke.HKDFSHA256()
var aead = hpke.AES256GCM()

var hpkeInfo = []byte("ironwood/session/v2")

var initSigCtx = []byte("ironwood-init-v2")
var pqInfoSigCtx = []byte("ironwood-pqinfo-v2")

type boxPub [boxPubSize]byte
type boxPriv [boxPrivSize]byte
type boxShared [boxSharedSize]byte
type boxNonce [boxNonceSize]byte
type boxCipher struct {
	aead cipher.AEAD
}
type pqPub [pqPubSize]byte
type pqPriv = mlkem.DecapsulationKey768
type ratchetSecret [ratchetSecretSize]byte

func newBoxKeys() (pub boxPub, priv boxPriv) {
	curve := ecdh.X25519()
	sk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic("failed to generate keypair")
	}
	copy(priv[:], sk.Bytes())
	copy(pub[:], sk.PublicKey().Bytes())
	return
}

func newPQKeys() (pub pqPub, priv *pqPriv) {
	sk, err := mlkem.GenerateKey768()
	if err != nil {
		panic("failed to generate pq keypair")
	}
	copy(pub[:], sk.EncapsulationKey().Bytes())
	return pub, sk
}

func newRatchetSecret() ratchetSecret {
	var secret ratchetSecret
	if _, err := rand.Read(secret[:]); err != nil {
		panic("failed to generate ratchet secret")
	}
	return secret
}

func getShared(out *boxShared, pub *boxPub, priv *boxPriv) {
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		panic("x25519 ecdh failed")
	}
	copy(out[:], shared)
}

func newBoxCipher(shared *boxShared) boxCipher {
	a, err := chacha20poly1305.New(shared[:])
	if err != nil {
		panic("invalid traffic key size")
	}
	return boxCipher{aead: a}
}

func mixSharedWithRatchetSecret(out *boxShared, secret *ratchetSecret, label byte) {
	var input [1 + boxSharedSize + ratchetSecretSize]byte
	input[0] = label
	offset := 1
	offset = bytesPush(input[:], out[:], offset)
	_ = bytesPush(input[:], secret[:], offset)
	sum := sha256.Sum256(input[:])
	copy(out[:], sum[:])
}

func boxOpen(out, boxed []byte, nonce uint64, bc *boxCipher) ([]byte, bool) {
	n := nonceForUint64(nonce)
	opened, err := bc.aead.Open(out, n[:], boxed, nil)
	if err != nil {
		return nil, false
	}
	return opened, true
}

func boxSeal(out, msg []byte, nonce uint64, bc *boxCipher) []byte {
	n := nonceForUint64(nonce)
	return bc.aead.Seal(out, n[:], msg, nil)
}

func (pub *pqPub) asEncapsulationKey() (*mlkem.EncapsulationKey768, error) {
	return mlkem.NewEncapsulationKey768(pub[:])
}

func (pub *edPub) toX25519Public() (*ecdh.PublicKey, error) {
	toBox, err := pub.toBox()
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(toBox[:])
}

func (priv *edPriv) toX25519Private() (*ecdh.PrivateKey, error) {
	toBox := priv.toBox()
	return ecdh.X25519().NewPrivateKey(toBox[:])
}

func hpkePublicKey(toEd *edPub, toPQ *pqPub) (hpke.PublicKey, error) {
	xPub, err := toEd.toX25519Public()
	if err != nil {
		return nil, err
	}
	pqEnc, err := toPQ.asEncapsulationKey()
	if err != nil {
		return nil, err
	}
	return hpke.NewHybridPublicKey(pqEnc, xPub)
}

func hpkePrivateKey(ed *edPriv, pq *pqPriv) (hpke.PrivateKey, error) {
	xPriv, err := ed.toX25519Private()
	if err != nil {
		return nil, err
	}
	return hpke.NewHybridPrivateKey(pq, xPriv)
}

func hpkeSeal(out, msg []byte, toEd *edPub, toPQ *pqPub) ([]byte, error) {
	toHPKE, err := hpkePublicKey(toEd, toPQ)
	if err != nil {
		return nil, err
	}
	sealed, err := hpke.Seal(toHPKE, kdf, aead, hpkeInfo, msg)
	if err != nil {
		return nil, err
	}
	return append(out, sealed...), nil
}

func hpkeOpen(out, msg []byte, ed *edPriv, pq *pqPriv) ([]byte, error) {
	privHPKE, err := hpkePrivateKey(ed, pq)
	if err != nil {
		return nil, err
	}
	opened, err := hpke.Open(privHPKE, kdf, aead, hpkeInfo, msg)
	if err != nil {
		return nil, err
	}
	return append(out, opened...), nil
}

// TODO we need to catch if nonce hits its max value and force a rekey
//  To that end, maybe we can use a smaller nonce size? or a vuint and reset on uint64 max?

func nonceForUint64(u64 uint64) boxNonce {
	var nonce boxNonce
	slice := nonce[boxNonceSize-8:]
	binary.BigEndian.PutUint64(slice, u64)
	return nonce
}
