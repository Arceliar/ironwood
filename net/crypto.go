package net

import "crypto/ed25519"

const (
	publicKeySize  = ed25519.PublicKeySize
	privateKeySize = ed25519.PrivateKeySize
	signatureSize  = ed25519.SignatureSize
)

type publicKey ed25519.PublicKey
type privateKey ed25519.PrivateKey
type signature []byte

type crypto struct {
	privateKey privateKey
	publicKey  publicKey
}

func (key *privateKey) sign(message []byte) signature {
	return ed25519.Sign(ed25519.PrivateKey(*key), message)
}

func (key *publicKey) verify(message []byte, sig signature) bool {
	return ed25519.Verify(ed25519.PublicKey(*key), message, sig)
}

func (c *crypto) init(secret ed25519.PrivateKey) {
	c.privateKey = privateKey(secret)
	c.publicKey = publicKey(secret.Public().(ed25519.PublicKey))
}
