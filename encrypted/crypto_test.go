package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func testEDKeypair(t *testing.T) (edPub, edPriv) {
	t.Helper()
	bsPub, bsPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	var pub edPub
	var priv edPriv
	copy(pub[:], bsPub)
	copy(priv[:], bsPriv)
	return pub, priv
}

func testPQKeypair(t *testing.T) (*pqPriv, pqPub) {
	t.Helper()
	pub, priv := newPQKeys()
	return priv, pub
}

func TestEdX25519(t *testing.T) {
	ePub, ePriv := testEDKeypair(t)
	pub1, err := ePub.toBox()
	if err != nil {
		t.Fatalf("public key conversion failed: %v", err)
	}
	priv1 := ePriv.toBox()
	pub2, priv2 := newBoxKeys()
	var encShared, decShared boxShared
	getShared(&encShared, pub1, &priv2)
	getShared(&decShared, &pub2, priv1)
	if encShared != decShared {
		t.Fatal("shared secret mismatch")
	}
}

func TestHybridHPKERoundTrip(t *testing.T) {
	toPub, toPriv := testEDKeypair(t)
	toPQPriv, toPQPub := testPQKeypair(t)

	msg := []byte("hybrid hpke test message")
	sealed, err := hpkeSeal(nil, msg, &toPub, &toPQPub)
	if err != nil {
		t.Fatalf("hpkeSeal failed: %v", err)
	}
	opened, err := hpkeOpen(nil, sealed, &toPriv, toPQPriv)
	if err != nil {
		t.Fatalf("hpkeOpen failed: %v", err)
	}
	if !bytes.Equal(opened, msg) {
		t.Fatalf("decrypted payload mismatch: got %q want %q", opened, msg)
	}
}

func TestHybridHPKEWrongPQKeyFails(t *testing.T) {
	toPub, toPriv := testEDKeypair(t)
	_, toPQPub := testPQKeypair(t)
	wrongPQPriv, _ := testPQKeypair(t)

	sealed, err := hpkeSeal(nil, []byte("test"), &toPub, &toPQPub)
	if err != nil {
		t.Fatalf("hpkeSeal failed: %v", err)
	}
	if _, err := hpkeOpen(nil, sealed, &toPriv, wrongPQPriv); err == nil {
		t.Fatal("hpkeOpen succeeded with wrong PQ private key")
	}
}

func TestSessionPQInfoSignatureValidation(t *testing.T) {
	fromPub, fromPriv := testEDKeypair(t)
	_, fromPQPub := testPQKeypair(t)

	pq := newSessionPQInfo(&fromPQPub, 42)
	data, ok := pq.encode(&fromPriv)
	if !ok {
		t.Fatal("pq info encode failed")
	}
	var decoded sessionPQInfo
	if !decoded.decode(&fromPub, data) {
		t.Fatal("pq info decode failed with correct identity key")
	}

	wrongPub, _ := testEDKeypair(t)
	if decoded.decode(&wrongPub, data) {
		t.Fatal("pq info decode succeeded with wrong identity key")
	}

	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-1] ^= 0x01
	if decoded.decode(&fromPub, tampered) {
		t.Fatal("pq info decode succeeded after tampering")
	}
}

func TestSessionInitRejectsWrongOrTamperedSignature(t *testing.T) {
	fromPub, fromPriv := testEDKeypair(t)
	_, fromPQPub := testPQKeypair(t)
	toPub, toPriv := testEDKeypair(t)
	toPQPriv, toPQPub := testPQKeypair(t)

	current, _ := newBoxKeys()
	next, _ := newBoxKeys()
	init := newSessionInit(&current, &next, 7, &fromPQPub, 42)

	data, err := init.encrypt(&fromPriv, &fromPQPub, &toPub, &toPQPub)
	if err != nil {
		t.Fatalf("session init encrypt failed: %v", err)
	}

	var decoded sessionInit
	if !decoded.decrypt(&toPriv, toPQPriv, &fromPub, data) {
		t.Fatal("session init decrypt failed with correct sender identity")
	}

	wrongFromPub, _ := testEDKeypair(t)
	if decoded.decrypt(&toPriv, toPQPriv, &wrongFromPub, data) {
		t.Fatal("session init decrypt succeeded with wrong sender identity")
	}

	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-8] ^= 0x80
	if decoded.decrypt(&toPriv, toPQPriv, &fromPub, tampered) {
		t.Fatal("session init decrypt succeeded after tampering")
	}
}

func TestMixSharedWithRatchetSecretChangesKey(t *testing.T) {
	pub, priv := newBoxKeys()
	var base boxShared
	getShared(&base, &pub, &priv)

	secretA := newRatchetSecret()
	secretB := newRatchetSecret()
	if bytes.Equal(secretA[:], secretB[:]) {
		t.Fatal("unexpected equal ratchet secrets")
	}

	sharedA1 := base
	mixSharedWithRatchetSecret(&sharedA1, &secretA, 0x01)
	sharedA2 := base
	mixSharedWithRatchetSecret(&sharedA2, &secretA, 0x01)
	if sharedA1 != sharedA2 {
		t.Fatal("ratchet mixing not deterministic for same inputs")
	}

	sharedB := base
	mixSharedWithRatchetSecret(&sharedB, &secretB, 0x01)
	if sharedA1 == sharedB {
		t.Fatal("ratchet secret did not affect mixed shared key")
	}
}
