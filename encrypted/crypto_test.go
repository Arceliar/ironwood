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

func TestSessionInitPasswordAuth(t *testing.T) {
	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate sender key: %v", err)
	}
	receiverPub, receiverPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate receiver key: %v", err)
	}

	var senderEd edPriv
	var senderEdPub edPub
	var receiverEdPriv edPriv
	var receiverEd edPub
	copy(senderEd[:], senderPriv)
	copy(senderEdPub[:], senderPub)
	copy(receiverEdPriv[:], receiverPriv)
	copy(receiverEd[:], receiverPub)

	current, _ := newBoxKeys()
	next, _ := newBoxKeys()

	init := newSessionInit(&current, &next, 9)
	tests := []struct {
		name             string
		senderPassword   string
		receiverPassword string
		wantOK           bool
	}{
		{
			name:             "both empty",
			senderPassword:   "",
			receiverPassword: "",
			wantOK:           true,
		},
		{
			name:             "both same password",
			senderPassword:   "shared-password",
			receiverPassword: "shared-password",
			wantOK:           true,
		},
		{
			name:             "sender password only",
			senderPassword:   "shared-password",
			receiverPassword: "",
			wantOK:           false,
		},
		{
			name:             "receiver password only",
			senderPassword:   "",
			receiverPassword: "shared-password",
			wantOK:           false,
		},
		{
			name:             "different passwords",
			senderPassword:   "shared-password",
			receiverPassword: "wrong-password",
			wantOK:           false,
		},
	}

	receiverBox := receiverEdPriv.toBox()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := init.encrypt(&senderEd, &receiverEd, newGroupAuth(tc.senderPassword))
			if err != nil {
				t.Fatalf("encrypt handshake: %v", err)
			}

			var decoded sessionInit
			ok := decoded.decrypt(receiverBox, &senderEdPub, data, newGroupAuth(tc.receiverPassword))
			if ok != tc.wantOK {
				t.Fatalf("decrypt = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if decoded.current != init.current || decoded.next != init.next || decoded.keySeq != init.keySeq || decoded.seq != init.seq {
				t.Fatal("decoded handshake did not round-trip")
			}
		})
	}
}
