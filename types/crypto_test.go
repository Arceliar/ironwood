package types

import (
	"encoding/hex"
	"testing"
)

func TestIsPublicKeyValid(t *testing.T) {
	keys := []string{
		"0200000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	}
	for _, key := range keys {
		ds, err := hex.DecodeString(key)
		if err != nil {
			t.Fatal(err)
			return
		}
		var pk [32]byte
		if copy(pk[:], ds); IsPublicKeyValid(pk) {
			t.Fatalf("key %q should not be valid", key)
		}
	}
}
