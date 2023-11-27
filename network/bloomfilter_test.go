package network

import "testing"

func TestBloom(t *testing.T) {
	b := newBloom()
	c := newBloom()
	var buf []byte
	var err error
	// Zero value test
	if buf, err = b.encode(buf); err != nil {
		panic(err)
	}
	if err = c.decode(buf); err != nil {
		panic(err)
	}
	if !b.filter.Equal(c.filter) {
		panic("unequal bitsets")
	}
	// Intermedaite value test, add some keys
	buf = buf[:0]
	var k publicKey
	b.addKey(k)
	for idx := 0; idx < len(k); idx++ {
		k[idx] = ^k[idx]
		b.addKey(k)
	}
	if buf, err = b.encode(buf); err != nil {
		panic(err)
	}
	if err = c.decode(buf); err != nil {
		panic(err)
	}
	if !b.filter.Equal(c.filter) {
		panic("unequal bitsets")
	}
	// Max value test
	buf = buf[:0]
	bitset := b.filter.BitSet()
	us := bitset.Bytes()
	for idx := range us {
		us[idx] = ^uint64(0)
	}
	bitset.SetBitsetFrom(us)
	if !b.filter.BitSet().All() {
		panic("bitset should be saturated")
	}
	if buf, err = b.encode(buf); err != nil {
		panic(err)
	}
	if err = c.decode(buf); err != nil {
		panic(err)
	}
	if !b.filter.Equal(c.filter) {
		panic("unequal bitsets")
	}
}
