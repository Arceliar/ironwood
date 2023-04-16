package network

import (
	"encoding/binary"

	bfilter "github.com/bits-and-blooms/bloom/v3"

	"github.com/Arceliar/ironwood/types"
)

const (
	bloomFilterM = 8192
	bloomFilterK = 22
	bloomFilterB = bloomFilterM / 8  // number of bytes in the backing array
	bloomFilterU = bloomFilterM / 64 // number of uint64s in the backing array
)

// bloom is an 8192 bit long bloom filter using 22 hash functions.
type bloom struct {
	seq    uint64
	filter *bfilter.BloomFilter
}

func newBloom(seq uint64) *bloom {
	return &bloom{
		seq:    seq,
		filter: bfilter.New(bloomFilterM, bloomFilterK),
	}
}

func (b *bloom) addKey(key publicKey) {
	b.filter.Add(key[:])
}

func (b *bloom) addFilter(f *bfilter.BloomFilter) {
	b.filter.Merge(f)
}

func (b *bloom) size() int {
	size := wireSizeUint(b.seq)
	size += bloomFilterB
	return size
}

func (b *bloom) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendUint(out, b.seq)
	us := b.filter.BitSet().Bytes()
	var buf [8]byte
	for _, u := range us {
		binary.BigEndian.PutUint64(buf[:], u)
		out = append(out, buf[:]...)
	}
	end := len(out)
	if end-start != b.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (b *bloom) decode(data []byte) error {
	var tmp bloom
	var usArray [bloomFilterU]uint64
	us := usArray[:0]
	if !wireChopUint(&tmp.seq, &data) {
		return types.ErrDecode
	}
	if len(data) != bloomFilterB {
		return types.ErrDecode
	}
	for len(data) != 0 {
		u := binary.BigEndian.Uint64(data[:8])
		us = append(us, u)
		data = data[8:]
	}
	tmp.filter = bfilter.From(us, bloomFilterK)
	*b = tmp
	return nil
}
