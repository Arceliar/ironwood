package network

import (
	"math"
	"sync"
)

const bytePoolSz = math.MaxUint16 // packet length field is uint16

var bytePool = sync.Pool{
	New: func() interface{} {
		b := [bytePoolSz]byte{}
		return &b
	},
}

func allocBytes(size int) []byte {
	bs := bytePool.Get().(*[bytePoolSz]byte)
	return bs[:size]
}

func freeBytes(bs []byte) {
	b := (*[bytePoolSz]byte)(bs[:bytePoolSz])
	bytePool.Put(b)
}

var trafficPool = sync.Pool{
	New: func() interface{} {
		return &traffic{}
	},
}

func allocTraffic() *traffic {
	tr := trafficPool.Get().(*traffic)
	tr.payload = allocBytes(0)
	return tr
}

func freeTraffic(tr *traffic) {
	freeBytes(tr.payload)
	*tr = traffic{}
	trafficPool.Put(tr)
}
