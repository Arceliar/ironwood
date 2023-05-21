package network

import "sync"

const byteSize = 65535 * 2

type byteSlice [byteSize]byte

var bytePool = sync.Pool{
	New: func() interface{} {
		b := byteSlice{}
		return &b
	},
}

func allocBytes(size int) []byte {
	bs := bytePool.Get().(*byteSlice)
	return bs[:size]
}

func freeBytes(bs []byte) {
	bu := (*byteSlice)(bs[:byteSize])
	bytePool.Put(bu)
}

var trafficPool = sync.Pool{
	New: func() interface{} {
		return new(traffic)
	},
}

func allocTraffic() *traffic {
	tr := trafficPool.Get().(*traffic)
	tr.payload = allocBytes(0)
	return tr
}

func freeTraffic(tr *traffic) {
	freeBytes(tr.payload)
	path := tr.path[:0]
	from := tr.from[:0]
	*tr = traffic{}
	tr.path = path
	tr.from = from
	trafficPool.Put(tr)
}
