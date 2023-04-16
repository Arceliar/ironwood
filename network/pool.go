package network

import "sync"

var bytePool = sync.Pool{New: func() interface{} { return []byte(nil) }}

func allocBytes(size int) []byte {
	bs := bytePool.Get().([]byte)
	if cap(bs) < size {
		bs = make([]byte, size)
	}
	return bs[:size]
}

func freeBytes(bs []byte) {
	bytePool.Put(bs[:0])
}

var trafficPool = sync.Pool{New: func() interface{} { return new(traffic) }}

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
