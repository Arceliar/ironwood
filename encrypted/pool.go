package encrypted

import "sync"

const byteSize = 65535 + sessionTrafficOverhead + 4

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
