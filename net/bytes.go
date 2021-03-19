package net

import "sync"

var bytePool = sync.Pool{New: func() interface{} { return new([]byte) }}

func getBytes(size int) []byte {
	bs := *(bytePool.Get().(*[]byte))
	if cap(bs) >= size {
		bs = bs[:size]
	} else {
		bs = make([]byte, size)
	}
	return bs
}

func putBytes(bs []byte) {
	bytePool.Put(&bs)
}
