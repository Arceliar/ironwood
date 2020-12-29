package net

// alloc returns a []byte of the given length, possibly stack allocated if small
func alloc(size int) []byte {
	var bs []byte
	if size < 65536 {
		bs = make([]byte, 65535)[:size]
	} else {
		bs = make([]byte, size)
	}
	return bs
}
