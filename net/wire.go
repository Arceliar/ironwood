package net

import "errors"

const (
	wireDummy = iota // unused
	wireProtoTree
)

var wireMarshalBinaryError = errors.New("wire MarshalBinary error")
var wireUnmarshalBinaryError = errors.New("wire UnmarshalBinary error")

func wireChopBytes(out *[]byte, data *[]byte, size int) bool {
	if len(*data) < size {
		return false
	}
	*out = append(*out, (*data)[:size]...)
	*data = (*data)[size:]
	return true
}
