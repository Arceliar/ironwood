package net

import (
	"encoding"
	"errors"
)

const (
	wireDummy = iota // unused
	wireProtoTree
	wireProtoDHTBootstrap
	wireProtoDHTSetup
	wireProtoDHTTeardown
	wireDHTTraffic
)

type binaryMarshaler encoding.BinaryMarshaler
type binaryUnmarshaler encoding.BinaryUnmarshaler

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

func wireEncode(pType uint8, obj binaryMarshaler) (data []byte, err error) {
	data, err = obj.MarshalBinary()
	data = append([]byte{pType}, data...)
	return
}

func wireDecode(data []byte) (obj binaryUnmarshaler, err error) {
	if len(data) == 0 {
		return nil, wireUnmarshalBinaryError
	}
	switch data[0] {
	case wireProtoTree:
		obj = new(treeInfo)
	case wireProtoDHTBootstrap:
		obj = new(dhtBootstrap)
	case wireProtoDHTSetup:
		obj = new(dhtSetup)
	case wireProtoDHTTeardown:
		obj = new(dhtTeardown)
	}
	err = obj.UnmarshalBinary(data[1:])
	return
}
