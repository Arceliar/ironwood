package net

import (
	"encoding"
	"encoding/binary"
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

func wireEncodeUint(dest []byte, u uint64) []byte {
	var b [10]byte
	l := binary.PutUvarint(b[:], u)
	return append(dest, b[:l]...)
}

func wireDecodeUint(source []byte) (uint64, int) {
	u, l := binary.Uvarint(source)
	if l < 0 {
		l = -l
	}
	return u, l
}

func wireEncodePath(dest []byte, path []peerPort) []byte {
	var buf [10]byte
	for _, p := range path {
		bs := wireEncodeUint(buf[:], uint64(p))
		dest = append(dest, bs...)
	}
	return dest
}

func wireDecodePath(source []byte) (path []peerPort, length int) {
	bs := source
	for len(bs) > 0 {
		u, l := wireDecodeUint(bs)
		path = append(path, peerPort(u))
		length += l
		if u == 0 {
			break
		}
	}
	return
}

func wireChopPath(out *[]peerPort, data *[]byte) bool {
	path, length := wireDecodePath(*data)
	*out = append(*out, path...)
	*data = (*data)[length:]
	return true
}
