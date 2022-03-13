package network

import (
	"encoding/binary"
	"errors"
)

const (
	wireDummy = iota // unused
	wireProtoTree
	wireProtoDHTBootstrap
	wireProtoDHTBranch
	wireProtoPathNotify
	wireProtoPathRequest
	wireProtoPathResponse
	wireDHTTraffic
	wirePathTraffic
	wireKeepAlive
)

// TODO? proper packet types for out-of-band, instead of embedding into ordinary traffic

const (
	wireTrafficDummy = iota
	wireTrafficStandard
	wireTrafficOutOfBand
)

var wireEncodeError = errors.New("wire encode error")
var wireDecodeError = errors.New("wire decode error")

func wireChopSlice(out []byte, data *[]byte) bool {
	if len(*data) < len(out) {
		return false
	}
	copy(out, *data)
	*data = (*data)[len(out):]
	return true
}

func wireChopBytes(out *[]byte, data *[]byte, size int) bool {
	if len(*data) < size {
		return false
	}
	*out = append(*out, (*data)[:size]...)
	*data = (*data)[size:]
	return true
}

type wireEncodeable interface {
	encode(out []byte) ([]byte, error)
}

func wireEncode(out []byte, pType uint8, obj wireEncodeable) ([]byte, error) {
	out = append(out, pType)
	var err error
	if out, err = obj.encode(out); err != nil {
		return nil, err
	}
	return out, nil
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

func wireChopUint(out *uint64, data *[]byte) bool {
	port, length := wireDecodeUint(*data)
	*out = port
	*data = (*data)[length:]
	return true
}

func wireEncodePath(dest []byte, path []peerPort) []byte {
	var buf [10]byte
	for _, p := range path {
		bs := wireEncodeUint(buf[:0], uint64(p))
		dest = append(dest, bs...)
	}
	return dest
}

func wireDecodePath(source []byte) (path []peerPort, length int) {
	bs := source
	for len(bs) > 0 {
		u, l := wireDecodeUint(bs)
		bs = bs[l:]
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
