package network

import "encoding/binary"

/***********
 * traffic *
 ***********/

type traffic struct {
	source    publicKey
	dest      publicKey
	watermark uint64 // TODO? uvarint
	payload   []byte
}

func (tr *traffic) size() int {
	size := len(tr.source)
	size += len(tr.dest)
	var wm [10]byte
	size += binary.PutUvarint(wm[:], tr.watermark)
	size += len(tr.payload)
	return size
}

func (tr *traffic) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = append(out, tr.source[:]...)
	out = append(out, tr.dest[:]...)
	out = binary.AppendUvarint(out, tr.watermark)
	out = append(out, tr.payload...)
	end := len(out)
	if end-start != tr.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (tr *traffic) decode(data []byte) error {
	var tmp traffic
	if !wireChopSlice(tmp.source[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.dest[:], &data) {
		return wireDecodeError
	} else if !wireChopUvarint(&tmp.watermark, &data) {
		return wireDecodeError
	}
	*tr = tmp
	tr.payload = append(tr.payload[:0], data...)
	return nil
}
