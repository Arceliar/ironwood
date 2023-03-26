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

func (tr *traffic) encode(out []byte) ([]byte, error) {
	out = append(out, tr.source[:]...)
	out = append(out, tr.dest[:]...)
	out = binary.AppendUvarint(out, tr.watermark)
	out = append(out, tr.payload...)
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
