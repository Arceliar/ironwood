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
	var wm [8]byte
	binary.BigEndian.PutUint64(wm[:], tr.watermark)
	out = append(out, wm[:]...)
	out = append(out, tr.payload...)
	return out, nil
}

func (tr *traffic) decode(data []byte) error {
	var tmp traffic
	var wm [8]byte
	if !wireChopSlice(tmp.source[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.dest[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(wm[:], &data) {
		return wireDecodeError
	}
	tmp.watermark = binary.BigEndian.Uint64(wm[:])
	*tr = tmp
	tr.payload = append(tr.payload[:0], data...)
	return nil
}
