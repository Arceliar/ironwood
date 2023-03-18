package network

import "encoding/binary"

/***********
 * traffic *
 ***********/

type traffic struct {
	source    publicKey
	dest      publicKey
	watermark uint64 // TODO? uvarint
	kind      byte   // in-band vs out-of-band, TODO? separate type?
	payload   []byte
}

func (t *traffic) encode(out []byte) ([]byte, error) {
	out = append(out, t.source[:]...)
	out = append(out, t.dest[:]...)
	var wm [8]byte
	binary.BigEndian.PutUint64(wm[:], t.watermark)
	out = append(out, wm[:]...)
	out = append(out, t.kind)
	out = append(out, t.payload...)
	return out, nil
}

func (t *traffic) decode(data []byte) error {
	var tmp traffic
	var wm [8]byte
	if !wireChopSlice(tmp.source[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(tmp.dest[:], &data) {
		return wireDecodeError
	} else if !wireChopSlice(wm[:], &data) {
		return wireDecodeError
	} else if len(data) < 1 {
		return wireDecodeError
	}
	tmp.watermark = binary.BigEndian.Uint64(wm[:])
	tmp.kind, data = data[0], data[1:]
	tmp.payload = append(tmp.payload[:0], data...)
	*t = tmp
	return nil
}
