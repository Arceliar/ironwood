package network

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"testing"
)

// Wire decoders run on bytes from peers. These fuzz tests check that
// random and mutated inputs do not cause panics in the parsers or in
// peer._handlePacket. Roundtrip variants also confirm that the
// encoders match what the decoders accept.

func seedTraffic() []byte {
	buf := make([]byte, 0, 1+1+32+32+1)
	buf = append(buf, 0)
	buf = append(buf, 0)
	buf = append(buf, bytes.Repeat([]byte{0xAB}, 32)...)
	buf = append(buf, bytes.Repeat([]byte{0xCD}, 32)...)
	buf = binary.AppendUvarint(buf, 0)
	return buf
}

func seedAnnounce() []byte {
	buf := make([]byte, 0, 32*2+8+8+8+64+64)
	buf = append(buf, bytes.Repeat([]byte{0x01}, 32)...)
	buf = append(buf, bytes.Repeat([]byte{0x02}, 32)...)
	buf = binary.AppendUvarint(buf, 1)
	buf = binary.AppendUvarint(buf, 1)
	buf = binary.AppendUvarint(buf, 0)
	buf = append(buf, bytes.Repeat([]byte{0x03}, 64)...)
	buf = append(buf, bytes.Repeat([]byte{0x04}, 64)...)
	return buf
}

func FuzzTrafficDecode(f *testing.F) {
	f.Add(seedTraffic())
	f.Fuzz(func(t *testing.T, data []byte) {
		var tr traffic
		_ = tr.decode(data)
	})
}

func FuzzRouterAnnounceDecode(f *testing.F) {
	f.Add(seedAnnounce())
	f.Fuzz(func(t *testing.T, data []byte) {
		var ann routerAnnounce
		_ = ann.decode(data)
	})
}

func FuzzRouterSigResDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var res routerSigRes
		_ = res.decode(data)
	})
}

func FuzzPathLookupDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var pl pathLookup
		_ = pl.decode(data)
	})
}

func FuzzPathNotifyDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var pn pathNotify
		_ = pn.decode(data)
	})
}

func FuzzPathBrokenDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var pb pathBroken
		_ = pb.decode(data)
	})
}

func FuzzBloomDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		b := newBloom()
		_ = b.decode(data)
	})
}

// FuzzPeerHandlePacket replicates the dispatch in (*peer)._handlePacket
// without needing a live core, so the fuzzer covers all decode paths
// reachable from a connected peer.
func FuzzPeerHandlePacket(f *testing.F) {
	f.Add([]byte{byte(wireKeepAlive)})
	f.Add(append([]byte{byte(wireProtoAnnounce)}, seedAnnounce()...))
	f.Add(append([]byte{byte(wireTraffic)}, seedTraffic()...))
	f.Fuzz(func(t *testing.T, bs []byte) {
		if len(bs) == 0 {
			return
		}
		body := bs[1:]
		switch wirePacketType(bs[0]) {
		case wireDummy, wireKeepAlive:
			return
		case wireProtoSigReq:
			var req routerSigReq
			_ = req.decode(body)
		case wireProtoSigRes:
			var res routerSigRes
			_ = res.decode(body)
		case wireProtoAnnounce:
			var ann routerAnnounce
			if err := ann.decode(body); err == nil {
				_ = ann.check()
			}
		case wireProtoBloomFilter:
			b := newBloom()
			_ = b.decode(body)
		case wireProtoPathLookup:
			var pl pathLookup
			_ = pl.decode(body)
		case wireProtoPathNotify:
			var pn pathNotify
			if err := pn.decode(body); err == nil {
				_ = pn.check()
			}
		case wireProtoPathBroken:
			var pb pathBroken
			_ = pb.decode(body)
		case wireTraffic:
			var tr traffic
			_ = tr.decode(body)
		}
	})
}

// FuzzAnnounceCheck stages syntactically valid announces with a real
// keypair so the ed25519 verify path is exercised on attacker-controlled
// payloads.
func FuzzAnnounceCheck(f *testing.F) {
	pk, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Skip(err)
	}
	f.Add(seedAnnounce())
	f.Fuzz(func(t *testing.T, data []byte) {
		var ann routerAnnounce
		if err := ann.decode(data); err != nil {
			return
		}
		copy(ann.key[:], pk)
		copy(ann.parent[:], pk)
		_ = ann.check()
	})
}

func FuzzTrafficRoundtrip(f *testing.F) {
	f.Add(seedTraffic())
	f.Fuzz(func(t *testing.T, data []byte) {
		var first traffic
		if err := first.decode(data); err != nil {
			return
		}
		out, err := first.encode(nil)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var second traffic
		if err := second.decode(out); err != nil {
			t.Fatalf("re-decode: %v\nbytes: %x", err, out)
		}
		out2, err := second.encode(nil)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		if !bytes.Equal(out, out2) {
			t.Fatalf("roundtrip not stable\nfirst : %x\nsecond: %x", out, out2)
		}
	})
}

func FuzzAnnounceRoundtrip(f *testing.F) {
	f.Add(seedAnnounce())
	f.Fuzz(func(t *testing.T, data []byte) {
		var first routerAnnounce
		if err := first.decode(data); err != nil {
			return
		}
		out, err := first.encode(nil)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var second routerAnnounce
		if err := second.decode(out); err != nil {
			t.Fatalf("re-decode: %v\nbytes: %x", err, out)
		}
		out2, err := second.encode(nil)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		if !bytes.Equal(out, out2) {
			t.Fatalf("roundtrip not stable\nfirst : %x\nsecond: %x", out, out2)
		}
	})
}
