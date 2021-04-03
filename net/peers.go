package net

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Arceliar/phony"
)

type peerPort uint64

type peers struct {
	phony.Inbox // Used to create/remove peers
	core        *core
	peers       map[peerPort]*peer
}

func (ps *peers) init(c *core) {
	ps.core = c
	ps.peers = make(map[peerPort]*peer)
}

func (ps *peers) addPeer(key publicKey, conn net.Conn) (*peer, error) {
	var p *peer
	var err error
	ps.core.pconn.closeMutex.Lock()
	defer ps.core.pconn.closeMutex.Unlock()
	select {
	case <-ps.core.pconn.closed:
		return nil, errors.New("cannot add peer to closed PacketConn")
	default:
	}
	phony.Block(ps, func() {
		var port peerPort
		for idx := 1; ; idx++ { // skip 0
			if _, isIn := ps.peers[peerPort(idx)]; isIn {
				continue
			}
			port = peerPort(idx)
			break
		}
		p = new(peer)
		p.peers = ps
		p.conn = conn
		p.key = key
		p.port = port
		ps.peers[port] = p
	})
	return p, err
}

func (ps *peers) removePeer(port peerPort) error {
	var err error
	phony.Block(ps, func() {
		if _, isIn := ps.peers[port]; !isIn {
			err = errors.New("peer not found")
		} else {
			delete(ps.peers, port)
		}
	})
	return err
}

type peer struct {
	phony.Inbox // Only used to process or send some protocol traffic
	peers       *peers
	conn        net.Conn
	key         publicKey
	info        *treeInfo
	port        peerPort
}

func (p *peer) _write(bs []byte) {
	out := getBytes(2 + len(bs))
	defer putBytes(out)
	if len(bs) > int(^uint16(0)) {
		panic("this should never happen in testing")
		// return
	}
	binary.BigEndian.PutUint16(out[:2], uint16(len(bs)))
	copy(out[2:], bs)
	_, _ = p.conn.Write(out)
}

func (p *peer) handler() error {
	defer func() {
		if p.info != nil {
			p.peers.core.dhtree.remove(nil, p)
		}
	}()
	done := make(chan struct{})
	defer close(done)
	var keepAlive func()
	keepAlive = func() {
		select {
		case <-done:
			return
		default:
		}
		p._write([]byte{wireDummy})
		time.AfterFunc(time.Second, keepAlive)
	}
	go keepAlive()
	p.peers.core.dhtree.Act(nil, func() {
		info := p.peers.core.dhtree.self
		p.peers.Act(&p.peers.core.dhtree, func() {
			p.sendTree(p.peers, info)
		})
	})
	var lenBuf [2]byte
	bs := make([]byte, 65535)
	for {
		if err := p.conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			return err
		}
		if _, err := io.ReadFull(p.conn, lenBuf[:]); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint16(lenBuf[:]))
		bs = bs[:size]
		if err := p.conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			return err
		}
		if _, err := io.ReadFull(p.conn, bs); err != nil {
			return err
		}
		if err := p.handlePacket(bs); err != nil {
			return err
		}
	}
}

func (p *peer) handlePacket(bs []byte) error {
	// Note: this function should be non-blocking.
	// Individual handlers should send actor messages as needed.
	if len(bs) == 0 {
		return errors.New("empty packet")
	}
	switch pType := bs[0]; pType {
	case wireDummy:
		return nil
	case wireProtoTree:
		return p.handleTree(bs[1:])
	case wireProtoDHTBootstrap:
		return p.handleBootstrap(bs[1:])
	case wireProtoDHTSetup:
		return p.handleSetup(bs[1:])
	case wireProtoDHTTeardown:
		return p.handleTeardown(bs[1:])
	case wireProtoPathNotify:
		return p.handlePathNotify(bs[1:])
	case wireProtoPathLookup:
		return p.handlePathLookup(bs[1:])
	case wireProtoPathResponse:
		return p.handlePathResponse(bs[1:])
	case wireDHTTraffic:
		return p.handleDHTTraffic(bs[1:])
	case wirePathTraffic:
		return p.handlePathTraffic(bs[1:])
	default:
		return errors.New("unrecognized packet type")
	}
}

func (p *peer) handleTree(bs []byte) error {
	info := new(treeInfo)
	if err := info.UnmarshalBinary(bs); err != nil {
		return err
	}
	if !info.checkSigs() {
		return errors.New("invalid signature")
	}
	if !p.key.equal(info.from()) {
		return errors.New("unrecognized publicKey")
	}
	dest := info.hops[len(info.hops)-1].next
	if !p.peers.core.crypto.publicKey.equal(dest) {
		panic("This shouldn't happen in testing")
		// return errors.New("incorrect destination")
	}
	p.info = info
	p.peers.core.dhtree.update(nil, info, p)
	return nil
}

func (p *peer) _sendProto(pType byte, data binaryMarshaler) {
	bs, err := wireEncode(pType, data)
	if err != nil {
		panic(err)
	}
	p._write(bs)
}

func (p *peer) sendTree(from phony.Actor, info *treeInfo) {
	p.Act(from, func() {
		info = info.add(p.peers.core.crypto.privateKey, p.key)
		p._sendProto(wireProtoTree, info)
	})
}

func (p *peer) handleBootstrap(bs []byte) error {
	bootstrap := new(dhtBootstrap)
	if err := bootstrap.UnmarshalBinary(bs); err != nil {
		return err
	}
	if !bootstrap.check() {
		return errors.New("invalid bootstrap")
	}
	p.peers.core.dhtree.handleBootstrap(nil, bootstrap)
	return nil
}

func (p *peer) sendBootstrap(from phony.Actor, bootstrap *dhtBootstrap) {
	p.Act(from, func() {
		p._sendProto(wireProtoDHTBootstrap, bootstrap)
	})
}

func (p *peer) handleSetup(bs []byte) error {
	setup := new(dhtSetup)
	if err := setup.UnmarshalBinary(bs); err != nil {
		return err
	}
	if !setup.check() {
		panic("DEBUG bad setup")
		return errors.New("invalid setup")
	}
	p.peers.core.dhtree.handleSetup(nil, p, setup)
	return nil
}

func (p *peer) sendSetup(from phony.Actor, setup *dhtSetup) {
	p.Act(from, func() {
		p._sendProto(wireProtoDHTSetup, setup)
	})
}

func (p *peer) handleTeardown(bs []byte) error {
	teardown := new(dhtTeardown)
	if err := teardown.UnmarshalBinary(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.teardown(nil, p, teardown)
	return nil
}

func (p *peer) sendTeardown(from phony.Actor, teardown *dhtTeardown) {
	p.Act(from, func() {
		p._sendProto(wireProtoDHTTeardown, teardown)
	})
}

func (p *peer) handlePathNotify(bs []byte) error {
	notify := new(pathNotify)
	if err := notify.UnmarshalBinary(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.pathfinder.handleNotify(nil, notify)
	return nil
}

func (p *peer) sendPathNotify(from phony.Actor, notify *pathNotify) {
	p.Act(from, func() {
		p._sendProto(wireProtoPathNotify, notify)
	})
}

func (p *peer) handlePathLookup(bs []byte) error {
	lookup := new(pathLookup)
	if err := lookup.UnmarshalBinary(bs); err != nil {
		return err
	}
	lookup.rpath = append(lookup.rpath, p.port)
	p.peers.core.dhtree.pathfinder.handleLookup(nil, lookup)
	return nil
}

func (p *peer) sendPathLookup(from phony.Actor, lookup *pathLookup) {
	p.Act(from, func() {
		p._sendProto(wireProtoPathLookup, lookup)
	})
}

func (p *peer) handlePathResponse(bs []byte) error {
	response := new(pathResponse)
	if err := response.UnmarshalBinary(bs); err != nil {
		return err
	}
	response.rpath = append(response.rpath, p.port)
	p.peers.core.dhtree.pathfinder.handleResponse(nil, response)
	return nil
}

func (p *peer) sendPathResponse(from phony.Actor, response *pathResponse) {
	p.Act(from, func() {
		p._sendProto(wireProtoPathResponse, response)
	})
}

func (p *peer) handleDHTTraffic(bs []byte) error {
	tr := new(dhtTraffic)
	if err := tr.UnmarshalBinaryInPlace(bs); err != nil {
		return err // This is just to check that it unmarshals correctly
	}
	trbs := append(getBytes(0), bs...)
	p.peers.core.dhtree.handleDHTTraffic(nil, trbs)
	return nil
}

func (p *peer) sendDHTTraffic(from phony.Actor, trbs []byte) {
	p.Act(from, func() {
		out := getBytes(0)
		out = append(out, wireDHTTraffic)
		out = append(out, trbs...)
		p._write(out)
		putBytes(out)
		putBytes(trbs)
	})
}

func (p *peer) handlePathTraffic(bs []byte) error {
	tr := new(pathTraffic)
	if err := tr.UnmarshalBinaryInPlace(bs); err != nil {
		return err
	}
	// TODO? skip all of the above and just trust it?...
	// TODO? don't send to p.peers, have a (read-only) copy of the map locally? via atomics?
	trbs := append(getBytes(0), bs...)
	p.peers.handlePathTraffic(nil, trbs)
	return nil
}

func (ps *peers) handlePathTraffic(from phony.Actor, trbs []byte) {
	ps.Act(from, func() {
		nextPort, trbs := pathPopFirstHop(trbs)
		if next, isIn := ps.peers[nextPort]; isIn {
			next.sendPathTraffic(nil, trbs)
			fmt.Println("DEBUG sendPathTraffic success")
		} else {
			// Fall back to dhtTraffic
			if nextPort != 0 {
				tr := new(pathTraffic)
				if err := tr.UnmarshalBinaryInPlace(trbs); err != nil {
					panic("DEBUG")
					return
				}
				var err error
				if trbs, err = tr.dt.MarshalBinaryTo(trbs[:0]); err != nil {
					panic("DEBUG")
					return
				}
			}
			// TODO never trigger a notify if nextPort == 0 (we're the destination)
			fmt.Println("DEBUG sendPathTraffic fail:", nextPort)
			ps.core.dhtree.handleDHTTraffic(nil, trbs)
		}
	})
}

func (p *peer) sendPathTraffic(from phony.Actor, trbs []byte) {
	p.Act(from, func() {
		out := getBytes(0)
		out = append(out, wirePathTraffic)
		out = append(out, trbs...)
		p._write(out)
		putBytes(out)
		putBytes(trbs)
	})
}
