package net

import (
	"encoding/binary"
	"errors"
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
		for idx := 0; ; idx++ {
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

func (ps *peers) sendTree(from phony.Actor, info *treeInfo) {
	ps.Act(from, func() {
		for _, p := range ps.peers {
			p.sendTree(ps, info)
		}
	})
}

func (ps *peers) sendBootstrap(from phony.Actor, port peerPort, bootstrap *dhtBootstrap) {
	ps.Act(from, func() {
		if p, isIn := ps.peers[port]; isIn {
			p.sendBootstrap(ps, bootstrap)
		}
	})
}

func (ps *peers) sendTeardown(from phony.Actor, port peerPort, teardown *dhtTeardown) {
	ps.Act(from, func() {
		if p, isIn := ps.peers[port]; isIn {
			p.sendTeardown(ps, teardown)
		} else {
			return // Skip the below for now, it can happen if peers are removed
			//panic("DEBUG tried to send teardown to nonexistant peer")
		}
	})
}

func (ps *peers) sendSetup(from phony.Actor, port peerPort, setup *dhtSetup) {
	ps.Act(from, func() {
		if p, isIn := ps.peers[port]; isIn {
			p.sendSetup(ps, setup)
		} else {
			panic("FIXME publicKey / teardown logic")
			ps.core.dhtree.teardown(ps, nil, setup.getTeardown()) // FIXME middle arg = peer for peer.port
		}
	})
}

func (ps *peers) sendDHTTraffic(from phony.Actor, port peerPort, trbs []byte) {
	ps.Act(from, func() {
		if p, isIn := ps.peers[port]; isIn {
			p.sendDHTTraffic(ps, trbs)
		} else {
			putBytes(trbs)
		}
	})
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
	case wireDHTTraffic:
		return p.handleDHTTraffic(bs[1:])
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
