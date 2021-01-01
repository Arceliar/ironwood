package net

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/Arceliar/phony"
)

type peers struct {
	phony.Inbox // Used to create/remove peers
	core        *core
	peers       map[string]*peer
}

func (ps *peers) init(c *core) {
	ps.core = c
	ps.peers = make(map[string]*peer)
}

func (ps *peers) addPeer(key publicKey, conn net.Conn) (*peer, error) {
	var p *peer
	var err error
	phony.Block(ps, func() {
		if _, isIn := ps.peers[string(key)]; isIn {
			err = errors.New("peer already exists")
		} else {
			p = new(peer)
			p.peers = ps
			p.conn = conn
			p.key = key
			ps.peers[string(key)] = p
		}
	})
	return p, err
}

func (ps *peers) removePeer(from publicKey) error {
	var err error
	phony.Block(ps, func() {
		if _, isIn := ps.peers[string(from)]; !isIn {
			err = errors.New("peer not found")
		} else {
			delete(ps.peers, string(from))
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

func (ps *peers) sendBootstrap(from phony.Actor, peerKey publicKey, bootstrap *dhtBootstrap) {
	ps.Act(from, func() {
		if p, isIn := ps.peers[string(peerKey)]; isIn {
			p.sendBootstrap(ps, bootstrap)
		}
	})
}

func (ps *peers) sendTeardown(from phony.Actor, peerKey publicKey, teardown *dhtTeardown) {
	ps.Act(from, func() {
		if p, isIn := ps.peers[string(peerKey)]; isIn {
			p.sendTeardown(ps, teardown)
		} else {
			panic("DEBUG tried to send teardown to nonexistant peer")
		}
	})
}

func (ps *peers) sendSetup(from phony.Actor, peerKey publicKey, setup *dhtSetup) {
	ps.Act(from, func() {
		if p, isIn := ps.peers[string(peerKey)]; isIn {
			p.sendSetup(ps, setup)
		} else {
			ps.core.dhtree.teardown(ps, peerKey, &dhtTeardown{source: setup.source})
		}
	})
}

func (ps *peers) sendDHTTraffic(from phony.Actor, peerKey publicKey, tr *dhtTraffic) {
	ps.Act(from, func() {
		if p, isIn := ps.peers[string(peerKey)]; isIn {
			p.sendDHTTraffic(ps, tr)
		}
	})
}

type peer struct {
	phony.Inbox // Only used to process or send some protocol traffic
	peers       *peers
	conn        net.Conn
	key         publicKey
	info        *treeInfo
}

func (p *peer) _write(bs []byte) {
	out := make([]byte, 8+len(bs))
	binary.BigEndian.PutUint64(out[:8], uint64(len(bs)))
	copy(out[8:], bs)
	p.conn.Write(out)
	if bs[0] == wireProtoDHTTeardown {
		panic("DEBUG write")
	}
}

func (p *peer) handler() error {
	defer func() {
		if p.info != nil {
			p.peers.core.dhtree.remove(nil, p.info)
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
	var info *treeInfo
	phony.Block(&p.peers.core.dhtree, func() {
		info = p.peers.core.dhtree.self
	})
	p.sendTree(nil, info)
	go keepAlive()
	for {
		var lenBuf [8]byte
		if err := p.conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			return err
		}
		if _, err := io.ReadFull(p.conn, lenBuf[:]); err != nil {
			return err
		}
		l := binary.BigEndian.Uint64(lenBuf[:])
		bs := make([]byte, int(l))
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
		return errors.New("incorrect destination")
	}
	p.info = info
	p.peers.core.dhtree.update(nil, info)
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
		return errors.New("invalid setup")
	}
	p.peers.core.dhtree.handleSetup(nil, p.key, setup)
	return nil
}

func (p *peer) sendSetup(from phony.Actor, setup *dhtSetup) {
	p.Act(from, func() {
		p._sendProto(wireProtoDHTSetup, setup)
	})
}

func (p *peer) handleTeardown(bs []byte) error {
	panic("DEBUG ht1") // FIXME this isn't triggered, even though we send teardowns...
	teardown := new(dhtTeardown)
	if err := teardown.UnmarshalBinary(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.teardown(nil, p.key, teardown)
	return nil
}

func (p *peer) sendTeardown(from phony.Actor, teardown *dhtTeardown) {
	p.Act(from, func() {
		p._sendProto(wireProtoDHTTeardown, teardown)
	})
}

func (p *peer) handleDHTTraffic(bs []byte) error {
	tr := new(dhtTraffic)
	if err := tr.UnmarshalBinary(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.handleDHTTraffic(nil, tr)
	return nil
}

func (p *peer) sendDHTTraffic(from phony.Actor, tr *dhtTraffic) {
	p.Act(from, func() {
		p._sendProto(wireDHTTraffic, tr)
	})
}
