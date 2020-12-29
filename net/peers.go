package net

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/Arceliar/phony"
)

type peers struct {
	phony.Actor // Used to create/remove peers
	core        *core
	peers       map[string]*peer
}

func (ps *peers) init(c *core) {
	ps.core = c
	ps.peers = make(map[string]*peer)
}

func (ps *peers) addPeer(from publicKey, conn net.Conn) (*peer, error) {
	var p *peer
	var err error
	phony.Block(ps, func() {
		if _, isIn := ps.peers[string(from)]; isIn {
			err = errors.New("peer already exists")
		} else {
			p = new(peer)
			p.peers = ps
			p.conn = conn
			p.from = from
			ps.peers[string(from)] = p
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

type peer struct {
	phony.Actor // Only used to process or send some protocol traffic
	peers       *peers
	conn        net.Conn
	from        publicKey
	info        *treeInfo
}

func (p *peer) write(bs []byte) {
	var size []byte
	binary.BigEndian.PutUint64(size, uint64(len(bs)))
	buf := net.Buffers{size, bs}
	buf.WriteTo(p.conn)
}

func (p *peer) handler() error {
	defer func() {
		if p.info != nil {
			p.peers.core.tree.remove(nil, p.info)
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
		p.write([]byte{wireDummy})
		time.AfterFunc(time.Second, keepAlive)
	}
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
		bs := alloc(int(l))
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
	if len(bs) == 0 {
		return errors.New("empty packet")
	}
	switch pType := bs[0]; pType {
	case wireDummy:
		return nil
	case wireProtoTree:
		return p.handleTree(bs)
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
	if !bytes.Equal(p.from, info.from()) {
		return errors.New("unrecognized publicKey")
	}
	dest := info.hops[len(info.hops)-1].next
	if !bytes.Equal(p.peers.core.crypto.publicKey, dest) {
		return errors.New("incorrect destination")
	}
	p.info = info
	p.peers.core.tree.update(nil, info)
	return nil
}

func (p *peer) sendTree(from phony.Actor, info *treeInfo) {
	p.Act(from, func() {
		info = info.add(p.peers.core.crypto.privateKey, p.from)
		bs, _ := info.MarshalBinary()
		bs = append([]byte{wireProtoTree}, bs...)
		p.write(bs)
	})
}
