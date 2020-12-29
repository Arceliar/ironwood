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
	phony.Actor
	core  *core
	peers map[string]*peer
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

type peer struct {
	phony.Actor // Only used to process or send some protocol traffic
	peers       *peers
	conn        net.Conn
	from        publicKey
	info        *treeInfo
}

func (p *peer) handler() error {
	defer func() {
		if p.info != nil {
			p.peers.core.tree.remove(nil, p.info)
		}
	}()
	// TODO send keep-alive traffic to prevent these deadlines from passing
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
	p.info = info
	p.peers.core.tree.update(nil, info)
	return nil
}
