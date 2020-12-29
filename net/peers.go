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

type peer struct {
	phony.Actor // Used by some protocol traffic, while the handler deal with reading etc...
	peers       *peers
	conn        net.Conn
	info        *treeInfo
}

func (p *peer) handler() error {
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
	if p.info != nil && !bytes.Equal(p.info.from(), info.from()) {
		return errors.New("unrecognized publicKey")
	}
	p.Act(nil, func() {
		p.info = info
		p.peers.core.tree.update(p, info)
	})
	return nil
}
