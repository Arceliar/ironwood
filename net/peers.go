package net

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

type peers struct {
	core *core
}

type peer struct {
	peers *peers
	conn  net.Conn
	info  *treeInfo
}

func (p *peer) handler() error {
	ch := make(chan error)
	done := make(chan struct{})
	close(done)
	var reader func()
	reader = func() {
		wait := done
		done = make(chan struct{})
		defer close(done)
		var lenBuf [8]byte
		if err := p.conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			ch <- err
			return
		}
		if _, err := io.ReadFull(p.conn, lenBuf[:]); err != nil {
			ch <- err
			return
		}
		l := binary.BigEndian.Uint64(lenBuf[:])
		bs := alloc(int(l))
		if err := p.conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			ch <- err
			return
		}
		if _, err := io.ReadFull(p.conn, bs); err != nil {
			ch <- err
			return
		}
		handler, err := p.getHandler(bs)
		if err != nil {
			ch <- err
			return
		}
		go reader()
		<-wait
		handler(bs)
	}
	go reader()
	return <-ch
}

func (p *peer) getHandler(bs []byte) (func([]byte), error) {
	if len(bs) == 0 {
		return nil, errors.New("empty packet")
	}
	switch pType := bs[0]; pType {
	case wireDummy:
		return func(_ []byte) {}, nil
	case wireProtoTree:
		return nil, p.handleTree(bs)
	default:
		return nil, errors.New("unrecognized packet type")
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
	panic("TODO handleTree")
	// TODO check if info is sane compared to p.info, e.g. same keys
	p.info = info
	p.peers.core.tree.update(info) // TODO make this thread safe
	return nil
}
