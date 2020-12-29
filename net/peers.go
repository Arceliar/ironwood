package net

import (
	"encoding/binary"
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
		p.conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.ReadFull(p.conn, lenBuf[:]); err != nil {
			ch <- err
			return
		}
		l := binary.BigEndian.Uint64(lenBuf[:])
		bs := alloc(int(l))
		p.conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.ReadFull(p.conn, bs); err != nil {
			ch <- err
			return
		}
		p.handlePacket(bs, wait, reader)
	}
	go reader()
	return <-ch
}

func (p *peer) handlePacket(bs []byte, wait chan struct{}, reader func()) {
	panic("TODO handlePacket")
	// TODO decode packet type and run the proper handler
	//  start the next reader at the earliest possibe safe point
	//  wait at the latest possible safe point
	<-wait
	go reader()
}
