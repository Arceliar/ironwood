package net

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"runtime"
	"time"

	"github.com/Arceliar/phony"
)

type PacketConn struct {
	actor        phony.Inbox
	core         *core
	recv         chan *dhtTraffic // read buffer
	recvWrongKey chan *dhtTraffic // read buffer for packets sent to a different key
}

type Addr ed25519.PublicKey

func (key *publicKey) addr() *Addr {
	return (*Addr)(key)
}

func (a *Addr) key() publicKey {
	return publicKey(*a)
}

func (a *Addr) Network() string {
	return "ed25519.PublicKey"
}

func (a *Addr) String() string {
	return hex.EncodeToString(*a)
}

func NewPacketConn(secret ed25519.PrivateKey) (*PacketConn, error) {
	c := new(core)
	if err := c.init(secret); err != nil {
		return nil, err
	}
	return &c.pconn, nil
}

func (pc *PacketConn) init(c *core) {
	pc.core = c
	pc.recv = make(chan *dhtTraffic, 32)
	pc.recvWrongKey = make(chan *dhtTraffic, 32)
}

func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	tr := <-pc.recv
	copy(p, tr.payload)
	n = len(tr.payload)
	if len(p) < len(tr.payload) {
		n = len(p)
	}
	from = tr.source.addr()
	return
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if _, ok := addr.(*Addr); !ok {
		return 0, errors.New("incorrect address type")
	}
	dest := addr.(*Addr).key()
	if len(dest) != publicKeySize {
		return 0, errors.New("incorrect address length")
	}
	tr := new(dhtTraffic)
	tr.source = append(tr.source, pc.core.crypto.publicKey...)
	tr.dest = append(tr.dest, dest...)
	tr.payload = append(tr.payload, p...)
	pc.core.dhtree.handleDHTTraffic(nil, tr)
	return len(p), nil
}

func (pc *PacketConn) Close() error {
	panic("TODO implement Close")
	return nil
}

func (pc *PacketConn) LocalAddr() net.Addr {
	a := Addr(append([]byte(nil), pc.core.crypto.publicKey...))
	return &a
}

func (pc *PacketConn) SetDeadline(t time.Time) error {
	panic("TODO implement SetDeadline")
	return nil
}

func (pc *PacketConn) SetReadDeadline(t time.Time) error {
	panic("TODO implement SetReadDeadline")
	return nil
}

func (pc *PacketConn) SetWriteDeadline(t time.Time) error {
	panic("TODO implement SetWriteDeadline")
	return nil
}

func (pc *PacketConn) HandleConn(key ed25519.PublicKey, conn net.Conn) error {
	// Note: This should block until we're done with the Conn, then return without closing it
	if len(key) != publicKeySize {
		return errors.New("incorrect key length")
	}
	p, err := pc.core.peers.addPeer(publicKey(key), conn)
	if err != nil {
		return err
	}
	err = p.handler()
	if e := pc.core.peers.removePeer(publicKey(key)); e != nil {
		return e
	}
	return err
}

func (pc *PacketConn) ReadUndeliverable(p []byte) (n int, local, remote net.Addr, err error) {
	tr := <-pc.recvWrongKey
	copy(p, tr.payload)
	n = len(tr.payload)
	if len(p) < len(tr.payload) {
		n = len(p)
	}
	local = tr.dest.addr()
	remote = tr.source.addr()
	return
}

func (pc *PacketConn) handleTraffic(from phony.Actor, tr *dhtTraffic) {
	if !tr.dest.equal(pc.core.crypto.publicKey) {
		pc.actor.Act(from, func() {
			select {
			case pc.recvWrongKey <- tr:
			default:
			}
			runtime.Gosched() // Give readers a chance to drain the queue
		})
	} else {
		pc.actor.Act(from, func() {
			select {
			case pc.recv <- tr:
			default:
			}
			runtime.Gosched() // Give readers a chance to drain the queue
		})
	}
}
