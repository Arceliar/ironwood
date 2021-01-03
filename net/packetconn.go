package net

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"github.com/Arceliar/phony"
)

type PacketConn interface {
	net.PacketConn
	HandleConn(ed25519.PublicKey, net.Conn) error
}

type packetConn struct {
	actor phony.Inbox
	core  *core
	recv  chan *dhtTraffic // read buffer
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

func NewPacketConn(secret ed25519.PrivateKey) (PacketConn, error) {
	c := new(core)
	if err := c.init(secret); err != nil {
		return nil, err
	}
	return &c.pconn, nil
}

func (pc *packetConn) init(c *core) {
	pc.core = c
	pc.recv = make(chan *dhtTraffic, 1)
}

func (pc *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// TODO timeout, also sanity check dest address
	//  maybe return an error that contains the dest address if it's not an exact match?
	//  Or add some way to set up how many matching bits are required
	//    Needed for e.g. cryptographically generated ipv6 addresses
	//  Part of NewPacketConn or some function called at some point?...
	tr := <-pc.recv
	copy(p, tr.payload)
	n = len(tr.payload)
	if len(p) < len(tr.payload) {
		n = len(p)
	}
	addr = tr.source.addr()
	return
}

func (pc *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

func (pc *packetConn) Close() error {
	panic("TODO implement Close")
	return nil
}

func (pc *packetConn) LocalAddr() net.Addr {
	a := Addr(pc.core.crypto.publicKey)
	return &a
}

func (pc *packetConn) SetDeadline(t time.Time) error {
	panic("TODO implement SetDeadline")
	return nil
}

func (pc *packetConn) SetReadDeadline(t time.Time) error {
	panic("TODO implement SetReadDeadline")
	return nil
}

func (pc *packetConn) SetWriteDeadline(t time.Time) error {
	panic("TODO implement SetWriteDeadline")
	return nil
}

func (pc *packetConn) HandleConn(key ed25519.PublicKey, conn net.Conn) error {
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

func (pc *packetConn) handleTraffic(from phony.Actor, tr *dhtTraffic) {
	from = nil // TODO buffer things intelligently, instead of just the actor queue
	pc.actor.Act(from, func() {
		pc.recv <- tr
	})
}
