package net

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"testing"
	"time"
)

func TestDummy(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	a, _ := NewPacketConn(privA)
	b, _ := NewPacketConn(privB)
	cA, cB := newDummyConn(pubA, pubB)
	go a.HandleConn(pubB, cA)
	go b.HandleConn(pubA, cB)
	time.Sleep(time.Second)
	rA := a.(*packetConn).core.tree.self.root
	rB := b.(*packetConn).core.tree.self.root
	if !bytes.Equal(rA, rB) {
		panic("not equal")
	}
}

/*************
 * dummyConn *
 *************/

type dummyConn struct {
	recv chan []byte
	send chan []byte
}

func newDummyConn(keyA, keyB ed25519.PublicKey) (*dummyConn, *dummyConn) {
	toA := make(chan []byte)
	toB := make(chan []byte)
	connA := dummyConn{recv: toA, send: toB}
	connB := dummyConn{recv: toB, send: toA}
	return &connA, &connB
}

func (d *dummyConn) Read(b []byte) (n int, err error) {
	bs := <-d.recv
	copy(b, bs)
	n = len(bs)
	if len(b) < len(bs) {
		n = len(b)
	}
	return n, nil
}

func (d *dummyConn) Write(b []byte) (n int, err error) {
	bs := append([]byte(nil), b...)
	d.send <- bs
	return len(bs), nil
}

func (d *dummyConn) Close() error {
	panic("TODO Close")
	return nil
}

func (d *dummyConn) LocalAddr() net.Addr {
	panic("TODO LocalAddr")
	return nil
}

func (d *dummyConn) RemoteAddr() net.Addr {
	panic("TODO RemoteAddr")
	return nil
}

func (d *dummyConn) SetDeadline(t time.Time) error {
	panic("TODO implement SetDeadline")
	return nil
}

func (d *dummyConn) SetReadDeadline(t time.Time) error {
	//panic("TODO implement SetReadDeadline")
	return nil
}

func (d *dummyConn) SetWriteDeadline(t time.Time) error {
	panic("TODO implement SetWriteDeadline")
	return nil
}
