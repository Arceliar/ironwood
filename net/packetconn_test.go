package net

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Arceliar/phony"
)

func TestTwoNodes(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	a, _ := NewPacketConn(privA)
	b, _ := NewPacketConn(privB)
	cA, cB := newDummyConn(pubA, pubB)
	defer cA.Close()
	defer cB.Close()
	go a.HandleConn(pubB, cA)
	go b.HandleConn(pubA, cB)
	timer := time.NewTimer(time.Second)
	tA := &a.(*packetConn).core.tree
	tB := &b.(*packetConn).core.tree
	for {
		select {
		case <-timer.C:
			panic("timeout")
		default:
		}
		var rA, rB publicKey
		phony.Block(tA, func() {
			rA = tA.self.root
		})
		phony.Block(tB, func() {
			rB = tB.self.root
		})
		if bytes.Equal(rA, rB) {
			break
		}
	}
	var sA, sB *treeInfo
	phony.Block(tA, func() {
		sA = tA.self
	})
	phony.Block(tB, func() {
		sB = tB.self
	})
	var aL, bL publicKey
	phony.Block(tA, func() {
		aL = tA._lookup(sB)
	})
	phony.Block(tB, func() {
		bL = tB._lookup(sA)
	})
	if !bytes.Equal(aL, tB.core.crypto.publicKey) {
		println(aL[0], tB.core.crypto.publicKey[0], tA.core.crypto.publicKey[0])
		panic("wrong lookup result aL")
	}
	if !bytes.Equal(bL, tA.core.crypto.publicKey) {
		println(bL[0], tA.core.crypto.publicKey[0], tB.core.crypto.publicKey[0])
		panic("wrong lookup result bL")
	}
}

/*************
 * dummyConn *
 *************/

type dummyConn struct {
	readLock  sync.Mutex
	recv      chan []byte
	recvBuf   []byte
	writeLock sync.Mutex
	send      chan []byte
	closeLock *sync.Mutex
	closed    chan struct{}
}

func newDummyConn(keyA, keyB ed25519.PublicKey) (*dummyConn, *dummyConn) {
	toA := make(chan []byte)
	toB := make(chan []byte)
	cl := new(sync.Mutex)
	closed := make(chan struct{})
	connA := dummyConn{recv: toA, send: toB, closeLock: cl, closed: closed}
	connB := dummyConn{recv: toB, send: toA, closeLock: cl, closed: closed}
	return &connA, &connB
}

func (d *dummyConn) Read(b []byte) (n int, err error) {
	d.readLock.Lock()
	defer d.readLock.Unlock()
	if len(d.recvBuf) == 0 {
		select {
		case <-d.closed:
			return 0, errors.New("closed")
		case bs := <-d.recv:
			d.recvBuf = append(d.recvBuf, bs...)
		}
	}
	n = len(b)
	if len(d.recvBuf) < n {
		n = len(d.recvBuf)
	}
	copy(b, d.recvBuf[:n])
	d.recvBuf = d.recvBuf[n:]
	return n, nil
}

func (d *dummyConn) Write(b []byte) (n int, err error) {
	d.writeLock.Lock()
	defer d.writeLock.Unlock()
	bs := append([]byte(nil), b...)
	select {
	case <-d.closed:
		return 0, errors.New("closed")
	case d.send <- bs:
		return len(bs), nil
	}
}

func (d *dummyConn) Close() error {
	d.closeLock.Lock()
	defer d.closeLock.Unlock()
	select {
	case <-d.closed:
		return errors.New("closed")
	default:
		close(d.closed)
	}
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
