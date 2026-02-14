package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Arceliar/ironwood/types"
)

func TestTwoNodes(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	a, _ := NewPacketConn(privA)
	b, _ := NewPacketConn(privB)
	defer a.Close()
	defer b.Close()
	cA, cB := newDummyConn(pubA, pubB)
	defer cA.Close()
	defer cB.Close()
	go a.HandleConn(pubB, cA, 0)
	go b.HandleConn(pubA, cB, 0)

	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	addrA := a.LocalAddr()
	addrB := b.LocalAddr()
	done := make(chan struct{})
	go func() {
		defer func() {
			defer func() { recover() }()
			close(done)
		}()
		msg := make([]byte, 2048)
		n, from, err := b.ReadFrom(msg)
		if err != nil {
			panic("err")
		}
		msg = msg[:n]
		aA := addrA.(types.Addr)
		fA := from.(types.Addr)
		if !bytes.Equal(aA, fA) {
			panic("wrong source address")
		}
	}()
	go func() {
		msg := []byte("test")
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := a.WriteTo(msg, addrB); err != nil {
				panic(err)
			}
			time.Sleep(time.Second)
		}
	}()
	select {
	case <-timer.C:
		t.Log("timeout")
		panic("timeout")
	case <-done:
	}
}

type dummyConn struct {
	readLock  sync.Mutex
	recv      chan []byte
	recvBuf   []byte
	writeLock sync.Mutex
	send      chan []byte
	closeLock *sync.Mutex
	closed    chan struct{}
}

func newDummyConn(_ ed25519.PublicKey, _ ed25519.PublicKey) (*dummyConn, *dummyConn) {
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

func (d *dummyConn) LocalAddr() net.Addr              { return nil }
func (d *dummyConn) RemoteAddr() net.Addr             { return nil }
func (d *dummyConn) SetDeadline(time.Time) error      { return nil }
func (d *dummyConn) SetReadDeadline(time.Time) error  { return nil }
func (d *dummyConn) SetWriteDeadline(time.Time) error { return nil }
