package net

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Arceliar/phony"
)

type PacketConn struct {
	actor        phony.Inbox
	core         *core
	recv         chan *dhtTraffic // read buffer
	recvWrongKey chan *dhtTraffic // read buffer for packets sent to a different key
	closeMutex   sync.Mutex
	closed       chan struct{}
	readDeadline deadline
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
	pc.readDeadline = newDeadline()
}

func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	var tr *dhtTraffic
	select {
	case <-pc.closed:
		return 0, nil, errors.New("closed")
	case <-pc.readDeadline.getCancel():
		return 0, nil, errors.New("deadline exceeded")
	case tr = <-pc.recv:
	}
	copy(p, tr.payload)
	n = len(tr.payload)
	if len(p) < len(tr.payload) {
		n = len(p)
	}
	from = tr.source.addr()
	return
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-pc.closed:
		return 0, errors.New("closed")
	default:
	}
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
	pc.closeMutex.Lock()
	defer pc.closeMutex.Unlock()
	select {
	case <-pc.closed:
		return errors.New("closed")
	default:
	}
	close(pc.closed)
	return nil
}

func (pc *PacketConn) LocalAddr() net.Addr {
	a := Addr(append([]byte(nil), pc.core.crypto.publicKey...))
	return &a
}

func (pc *PacketConn) SetDeadline(t time.Time) error {
	if err := pc.SetReadDeadline(t); err != nil {
		return err
	} else if err := pc.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

func (pc *PacketConn) SetReadDeadline(t time.Time) error {
	pc.readDeadline.set(t)
	return nil
}

func (pc *PacketConn) SetWriteDeadline(t time.Time) error {
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

type deadline struct {
	m      sync.Mutex
	timer  *time.Timer
	once   *sync.Once
	cancel chan struct{}
}

func newDeadline() deadline {
	var d deadline
	d.once = new(sync.Once)
	d.cancel = make(chan struct{})
	return d
}

func (d *deadline) set(t time.Time) {
	d.m.Lock()
	defer d.m.Unlock()
	d.once.Do(func() {
		if d.timer != nil {
			d.timer.Stop()
		}
	})
	select {
	case <-d.cancel:
		d.cancel = make(chan struct{})
	default:
	}
	d.once = new(sync.Once)
	var zero time.Time
	if t != zero {
		once := d.once
		cancel := d.cancel
		d.timer = time.AfterFunc(time.Until(t), func() {
			once.Do(func() { close(cancel) })
		})
	}
}

func (d *deadline) getCancel() chan struct{} {
	d.m.Lock()
	defer d.m.Unlock()
	ch := d.cancel
	return ch
}
