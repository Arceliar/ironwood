package ironwood

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Arceliar/phony"
)

type PacketConn struct {
	actor        phony.Inbox
	core         *core
	recv         chan []byte // dhtTraffic read buffer
	recvWrongKey chan []byte // dhtTraffic read buffer for packets sent to a different key
	closeMutex   sync.Mutex
	closed       chan struct{}
	readDeadline *deadline
}

// Addr implements the `net.Addr` interface for `ed25519.PublicKey` values.
// An *Addr pointer is used as a net.Addr for PacketConn.
type Addr ed25519.PublicKey

func (key *publicKey) addr() *Addr {
	return (*Addr)(key)
}

func (a *Addr) key() publicKey {
	return publicKey(*a)
}

// Network returns "ed25519.PublicKey" as a string, but is otherwise unused.
func (a *Addr) Network() string {
	return "ed25519.PublicKey"
}

// String returns the ed25519.PublicKey as a hexidecimal string, but is otherwise unused.
func (a *Addr) String() string {
	return hex.EncodeToString(*a)
}

// NewPacketConn returns a *PacketConn struct which implements the net.PacketConn interface.
func NewPacketConn(secret ed25519.PrivateKey) (*PacketConn, error) {
	c := new(core)
	if err := c.init(secret); err != nil {
		return nil, err
	}
	return &c.pconn, nil
}

func (pc *PacketConn) init(c *core) {
	pc.core = c
	pc.recv = make(chan []byte, 1)
	pc.recvWrongKey = make(chan []byte, 1)
	pc.readDeadline = newDeadline()
	pc.closed = make(chan struct{})
}

// ReadFrom fulfills the net.PacketConn interface, with a *Addr returned as the from address.
// Note that failing to call ReadFrom may cause the connection to block and/or leak memory.
func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	var trbs []byte
	select {
	case <-pc.closed:
		return 0, nil, errors.New("closed")
	case <-pc.readDeadline.getCancel():
		return 0, nil, errors.New("deadline exceeded")
	case trbs = <-pc.recv:
	}
	defer putBytes(trbs)
	var tr dhtTraffic
	if err := tr.UnmarshalBinaryInPlace(trbs); err != nil {
		panic("this should never happen")
	}
	copy(p, tr.payload)
	n = len(tr.payload)
	if len(p) < len(tr.payload) {
		n = len(p)
	}
	fromSlice := publicKey(append([]byte(nil), tr.source...))
	from = fromSlice.addr()

	return
}

// WriteTo fulfills the net.PacketConn interface, with a *Addr expected as the destination address.
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
	var tr dhtTraffic
	tr.source = pc.core.crypto.publicKey
	tr.dest = dest
	tr.payload = p
	trbs, err := tr.MarshalBinaryTo(getBytes(0))
	if err != nil {
		// TODO do this when there's an oversized packet maybe?
		putBytes(trbs)
		return 0, errors.New("failed to encode traffic")
	}
	pc.core.dhtree.sendTraffic(nil, trbs)
	return len(p), nil
}

// Close shuts down the PacketConn.
func (pc *PacketConn) Close() error {
	pc.closeMutex.Lock()
	defer pc.closeMutex.Unlock()
	select {
	case <-pc.closed:
		return errors.New("closed")
	default:
	}
	close(pc.closed)
	phony.Block(&pc.core.peers, func() {
		for _, p := range pc.core.peers.peers {
			p.conn.Close()
		}
	})
	phony.Block(&pc.core.dhtree, func() {
		if pc.core.dhtree.timer != nil {
			pc.core.dhtree.timer.Stop()
			pc.core.dhtree.timer = nil
		}
	})
	return nil
}

// LocalAddr returns an *Addr of the ed25519.PublicKey for this PacketConn.
func (pc *PacketConn) LocalAddr() net.Addr {
	a := Addr(append([]byte(nil), pc.core.crypto.publicKey...))
	return &a
}

// SetDeadline fulfills the net.PacketConn interface. Note that only read deadlines are affected.
func (pc *PacketConn) SetDeadline(t time.Time) error {
	if err := pc.SetReadDeadline(t); err != nil {
		return err
	} else if err := pc.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetReadDeadline fulfills the net.PacketConn interface.
func (pc *PacketConn) SetReadDeadline(t time.Time) error {
	pc.readDeadline.set(t)
	return nil
}

// SetWriteDeadline fulfills the net.PacketConn interface.
func (pc *PacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// HandleConn expects a peer's public key as its first argument, and a net.Conn with TCP-like semantics (reliable ordered delivery) as its second argument.
// This function blocks while the net.Conn is in use, and returns (without closing the net.Conn) if any error occurs.
// This function returns (after closing the net.Conn) if PacketConn.Close() is called.
func (pc *PacketConn) HandleConn(key ed25519.PublicKey, conn net.Conn) error {
	// Note: This should block until we're done with the Conn, then return without closing it
	if len(key) != publicKeySize {
		return errors.New("incorrect key length")
	}
	if pc.core.crypto.publicKey.equal(publicKey(key)) {
		return errors.New("attempted to connect to self")
	}
	p, err := pc.core.peers.addPeer(publicKey(key), conn)
	if err != nil {
		return err
	}
	err = p.handler()
	if e := pc.core.peers.removePeer(p.port); e != nil {
		return e
	}
	return err
}

// ReadUndeliverable works exactly like ReadFrom, except it returns any packets that were sent to a different local address but cannot be forwarded further.
// This happens if the LocalAddr is the immediate successor of the destination (higher by the smallest amount, modulo the keyspace size).
// This may be useful for key discovery when a destination's full ed25519.PublicKey is not known (by zero padding the least unknown least significant bits).
// Note that failing to call ReadUndeliverable may cause the connection to block and/or leak memory.
func (pc *PacketConn) ReadUndeliverable(p []byte) (n int, local, remote net.Addr, err error) {
	var trbs []byte
	select {
	case <-pc.closed:
		return 0, nil, nil, errors.New("closed")
	case <-pc.readDeadline.getCancel():
		return 0, nil, nil, errors.New("deadline exceeded")
	case trbs = <-pc.recvWrongKey:
	}
	defer putBytes(trbs)
	var tr dhtTraffic
	if err := tr.UnmarshalBinaryInPlace(trbs); err != nil {
		panic("this should never happen")
	}
	copy(p, tr.payload)
	n = len(tr.payload)
	if len(p) < len(tr.payload) {
		n = len(p)
	}
	localSlice := publicKey(append([]byte(nil), tr.dest...))
	remoteSlice := publicKey(append([]byte(nil), tr.source...))
	local = localSlice.addr()
	remote = remoteSlice.addr()
	return
}

func (pc *PacketConn) handleTraffic(trbs []byte) {
	var tr dhtTraffic
	if err := tr.UnmarshalBinaryInPlace(trbs); err != nil {
		panic("this should never happen")
	}
	var ch chan []byte
	if !tr.dest.equal(pc.core.crypto.publicKey) {
		ch = pc.recvWrongKey
	} else {
		ch = pc.recv
	}
	pc.actor.Act(nil, func() {
		select {
		case ch <- trbs:
		case <-pc.closed:
			putBytes(trbs)
		}
	})
}

type deadline struct {
	m      sync.Mutex
	timer  *time.Timer
	once   *sync.Once
	cancel chan struct{}
}

func newDeadline() *deadline {
	return &deadline{
		once:   new(sync.Once),
		cancel: make(chan struct{}),
	}
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
