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
	recvCheck    func(ed25519.PublicKey) bool
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
// This function blocks while the net.Conn is in use, and returns an error if any occurs.
// This function returns (almost) immediately if PacketConn.Close() is called.
// In all cases, the net.Conn is closed before returning.
func (pc *PacketConn) HandleConn(key ed25519.PublicKey, conn net.Conn) error {
	defer conn.Close()
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

// SetRecvCheck sets a function that is called on the destination key of any received packet.
// If the function is not set, or set to nil, then packets are received (by calling ReadFrom) if and only if the destination key exactly matches this node's public key.
// If the function is set, then packet are received any time the provided function returns true.
// This is used to allow packets to be received if e.g. only a certain part of this connection's public key would be known by the sender.
func (pc *PacketConn) SetRecvCheck(isGood func(ed25519.PublicKey) bool) error {
	phony.Block(&pc.actor, func() {
		pc.recvCheck = isGood
	})
	return nil
}

func (pc *PacketConn) handleTraffic(trbs []byte) {
	pc.actor.Act(nil, func() {
		var tr dhtTraffic
		if err := tr.UnmarshalBinaryInPlace(trbs); err != nil {
			panic("this should never happen")
		}
		var doRecv bool
		if pc.recvCheck != nil {
			if pc.recvCheck(ed25519.PublicKey(tr.dest)) {
				doRecv = true
			}
		} else if tr.dest.equal(pc.core.crypto.publicKey) {
			doRecv = true
		}
		if doRecv {
			select {
			case pc.recv <- trbs:
			case <-pc.closed:
				putBytes(trbs)
			}
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
