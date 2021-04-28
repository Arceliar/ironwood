package network

import (
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

func _type_asserts_() {
	var _ types.PacketConn = new(PacketConn)
}

type PacketConn struct {
	actor        phony.Inbox
	core         *core
	recv         chan []byte // dhtTraffic read buffer
	oobHandler   func(ed25519.PublicKey, ed25519.PublicKey, []byte) []byte
	readDeadline *deadline
	closeMutex   sync.Mutex
	closed       chan struct{}
}

// NewPacketConn returns a *PacketConn struct which implements the types.PacketConn interface.
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
	if _, ok := addr.(types.Addr); !ok {
		return 0, errors.New("incorrect address type, expected types.Addr")
	}
	dest := publicKey(addr.(types.Addr))
	if len(dest) != publicKeySize {
		return 0, errors.New("incorrect address length")
	}
	var tr dhtTraffic
	tr.source = pc.core.crypto.publicKey
	tr.dest = dest
	tr.kind = wireTrafficStandard
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
	a := types.Addr(append([]byte(nil), pc.core.crypto.publicKey...))
	return a
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

// SendOutOfBand sends some out-of-band data to a key.
// The data will be forwarded towards the destination key as far as possible, and then handled by the out-of-band handler of the terminal node.
// This could be used to do e.g. key discovery based on an incomplete key, or to implement application-specific helpers for debugging and analytics.
func (pc *PacketConn) SendOutOfBand(toKey ed25519.PublicKey, data []byte) error {
	var err error
	phony.Block(&pc.actor, func() {
		select {
		case <-pc.closed:
			err = errors.New("closed")
			return
		default:
		}
		if len(toKey) != publicKeySize {
			err = errors.New("incorrect address length")
			return
		}
		var tr dhtTraffic
		tr.source = pc.core.crypto.publicKey
		tr.dest = publicKey(toKey)
		tr.kind = wireTrafficOutOfBand
		tr.payload = data
		trbs, err := tr.MarshalBinaryTo(getBytes(0))
		if err != nil {
			// TODO do this when there's an oversized packet maybe?
			putBytes(trbs)
			err = errors.New("failed to encode traffic")
			return
		}
		pc.core.dhtree.sendTraffic(nil, trbs)
	})
	return err
}

// SetOutOfBandHandler sets a function to handle out-of-band data.
// This function will be called every time out-of-band data is received.
// If no handler has been set, then any received out-of-band data is dropped.
// If the handler returns a non-nil slice then that is treated as in-band data (accessible with ReadFrom).
func (pc *PacketConn) SetOutOfBandHandler(handler func(fromKey, toKey ed25519.PublicKey, data []byte) (inBand []byte)) error {
	var err error
	phony.Block(&pc.actor, func() {
		select {
		case <-pc.closed:
			err = errors.New("closed")
			return
		default:
		}
		pc.oobHandler = handler
	})
	return err
}

// IsClosed returns true if and only if the connection is closed.
// This is to check if the PacketConn is closed without potentially being stuck on a blocking operation (e.g. a read or write).
func (pc *PacketConn) IsClosed() bool {
	select {
	case <-pc.closed:
		return true
	default:
	}
	return false
}

func (pc *PacketConn) handleTraffic(trbs []byte) {
	pc.actor.Act(nil, func() {
		var tr dhtTraffic
		if err := tr.UnmarshalBinaryInPlace(trbs); err != nil {
			panic("this should never happen")
		}
		var doRecv bool
		switch tr.kind {
		case wireTrafficDummy:
		case wireTrafficStandard:
			if tr.dest.equal(pc.core.crypto.publicKey) {
				doRecv = true
			}
		case wireTrafficOutOfBand:
			if pc.oobHandler != nil {
				if inBand := pc.oobHandler(ed25519.PublicKey(tr.source), ed25519.PublicKey(tr.dest), tr.payload); inBand != nil {
					var newTr dhtTraffic
					newTr.source = tr.source
					newTr.dest = tr.dest
					newTr.kind = wireTrafficStandard
					newTr.payload = inBand
					if tmp, err := newTr.MarshalBinaryTo(getBytes(0)); err == nil {
						putBytes(trbs)
						trbs = tmp
						doRecv = true
					}
				}
			}
		default:
			// Drop the traffic
		}
		if doRecv {
			select {
			case pc.recv <- trbs:
			case <-pc.closed:
				putBytes(trbs)
			}
		} else {
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
