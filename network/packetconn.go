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
	recv         chan *traffic //read buffer
	recvReady    uint64
	recvq        packetQueue
	readDeadline *deadline
	closeMutex   sync.Mutex
	closed       chan struct{}
	Debug        Debug
}

// NewPacketConn returns a *PacketConn struct which implements the types.PacketConn interface.
func NewPacketConn(secret ed25519.PrivateKey, options ...Option) (*PacketConn, error) {
	c := new(core)
	if err := c.init(secret, options...); err != nil {
		return nil, err
	}
	return &c.pconn, nil
}

func (pc *PacketConn) init(c *core) {
	pc.core = c
	pc.recv = make(chan *traffic, 1)
	pc.readDeadline = newDeadline()
	pc.closed = make(chan struct{})
	pc.Debug.init(c)
}

// ReadFrom fulfills the net.PacketConn interface, with a types.Addr returned as the from address.
// Note that failing to call ReadFrom may cause the connection to block and/or leak memory.
func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	var tr *traffic
	pc.doPop()
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
	fromKey := tr.source // copy, since tr is going back in the pool
	from = fromKey.addr()
	freeTraffic(tr)
	return
}

// WriteTo fulfills the net.PacketConn interface, with a types.Addr expected as the destination address.
func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-pc.closed:
		return 0, errors.New("closed")
	default:
	}
	if _, ok := addr.(types.Addr); !ok {
		return 0, errors.New("incorrect address type, expected types.Addr")
	}
	dest := addr.(types.Addr)
	if len(dest) != publicKeySize {
		return 0, errors.New("incorrect address length")
	}
	if uint64(len(p)) > pc.MTU() {
		return 0, errors.New("oversized message")
	}
	tr := allocTraffic()
	tr.source = pc.core.crypto.publicKey
	copy(tr.dest[:], dest)
	tr.watermark = ^uint64(0)
	tr.payload = append(tr.payload, p...)
	pc.core.crdtree.sendTraffic(tr)
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
	phony.Block(&pc.core.crdtree, pc.core.crdtree._shutdown)
	return nil
}

// LocalAddr returns a types.Addr of the ed25519.PublicKey for this PacketConn.
func (pc *PacketConn) LocalAddr() net.Addr {
	return pc.core.crypto.publicKey.addr()
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
func (pc *PacketConn) HandleConn(key ed25519.PublicKey, conn net.Conn, prio uint8) error {
	defer conn.Close()
	if len(key) != publicKeySize {
		return errors.New("incorrect key length")
	}
	var pk publicKey
	copy(pk[:], key)
	if pc.core.crypto.publicKey.equal(pk) {
		return errors.New("attempted to connect to self")
	}
	p, err := pc.core.peers.addPeer(pk, conn, prio)
	if err != nil {
		return err
	}
	err = p.handler()
	if e := pc.core.peers.removePeer(p.port); e != nil {
		return e
	}
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

// PrivateKey() returns the ed25519.PrivateKey used to initialize the PacketConn.
func (pc *PacketConn) PrivateKey() ed25519.PrivateKey {
	sk := pc.core.crypto.privateKey
	return ed25519.PrivateKey(sk[:])
}

// MTU returns the maximum transmission unit of the PacketConn, i.e. maximum safe message size to send over the network.
func (pc *PacketConn) MTU() uint64 {
	// TODO update this for packet format changes, it needs to read from the config now...
	const maxPeerMessageSize = 65535
	const messageTypeSize = 1
	const rootSeqSize = 8
	const treeUpdateOverhead = messageTypeSize + publicKeySize + rootSeqSize
	const maxPortSize = 10 // maximum vuint size in bytes
	const treeHopSize = publicKeySize + maxPortSize + signatureSize
	const maxHops = (maxPeerMessageSize - treeUpdateOverhead) / treeHopSize
	const maxPathBytes = publicKeySize + maxPortSize*maxHops + 1 // root + treespace coords + 0 (terminate coords)
	const pathTrafficOverhead = messageTypeSize + maxPathBytes + publicKeySize + publicKeySize + messageTypeSize
	const MTU = maxPeerMessageSize - pathTrafficOverhead
	return MTU
}

func (pc *PacketConn) handleTraffic(from phony.Actor, tr *traffic) {
	// FIXME? if there are multiple concurrent ReadFrom calls, packets can be returned out-of-order
	pc.actor.Act(from, func() {
		if !tr.dest.equal(pc.core.crypto.publicKey) {
			// Wrong key, do nothing
		} else if pc.recvReady > 0 {
			// Send immediately
			select {
			case pc.recv <- tr:
				pc.recvReady -= 1
			case <-pc.closed:
			}
		} else {
			if info, ok := pc.recvq.peek(); ok && time.Since(info.time) > 25*time.Millisecond {
				// The queue already has a significant delay
				// Drop the oldest packet from the larget queue to make room
				pc.recvq.drop()
			}
			pc.recvq.push(tr.source, tr.dest, tr, len(tr.payload))
		}
	})
}

func (pc *PacketConn) doPop() {
	pc.actor.Act(nil, func() {
		if info, ok := pc.recvq.pop(); ok {
			select {
			case pc.recv <- info.packet:
			case <-pc.closed:
			default:
				panic("this should never happen")
			}
		} else {
			pc.recvReady += 1
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

/////

func (pc *PacketConn) GetKeyFor(target ed25519.PublicKey) (key ed25519.PublicKey) {
	phony.Block(&pc.core.crdtree, func() {
		var k publicKey
		copy(k[:], target[:])
		k = pc.core.crdtree._keyLookup(k)
		key = ed25519.PublicKey(k[:])
	})
	return
}
