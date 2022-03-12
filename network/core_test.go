package network

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
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
	waitForRoot([]*PacketConn{a, b}, 10*time.Second)
	timer := time.NewTimer(time.Second)
	defer func() { timer.Stop() }()
	tA := &a.core.dhtree
	tB := &b.core.dhtree
	for {
		select {
		case <-timer.C:
			panic("timeout")
		default:
		}
		var sA, sB *treeLabel
		phony.Block(tA, func() {
			sA = tA._getLabel()
		})
		phony.Block(tB, func() {
			sB = tB._getLabel()
		})
		var lA, lB *peer
		phony.Block(tA, func() {
			lA = tA._treeLookup(sB)
		})
		phony.Block(tB, func() {
			lB = tB._treeLookup(sA)
		})
		if lA == nil || !bytes.Equal(lA.key[:], tB.core.crypto.publicKey[:]) {
			continue
		}
		if lB == nil || !bytes.Equal(lB.key[:], tA.core.crypto.publicKey[:]) {
			continue
		}
		break
	}
	timer.Stop()
	timer = time.NewTimer(13 * time.Second)
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
		panic("timeout")
	case <-done:
	}
}

func TestLineNetwork(t *testing.T) {
	var conns []*PacketConn
	for idx := 0; idx < 8; idx++ {
		_, priv, _ := ed25519.GenerateKey(nil)
		conn, err := NewPacketConn(priv)
		if err != nil {
			panic(err)
		}
		conns = append(conns, conn)
	}
	wait := make(chan struct{})
	for idx := range conns {
		if idx == 0 {
			continue
		}
		prev := conns[idx-1]
		here := conns[idx]
		keyA := ed25519.PublicKey(prev.LocalAddr().(types.Addr))
		keyB := ed25519.PublicKey(here.LocalAddr().(types.Addr))
		linkA, linkB := newDummyConn(keyA, keyB)
		defer linkA.Close()
		defer linkB.Close()
		go func() {
			<-wait
			prev.HandleConn(keyB, linkA)
			//linkA.Close()
		}()
		go func() {
			<-wait
			here.HandleConn(keyA, linkB)
			//linkB.Close()
		}()
	}
	close(wait)
	waitForRoot(conns, 10*time.Second)
	for aIdx := range conns {
		a := conns[aIdx]
		aAddr := a.LocalAddr()
		var aK publicKey
		copy(aK[:], aAddr.(types.Addr))
		for bIdx := range conns {
			if bIdx == aIdx {
				continue
			}
			b := conns[bIdx]
			bAddr := b.LocalAddr()
			done := make(chan struct{})
			msg := []byte("test")
			go func() {
				// Send from a to b
				for {
					select {
					case <-done:
						return
					default:
					}
					if n, err := a.WriteTo(msg, bAddr); n != len(msg) || err != nil {
						panic("write problem")
					}
					time.Sleep(time.Second)
				}
			}()
			go func() {
				defer func() {
					defer func() { recover() }()
					close(done)
				}()
				// Recv from a at b
				read := make([]byte, 2048)
				for {
					n, from, err := b.ReadFrom(read)
					bs := read[:n]
					if !bytes.Equal(bs, msg) || err != nil {
						if !bytes.Equal(bs, msg) {
							println(string(bs), string(msg))
							//panic("unequal")
						}
						if err != nil {
							//panic(err)
						}
						//panic("read problem")
					}
					var fK publicKey
					copy(fK[:], from.(types.Addr))
					if fK.equal(aK) {
						break
					}
				}
			}()
			timer := time.NewTimer(13 * time.Second)
			select {
			case <-timer.C:
				func() {
					defer func() { recover() }()
					close(done)
				}()
				for _, conn := range conns {
					// Timeout could come from split rings, if the DHT isn't converging
					//  FIXME this could race if the network is flapping for some reason, though it shouldn't be
					var here, prev, next, root string
					here = conn.LocalAddr().String()
          /*
					if dinfo := conn.core.dhtree.prev; dinfo != nil {
						k := conn.core.dhtree.dkeys[dinfo]
						prev = k.addr().String()
					}
					if dinfo := conn.core.dhtree.next; dinfo != nil {
						next = dinfo.key.addr().String()
					}
					*/
					root = conn.core.dhtree.self.root.addr().String()
					t.Log(prev, ":", here, ":", next, ":", root)
				}
				t.Log("test")
				panic("timeout")
			case <-done:
				timer.Stop()
			}
		}
	}
}

func TestRandomTreeNetwork(t *testing.T) {
	var conns []*PacketConn
	randIdx := func() int {
		return int(time.Now().UnixNano() % int64(len(conns)))
	}
	wait := make(chan struct{})
	for idx := 0; idx < 32; idx++ {
		_, priv, _ := ed25519.GenerateKey(nil)
		conn, err := NewPacketConn(priv)
		if err != nil {
			panic(err)
		}
		if len(conns) > 0 {
			pIdx := randIdx()
			p := conns[pIdx]
			keyA := ed25519.PublicKey(conn.LocalAddr().(types.Addr))
			keyB := ed25519.PublicKey(p.LocalAddr().(types.Addr))
			linkA, linkB := newDummyConn(keyA, keyB)
			defer linkA.Close()
			defer linkB.Close()
			go func() {
				<-wait
				conn.HandleConn(keyB, linkA)
			}()
			go func() {
				<-wait
				p.HandleConn(keyA, linkB)
			}()
		}
		conns = append(conns, conn)
	}
	close(wait)
	waitForRoot(conns, 10*time.Second)
	for aIdx := range conns {
		a := conns[aIdx]
		aAddr := a.LocalAddr()
		var aK publicKey
		copy(aK[:], aAddr.(types.Addr))
		for bIdx := range conns {
			if bIdx == aIdx {
				continue
			}
			b := conns[bIdx]
			bAddr := b.LocalAddr()
			done := make(chan struct{})
			msg := []byte("test")
			go func() {
				// Send from a to b
				for {
					select {
					case <-done:
						return
					default:
					}
					if n, err := a.WriteTo(msg, bAddr); n != len(msg) || err != nil {
						panic("write problem")
					}
					time.Sleep(time.Second)
				}
			}()
			go func() {
				defer func() {
					defer func() { recover() }()
					close(done)
				}()
				// Recv from a at b
				read := make([]byte, 2048)
				for {
					n, from, err := b.ReadFrom(read)
					bs := read[:n]
					if !bytes.Equal(bs, msg) || err != nil {
						if !bytes.Equal(bs, msg) {
							println(string(bs), string(msg))
							//panic("unequal")
						}
						if err != nil {
							//panic(err)
						}
						//panic("read problem")
					}
					var fK publicKey
					copy(fK[:], from.(types.Addr))
					if fK.equal(aK) {
						break
					}
				}
			}()
			timer := time.NewTimer(13 * time.Second)
			select {
			case <-timer.C:
				func() {
					defer func() { recover() }()
					close(done)
				}()
				for _, conn := range conns {
					// Timeout could come from split rings, if the DHT isn't converging
					//  FIXME this could race if the network is flapping for some reason, though it shouldn't be
					var here, prev, next, root string
					here = conn.LocalAddr().String()
					/*
					if dinfo := conn.core.dhtree.prev; dinfo != nil {
						k := conn.core.dhtree.dkeys[dinfo]
						prev = k.addr().String()
					}
					if dinfo := conn.core.dhtree.next; dinfo != nil {
						next = dinfo.key.addr().String()
					}
					*/
					root = conn.core.dhtree.self.root.addr().String()
					t.Log(prev, ":", here, ":", next, ":", root)
				}
				t.Log("test")
				panic("timeout")
			case <-done:
				timer.Stop()
			}
		}
	}
}

// waitForRoot is a helper function that waits until all nodes are using the same root
// that should usually mean the network has settled into a stable state, at least for static network tests
func waitForRoot(conns []*PacketConn, timeout time.Duration) {
	begin := time.Now()
	for {
		if time.Since(begin) > timeout {
			panic("timeout")
		}
		var root publicKey
		for _, conn := range conns {
			phony.Block(&conn.core.dhtree, func() {
				root = conn.core.dhtree.self.root
			})
			break
		}
		var bad bool
		for _, conn := range conns {
			var croot publicKey
			phony.Block(&conn.core.dhtree, func() {
				croot = conn.core.dhtree.self.root
			})
			if !croot.equal(root) {
				bad = true
				break
			}
		}
		if !bad {
			break
		}
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
