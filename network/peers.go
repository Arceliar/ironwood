package network

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/Arceliar/phony"
)

const (
	peerKEEPALIVE = 4 * time.Second
	peerTIMEOUT   = 6 * time.Second
)

type peerPort uint64

type peers struct {
	phony.Inbox // Used to create/remove peers
	core        *core
	peers       map[peerPort]*peer
}

func (ps *peers) init(c *core) {
	ps.core = c
	ps.peers = make(map[peerPort]*peer)
}

func (ps *peers) addPeer(key publicKey, conn net.Conn) (*peer, error) {
	var p *peer
	var err error
	ps.core.pconn.closeMutex.Lock()
	defer ps.core.pconn.closeMutex.Unlock()
	select {
	case <-ps.core.pconn.closed:
		return nil, errors.New("cannot add peer to closed PacketConn")
	default:
	}
	phony.Block(ps, func() {
		var port peerPort
		for idx := 1; ; idx++ { // skip 0
			if _, isIn := ps.peers[peerPort(idx)]; isIn {
				continue
			}
			port = peerPort(idx)
			break
		}
		p = new(peer)
		p.peers = ps
		p.conn = conn
		p.key = key
		p.port = port
		p.writer.peer = p
		p.writer.timer = time.AfterFunc(0, func() {})
		ps.peers[port] = p
	})
	return p, err
}

func (ps *peers) removePeer(port peerPort) error {
	var err error
	phony.Block(ps, func() {
		if _, isIn := ps.peers[port]; !isIn {
			err = errors.New("peer not found")
		} else {
			delete(ps.peers, port)
		}
	})
	return err
}

type peer struct {
	phony.Inbox // Only used to process or send some protocol traffic
	peers       *peers
	conn        net.Conn
	key         publicKey
	info        *treeInfo
	port        peerPort
	queue       packetQueue
	ready       bool // is the writer ready for traffic?
	writer      peerWriter
}

type peerWriter struct {
	phony.Inbox
	peer      *peer
	keepAlive func()
	writeBuf  []byte
	seq       uint64
	timer     *time.Timer
}

func (w *peerWriter) _write(bs []byte) {
	w.timer.Stop()
	_, _ = w.peer.conn.Write(bs)
	w.timer = time.AfterFunc(peerKEEPALIVE, w.keepAlive)
	w.seq++
	seq := w.seq
	w.Act(nil, func() {
		if seq == w.seq {
			w.peer.pop() // Ask for more traffic to send
		}
	})
}

func (w *peerWriter) sendPacket(pType byte, data wireEncodeable) {
	w.Act(nil, func() {
		w.writeBuf = append(w.writeBuf[:0], 0x00, 0x00) // This will be the length
		var err error
		w.writeBuf, err = wireEncode(w.writeBuf, pType, data)
		if err != nil {
			panic(err)
		}
		bs := w.writeBuf[2:] // The message part
		if len(bs) > int(^uint16(0)) {
			return
		}
		binary.BigEndian.PutUint16(w.writeBuf[:2], uint16(len(bs)))
		w._write(w.writeBuf)
	})
}

func (p *peer) handler() error {
	defer func() {
		if p.info != nil {
			p.peers.core.dhtree.remove(nil, p)
		}
	}()
	done := make(chan struct{})
	defer close(done)
	p.writer.keepAlive = func() {
		select {
		case <-done:
			return
		default:
		}
		p.writer.Act(nil, func() {
			p.writer._write([]byte{0x00, 0x01, wireDummy})
		})
	}
	// Hack to get ourself into the remote node's dhtree
	// They send a similar message and we'll respond with correct info
	p.sendTree(nil, &treeInfo{root: p.peers.core.crypto.publicKey})
	// Now allocate buffers and start reading / handling packets...
	var lenBuf [2]byte // packet length is a uint16
	bs := make([]byte, 65535)
	for {
		if err := p.conn.SetReadDeadline(time.Now().Add(peerTIMEOUT)); err != nil {
			return err
		}
		if _, err := io.ReadFull(p.conn, lenBuf[:]); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint16(lenBuf[:]))
		bs = bs[:size]
		if _, err := io.ReadFull(p.conn, bs); err != nil {
			return err
		}
		var err error
		phony.Block(p, func() {
			err = p._handlePacket(bs)
		})
		if err != nil {
			return err
		}
	}
}

func (p *peer) _handlePacket(bs []byte) error {
	// Note: this function should be non-blocking.
	// Individual handlers should send actor messages as needed.
	if len(bs) == 0 {
		return errors.New("empty packet")
	}
	switch pType := bs[0]; pType {
	case wireDummy:
		return nil
	case wireProtoTree:
		return p._handleTree(bs[1:])
	case wireProtoDHTBootstrap:
		return p._handleBootstrap(bs[1:])
	case wireProtoDHTBootstrapAck:
		return p._handleBootstrapAck(bs[1:])
	case wireProtoDHTSetup:
		return p._handleSetup(bs[1:])
	case wireProtoDHTTeardown:
		return p._handleTeardown(bs[1:])
	case wireProtoPathNotify:
		return p._handlePathNotify(bs[1:])
	case wireProtoPathLookup:
		// TODO remove, temporary workaround for partial backwards compatibility
		return nil
	case wireProtoPathResponse:
		// TODO remove, temporary workaround for partial backwards compatibility
		return nil
	case wireDHTTraffic:
		return p._handleDHTTraffic(bs[1:])
	case wirePathTraffic:
		return p._handlePathTraffic(bs[1:])
	default:
		return errors.New("unrecognized packet type")
	}
}

func (p *peer) _handleTree(bs []byte) error {
	info := new(treeInfo)
	if err := info.decode(bs); err != nil {
		return err
	}
	if !info.checkSigs() {
		return errors.New("invalid signature")
	}
	if !p.key.equal(info.from()) {
		return errors.New("unrecognized publicKey")
	}
	dest := info.hops[len(info.hops)-1].next
	if !p.peers.core.crypto.publicKey.equal(dest) {
		return errors.New("incorrect destination")
	}
	p.info = info
	p.peers.core.dhtree.update(p, info, p)
	return nil
}

func (p *peer) sendTree(from phony.Actor, info *treeInfo) {
	p.Act(from, func() {
		info = info.add(p.peers.core.crypto.privateKey, p)
		p.writer.sendPacket(wireProtoTree, info)
	})
}

func (p *peer) _handleBootstrap(bs []byte) error {
	bootstrap := new(dhtBootstrap)
	if err := bootstrap.decode(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.handleBootstrap(p, bootstrap)
	return nil
}

func (p *peer) sendBootstrap(from phony.Actor, bootstrap *dhtBootstrap) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoDHTBootstrap, bootstrap)
	})
}

func (p *peer) _handleBootstrapAck(bs []byte) error {
	ack := new(dhtBootstrapAck)
	if err := ack.decode(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.handleBootstrapAck(p, ack)
	return nil
}

func (p *peer) sendBootstrapAck(from phony.Actor, ack *dhtBootstrapAck) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoDHTBootstrapAck, ack)
	})
}

func (p *peer) _handleSetup(bs []byte) error {
	setup := new(dhtSetup)
	if err := setup.decode(bs); err != nil {
		return err
	}
	if !setup.check() {
		return errors.New("invalid setup")
	}
	p.peers.core.dhtree.handleSetup(p, p, setup)
	return nil
}

func (p *peer) sendSetup(from phony.Actor, setup *dhtSetup) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoDHTSetup, setup)
	})
}

func (p *peer) _handleTeardown(bs []byte) error {
	teardown := new(dhtTeardown)
	if err := teardown.decode(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.teardown(p, p, teardown)
	return nil
}

func (p *peer) sendTeardown(from phony.Actor, teardown *dhtTeardown) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoDHTTeardown, teardown)
	})
}

func (p *peer) _handlePathNotify(bs []byte) error {
	notify := new(pathNotify)
	if err := notify.decode(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.pathfinder.handleNotify(p, notify)
	return nil
}

func (p *peer) sendPathNotify(from phony.Actor, notify *pathNotify) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoPathNotify, notify)
	})
}

func (p *peer) _handleDHTTraffic(bs []byte) error {
	tr := new(dhtTraffic)
	if err := tr.decode(bs); err != nil {
		return err // This is just to check that it unmarshals correctly
	}
	p.peers.core.dhtree.handleDHTTraffic(p, tr, true)
	return nil
}

func (p *peer) sendDHTTraffic(from phony.Actor, tr *dhtTraffic) {
	p.Act(from, func() {
		p._push(tr)
	})
}

func (p *peer) _handlePathTraffic(bs []byte) error {
	tr := new(pathTraffic)
	if err := tr.decode(bs); err != nil {
		return err
	}
	// TODO? don't send to the dhtree, have a (read-only) copy of the map locally? via atomics?
	p.peers.core.dhtree.handlePathTraffic(p, tr)
	return nil
}

func (p *peer) sendPathTraffic(from phony.Actor, tr *pathTraffic) {
	p.Act(from, func() {
		p._push(tr)
	})
}

func (p *peer) _push(packet wireEncodeable) {
	if p.ready {
		var pType byte
		switch packet.(type) {
		case *dhtTraffic:
			pType = wireDHTTraffic
		case *pathTraffic:
			pType = wirePathTraffic
		default:
			panic("this should never happen")
		}
		p.writer.sendPacket(pType, packet)
		p.ready = false
		return
	}
	// We're waiting, so queue the packet up for later
	var id pqStreamID
	var size int
	switch tr := packet.(type) {
	case *dhtTraffic:
		id = pqStreamID{
			source: tr.source,
			dest:   tr.dest,
		}
		size = len(tr.payload)
	case *pathTraffic:
		id = pqStreamID{
			source: tr.dt.source,
			dest:   tr.dt.dest,
		}
		size = len(tr.dt.payload)
	default:
		panic("this should never happen")
	}
	if info, ok := p.queue.peek(); ok && time.Since(info.time) > 25*time.Millisecond {
		// The queue already has a significant delay
		// Drop the oldest packet from the larget queue to make room
		p.queue.drop()
	}
	// Add the packet to the queue
	p.queue.push(id, packet, size)
}

func (p *peer) pop() {
	p.Act(nil, func() {
		if info, ok := p.queue.pop(); ok {
			switch info.packet.(type) {
			case *dhtTraffic:
				p.writer.sendPacket(wireDHTTraffic, info.packet)
			case *pathTraffic:
				p.writer.sendPacket(wirePathTraffic, info.packet)
			default:
				panic("this should never happen")
			}
		} else {
			p.ready = true
		}
	})
}
