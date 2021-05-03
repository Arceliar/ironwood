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
	peerKEEPALIVE = time.Second
	peerTIMEOUT   = time.Second * 5 / 2
	peerMINQUEUE  = 1048576 // 1 MB, TODO something sensible
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
	queueMax    uint64
	queueSeq    uint64
	blocked     bool // is the writer (seemingly) blocked on a send?
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
	w.peer.notifySending()
	_, _ = w.peer.conn.Write(bs)
	w.peer.notifySent()
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
	p.peers.core.dhtree.Act(nil, func() {
		info := p.peers.core.dhtree.self
		p.peers.Act(&p.peers.core.dhtree, func() {
			p.sendTree(p.peers, info)
		})
	})
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
		if err := p.handlePacket(bs); err != nil {
			return err
		}
	}
}

func (p *peer) handlePacket(bs []byte) error {
	// Note: this function should be non-blocking.
	// Individual handlers should send actor messages as needed.
	if len(bs) == 0 {
		return errors.New("empty packet")
	}
	switch pType := bs[0]; pType {
	case wireDummy:
		return nil
	case wireProtoTree:
		return p.handleTree(bs[1:])
	case wireProtoDHTBootstrap:
		return p.handleBootstrap(bs[1:])
	case wireProtoDHTBootstrapAck:
		return p.handleBootstrapAck(bs[1:])
	case wireProtoDHTSetup:
		return p.handleSetup(bs[1:])
	case wireProtoDHTTeardown:
		return p.handleTeardown(bs[1:])
	case wireProtoPathNotify:
		return p.handlePathNotify(bs[1:])
	case wireProtoPathLookup:
		return p.handlePathLookup(bs[1:])
	case wireProtoPathResponse:
		return p.handlePathResponse(bs[1:])
	case wireDHTTraffic:
		return p.handleDHTTraffic(bs[1:])
	case wirePathTraffic:
		return p.handlePathTraffic(bs[1:])
	default:
		return errors.New("unrecognized packet type")
	}
}

func (p *peer) handleTree(bs []byte) error {
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
	p.peers.core.dhtree.update(nil, info, p)
	return nil
}

func (p *peer) sendTree(from phony.Actor, info *treeInfo) {
	p.Act(from, func() {
		info = info.add(p.peers.core.crypto.privateKey, p)
		p.writer.sendPacket(wireProtoTree, info)
	})
}

func (p *peer) handleBootstrap(bs []byte) error {
	bootstrap := new(dhtBootstrap)
	if err := bootstrap.decode(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.handleBootstrap(nil, bootstrap)
	return nil
}

func (p *peer) sendBootstrap(from phony.Actor, bootstrap *dhtBootstrap) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoDHTBootstrap, bootstrap)
	})
}

func (p *peer) handleBootstrapAck(bs []byte) error {
	ack := new(dhtBootstrapAck)
	if err := ack.decode(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.handleBootstrapAck(nil, ack)
	return nil
}

func (p *peer) sendBootstrapAck(from phony.Actor, ack *dhtBootstrapAck) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoDHTBootstrapAck, ack)
	})
}

func (p *peer) handleSetup(bs []byte) error {
	setup := new(dhtSetup)
	if err := setup.decode(bs); err != nil {
		return err
	}
	if !setup.check() {
		return errors.New("invalid setup")
	}
	p.peers.core.dhtree.handleSetup(nil, p, setup)
	return nil
}

func (p *peer) sendSetup(from phony.Actor, setup *dhtSetup) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoDHTSetup, setup)
	})
}

func (p *peer) handleTeardown(bs []byte) error {
	teardown := new(dhtTeardown)
	if err := teardown.decode(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.teardown(nil, p, teardown)
	return nil
}

func (p *peer) sendTeardown(from phony.Actor, teardown *dhtTeardown) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoDHTTeardown, teardown)
	})
}

func (p *peer) handlePathNotify(bs []byte) error {
	notify := new(pathNotify)
	if err := notify.decode(bs); err != nil {
		return err
	}
	p.peers.core.dhtree.pathfinder.handleNotify(nil, notify)
	return nil
}

func (p *peer) sendPathNotify(from phony.Actor, notify *pathNotify) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoPathNotify, notify)
	})
}

func (p *peer) handlePathLookup(bs []byte) error {
	lookup := new(pathLookup)
	if err := lookup.decode(bs); err != nil {
		return err
	}
	lookup.rpath = append(lookup.rpath, p.port)
	p.peers.core.dhtree.pathfinder.handleLookup(nil, lookup)
	return nil
}

func (p *peer) sendPathLookup(from phony.Actor, lookup *pathLookup) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoPathLookup, lookup)
	})
}

func (p *peer) handlePathResponse(bs []byte) error {
	response := new(pathResponse)
	if err := response.decode(bs); err != nil {
		return err
	}
	response.rpath = append(response.rpath, p.port)
	p.peers.handlePathResponse(nil, response)
	return nil
}

func (ps *peers) handlePathResponse(from phony.Actor, response *pathResponse) {
	ps.Act(from, func() {
		var nextPort peerPort
		if len(response.path) > 0 {
			nextPort = response.path[0]
			response.path = response.path[1:]
		}
		if next, isIn := ps.peers[nextPort]; isIn {
			next.sendPathResponse(ps, response)
		} else {
			ps.core.dhtree.pathfinder.handleResponse(ps, response)
		}
	})
}

func (p *peer) sendPathResponse(from phony.Actor, response *pathResponse) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoPathResponse, response)
	})
}

func (p *peer) handleDHTTraffic(bs []byte) error {
	tr := new(dhtTraffic)
	if err := tr.decode(bs); err != nil {
		return err // This is just to check that it unmarshals correctly
	}
	p.peers.core.dhtree.handleDHTTraffic(nil, tr, true)
	return nil
}

func (p *peer) sendDHTTraffic(from phony.Actor, tr *dhtTraffic) {
	p.Act(from, func() {
		p._push(tr)
	})
}

func (p *peer) handlePathTraffic(bs []byte) error {
	tr := new(pathTraffic)
	if err := tr.decode(bs); err != nil {
		return err
	}
	// TODO? don't send to p.peers, have a (read-only) copy of the map locally? via atomics?
	p.peers.handlePathTraffic(nil, tr)
	return nil
}

func (ps *peers) handlePathTraffic(from phony.Actor, tr *pathTraffic) {
	ps.Act(from, func() {
		var nextPort peerPort
		if len(tr.path) > 0 {
			nextPort, tr.path = tr.path[0], tr.path[1:]
		}
		if next := ps.peers[nextPort]; next != nil {
			// Forward using the source routed path
			next.sendPathTraffic(nil, tr)
		} else {
			// Fall back to dhtTraffic
			ps.core.dhtree.handleDHTTraffic(nil, &tr.dt, false)
		}
	})
}

func (p *peer) sendPathTraffic(from phony.Actor, tr *pathTraffic) {
	p.Act(from, func() {
		p._push(tr)
	})
}

func (p *peer) _push(packet wireEncodeable) {
	if !p.blocked {
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
	p.queue.push(id, packet, size)
	for p.queue.size > p.queueMax {
		p.queue.pop()
	}
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
			// Adjust queueMax, to make sure the queue eventually drains
			p.queueMax -= info.size
		}
		if p.queue.size == 0 {
			p.blocked = false
		}
	})
}

func (p *peer) notifySending() {
	p.Act(nil, func() {
		p.queueSeq++
		seq := p.queueSeq
		p.Act(nil, func() {
			if !p.blocked && seq == p.queueSeq {
				p.blocked = true
				p.queueMax = ^uint64(0)
				p.Act(nil, func() {
					// Queue the packets already in memory somewhere
					// Then set the max size of the queue
					p.queueMax = p.queue.size + peerMINQUEUE
				})
			}
		})
	})
}

func (p *peer) notifySent() {
	p.Act(nil, func() {
		p.queueSeq++
	})
}
