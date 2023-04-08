package network

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"

	//"math"
	"net"
	"time"

	"github.com/Arceliar/phony"
)

// TODO? copy relevant config info to structs here, to avoid needing to dereference pointers all the way back to the core

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

func (ps *peers) addPeer(key publicKey, conn net.Conn, prio uint8) (*peer, error) {
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
		p.done = make(chan struct{})
		p.key = key
		p.port = port
		p.prio = prio
		p.monitor.peer = p
		p.writer.peer = p
		p.writer.wbuf = bufio.NewWriter(p.conn)
		p.time = time.Now()
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
	done        chan struct{}
	key         publicKey
	port        peerPort
	prio        uint8
	queue       packetQueue
	time        time.Time // time when the peer was initialized
	monitor     peerMonitor
	writer      peerWriter
	ready       bool // is the writer ready for traffic?
}

type peerMonitor struct {
	phony.Inbox
	peer           *peer
	keepAliveTimer *time.Timer
	pingTimer      *time.Timer
	pDelay         uint64
	deadlined      bool
}

func (m *peerMonitor) keepAlive() {
	m.Act(nil, func() {
		select {
		case <-m.peer.done:
			return
		default:
		}
		m.peer.writer.Act(m, func() {
			m.peer.writer._write([]byte{0x01, byte(wireKeepAlive)}, wireKeepAlive)
		})
	})
}

func (m *peerMonitor) doPing() {
	m.Act(nil, func() {
		select {
		case <-m.peer.done:
			return
		default:
		}
		m.peer.writer.Act(m, func() {
			m.peer.writer._write([]byte{0x01, byte(wirePing)}, wirePing)
		})
	})
}

func (m *peerMonitor) sent(pType wirePacketType) {
	m.Act(&m.peer.writer, func() {
		defer func() {
			if m.pingTimer != nil {
				// In a defer so we reset to the new delay
				delay := time.Duration(m.pDelay) * time.Second // TODO? slightly randomize
				m.pingTimer.Reset(delay)
			}
		}()
		if m.keepAliveTimer != nil {
			// We're sending a packet, so we definitely don't need to send a keepalive after this
			m.keepAliveTimer.Stop()
			m.keepAliveTimer = nil
		}
		switch {
		case m.deadlined:
			return
		case pType == wireDummy:
		case pType == wireKeepAlive:
		case pType == wirePing:
			m.pDelay += 1
			delay := time.Duration(m.pDelay) * time.Second // TODO? slightly randomize
			if delay < m.peer.peers.core.config.peerPingMaxDelay {
				select {
				case <-m.peer.done:
				default:
					m.pingTimer = time.AfterFunc(delay, m.doPing)
				}
			} else if m.pingTimer != nil {
				m.pingTimer.Stop()
				m.pingTimer = nil
			}
			fallthrough
		default:
			// We're sending non-keepalive traffic
			// This means we expect some kind of acknowledgement (at least a keepalive)
			// Set a read deadline for that (and make a note that we did so)
			m.peer.conn.SetReadDeadline(time.Now().Add(m.peer.peers.core.config.peerTimeout))
			m.deadlined = true
		}
	})
}

func (m *peerMonitor) recv(pType wirePacketType) {
	m.Act(nil, func() {
		m.peer.conn.SetReadDeadline(time.Time{})
		m.deadlined = false
		switch {
		case m.keepAliveTimer != nil:
		case pType == wireDummy:
		case pType == wireKeepAlive:
		default:
			// We just received non-keepalive traffic
			// The other side is expecting some kind of response, at least a keepalive
			// We set a timer to trigger a response later, if we don't send any traffic in the mean time
			select {
			case <-m.peer.done:
			default:
				m.keepAliveTimer = time.AfterFunc(m.peer.peers.core.config.peerKeepAliveDelay, m.keepAlive)
			}
		}
	})
}

type peerWriter struct {
	phony.Inbox
	peer *peer
	wbuf *bufio.Writer
	seq  uint64
}

func (w *peerWriter) _write(bs []byte, pType wirePacketType) {
	w.peer.monitor.sent(pType)
	// _, _ = w.peer.conn.Write(bs)
	_, _ = w.wbuf.Write(bs)
	w.seq++
	seq := w.seq
	w.Act(nil, func() {
		if seq == w.seq {
			w.peer.pop() // Ask for more traffic to send
		}
	})
}

func (w *peerWriter) sendPacket(pType wirePacketType, data wireEncodeable) {
	w.Act(nil, func() {
		bufSize := uint64(data.size() + 1)
		if bufSize > w.peer.peers.core.config.peerMaxMessageSize {
			return
		}
		// TODO packet size checks (right now there's no max, that's bad)
		writeBuf := allocBytes(0)
		defer freeBytes(writeBuf)
		// The +1 is from 1 byte for the pType
		writeBuf = binary.AppendUvarint(writeBuf[:], bufSize)
		var err error
		writeBuf, err = wireEncode(writeBuf, byte(pType), data)
		if err != nil {
			panic(err)
		}
		w._write(writeBuf, pType)
		switch tr := data.(type) {
		case *traffic:
			freeTraffic(tr)
		default:
			// Not a special case, don't free anything
		}
	})
}

func (p *peer) handler() error {
	defer func() {
		p.peers.core.crdtree.removePeer(nil, p)
	}()
	defer p.monitor.Act(nil, func() {
		if p.monitor.keepAliveTimer != nil {
			p.monitor.keepAliveTimer.Stop()
			p.monitor.keepAliveTimer = nil
		}
	})
	defer p.monitor.Act(nil, func() {
		if p.monitor.pingTimer != nil {
			p.monitor.pingTimer.Stop()
			p.monitor.pingTimer = nil
		}
	})
	defer close(p.done)
	p.conn.SetDeadline(time.Time{})
	// Calling doPing here ensures that it's the first traffic we ever send
	// That helps to e.g. initialize the pingTimer
	p.monitor.doPing()
	// Add peer to the crdtree, to kick off protocol exchanges
	p.peers.core.crdtree.addPeer(p, p)
	// Now allocate buffers and start reading / handling packets...
	rbuf := bufio.NewReader(p.conn)
	for {
		var usize uint64
		var err error
		if usize, err = binary.ReadUvarint(rbuf); err != nil {
			return err
		}
		if usize > p.peers.core.config.peerMaxMessageSize {
			return errors.New("oversized packet")
		}
		// TODO max packet size logic (right now there's no max, that's bad)
		size := int(usize)
		bs := allocBytes(size)
		if _, err = io.ReadFull(rbuf, bs); err != nil {
			freeBytes(bs)
			return err
		}
		phony.Block(p, func() {
			err = p._handlePacket(bs)
		})
		freeBytes(bs)
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
	pType := wirePacketType(bs[0])
	p.monitor.recv(pType)
	switch pType {
	case wireDummy:
		return nil
	case wireKeepAlive:
		return nil
	case wirePing:
		return nil
	case wireProtoSigReq:
		return p._handleSigReq(bs[1:])
	case wireProtoSigRes:
		return p._handleSigRes(bs[1:])
	case wireProtoAnnounce:
		return p._handleAnnounce(bs[1:])
	case wireProtoMirrorReq:
		return p._handleMirrorReq(bs[1:])
	case wireTraffic:
		return p._handleTraffic(bs[1:])
	default:
		return errors.New("unrecognized packet type")
	}
}

func (p *peer) _handleSigReq(bs []byte) error {
	req := new(crdtreeSigReq)
	if err := req.decode(bs); err != nil {
		return err
	}
	p.peers.core.crdtree.handleRequest(p, p, req)
	return nil
}

func (p *peer) sendSigReq(from phony.Actor, req *crdtreeSigReq) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoSigReq, req)
	})
}

func (p *peer) _handleSigRes(bs []byte) error {
	res := new(crdtreeSigRes)
	if err := res.decode(bs); err != nil {
		return err
	}
	if !res.check(p.peers.core.crypto.publicKey, p.key) {
		return errors.New("bad SigRes")
	}
	p.peers.core.crdtree.handleResponse(p, p, res)
	return nil
}

func (p *peer) sendSigRes(from phony.Actor, res *crdtreeSigRes) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoSigRes, res)
	})
}

func (p *peer) _handleAnnounce(bs []byte) error {
	ann := new(crdtreeAnnounce)
	if err := ann.decode(bs); err != nil {
		return err
	}
	if !ann.check() {
		return errors.New("bad Announce")
	}
	p.peers.core.crdtree.handleAnnounce(p, p, ann)
	return nil
}

func (p *peer) sendAnnounce(from phony.Actor, ann *crdtreeAnnounce) {
	p.Act(from, func() {
		p.writer.sendPacket(wireProtoAnnounce, ann)
	})
}

func (p *peer) _handleMirrorReq(bs []byte) error {
	if len(bs) != 0 {
		return errors.New("bad mirror request")
	}
	p.peers.core.crdtree.handleMirrorReq(p, p)
	return nil
}

func (p *peer) sendMirrorReq(from phony.Actor) {
	p.Act(from, func() {
		p.writer.Act(nil, func() {
			p.writer._write([]byte{0x01, byte(wireProtoMirrorReq)}, wireProtoMirrorReq)
		})
	})
}

func (p *peer) _handleTraffic(bs []byte) error {
	tr := allocTraffic()
	if err := tr.decode(bs); err != nil {
		return err // This is just to check that it unmarshals correctly
	}
	p.peers.core.crdtree.handleTraffic(p, tr)
	return nil
}

func (p *peer) sendTraffic(from phony.Actor, tr *traffic) {
	p.Act(from, func() {
		p._push(tr)
	})
}

func (p *peer) _push(tr *traffic) {
	if p.ready {
		var pType wirePacketType
		pType = wireTraffic
		p.writer.sendPacket(pType, tr)
		p.ready = false
		return
	}
	// We're waiting, so queue the packet up for later
	sKey, dKey := tr.source, tr.dest
	size := len(tr.payload)
	if info, ok := p.queue.peek(); ok && time.Since(info.time) > 25*time.Millisecond {
		// The queue already has a significant delay
		// Drop the oldest packet from the larget queue to make room
		p.queue.drop()
	}
	// Add the packet to the queue
	p.queue.push(sKey, dKey, tr, size)
}

func (p *peer) pop() {
	p.Act(nil, func() {
		if info, ok := p.queue.pop(); ok {
			p.writer.sendPacket(wireTraffic, info.packet)
		} else {
			p.ready = true
			p.writer.Act(nil, func() {
				p.writer.wbuf.Flush()
			})
		}
	})
}
