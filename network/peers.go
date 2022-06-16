package network

import (
	"encoding/binary"
	"errors"
	"io"
	//"math"
	"net"
	"time"

	"github.com/Arceliar/phony"
)

const (
	peerENABLE_DELAY_SCALING = 1
	peerRETRY_WINDOW         = 2 // seconds to wait between expected time and timeout
	peerINIT_DELAY           = 4 // backwards compatibiity / historical reasons
	peerINIT_TIMEOUT         = 6 // backwards compatiblity / historical reasons
	peerMIN_DELAY            = 1
	peerMAX_DELAY            = 10 // TODO figure out what makes sense
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
		p.writer.delay = peerINIT_DELAY
		p.timeout = peerINIT_TIMEOUT
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
	key         publicKey
	port        peerPort
	queue       packetQueue
	ready       bool // is the writer ready for traffic?
	writer      peerWriter
	timeout     byte
	time        time.Time // time when the peer was initialized
}

type peerWriter struct {
	phony.Inbox
	peer      *peer
	keepAlive func()
	writeBuf  []byte
	seq       uint64
	timer     *time.Timer
	delay     byte
}

func (w *peerWriter) _write(bs []byte) {
	w.timer.Stop()
	_, _ = w.peer.conn.Write(bs)
	delay := time.Duration(w.delay) * time.Second
	w.timer = time.AfterFunc(delay, w.keepAlive)
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
		p.peers.core.crdtree.removePeer(nil, p)
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
			if peerENABLE_DELAY_SCALING == 0 {
				p.writer._write([]byte{0x00, 0x01, wireDummy})
				return
			}
			// TODO figure out a good delay schedule, this is just a placeholder
			uptime := time.Since(p.time)
			delay := uint(uptime.Minutes()) //uint(math.Sqrt(uptime.Minutes()))
			// Clamp to allowed range
			switch {
			case delay < peerMIN_DELAY:
				delay = peerMIN_DELAY
			case delay > peerMAX_DELAY:
				delay = peerMAX_DELAY
			}
			p.writer.delay = byte(delay)
			p.writer._write([]byte{0x00, 0x02, wireKeepAlive, p.writer.delay})
		})
	}
	// Add peer to the crdtree, to kick off protocol exchanges
	p.peers.core.crdtree.addPeer(p, p)
	// Now allocate buffers and start reading / handling packets...
	var lenBuf [2]byte // packet length is a uint16
	bs := make([]byte, 65535)
	for {
		timeout := time.Duration(p.timeout) * time.Second
		if err := p.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
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
	case wireProtoSigReq:
		return p._handleSigReq(bs[1:])
	case wireProtoSigRes:
		return p._handleSigRes(bs[1:])
	case wireProtoAnnounce:
		return p._handleAnnounce(bs[1:])
	case wireTraffic:
		return p._handleTraffic(bs[1:])
	case wireKeepAlive:
		return p._handleKeepAlive(bs[1:])
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
	if !res.check() {
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

func (p *peer) _handleTraffic(bs []byte) error {
	tr := new(traffic)
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

func (p *peer) _handleKeepAlive(bs []byte) error {
	if len(bs) != 1 {
		return errors.New("wrong wireKeepAlive length")
	}
	delay := bs[0]
	// TODO? don't error here, just move it to the allowed range
	switch {
	case delay < peerMIN_DELAY:
		return errors.New("wireKeepAlive delay too short")
	case delay > peerMAX_DELAY:
		return errors.New("wireKeepAlive delay too long")
	}
	p.timeout = bs[0] + peerRETRY_WINDOW
	return nil
}

func (p *peer) _push(packet wireEncodeable) {
	if p.ready {
		var pType byte
		switch packet.(type) {
		case *traffic:
			pType = wireTraffic
		default:
			panic("this should never happen")
		}
		p.writer.sendPacket(pType, packet)
		p.ready = false
		return
	}
	// We're waiting, so queue the packet up for later
	var sKey, dKey publicKey
	var size int
	switch tr := packet.(type) {
	case *traffic:
		sKey, dKey = tr.source, tr.dest
		size = len(tr.payload)
	default:
		panic("this should never happen")
	}
	if info, ok := p.queue.peek(); ok && time.Since(info.time) > 25*time.Millisecond {
		// The queue already has a significant delay
		// Drop the oldest packet from the larget queue to make room
		p.queue.drop()
	}
	// Add the packet to the queue
	p.queue.push(sKey, dKey, packet, size)
}

func (p *peer) pop() {
	p.Act(nil, func() {
		if info, ok := p.queue.pop(); ok {
			switch info.packet.(type) {
			case *traffic:
				p.writer.sendPacket(wireTraffic, info.packet)
			default:
				panic("this should never happen")
			}
		} else {
			p.ready = true
		}
	})
}
