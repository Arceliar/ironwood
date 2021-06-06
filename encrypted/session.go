package encrypted

import (
	"encoding/binary"
	"time"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

/*

TODO:
  We either need to save the private keys for sent inits (so we can make a session when we receive an ack...) *or* we need to send an ack back when we receive an ack and we create a session because of it

*/

const (
	sessionTimeout         = time.Minute
	sessionTrafficOverhead = 1 + 8 + 8 + boxPubSize + boxPubSize + boxNonceSize + boxOverhead + boxPubSize
	sessionInitSize        = 1 + boxNonceSize + boxOverhead + boxPubSize + boxPubSize + 8 + 8
	sessionAckSize         = sessionInitSize
)

const (
	sessionTypeDummy = iota
	sessionTypeInit
	sessionTypeAck
	sessionTypeTraffic
)

/******************
 * sessionManager *
 ******************/

type sessionManager struct {
	phony.Inbox
	pc       *PacketConn
	sessions map[edPub]*sessionInfo
	buffers  map[edPub]*sessionBuffer
}

func (mgr *sessionManager) init(pc *PacketConn) {
	mgr.pc = pc
	mgr.sessions = make(map[edPub]*sessionInfo)
	mgr.buffers = make(map[edPub]*sessionBuffer)
}

func (mgr *sessionManager) _newSession(ed *edPub, recv, send boxPub, seq uint64) *sessionInfo {
	info := newSession(ed, recv, send, seq)
	info.Act(mgr, func() {
		info.mgr = mgr
		info._resetTimer()
	})
	mgr.sessions[info.ed] = info
	return info
}

func (mgr *sessionManager) _sessionForInit(pub *edPub, init *sessionInit) (*sessionInfo, *sessionBuffer) {
	var info *sessionInfo
	var buf *sessionBuffer
	if info = mgr.sessions[*pub]; info == nil {
		info = mgr._newSession(pub, init.current, init.next, init.seq)
		if buf = mgr.buffers[*pub]; buf != nil {
			buf.timer.Stop()
			delete(mgr.buffers, *pub)
			info.sendPub, info.sendPriv = buf.init.current, buf.currentPriv
			info.nextPub, info.nextPriv = buf.init.next, buf.nextPriv
			info._fixShared(&boxNonce{}, &boxNonce{})
			// The caller is responsible for sending buf.data when ready
		}
	}
	return info, buf
}

func (mgr *sessionManager) handleData(from phony.Actor, pub *edPub, data []byte) {
	mgr.Act(from, func() {
		if len(data) == 0 {
			return
		}
		switch data[0] {
		case sessionTypeDummy:
		case sessionTypeInit:
			init := new(sessionInit)
			if init.decrypt(&mgr.pc.secret, pub, data) {
				mgr._handleInit(pub, init)
			}
		case sessionTypeAck:
			ack := new(sessionAck)
			if ack.decrypt(&mgr.pc.secret, pub, data) {
				mgr._handleAck(pub, ack)
			}
		case sessionTypeTraffic:
			mgr._handleTraffic(pub, data)
		default:
		}
	})
}

func (mgr *sessionManager) _handleInit(pub *edPub, init *sessionInit) {
	if info, buf := mgr._sessionForInit(pub, init); info != nil {
		info.handleInit(mgr, init)
		if buf != nil && buf.data != nil {
			info.doSend(mgr, buf.data)
		}
	}
}

func (mgr *sessionManager) _handleAck(pub *edPub, ack *sessionAck) {
	_, isOld := mgr.sessions[*pub]
	if info, buf := mgr._sessionForInit(pub, &ack.sessionInit); info != nil {
		if isOld {
			info.handleAck(mgr, ack)
		} else {
			info.handleInit(mgr, &ack.sessionInit)
		}
		if buf != nil && buf.data != nil {
			info.doSend(mgr, buf.data)
		}
	}
}

func (mgr *sessionManager) _handleTraffic(pub *edPub, msg []byte) {
	if info := mgr.sessions[*pub]; info != nil {
		info.doRecv(mgr, msg)
	} else {
		// We don't know that the node really exists, it could be spoofed/replay
		// So we don't want to save session or a buffer based on this node
		// So we send an init with keys we'll forget
		// If they ack, we'll set up a session and let it self-heal...
		currentPub, _ := newBoxKeys()
		nextPub, _ := newBoxKeys()
		init := newSessionInit(&currentPub, &nextPub, 0)
		mgr.sendInit(pub, &init)
	}
}

func (mgr *sessionManager) writeTo(toKey edPub, msg []byte) {
	phony.Block(mgr, func() {
		if info := mgr.sessions[toKey]; info != nil {
			info.doSend(mgr, msg)
		} else {
			// Need to buffer the traffic
			mgr._bufferAndInit(toKey, msg)
		}
	})
}

func (mgr *sessionManager) _bufferAndInit(toKey edPub, msg []byte) {
	var buf *sessionBuffer
	if buf = mgr.buffers[toKey]; buf == nil {
		// Create a new buffer (including timer)
		buf = new(sessionBuffer)
		currentPub, currentPriv := newBoxKeys()
		nextPub, nextPriv := newBoxKeys()
		buf.init = newSessionInit(&currentPub, &nextPub, 0)
		buf.currentPriv = currentPriv
		buf.nextPriv = nextPriv
		buf.timer = time.AfterFunc(0, func() {})
		mgr.buffers[toKey] = buf
	}
	buf.data = msg
	buf.timer.Stop()
	mgr.sendInit(&toKey, &buf.init)
	buf.timer = time.AfterFunc(sessionTimeout, func() {
		mgr.Act(nil, func() {
			if b := mgr.buffers[toKey]; b == buf {
				b.timer.Stop()
				delete(mgr.buffers, toKey)
			}
		})
	})
}

func (mgr *sessionManager) sendInit(dest *edPub, init *sessionInit) {
	if bs, err := init.encrypt(&mgr.pc.secret, dest); err == nil {
		mgr.pc.PacketConn.WriteTo(bs, types.Addr(dest.asKey()))
	}
}

func (mgr *sessionManager) sendAck(dest *edPub, ack *sessionAck) {
	if bs, err := ack.encrypt(&mgr.pc.secret, dest); err == nil {
		mgr.pc.PacketConn.WriteTo(bs, types.Addr(dest.asKey()))
	}
}

/***************
 * sessionInfo *
 ***************/

type sessionInfo struct {
	phony.Inbox
	mgr          *sessionManager
	seq          uint64 // remote seq
	ed           edPub  // remote ed key
	remoteKeySeq uint64 // signals rotation of current/next
	current      boxPub // send to this, expect to receive from it
	next         boxPub // if we receive from this, then rotate it to current
	localKeySeq  uint64 // signals rotation of recv/send/next
	recvPriv     boxPriv
	recvPub      boxPub
	recvShared   boxShared
	recvNonce    boxNonce
	sendPriv     boxPriv // becomes recvPriv when we rachet forward
	sendPub      boxPub  // becomes recvPub
	sendShared   boxShared
	sendNonce    boxNonce
	nextPriv     boxPriv // becomes sendPriv
	nextPub      boxPub  // becomes sendPub
	timer        *time.Timer
	ack          *sessionAck
}

func newSession(ed *edPub, current, next boxPub, seq uint64) *sessionInfo {
	info := new(sessionInfo)
	info.seq = seq - 1 // so the first update works
	info.ed = *ed
	info.current, info.next = current, next
	info.recvPub, info.recvPriv = newBoxKeys()
	info.sendPub, info.sendPriv = newBoxKeys()
	info.nextPub, info.nextPriv = newBoxKeys()
	info._fixShared(&boxNonce{}, &boxNonce{})
	return info
}

// happens at session creation or after receiving an init/ack
func (info *sessionInfo) _fixShared(recvNonce, sendNonce *boxNonce) {
	getShared(&info.recvShared, &info.current, &info.recvPriv)
	getShared(&info.sendShared, &info.current, &info.sendPriv)
	info.recvNonce, info.sendNonce = *recvNonce, *sendNonce
}

func (info *sessionInfo) _resetTimer() {
	if info.timer != nil {
		info.timer.Stop()
	}
	info.timer = time.AfterFunc(sessionTimeout, func() {
		info.mgr.Act(nil, func() {
			if oldInfo := info.mgr.sessions[info.ed]; oldInfo == info {
				delete(info.mgr.sessions, info.ed)
			}
		})
	})
}

func (info *sessionInfo) handleInit(from phony.Actor, init *sessionInit) {
	info.Act(from, func() {
		if init.seq <= info.seq {
			return
		}
		info._handleUpdate(init)
		// Send a sessionAck
		init := newSessionInit(&info.sendPub, &info.nextPub, info.localKeySeq)
		ack := sessionAck{init}
		info._sendAck(&ack)
	})
}

func (info *sessionInfo) handleAck(from phony.Actor, ack *sessionAck) {
	info.Act(from, func() {
		if ack.seq <= info.seq {
			return
		}
		info._handleUpdate(&ack.sessionInit)
	})
}

// return true if everything looks OK and the session was updated
func (info *sessionInfo) _handleUpdate(init *sessionInit) {
	info.current = init.current
	info.next = init.next
	info.seq = init.seq
	info.remoteKeySeq = init.keySeq
	// Advance our keys, since this counts as a response
	info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
	info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
	info.nextPub, info.nextPriv = newBoxKeys()
	info.localKeySeq++
	// Don't roll back sendNonce, just to be extra safe
	info._fixShared(&boxNonce{}, &info.sendNonce)
	info._resetTimer()
}

func (info *sessionInfo) doSend(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		info.sendNonce.inc() // Advance the nonce before anything else
		bs := make([]byte, 1, sessionTrafficOverhead+len(msg))
		bs[0] = sessionTypeTraffic
		seq := make([]byte, 8)
		binary.BigEndian.PutUint64(seq, info.localKeySeq)
		bs = append(bs, seq...)
		binary.BigEndian.PutUint64(seq, info.remoteKeySeq)
		bs = append(bs, seq...)
		bs = append(bs, info.sendPub[:]...)
		bs = append(bs, info.current[:]...)
		bs = append(bs, info.sendNonce[:]...)
		// We need to include info.nextPub below the layer of encryption
		// That way the remote side knows it's us when we send from it later...
		var tmp []byte
		tmp = append(tmp, info.nextPub[:]...)
		tmp = append(tmp, msg...)
		bs = boxSeal(bs, tmp, &info.sendNonce, &info.sendShared)
		// send
		info.mgr.pc.PacketConn.WriteTo(bs, types.Addr(info.ed[:]))
		info._resetTimer()
	})
}

func (info *sessionInfo) doRecv(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		if len(msg) < sessionTrafficOverhead || msg[0] != sessionTypeTraffic {
			return
		}
		var xtheirKey, xmyKey boxPub
		var nonce boxNonce
		offset := 1
		remoteKeySeq := binary.BigEndian.Uint64(msg[offset : offset+8])
		offset += 8
		localKeySeq := binary.BigEndian.Uint64(msg[offset : offset+8])
		offset += 8
		offset = bytesPop(xtheirKey[:], msg, offset)
		offset = bytesPop(xmyKey[:], msg, offset)
		offset = bytesPop(nonce[:], msg, offset)
		msg := msg[offset:]
		fromCurrent := remoteKeySeq == info.remoteKeySeq
		fromNext := remoteKeySeq == info.remoteKeySeq+1
		toRecv := localKeySeq+1 == info.localKeySeq
		toSend := localKeySeq == info.localKeySeq
		var sharedKey *boxShared
		var onSuccess func(boxPub)
		switch {
		case fromCurrent && toRecv:
			// The boring case, nothing to ratchet, just update nonce
			if !info.recvNonce.lessThan(&nonce) {
				return
			}
			sharedKey = &info.recvShared
			onSuccess = func(_ boxPub) {
				info.recvNonce = nonce
			}
		case fromNext && toSend:
			// The remote side appears to have ratcheted forward
			sharedKey = new(boxShared)
			getShared(sharedKey, &info.next, &info.sendPriv)
			onSuccess = func(innerKey boxPub) {
				// Rotate their keys
				info.current = info.next
				info.next = innerKey
				info.remoteKeySeq++ // = remoteKeySeq
				// Rotate our own keys
				info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
				info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
				info.localKeySeq++
				// Generate new next keys
				info.nextPub, info.nextPriv = newBoxKeys()
				// Update nonces
				info._fixShared(&nonce, &boxNonce{})
			}
		case fromNext && toRecv:
			// The remote side appears to have ratcheted forward early
			// Technically there's no reason we can't handle this
			//panic("DEBUG") // TODO test this
			sharedKey = new(boxShared)
			getShared(sharedKey, &info.next, &info.recvPriv)
			onSuccess = func(innerKey boxPub) {
				// Rotate their keys
				info.current = info.next
				info.next = innerKey
				info.remoteKeySeq++ // = remoteKeySeq
				// Rotate our own keys
				info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
				info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
				info.localKeySeq++
				// Generate new next keys
				info.nextPub, info.nextPriv = newBoxKeys()
				// Update nonces
				info._fixShared(&nonce, &boxNonce{})
			}
		default:
			// We can't make sense of their message
			// Send a sessionInit and hope they ack so we can fix things
			init := newSessionInit(&info.sendPub, &info.nextPub, info.localKeySeq)
			info._sendInit(&init)
			return
		}
		// Decrypt and handle packet
		if unboxed, ok := boxOpen(nil, msg, &nonce, sharedKey); ok {
			var key boxPub
			copy(key[:], unboxed)
			msg = unboxed[len(key):]
			info.mgr.pc.network.recv(info, msg)
			// Misc remaining followup work
			onSuccess(key)
			info._resetTimer()
		} else {
			// This shouldn't happen during testing
			// Not sure if we should do anything outside of testing...
		}
	})
}

func (info *sessionInfo) _sendInit(init *sessionInit) {
	info.mgr.sendInit(&info.ed, init)
}

func (info sessionInfo) _sendAck(ack *sessionAck) {
	info.mgr.sendAck(&info.ed, ack)
}

/***************
 * sessionInit *
 ***************/

type sessionInit struct {
	current boxPub
	next    boxPub
	keySeq  uint64
	seq     uint64 // timestamp or similar
}

func newSessionInit(current, next *boxPub, keySeq uint64) sessionInit {
	var init sessionInit
	init.current = *current
	init.next = *next
	init.keySeq = keySeq
	init.seq = uint64(time.Now().Unix())
	return init
}

func (init *sessionInit) encrypt(from *boxPriv, to *edPub) ([]byte, error) {
	var toBox *boxPub
	var err error
	if toBox, err = to.toBox(); err != nil {
		return nil, err
	}
	var nonce *boxNonce
	if nonce, err = newRandomNonce(); err != nil {
		return nil, err
	}
	// Prepare the payload (to be encrypted)
	payload := make([]byte, 0, sessionInitSize) // TODO correct size, this is overkill
	payload = append(payload, init.current[:]...)
	payload = append(payload, init.next[:]...)
	offset := len(payload)
	payload = payload[:offset+8]
	binary.BigEndian.PutUint64(payload[offset:offset+8], init.keySeq)
	offset = len(payload)
	payload = payload[:offset+8]
	binary.BigEndian.PutUint64(payload[offset:offset+8], init.seq)
	// Encrypt
	var shared boxShared
	getShared(&shared, toBox, from)
	bs := boxSeal(nil, payload, nonce, &shared)
	// Assemble final message
	data := make([]byte, 1, sessionInitSize)
	data[0] = sessionTypeInit
	data = append(data, nonce[:]...)
	data = append(data, bs...)
	return data, nil
}

func (init *sessionInit) decrypt(priv *boxPriv, from *edPub, data []byte) bool {
	if len(data) != sessionInitSize {
		return false
	}
	fromBox, err := from.toBox()
	if err != nil {
		return false
	}
	var shared boxShared
	getShared(&shared, fromBox, priv)
	var nonce boxNonce
	offset := 1
	offset = bytesPop(nonce[:], data, offset)
	bs := data[offset:]
	payload := make([]byte, 0, sessionInitSize) // TODO correct size
	var ok bool
	if payload, ok = boxOpen(payload, bs, &nonce, &shared); !ok {
		return false
	}
	offset = 0
	offset = bytesPop(init.current[:], payload, offset)
	offset = bytesPop(init.next[:], payload, offset)
	init.keySeq = binary.BigEndian.Uint64(payload[offset : offset+8])
	offset += 8
	init.seq = binary.BigEndian.Uint64(payload[offset:])
	return true
}

/**************
 * sessionAck *
 **************/

type sessionAck struct {
	sessionInit
}

func (ack *sessionAck) encrypt(from *boxPriv, to *edPub) ([]byte, error) {
	data, err := ack.sessionInit.encrypt(from, to)
	if err == nil {
		data[0] = sessionTypeAck
	}
	return data, err
}

/*****************
 * sessionBuffer *
 *****************/

type sessionBuffer struct {
	data        []byte
	init        sessionInit
	currentPriv boxPriv     // pairs with init.recv
	nextPriv    boxPriv     // pairs with init.send
	timer       *time.Timer // time.AfterFunc to clean up
}
