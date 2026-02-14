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
	sessionTimeout            = time.Minute
	sessionTrafficOverheadMin = 1 + 1 + 1 + 1 + boxOverhead + boxPubSize // header, seq, seq, nonce
	sessionTrafficOverhead    = sessionTrafficOverheadMin + 9 + 9 + 9
	sessionInitSize           = 1 + hpkeOverhead + edSigSize + pqPubSize + 8 + ratchetSecretSize + boxPubSize + boxPubSize + 8 + 8
	sessionAckSize            = sessionInitSize
	sessionPQInfoSize         = 1 + pqPubSize + 8 + edSigSize
)

const (
	sessionTypeDummy = iota
	sessionTypeInit
	sessionTypeAck
	sessionTypePQInfo
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
	pq       map[edPub]pqPub
	pqSeq    map[edPub]uint64
}

func (mgr *sessionManager) init(pc *PacketConn) {
	mgr.pc = pc
	mgr.sessions = make(map[edPub]*sessionInfo)
	mgr.buffers = make(map[edPub]*sessionBuffer)
	mgr.pq = make(map[edPub]pqPub)
	mgr.pqSeq = make(map[edPub]uint64)
}

func (mgr *sessionManager) _newSession(ed *edPub, recv, send boxPub, secret ratchetSecret, seq uint64) *sessionInfo {
	info := newSession(ed, recv, send, secret, seq)
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
		info = mgr._newSession(pub, init.current, init.next, init.secret, init.seq)
		if buf = mgr.buffers[*pub]; buf != nil {
			buf.timer.Stop()
			delete(mgr.buffers, *pub)
			info.sendPub, info.sendPriv = buf.init.current, buf.currentPriv
			info.nextPub, info.nextPriv = buf.init.next, buf.nextPriv
			info._fixShared(0, 0)
			// The caller is responsible for sending buf.data when ready
		}
	}
	return info, buf
}

func (mgr *sessionManager) _setPQ(pub *edPub, pq *pqPub, seq uint64) (accepted bool, updated bool) {
	if old, ok := mgr.pq[*pub]; ok {
		oldSeq := mgr.pqSeq[*pub]
		if seq < oldSeq {
			return false, false
		}
		sameKey := bytesEqual(old[:], pq[:])
		if seq == oldSeq {
			return sameKey, false
		}
		if !sameKey {
			if info := mgr.sessions[*pub]; info != nil {
				if info.timer != nil {
					info.timer.Stop()
				}
				delete(mgr.sessions, *pub)
			}
		}
	}
	mgr.pq[*pub] = *pq
	mgr.pqSeq[*pub] = seq
	return true, true
}

func (mgr *sessionManager) _sendInitIfBuffered(pub *edPub) {
	buf := mgr.buffers[*pub]
	if buf == nil {
		return
	}
	mgr.sendInit(pub, &buf.init)
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
			if init.decrypt(&mgr.pc.secretEd, mgr.pc.secretPQ, pub, data) {
				mgr._handleInit(pub, init)
			}
			freeBytes(data)
		case sessionTypeAck:
			ack := new(sessionAck)
			if ack.decrypt(&mgr.pc.secretEd, mgr.pc.secretPQ, pub, data) {
				mgr._handleAck(pub, ack)
			}
			freeBytes(data)
		case sessionTypePQInfo:
			pq := new(sessionPQInfo)
			if pq.decode(pub, data) {
				if accepted, updated := mgr._setPQ(pub, &pq.pub, pq.seq); accepted && updated {
					mgr.sendPQInfo(pub)
					mgr._sendInitIfBuffered(pub)
				}
			}
			freeBytes(data)
		case sessionTypeTraffic:
			mgr._handleTraffic(pub, data)
		default:
		}
	})
}

func (mgr *sessionManager) _handleInit(pub *edPub, init *sessionInit) {
	if accepted, _ := mgr._setPQ(pub, &init.senderPQ, init.senderPQSeq); !accepted {
		return
	}
	if info, buf := mgr._sessionForInit(pub, init); info != nil {
		info.handleInit(mgr, init)
		if buf != nil && buf.data != nil {
			info.doSend(mgr, buf.data)
		}
	}
}

func (mgr *sessionManager) _handleAck(pub *edPub, ack *sessionAck) {
	if accepted, _ := mgr._setPQ(pub, &ack.senderPQ, ack.senderPQSeq); !accepted {
		return
	}
	if info, buf := mgr._sessionForInit(pub, &ack.sessionInit); info != nil {
		info.handleAck(mgr, ack)
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
		init := newSessionInit(&currentPub, &nextPub, 0, &mgr.pc.publicPQ, mgr.pc.publicPQSeq)
		if _, ok := mgr.pq[*pub]; ok {
			mgr.sendInit(pub, &init)
		} else {
			mgr.sendPQInfo(pub)
		}
	}
}

func (mgr *sessionManager) writeTo(toKey edPub, msg []byte) {
	// WARNING: unsafe to call from within an actor, must only be exposed over the PacketConn functions (which are, themselves, unsafe for actors to call in most cases, since they may block)
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
		buf.init = newSessionInit(&currentPub, &nextPub, 0, &mgr.pc.publicPQ, mgr.pc.publicPQSeq)
		buf.currentPriv = currentPriv
		buf.nextPriv = nextPriv
		buf.timer = time.AfterFunc(0, func() {})
		mgr.buffers[toKey] = buf
	}
	buf.data = msg
	buf.timer.Stop()
	mgr.sendPQInfo(&toKey)
	if _, ok := mgr.pq[toKey]; ok {
		mgr.sendInit(&toKey, &buf.init)
	}
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
	toPQ, ok := mgr.pq[*dest]
	if !ok {
		mgr.sendPQInfo(dest)
		return
	}
	if bs, err := init.encrypt(&mgr.pc.secretEd, &mgr.pc.publicPQ, dest, &toPQ); err == nil {
		mgr.pc.PacketConn.WriteTo(bs, types.Addr(dest.asKey()))
	}
}

func (mgr *sessionManager) sendAck(dest *edPub, ack *sessionAck) {
	toPQ, ok := mgr.pq[*dest]
	if !ok {
		mgr.sendPQInfo(dest)
		return
	}
	if bs, err := ack.encrypt(&mgr.pc.secretEd, &mgr.pc.publicPQ, dest, &toPQ); err == nil {
		mgr.pc.PacketConn.WriteTo(bs, types.Addr(dest.asKey()))
	}
}

func (mgr *sessionManager) sendPQInfo(dest *edPub) {
	pq := newSessionPQInfo(&mgr.pc.publicPQ, mgr.pc.publicPQSeq)
	if bs, ok := pq.encode(&mgr.pc.secretEd); ok {
		mgr.pc.PacketConn.WriteTo(bs, types.Addr(dest.asKey()))
	}
}

/***************
 * sessionInfo *
 ***************/

type sessionInfo struct {
	phony.Inbox
	mgr            *sessionManager
	seq            uint64 // remote seq
	ed             edPub  // remote ed key
	remoteKeySeq   uint64 // signals rotation of current/next
	ratchetSecret  ratchetSecret
	current        boxPub // send to this, expect to receive from it
	next           boxPub // if we receive from this, then rotate it to current
	localKeySeq    uint64 // signals rotation of recv/send/next
	recvPriv       boxPriv
	recvPub        boxPub
	recvShared     boxShared
	recvCipher     boxCipher
	recvNonce      uint64
	sendPriv       boxPriv // becomes recvPriv when we ratchet forward
	sendPub        boxPub  // becomes recvPub
	sendShared     boxShared
	sendCipher     boxCipher
	sendNonce      uint64
	nextPriv       boxPriv // becomes sendPriv
	nextPub        boxPub  // becomes sendPub
	timer          *time.Timer
	ack            *sessionAck
	since          time.Time
	rotated        time.Time // last time we rotated keys
	rx             uint64
	tx             uint64
	nextSendShared boxShared
	nextSendCipher boxCipher
	nextSendNonce  uint64
	nextRecvShared boxShared
	nextRecvCipher boxCipher
	nextRecvNonce  uint64
}

func newSession(ed *edPub, current, next boxPub, secret ratchetSecret, seq uint64) *sessionInfo {
	info := new(sessionInfo)
	info.seq = seq - 1 // so the first update works
	info.ed = *ed
	info.ratchetSecret = secret
	info.current, info.next = current, next
	info.recvPub, info.recvPriv = newBoxKeys()
	info.sendPub, info.sendPriv = newBoxKeys()
	info.nextPub, info.nextPriv = newBoxKeys()
	info.since = time.Now()
	info._fixShared(0, 0)
	return info
}

// happens at session creation or after receiving an init/ack
func (info *sessionInfo) _fixShared(recvNonce, sendNonce uint64) {
	getShared(&info.recvShared, &info.current, &info.recvPriv)
	info.recvCipher = newBoxCipher(&info.recvShared)
	getShared(&info.sendShared, &info.current, &info.sendPriv)
	info.sendCipher = newBoxCipher(&info.sendShared)
	getShared(&info.nextSendShared, &info.next, &info.sendPriv)
	info.nextSendCipher = newBoxCipher(&info.nextSendShared)
	getShared(&info.nextRecvShared, &info.next, &info.recvPriv)
	info.nextRecvCipher = newBoxCipher(&info.nextRecvShared)
	info.nextSendNonce, info.nextRecvNonce = 0, 0
	info.recvNonce, info.sendNonce = recvNonce, sendNonce
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
		info._sendAck()
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
	info.ratchetSecret = init.secret
	info.seq = init.seq
	info.remoteKeySeq = init.keySeq
	// Advance our keys, since this counts as a response
	info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
	info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
	info.nextPub, info.nextPriv = newBoxKeys()
	info.localKeySeq++
	// Don't roll back sendNonce, just to be extra safe
	info._fixShared(0, info.sendNonce)
	info._resetTimer()
}

func (info *sessionInfo) doSend(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		defer freeBytes(msg)
		info.sendNonce += 1 // Advance the nonce before anything else
		if info.sendNonce == 0 {
			// Nonce overflowed, so rotate keys
			info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
			info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
			info.nextPub, info.nextPriv = newBoxKeys()
			info.localKeySeq++
			info._fixShared(0, 0)
		}
		plaintextLen := len(info.nextPub) + len(msg)
		packet := allocBytes(sessionTrafficOverhead + plaintextLen)
		defer freeBytes(packet)

		packet[0] = sessionTypeTraffic
		offset := 1
		offset += binary.PutUvarint(packet[offset:], info.localKeySeq)
		offset += binary.PutUvarint(packet[offset:], info.remoteKeySeq)
		offset += binary.PutUvarint(packet[offset:], info.sendNonce)

		// Include nextPub beneath encryption so the receiver can bind future packets.
		plaintext := allocBytes(plaintextLen)
		copy(plaintext, info.nextPub[:])
		copy(plaintext[len(info.nextPub):], msg)
		packet = boxSeal(packet[:offset], plaintext, info.sendNonce, &info.sendCipher)
		freeBytes(plaintext)
		// send
		info.mgr.pc.PacketConn.WriteTo(packet, types.Addr(info.ed[:]))
		info.tx += uint64(len(msg))
		info._resetTimer()
	})
}

func (info *sessionInfo) doRecv(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		orig := msg
		defer freeBytes(orig)
		if len(msg) < sessionTrafficOverheadMin || msg[0] != sessionTypeTraffic {
			return
		}
		offset := 1
		remoteKeySeq, rksLen := binary.Uvarint(msg[offset:])
		if rksLen <= 0 {
			return
		}
		offset += rksLen
		localKeySeq, lksLen := binary.Uvarint(msg[offset:])
		if lksLen <= 0 {
			return
		}
		offset += lksLen
		nonce, nonceLen := binary.Uvarint(msg[offset:])
		if nonceLen <= 0 {
			return
		}
		offset += nonceLen
		msg := msg[offset:]
		fromCurrent := remoteKeySeq == info.remoteKeySeq
		fromNext := remoteKeySeq == info.remoteKeySeq+1
		toRecv := localKeySeq+1 == info.localKeySeq
		toSend := localKeySeq == info.localKeySeq
		var sharedKey *boxCipher
		var onSuccess func(boxPub)
		switch {
		case fromCurrent && toRecv:
			// The boring case, nothing to ratchet, just update nonce
			if !(info.recvNonce < nonce) {
				return
			}
			sharedKey = &info.recvCipher
			onSuccess = func(_ boxPub) {
				info.recvNonce = nonce
			}
		case fromNext && toSend:
			// The remote side appears to have ratcheted forward
			if !(info.nextSendNonce < nonce) {
				return
			}
			sharedKey = &info.nextSendCipher
			onSuccess = func(innerKey boxPub) {
				info.nextSendNonce = nonce
				if info.rotated.IsZero() || time.Since(info.rotated) > time.Minute {
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
					info._fixShared(nonce, 0)
					info.rotated = time.Now()
				}
			}
		case fromNext && toRecv:
			// The remote side appears to have ratcheted forward early
			// Technically there's no reason we can't handle this
			//panic("DEBUG") // TODO test this
			if !(info.nextRecvNonce < nonce) {
				return
			}
			sharedKey = &info.nextRecvCipher
			onSuccess = func(innerKey boxPub) {
				info.nextRecvNonce = nonce
				if info.rotated.IsZero() || time.Since(info.rotated) > time.Minute {
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
					info._fixShared(nonce, 0)
					info.rotated = time.Now()
				}
			}
		default:
			// We can't make sense of their message
			// Send a sessionInit and hope they ack so we can fix things
			info._sendInit()
			return
		}
		// Decrypt and handle packet
		unboxed, ok := allocBytes(0), false
		defer func() { freeBytes(unboxed) }()
		if unboxed, ok = boxOpen(unboxed, msg, nonce, sharedKey); ok {
			var key boxPub
			if len(unboxed) < len(key) {
				return
			}
			copy(key[:], unboxed)
			payload := allocBytes(len(unboxed) - len(key))
			copy(payload, unboxed[len(key):])
			info.mgr.pc.network.recv(info, payload)
			// Misc remaining followup work
			onSuccess(key)
			info.rx += uint64(len(payload))
			info._resetTimer()
		} else {
			// Keys somehow became out-of-sync
			// This seems to happen in some edge cases if a node restarts
			// Fix by sending a new init
			info._sendInit()
		}
	})
}

func (info *sessionInfo) _sendInit() {
	init := newSessionInit(&info.sendPub, &info.nextPub, info.localKeySeq, &info.mgr.pc.publicPQ, info.mgr.pc.publicPQSeq)
	info.mgr.sendInit(&info.ed, &init)
}

func (info *sessionInfo) _sendAck() {
	init := newSessionInit(&info.sendPub, &info.nextPub, info.localKeySeq, &info.mgr.pc.publicPQ, info.mgr.pc.publicPQSeq)
	ack := sessionAck{init}
	info.mgr.sendAck(&info.ed, &ack)
}

/***************
 * sessionInit *
 ***************/

type sessionInit struct {
	senderPQ    pqPub
	senderPQSeq uint64
	secret      ratchetSecret
	current     boxPub
	next        boxPub
	keySeq      uint64
	seq         uint64 // timestamp or similar
}

func newSessionInit(current, next *boxPub, keySeq uint64, senderPQ *pqPub, senderPQSeq uint64) sessionInit {
	var init sessionInit
	init.senderPQ = *senderPQ
	init.senderPQSeq = senderPQSeq
	init.secret = newRatchetSecret()
	init.current = *current
	init.next = *next
	init.keySeq = keySeq
	init.seq = uint64(time.Now().Unix())
	return init
}

func (init *sessionInit) sigBytes() []byte {
	sigSize := len(initSigCtx) + pqPubSize + 8 + ratchetSecretSize + boxPubSize + boxPubSize + 8 + 8
	sigBytes := make([]byte, sigSize)
	offset := 0
	offset = bytesPush(sigBytes, initSigCtx, offset)
	offset = bytesPush(sigBytes, init.senderPQ[:], offset)
	binary.BigEndian.PutUint64(sigBytes[offset:offset+8], init.senderPQSeq)
	offset += 8
	offset = bytesPush(sigBytes, init.secret[:], offset)
	offset = bytesPush(sigBytes, init.current[:], offset)
	offset = bytesPush(sigBytes, init.next[:], offset)
	binary.BigEndian.PutUint64(sigBytes[offset:offset+8], init.keySeq)
	offset += 8
	binary.BigEndian.PutUint64(sigBytes[offset:offset+8], init.seq)
	return sigBytes
}

func (init *sessionInit) encrypt(from *edPriv, fromPQ *pqPub, to *edPub, toPQ *pqPub) ([]byte, error) {
	init.senderPQ = *fromPQ
	sig := edSign(init.sigBytes(), from)

	payloadSize := edSigSize + pqPubSize + 8 + ratchetSecretSize + boxPubSize + boxPubSize + 8 + 8
	payload := make([]byte, payloadSize)
	offset := 0
	offset = bytesPush(payload, sig[:], offset)
	offset = bytesPush(payload, init.senderPQ[:], offset)
	binary.BigEndian.PutUint64(payload[offset:offset+8], init.senderPQSeq)
	offset += 8
	offset = bytesPush(payload, init.secret[:], offset)
	offset = bytesPush(payload, init.current[:], offset)
	offset = bytesPush(payload, init.next[:], offset)
	binary.BigEndian.PutUint64(payload[offset:offset+8], init.keySeq)
	offset += 8
	binary.BigEndian.PutUint64(payload[offset:offset+8], init.seq)

	bs, err := hpkeSeal(nil, payload, to, toPQ)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 1+len(bs))
	data[0] = sessionTypeInit
	copy(data[1:], bs)
	if len(data) != sessionInitSize {
		panic("this should never happen")
	}
	return data, nil
}

func (init *sessionInit) decrypt(privEd *edPriv, privPQ *pqPriv, from *edPub, data []byte) bool {
	if len(data) != sessionInitSize {
		return false
	}
	payload, err := hpkeOpen(nil, data[1:], privEd, privPQ)
	if err != nil {
		return false
	}
	offset := 0
	var sig edSig
	offset = bytesPop(sig[:], payload, offset)
	offset = bytesPop(init.senderPQ[:], payload, offset)
	init.senderPQSeq = binary.BigEndian.Uint64(payload[offset : offset+8])
	offset += 8
	offset = bytesPop(init.secret[:], payload, offset)
	offset = bytesPop(init.current[:], payload, offset)
	offset = bytesPop(init.next[:], payload, offset)
	init.keySeq = binary.BigEndian.Uint64(payload[offset : offset+8])
	offset += 8
	init.seq = binary.BigEndian.Uint64(payload[offset : offset+8])

	return edCheck(init.sigBytes(), &sig, from)
}

/**************
 * sessionAck *
 **************/

type sessionAck struct {
	sessionInit
}

func (ack *sessionAck) encrypt(from *edPriv, fromPQ *pqPub, to *edPub, toPQ *pqPub) ([]byte, error) {
	data, err := ack.sessionInit.encrypt(from, fromPQ, to, toPQ)
	if err == nil {
		data[0] = sessionTypeAck
	}
	return data, err
}

/*****************
 * sessionPQInfo *
 *****************/

type sessionPQInfo struct {
	pub pqPub
	seq uint64
}

func newSessionPQInfo(pub *pqPub, seq uint64) sessionPQInfo {
	return sessionPQInfo{pub: *pub, seq: seq}
}

func (pq *sessionPQInfo) sigBytes() []byte {
	sigBytes := make([]byte, len(pqInfoSigCtx)+pqPubSize+8)
	offset := 0
	offset = bytesPush(sigBytes, pqInfoSigCtx, offset)
	offset = bytesPush(sigBytes, pq.pub[:], offset)
	binary.BigEndian.PutUint64(sigBytes[offset:offset+8], pq.seq)
	return sigBytes
}

func (pq *sessionPQInfo) encode(from *edPriv) ([]byte, bool) {
	sig := edSign(pq.sigBytes(), from)
	data := make([]byte, sessionPQInfoSize)
	data[0] = sessionTypePQInfo
	offset := 1
	offset = bytesPush(data, pq.pub[:], offset)
	binary.BigEndian.PutUint64(data[offset:offset+8], pq.seq)
	offset += 8
	bytesPush(data, sig[:], offset)
	return data, true
}

func (pq *sessionPQInfo) decode(from *edPub, data []byte) bool {
	if len(data) != sessionPQInfoSize {
		return false
	}
	offset := 1
	offset = bytesPop(pq.pub[:], data, offset)
	pq.seq = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	var sig edSig
	bytesPop(sig[:], data, offset)
	return edCheck(pq.sigBytes(), &sig, from)
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
