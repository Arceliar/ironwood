package encrypted

import (
	"encoding/binary"
	"errors"
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
	sessionTrafficOverhead = boxPubSize + boxPubSize + boxNonceSize + boxOverhead + boxPubSize
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

func (mgr *sessionManager) _sessionForInit(pub *edPub, init *sessionInit) *sessionInfo {
	var info *sessionInfo
	if info = mgr.sessions[*pub]; info == nil && init.check(pub) {
		info = mgr._newSession(pub, init.recv, init.send, init.seq)
		if buf := mgr.buffers[*pub]; buf != nil {
			buf.timer.Stop()
			delete(mgr.buffers, *pub)
			info.recvPub, info.recvPriv = buf.init.recv, buf.recvPriv
			info.sendPub, info.sendPriv = buf.init.send, buf.sendPriv
			info._fixShared()
			//panic("TODO") // send message... when?
		}
	}
	return info
}

func (mgr *sessionManager) handleInit(pub *edPub, init *sessionInit) {
	mgr.Act(nil, func() {
		if info := mgr._sessionForInit(pub, init); info != nil {
			info.handleInit(mgr, init)
		}
	})
}

func (mgr *sessionManager) handleAck(pub *edPub, ack *sessionAck) {
	mgr.Act(nil, func() {
		_, isOld := mgr.sessions[*pub]
		if info := mgr._sessionForInit(pub, &ack.sessionInit); info != nil {
			if isOld {
				info.handleAck(mgr, ack)
			} else {
				info.handleInit(mgr, &ack.sessionInit)
			}
		}
	})
}

func (mgr *sessionManager) handleTraffic(from phony.Actor, fromKey edPub, msg []byte) {
	mgr.Act(from, func() {
		if info := mgr.sessions[fromKey]; info != nil {
			info.doRecv(mgr, msg)
		} else {
			// TODO? create a sessionBuffer for this?
			sPub, _ := newBoxKeys()
			nPub, _ := newBoxKeys()
			init := newSessionInit(&mgr.pc.secret, &fromKey, &sPub, &nPub)
			init.sendOob(mgr.pc)
		}
	})
}

func (mgr *sessionManager) writeTo(toKey edPub, msg []byte) {
	phony.Block(mgr, func() {
		if info := mgr.sessions[toKey]; info != nil {
			info.doSend(mgr, msg)
		} else {
			// Need to buffer the traffic
			var buf *sessionBuffer
			if buf = mgr.buffers[toKey]; buf == nil {
				// Create a new buffer (including timer)
				buf = new(sessionBuffer)
				recvPub, recvPriv := newBoxKeys()
				sendPub, sendPriv := newBoxKeys()
				buf.init = newSessionInit(&mgr.pc.secret, &toKey, &recvPub, &sendPub)
				buf.recvPriv = recvPriv
				buf.sendPriv = sendPriv
				buf.timer = time.AfterFunc(0, func() {})
				mgr.buffers[toKey] = buf
			}
			buf.data = msg
			buf.timer.Stop()
			buf.timer = time.AfterFunc(sessionTimeout, func() {
				mgr.Act(nil, func() {
					if b := mgr.buffers[toKey]; b == buf {
						b.timer.Stop()
						delete(mgr.buffers, toKey)
					}
				})
			})
		}
	})
}

/***************
 * sessionInfo *
 ***************/

type sessionInfo struct {
	phony.Inbox
	mgr        *sessionManager
	seq        uint64 // remote seq
	ed         edPub  // remote ed key
	recv       boxPub // remote recv key
	send       boxPub // remote send key, becomes recv when they rachet forward
	recvPriv   boxPriv
	recvPub    boxPub
	recvShared boxShared
	recvNonce  boxNonce
	sendPriv   boxPriv // becomes recvPriv when we rachet forward
	sendPub    boxPub  // becomes recvPub
	sendShared boxShared
	sendNonce  boxNonce
	nextPriv   boxPriv // becomes sendPriv
	nextPub    boxPub  // becomes sendPub
	timer      *time.Timer
	ack        *sessionAck
}

func newSession(ed *edPub, recv, send boxPub, seq uint64) *sessionInfo {
	info := new(sessionInfo)
	info.seq = seq - 1 // so the first update works
	info.ed = *ed
	info.recv, info.send = recv, send
	info.recvPub, info.recvPriv = newBoxKeys()
	info.sendPub, info.sendPriv = newBoxKeys()
	info.nextPub, info.nextPriv = newBoxKeys()
	info._fixShared()
	return info
}

// happens at session creation or after receiving an init/ack
func (info *sessionInfo) _fixShared() {
	getShared(&info.recvShared, &info.recv, &info.recvPriv)
	getShared(&info.sendShared, &info.send, &info.sendPriv)
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
		if !init.check(&info.ed) {
			return
		}
		if info._handleUpdate(init) {
			// Send a sessionAck
			//  TODO save this somewhere?
			//  To avoid constantly crating/signing new ones from init spam
			//  On the off chance that someone is repalying old init packets...
			init := newSessionInit(&info.mgr.pc.secret, &info.ed, &info.sendPub, &info.nextPub)
			ack := sessionAck{init}
			ack.sendOob(info.mgr.pc)
		}
	})
}

func (info *sessionInfo) handleAck(from phony.Actor, ack *sessionAck) {
	info.Act(from, func() {
		if !ack.check(&info.ed) {
			return
		}
		info._handleUpdate(&ack.sessionInit)
	})
}

// return true if everything looks OK and the session was updated
func (info *sessionInfo) _handleUpdate(init *sessionInit) bool {
	if init.seq <= info.seq {
		return false
	}
	info.recv = init.recv
	info.send = init.send
	info.seq = init.seq
	info._fixShared()
	info._resetTimer()
	return true
}

func (info *sessionInfo) doSend(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		bs := make([]byte, 0, sessionTrafficOverhead+len(msg))
		bs = append(bs, info.sendPub[:]...)
		bs = append(bs, info.recv[:]...)
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
		if len(msg) < sessionTrafficOverhead {
			panic(len(msg))
			panic("DEBUG")
			return
		}
		var theirKey, myKey boxPub
		var nonce boxNonce
		offset := 0
		offset = bytesPop(theirKey[:], msg, offset)
		offset = bytesPop(myKey[:], msg, offset)
		offset = bytesPop(nonce[:], msg, offset)
		msg := msg[offset:]
		remoteRecv := bytesEqual(theirKey[:], info.recv[:])
		remoteSend := bytesEqual(theirKey[:], info.send[:])
		localRecv := bytesEqual(myKey[:], info.recvPub[:])
		localSend := bytesEqual(myKey[:], info.sendPub[:])
		var sharedKey *boxShared
		var onSuccess func(boxPub)
		switch {
		case remoteRecv && localRecv:
			// The boring case, nothing to ratchet, just update nonce
			if !info.recvNonce.lessThan(&nonce) {
				panic("DEBUG")
				return
			}
			sharedKey = &info.recvShared
			onSuccess = func(_ boxPub) {
				// TODO some kind of check on the inner key? we expect it to be info.send...
				info.recvNonce = nonce
			}
			panic("DEBUG")
		case remoteRecv && localSend:
			// We expect this to happen when they ratchet forward
			// The inner packet contains their new send key
			sharedKey = new(boxShared)
			getShared(sharedKey, &theirKey, &info.sendPriv)
			onSuccess = func(innerKey boxPub) {
				// Rotate our own keys and nonces
				info.recv, info.send = info.send, innerKey
				info.recvNonce, info.sendNonce = nonce, boxNonce{}
				info.recvPub, info.recvPriv = info.sendPub, info.sendPriv
				info.sendPub, info.sendPriv = info.nextPub, info.nextPriv
				info._fixShared() // TODO? reuse sharedKey as info.recvShared?
				// Generate new next keys
				info.nextPub, info.nextPriv = newBoxKeys()
			}
			panic("DEBUG")
		case remoteSend && localRecv:
			// For some reason, they ratcheted forward early
			// Advancing their side is better than spamming with sessionInit/Ack
			sharedKey = new(boxShared)
			getShared(sharedKey, &theirKey, &info.recvPriv)
			onSuccess = func(innerKey boxPub) {
				info.recv, info.send = info.send, innerKey
				info.recvNonce, info.sendNonce = nonce, boxNonce{}
				info._fixShared()
			}
			panic("DEBUG")
		default:
			// We can't make sense of their message
			// Send a sessionInit and hope they fix it
			init := newSessionInit(&info.mgr.pc.secret, &info.ed, &info.sendPub, &info.nextPub)
			init.sendOob(info.mgr.pc)
			panic("DEBUG")
			return
		}
		// Decrypt and handle packet
		if unboxed, ok := boxOpen(nil, msg, &nonce, sharedKey); ok {
			panic("DEBUG")
			var key boxPub
			copy(key[:], unboxed)
			msg = unboxed[len(key):]
			info.mgr.pc.network.recv(info, msg)
			// Misc remaining followup work
			onSuccess(key)
			info._resetTimer()
		}
		panic("DEBUG")
	})
}

/***************
 * sessionInit *
 ***************/

type sessionInit struct {
	sig  edSig  // edPub was the from address, so we get that for free already
	dest edPub  // intended dest key
	recv boxPub // dest.recv <- sender.sendPub
	send boxPub // dest.send <- sender.sendNext
	seq  uint64 // timestamp or similar
}

func newSessionInit(sig *edPriv, dest *edPub, send, next *boxPub) sessionInit {
	var init sessionInit
	init.dest = *dest
	init.recv = *send
	init.send = *next
	init.seq = uint64(time.Now().Unix())
	init.sign(sig)
	return init
}

const sessionInitSize = edSigSize + edPubSize + boxPubSize + boxPubSize + 8

func (si *sessionInit) bytesForSig() []byte {
	const msgSize = sessionInitSize - edSigSize
	bs := make([]byte, msgSize)
	offset := 0
	offset = bytesPush(bs, si.dest[:], offset)
	offset = bytesPush(bs, si.recv[:], offset)
	offset = bytesPush(bs, si.send[:], offset)
	binary.BigEndian.PutUint64(bs[offset:], si.seq)
	return bs
}

func (si *sessionInit) sign(priv *edPriv) {
	bs := si.bytesForSig()
	si.sig = *edSign(bs, priv)
}

func (si *sessionInit) check(pub *edPub) bool {
	bs := si.bytesForSig()
	return edCheck(bs, &si.sig, pub)
}

func (si *sessionInit) MarshalBinary() (data []byte, err error) {
	data = make([]byte, sessionInitSize)
	offset := 0
	offset = bytesPush(data, si.sig[:], offset)
	offset = bytesPush(data, si.dest[:], offset)
	offset = bytesPush(data, si.recv[:], offset)
	offset = bytesPush(data, si.send[:], offset)
	binary.BigEndian.PutUint64(data[offset:], si.seq)
	return
}

func (si *sessionInit) UnmarshalBinary(data []byte) error {
	if len(data) != sessionInitSize {
		return errors.New("wrong sessionInit size")
	}
	offset := 0
	offset = bytesPop(si.sig[:], data, offset)
	offset = bytesPop(si.dest[:], data, offset)
	offset = bytesPop(si.recv[:], data, offset)
	offset = bytesPop(si.send[:], data, offset)
	si.seq = binary.BigEndian.Uint64(data[offset:])
	return nil
}

func (si *sessionInit) sendOob(pc *PacketConn) {
	bs, _ := si.MarshalBinary()
	bs = append([]byte{outOfBandInit}, bs...)
	pc.PacketConn.SendOutOfBand(si.dest.asKey(), bs)
}

/**************
 * sessionAck *
 **************/

type sessionAck struct {
	sessionInit
}

func (sa *sessionAck) sendOob(pc *PacketConn) {
	bs, _ := sa.MarshalBinary()
	bs = append([]byte{outOfBandAck}, bs...)
	pc.PacketConn.SendOutOfBand(sa.dest.asKey(), bs)
}

/*****************
 * sessionBuffer *
 *****************/

type sessionBuffer struct {
	data     []byte
	init     sessionInit
	recvPriv boxPriv
	sendPriv boxPriv
	timer    *time.Timer // time.AfterFunc to clean up
}
