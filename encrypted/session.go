package encrypted

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/Arceliar/phony"
)

const (
	sessionTimeout  = time.Minute
	sessionOverhead = boxPubSize + boxPubSize + boxNonceSize + boxOverhead + boxPubSize
)

/******************
 * sessionManager *
 ******************/

type sessionManager struct {
	phony.Inbox
	pc       *PacketConn
	secret   edPriv
	public   edPub
	sessions map[edPub]*sessionInfo
}

func (mgr *sessionManager) init(pc *PacketConn) {
	mgr.pc = pc
	mgr.sessions = make(map[edPub]*sessionInfo)
}

func (mgr *sessionManager) _newSession(ed *edPub, box *boxPub, seq uint64) *sessionInfo {
	info := newSession(ed, box, seq)
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
		info = mgr._newSession(pub, &init.box, init.seq)
	}
	return info
}

func (mgr *sessionManager) handleInit(from phony.Actor, pub *edPub, init *sessionInit) {
	mgr.Act(from, func() {
		if info := mgr._sessionForInit(pub, init); info != nil {
			info.handleInit(mgr, init)
		}
	})
}

func (mgr *sessionManager) handleAck(from phony.Actor, pub *edPub, ack *sessionAck) {
	mgr.Act(from, func() {
		if info := mgr._sessionForInit(pub, &ack.sessionInit); info != nil {
			info.handleAck(mgr, ack)
		}
	})
}

/***************
 * sessionInfo *
 ***************/

type sessionInfo struct {
	phony.Actor
	mgr        *sessionManager
	seq        uint64 // remote seq
	ed         edPub  // remote ed key
	box        boxPub // remote box key
	recvPriv   boxPriv
	recvPub    boxPub
	recvShared boxShared
	recvNonce  boxNonce
	sendPriv   boxPriv
	sendPub    boxPub
	sendShared boxShared
	sendNonce  boxNonce
	timer      *time.Timer
}

func newSession(ed *edPub, box *boxPub, seq uint64) *sessionInfo {
	info := new(sessionInfo)
	info.seq = seq - 1 // so the first update works
	info.ed = *ed
	info.box = *box
	rpub, rpriv := newBoxKeys()
	info.recvPub = *rpub
	info.recvPriv = *rpriv
	spub, spriv := newBoxKeys()
	info.sendPub = *spub
	info.sendPriv = *spriv
	getShared(&info.recvShared, &info.box, &info.recvPriv)
	getShared(&info.sendShared, &info.box, &info.sendPriv)
	return info
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

// advance to the next set of crypto keys
func (info *sessionInfo) _ratchet() {
	panic("TODO") // this is wrong, need to handle either node ratcheting...
	info.recvPub = info.sendPub
	info.recvPriv = info.sendPriv
	getShared(&info.recvShared, &info.box, &info.recvPriv)
	info.recvNonce = boxNonce{}
	newPub, newPriv := newBoxKeys()
	info.sendPub = *newPub
	info.sendPriv = *newPriv
	info.sendNonce = boxNonce{}
	getShared(&info.sendShared, &info.box, &info.sendPriv)
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
			ack := sessionAck{newSessionInit(&info.mgr.pc.secret, &info.recvPub)}
			_ = ack
			panic("TODO")
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
	info.box = init.box
	info._ratchet()
	info._resetTimer()
	return true
}

func (info *sessionInfo) send(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		bs := make([]byte, 0, len(msg)+sessionOverhead)
		bs = append(bs, info.sendPub[:]...)
		bs = append(bs, info.box[:]...)
		bs = append(bs, info.sendNonce[:]...)
		// We need to include info.recvPub below the layer of encryption
		// The remote side checks this to confirm we're really us
		var tmp []byte
		tmp = append(tmp, info.recvPub[:]...)
		tmp = append(tmp, msg...)
		bs = boxSeal(bs, tmp, &info.sendNonce, &info.sendShared)
		// send bs somewhere
		panic("TODO")
	})
}

func (info *sessionInfo) recv(from phony.Actor, msg []byte) {
	// TODO? some worker pool to multi-thread this
	info.Act(from, func() {
		if len(msg) < sessionOverhead {
			return
		}
		var theirKey, myKey boxPub
		var nonce boxNonce
		offset := 0
		_, offset = copy(theirKey[:], msg[offset:]), offset+boxPubSize
		_, offset = copy(myKey[:], msg[offset:]), offset+boxPubSize
		_, offset = copy(nonce[:], msg[offset:]), offset+boxNonceSize
		// boxed := msg[offset:]
		matchRemote := bytesEqual(theirKey[:], info.box[:])
		matchRecv := bytesEqual(myKey[:], info.recvPub[:])
		matchSend := bytesEqual(myKey[:], info.sendPub[:])
		var sharedKey *boxShared
		var onSuccess func(boxPub)
		switch {
		case matchRemote && matchRecv:
			if !info.recvNonce.lessThan(&nonce) {
				return
			}
			sharedKey = &info.recvShared
			onSuccess = func(_ boxPub) {
				panic("TODO") // check key?...
				info.recvNonce = nonce
			}
		case matchRemote && matchSend:
			// this should never happen? it would mean bad shared key use?
			panic("TODO")
		case !matchRemote && matchRecv:
			// the remote side (maybe) ratcheted forward
			// TODO sequence number or something to prevent out-of-order problems?
			panic("TODO")
			// generate a new readShared, update if it works
			sharedKey = new(boxShared)
			getShared(sharedKey, &theirKey, &info.recvPriv)
			onSuccess = func(_ boxPub) {
				// their key was ratchted forward
				// update box, recvShared, sendShared, and nonces
				panic("TODO")
			}
		case !matchRemote && matchSend:
			// We have no way to confirm that this is really from them...
			// the remote side (maybe) ratcheted forward
			// generate a new tempShared
			// if it works, then ratchet our side forward and update their key too
			// TODO sequence number...
			// TODO should this ever happen in the first place?...
			panic("TODO")
		case !matchRecv && !matchSend:
			// no local key matches, so send an init? ack?
			panic("TODO")
			return
		default:
			panic("this should be impossible")
		}
		// Presumably we set a pointer to the right key above
		// Try decrypting, do something depending on what happened...
		panic("TODO")
		if msg, ok := boxOpen(nil, msg[offset:], &nonce, sharedKey); ok {
			var key boxPub
			copy(key[:], msg)
			msg = msg[len(key):]
			// TODO send packet somewhere
			panic("TODO")
			onSuccess(key)
		}
	})
}

/***************
 * sessionInit *
 ***************/

// Send keys to a remote node, so they can set up a session and ack it
// Used mainly for initial session setup

type sessionInit struct {
	sig edSig // edPub was the from address, so we get that for free already
	box boxPub
	seq uint64 // timestamp or similar
}

func newSessionInit(sig *edPriv, box *boxPub) sessionInit {
	var init sessionInit
	init.box = *box
	init.seq = uint64(time.Now().Unix())
	init.sign(sig)
	return init
}

const sessionInitSize = edSigSize + boxPubSize + 8

func (si *sessionInit) bytesForSig() []byte {
	bs := make([]byte, boxPubSize+8)
	copy(bs, si.box[:])
	binary.BigEndian.PutUint64(bs[boxPubSize:], si.seq)
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
	_, offset = copy(data[offset:], si.sig[:]), offset+edSigSize
	_, offset = copy(data[offset:], si.box[:]), offset+boxPubSize
	binary.BigEndian.PutUint64(data[offset:], si.seq)
	return
}

func (si *sessionInit) UnmarshalBinary(data []byte) error {
	if len(data) != sessionInitSize {
		return errors.New("wrong sessionInit size")
	}
	offset := 0
	_, offset = copy(si.sig[:], data[offset:]), offset+edSigSize
	_, offset = copy(si.box[:], data[offset:]), offset+boxPubSize
	si.seq = binary.BigEndian.Uint64(data[offset:])
	return nil
}

/**************
 * sessionAck *
 **************/

// Sent in response to a sessionInit, it's basically the same thing...

type sessionAck struct {
	sessionInit
}
