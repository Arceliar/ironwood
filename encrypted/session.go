package encrypted

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/Arceliar/phony"
)

const sessionTIMEOUT = time.Minute

/******************
 * sessionManager *
 ******************/

type sessionManager struct {
	phony.Inbox
	pc     *PacketConn
	secret edPriv
	public edPub
	// TODO maps of keys onto session state, etc
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
	mgr.sessions[info.theirEdPub] = info
	return info
}

func (mgr *sessionManager) _sessionForInit(pub *edPub, init *sessionInit) *sessionInfo {
	var info *sessionInfo
	if info = mgr.sessions[*pub]; info == nil && init.check(pub) {
		info = mgr._newSession(pub, &init.boxPub, init.seq)
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
	mgr            *sessionManager
	theirSeq       uint64
	theirEdPub     edPub
	theirBoxPub    boxPub
	ourReadBoxPriv boxPriv
	ourReadBoxPub  boxPub
	ourSendBoxPriv boxPriv // Rotates into read position if they send to us
	ourSendBoxPub  boxPub
	readShared     boxShared   // their pub, our current read priv
	sendShared     boxShared   // their pub, our current send priv / our next read priv
	readNonce      boxNonce    // non-decreasing, update when reading, reset on new shared
	sendNonce      boxNonce    // non-decreasing, update when sending, reset on new shared
	timer          *time.Timer // time.AfterFunc
}

func newSession(ed *edPub, box *boxPub, seq uint64) *sessionInfo {
	info := new(sessionInfo)
	info.theirSeq = seq - 1 // so the first update works
	info.theirEdPub = *ed
	info.theirBoxPub = *box
	rpub, rpriv := newBoxKeys()
	info.ourReadBoxPub = *rpub
	info.ourReadBoxPriv = *rpriv
	spub, spriv := newBoxKeys()
	info.ourSendBoxPub = *spub
	info.ourSendBoxPriv = *spriv
	getShared(&info.readShared, &info.theirBoxPub, &info.ourReadBoxPriv)
	getShared(&info.sendShared, &info.theirBoxPub, &info.ourSendBoxPriv)
	return info
}

func (info *sessionInfo) _resetTimer() {
	if info.timer != nil {
		info.timer.Stop()
	}
	info.timer = time.AfterFunc(sessionTIMEOUT, func() {
		info.mgr.Act(nil, func() {
			if oldInfo := info.mgr.sessions[info.theirEdPub]; oldInfo == info {
				delete(info.mgr.sessions, info.theirEdPub)
			}
		})
	})
}

// advance to the next set of crypto keys
func (info *sessionInfo) _ratchet() {
	info.ourReadBoxPub = info.ourSendBoxPub
	info.ourReadBoxPriv = info.ourSendBoxPriv
	getShared(&info.readShared, &info.theirBoxPub, &info.ourReadBoxPriv)
	info.readNonce = boxNonce{}
	newPub, newPriv := newBoxKeys()
	info.ourSendBoxPub = *newPub
	info.ourSendBoxPriv = *newPriv
	info.sendNonce = boxNonce{}
	getShared(&info.sendShared, &info.theirBoxPub, &info.ourSendBoxPriv)
}

func (info *sessionInfo) handleInit(from phony.Actor, init *sessionInit) {
	info.Act(from, func() {
		if !init.check(&info.theirEdPub) {
			return
		}
		if info._handleUpdate(init) {
			// Send a sessionAck
			ack := sessionAck{newSessionInit(&info.mgr.pc.secret, &info.ourSendBoxPub)}
			_ = ack
			panic("TODO")
		}
	})
}

func (info *sessionInfo) handleAck(from phony.Actor, ack *sessionAck) {
	info.Act(from, func() {
		if !ack.check(&info.theirEdPub) {
			return
		}
		info._handleUpdate(&ack.sessionInit)
	})
}

// return true if everything looks OK and the session was updated
func (info *sessionInfo) _handleUpdate(init *sessionInit) bool {
	if init.seq <= info.theirSeq {
		return false
	}
	info.theirBoxPub = init.boxPub
	info._ratchet()
	info._resetTimer()
	return true
}

func (info *sessionInfo) send(from phony.Actor, msg []byte) {
	// TODO some worker pool to multi-thread this
	info.Act(from, func() {
		defer info.sendNonce.inc()
		panic("TODO")
	})
}

func (info *sessionInfo) recv(from phony.Actor, msg []byte) {
	// TODO some worker pool to multi-thread this
	info.Act(from, func() {
		panic("TODO")
	})
}

/***************
 * sessionInit *
 ***************/

// Send keys to a remote node, so they can set up a session and ack it
// Used mainly for initial session setup

type sessionInit struct {
	sig    edSig // edPub was the from address, so we get that for free already
	boxPub boxPub
	seq    uint64 // timestamp or similar
}

func newSessionInit(sig *edPriv, box *boxPub) sessionInit {
	var init sessionInit
	init.boxPub = *box
	init.seq = uint64(time.Now().Unix())
	init.sign(sig)
	return init
}

const sessionInitSize = edSigSize + boxPubSize + 8

func (si *sessionInit) bytesForSig() []byte {
	bs := make([]byte, boxPubSize+8)
	copy(bs, si.boxPub[:])
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
	copy(data, si.sig[:])
	copy(data[edSigSize:], si.boxPub[:])
	binary.BigEndian.PutUint64(data[edSigSize+boxPubSize:], si.seq)
	return
}

func (si *sessionInit) UnmarshalBinary(data []byte) error {
	if len(data) != sessionInitSize {
		return errors.New("wrong sessionInit size")
	}
	copy(si.sig[:], data[:])
	copy(si.boxPub[:], data[edSigSize:])
	si.seq = binary.BigEndian.Uint64(data[edSigSize+boxPubSize:])
	return nil
}

/**************
 * sessionAck *
 **************/

// Sent in response to a sessionInit, it's basically the same thing...

type sessionAck struct {
	sessionInit
}
