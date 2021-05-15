package encrypted

import (
	"crypto/ed25519"

	"github.com/Arceliar/phony"
)

type Debug struct {
	pc *PacketConn
}

func (d *Debug) init(pc *PacketConn) {
	d.pc = pc
}

type DebugSessionInfo struct {
	Key ed25519.PublicKey
}

func (d *Debug) GetSessions() (infos []DebugSessionInfo) {
	phony.Block(&d.pc.sessions, func() {
		for key := range d.pc.sessions.sessions {
			var info DebugSessionInfo
			info.Key = append(info.Key, key[:]...)
			infos = append(infos, info)
		}
	})
	return
}
