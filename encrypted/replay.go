package encrypted

/*
	replayWindow: a reorder-tolerant anti-replay filter.

	The session layer seals each packet with a monotonically increasing
	nonce. Because the same key must never be accepted twice (nonce
	reuse under a stream cipher is a replay), the receiver must reject
	nonces it has already seen. The naive check, "nonce must exceed the
	highest accepted so far", also rejects any packet that was reordered
	in transit, silently discarding data that would have been perfectly
	good if it had arrived a moment earlier.

	This filter instead keeps a sliding window of accepted nonces, the
	approach used by WireGuard (after RFC 6479) and IPsec (RFC 4303): a
	nonce above the head of the window is accepted and advances it; a
	nonce below the head is accepted only if it falls inside the window
	and has not been seen before. Reordering within the window is then
	harmless, while true replays (and anything older than the window)
	are still rejected with a couple of arithmetic operations.

	The window is a ring of 64-bit blocks indexed by the nonce's
	absolute block number modulo the ring size, so advancing the window
	only requires zeroing the blocks it slides over, never shifting
	bits. The effective depth is one block less than the ring to keep
	in-window lookups from aliasing with stale bits. At the default size
	that tolerates reordering up to 8128 packets deep for 1 KiB of state
	per session.
*/

const (
	replayBlockBits   = 64
	replayRingBlocks  = 128 // must be a power of two
	replayWindowDepth = (replayRingBlocks - 1) * replayBlockBits
	replayBlockMask   = replayRingBlocks - 1
)

// replayWindow is not safe for concurrent use; it is only touched from
// the session's actor. The zero value is not a valid fresh window: use
// reset, which _fixShared calls whenever a session (re)starts.
type replayWindow struct {
	head uint64 // highest committed nonce
	ring [replayRingBlocks]uint64
}

// reset clears the window for a new nonce sequence. Nonce zero is
// marked as seen, preserving the convention that senders pre-increment
// their counter and so never legitimately use zero.
func (w *replayWindow) reset() {
	w.head = 0
	w.ring = [replayRingBlocks]uint64{}
	w.ring[0] = 1
}

// check reports whether nonce may be committed, without recording it.
// Commit only after the packet has authenticated, so that corrupted
// packets cannot burn window slots that a retransmission might need.
func (w *replayWindow) check(nonce uint64) bool {
	if nonce > w.head {
		return true
	}
	if w.head-nonce > replayWindowDepth {
		return false // older than the window
	}
	b := (nonce / replayBlockBits) & replayBlockMask
	return w.ring[b]&(1<<(nonce%replayBlockBits)) == 0
}

// commit records an accepted nonce, advancing the window if needed.
func (w *replayWindow) commit(nonce uint64) {
	if nonce > w.head {
		// Zero the blocks the window slides over. A jump larger than
		// the whole ring clears everything.
		oldB := w.head / replayBlockBits
		newB := nonce / replayBlockBits
		diff := newB - oldB
		if diff > replayRingBlocks {
			diff = replayRingBlocks
		}
		for i := oldB + 1; i <= oldB+diff; i++ {
			w.ring[i&replayBlockMask] = 0
		}
		w.head = nonce
	}
	b := (nonce / replayBlockBits) & replayBlockMask
	w.ring[b] |= 1 << (nonce % replayBlockBits)
}
