package encrypted

import (
	"math/rand"
	"testing"
)

// reference model: a set of seen nonces plus a high-water mark,
// accepting anything not seen that is at most replayWindowDepth below
// the mark.
type replayModel struct {
	seen map[uint64]bool
	head uint64
}

func (m *replayModel) check(n uint64) bool {
	if m.head-n > replayWindowDepth && n <= m.head {
		return false
	}
	return !m.seen[n]
}

func (m *replayModel) commit(n uint64) {
	m.seen[n] = true
	if n > m.head {
		m.head = n
	}
}

func TestReplayWindowSequential(t *testing.T) {
	var w replayWindow
	w.reset()
	for n := uint64(1); n < 10000; n++ {
		if !w.check(n) {
			t.Fatalf("sequential nonce %d rejected", n)
		}
		w.commit(n)
	}
}

func TestReplayWindowDuplicates(t *testing.T) {
	var w replayWindow
	w.reset()
	w.commit(1)
	w.commit(5)
	for _, n := range []uint64{1, 5} {
		if w.check(n) {
			t.Fatalf("duplicate nonce %d accepted", n)
		}
	}
}

func TestReplayWindowReorder(t *testing.T) {
	var w replayWindow
	w.reset()
	// Deliver a shuffled run of nonces: every nonce must be accepted
	// exactly once, in any order.
	rng := rand.New(rand.NewSource(1))
	const n = replayWindowDepth - 10
	perm := rng.Perm(n)
	for _, p := range perm {
		v := uint64(p + 1)
		if !w.check(v) {
			t.Fatalf("reordered nonce %d rejected (shuffled delivery)", v)
		}
		w.commit(v)
	}
	for _, p := range perm {
		if w.check(uint64(p + 1)) {
			t.Fatalf("nonce %d accepted twice", p+1)
		}
	}
}

func TestReplayWindowBoundary(t *testing.T) {
	var w replayWindow
	w.reset()
	w.commit(replayWindowDepth)
	// Just inside the window: accepted.
	if !w.check(1) {
		t.Fatal("nonce at window edge rejected")
	}
	w.commit(1)
	// Beyond the window: rejected without state.
	if w.check(0) {
		t.Fatal("nonce below window accepted")
	}
	// Exactly at the boundary depth below the head.
	if !w.check(replayWindowDepth - 1) {
		t.Fatal("nonce exactly within depth rejected")
	}
}

func TestReplayWindowBigJump(t *testing.T) {
	var w replayWindow
	w.reset()
	w.commit(1)
	// A jump far beyond the ring clears all stale bits.
	w.commit(1 << 20)
	// Old nonces are below the window.
	if w.check(2) {
		t.Fatal("stale nonce accepted after big jump")
	}
	// And new in-window traffic still works around the new head.
	w.commit((1 << 20) + 100)
	if !w.check((1<<20)+50) || !w.check((1<<20)+99) {
		t.Fatal("in-window reordering broken after jump")
	}
	w.commit((1 << 20) + 50)
	if w.check((1 << 20) + 50) {
		t.Fatal("in-window duplicate accepted after jump")
	}
}

func TestReplayWindowReset(t *testing.T) {
	var w replayWindow
	w.reset()
	w.commit(1000)
	w.commit(500)
	w.reset()
	// Fresh window: nonce 0 is the sentinel, 1 is the first real one.
	if w.check(0) {
		t.Fatal("sentinel nonce 0 accepted after reset")
	}
	if !w.check(1) {
		t.Fatal("first nonce rejected after reset")
	}
}

// TestReplayWindowAgainstModel cross-checks the window against the
// naive model under random interleavings of advances, in-window
// lookups, duplicates and below-window probes.
func TestReplayWindowAgainstModel(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for iter := 0; iter < 100; iter++ {
		var w replayWindow
		m := replayModel{seen: map[uint64]bool{}}
		w.reset()
		m.seen[0] = true // reset marks the sentinel
		for op := 0; op < 5000; op++ {
			var n uint64
			switch rng.Intn(4) {
			case 0: // advance by a small step
				n = m.head + uint64(rng.Intn(64))
			case 1: // something inside the window
				if m.head == 0 {
					continue
				}
				n = m.head - uint64(rng.Intn(replayWindowDepth))
			case 2: // replay of something near the head
				if m.head == 0 {
					continue
				}
				n = m.head - uint64(rng.Intn(64))
			case 3: // far below the window
				if m.head < replayWindowDepth+10 {
					continue
				}
				n = m.head - replayWindowDepth - 1 - uint64(rng.Intn(1000))
			}
			want := m.check(n)
			if got := w.check(n); got != want {
				t.Fatalf("iter %d op %d nonce %d (head %d): window says %v, model says %v",
					iter, op, n, m.head, got, want)
			}
			if want {
				w.commit(n)
				m.commit(n)
			}
		}
	}
}
