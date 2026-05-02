package pow

import (
	"fmt"
	"sync"
	"time"
)

// NonceCache implements server-side nonce tracking for NTP-independent validation.
//
// Problem (NTP Drift):
//   In an isolated network (Blackout), NTP servers are unreachable.
//   Cheap quartz oscillators on routers/phones drift ~1-2 minutes/day.
//   After a week offline, clocks can diverge by 10+ minutes.
//   Absolute-time TTL checks (Challenge.IsExpired()) would reject
//   legitimate nodes whose clocks have drifted.
//
// Solution:
//   The challenger issues a nonce and tracks it in a local cache.
//   The nonce is valid until the challenger explicitly invalidates it
//   (or the ring buffer overwrites it). No wall clock needed.
//
// Implementation: Ring Buffer + HashMap for O(1) insert, O(1) lookup, O(1) eviction.
//   - Ring buffer tracks insertion order for FIFO eviction
//   - HashMap provides O(1) lookup by nonce
//   - Under DDoS (10K+ handshake requests/sec), eviction never scans
//
// Memory bound: maxSize * (32 + 1 + 8 + 1) ≈ 42 bytes/entry → 10K entries ≈ 420KB.
// OOM is impossible even under sustained attack.
type NonceCache struct {
	mu sync.RWMutex

	// Ring buffer for O(1) FIFO eviction
	ring    []ringEntry
	head    int // Next write position
	count   int // Current number of entries

	// HashMap for O(1) lookup
	index map[[32]byte]int // nonce → ring index

	maxSize int
}

type ringEntry struct {
	nonce      [32]byte
	difficulty uint8
	createdAt  time.Time // Monotonic clock for diagnostics only
	used       bool
	occupied   bool      // Is this slot in use?
}

// DefaultMaxNonces is the maximum number of outstanding challenges.
// Memory: 10000 * ~50 bytes = ~500KB. Safe for embedded devices.
const DefaultMaxNonces = 10000

// NewNonceCache creates a new nonce tracker with O(1) ring buffer eviction.
func NewNonceCache(maxSize int) *NonceCache {
	if maxSize <= 0 {
		maxSize = DefaultMaxNonces
	}
	return &NonceCache{
		ring:    make([]ringEntry, maxSize),
		index:   make(map[[32]byte]int, maxSize),
		maxSize: maxSize,
	}
}

// Issue records a newly created challenge nonce. O(1) time complexity.
// If the ring buffer is full, the oldest entry is evicted automatically.
func (nc *NonceCache) Issue(nonce [32]byte, difficulty uint8) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// If slot is occupied, evict the old entry from the index
	if nc.ring[nc.head].occupied {
		delete(nc.index, nc.ring[nc.head].nonce)
	}

	// Write new entry to ring buffer
	nc.ring[nc.head] = ringEntry{
		nonce:      nonce,
		difficulty: difficulty,
		createdAt:  time.Now(),
		used:       false,
		occupied:   true,
	}

	// Update index
	nc.index[nonce] = nc.head

	// Advance head (ring wraps around)
	nc.head = (nc.head + 1) % nc.maxSize

	if nc.count < nc.maxSize {
		nc.count++
	}
}

// Validate checks if a nonce is known, unused, and matches the expected difficulty.
// On success, marks the nonce as used (one-time). O(1) time complexity.
func (nc *NonceCache) Validate(nonce [32]byte, difficulty uint8) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	idx, exists := nc.index[nonce]
	if !exists {
		return fmt.Errorf("unknown nonce — not issued by this node or already evicted")
	}

	entry := &nc.ring[idx]

	if entry.used {
		return fmt.Errorf("nonce already used — replay attack detected")
	}

	if entry.difficulty != difficulty {
		return fmt.Errorf("difficulty mismatch: issued %d, claimed %d",
			entry.difficulty, difficulty)
	}

	// Mark as used (one-time)
	entry.used = true

	return nil
}

// Invalidate explicitly removes a nonce. O(1).
func (nc *NonceCache) Invalidate(nonce [32]byte) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if idx, exists := nc.index[nonce]; exists {
		nc.ring[idx].occupied = false
		delete(nc.index, nonce)
		nc.count--
	}
}

// Size returns the number of outstanding (tracked) nonces.
func (nc *NonceCache) Size() int {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return len(nc.index)
}

// Cleanup removes all used nonces from the index, freeing their slots.
// O(n) but called infrequently (e.g., every 60s).
func (nc *NonceCache) Cleanup(maxAge time.Duration) int {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	removed := 0
	now := time.Now()

	for nonce, idx := range nc.index {
		entry := &nc.ring[idx]
		if entry.used || now.Sub(entry.createdAt) > maxAge {
			entry.occupied = false
			delete(nc.index, nonce)
			removed++
		}
	}

	return removed
}
