package pow

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Validator verifies incoming PoW solutions.
//
// Verification is O(1) — a single Argon2id computation to confirm the
// solution nonce produces a hash with sufficient leading zero bits.
// This is inherently ~2-5 seconds, which is acceptable for a one-time
// join protocol but prevents trivial brute-force on the verification side.
//
// Two validation modes:
//   - Validate():        uses wall-clock timestamps (online, NTP available)
//   - ValidateOffline(): uses NonceCache (offline, no NTP / clock drift)
type Validator struct {
	log        *slog.Logger
	hmacSecret []byte

	// NonceCache for NTP-independent validation (Blackout mode).
	// When set, ValidateOffline() checks nonces against this cache
	// instead of relying on wall-clock timestamps.
	nonceCache *NonceCache

	// Rate limiting: track recent solutions per public key
	rateLimiter map[[32]byte][]time.Time
	rlMu        sync.Mutex

	// Ban list: known-bad public keys
	banList map[[32]byte]struct{}
	banMu   sync.RWMutex

	// MaxSolutionsPerMinute per public key
	MaxSolutionsPerMinute int
}

// NewValidator creates a new PoW validator with both online and offline support.
func NewValidator(log *slog.Logger, hmacSecret []byte) *Validator {
	return &Validator{
		log:                   log,
		hmacSecret:            hmacSecret,
		nonceCache:            NewNonceCache(DefaultMaxNonces),
		rateLimiter:           make(map[[32]byte][]time.Time),
		banList:               make(map[[32]byte]struct{}),
		MaxSolutionsPerMinute: 5,
	}
}

// NonceCache returns the validator's nonce cache for issuing challenges.
func (v *Validator) NonceCache() *NonceCache {
	return v.nonceCache
}

// ValidationResult describes the outcome of a PoW validation.
type ValidationResult struct {
	Valid        bool
	Reason       string
	LeadingZeros int
	ComputeTime  time.Duration
}

// Validate checks a solution against its challenge.
//
// Steps:
//  1. Check challenge HMAC (not tampered)
//  2. Check challenge timestamp (not expired)
//  3. Check solver public key (not banned)
//  4. Check rate limit (not flooding)
//  5. Verify Ed25519 signature (solver owns the key)
//  6. Recompute Argon2id and check leading zero bits
func (v *Validator) Validate(challenge *Challenge, solution *Solution) ValidationResult {
	start := time.Now()

	// Step 1: Verify challenge HMAC
	mac := hmac.New(sha256.New, v.hmacSecret)
	mac.Write(challenge.Payload())
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(expectedMAC, challenge.MAC[:]) {
		return ValidationResult{Valid: false, Reason: "invalid challenge HMAC — possible tampering"}
	}

	// Step 2: Check timestamp
	if challenge.IsExpired() {
		return ValidationResult{Valid: false, Reason: fmt.Sprintf(
			"challenge expired: age=%s, max=%s",
			time.Since(time.Unix(challenge.Timestamp, 0)),
			ChallengeMaxAge,
		)}
	}

	// Step 3: Check ban list
	v.banMu.RLock()
	_, banned := v.banList[solution.SolverPubKey]
	v.banMu.RUnlock()
	if banned {
		return ValidationResult{Valid: false, Reason: "solver public key is banned"}
	}

	// Step 4: Rate limiting
	if !v.checkRateLimit(solution.SolverPubKey) {
		return ValidationResult{Valid: false, Reason: fmt.Sprintf(
			"rate limit exceeded: max %d solutions/min per pubkey",
			v.MaxSolutionsPerMinute,
		)}
	}

	// Step 5: Verify Ed25519 signature
	payload := challenge.Payload()
	signData := make([]byte, len(payload)+32)
	copy(signData, payload)
	copy(signData[len(payload):], solution.SolutionNonce[:])

	pubKey := ed25519.PublicKey(solution.SolverPubKey[:])
	if !ed25519.Verify(pubKey, signData, solution.Signature[:]) {
		return ValidationResult{Valid: false, Reason: "invalid Ed25519 signature"}
	}

	// Step 6: Recompute Argon2id and verify
	input := make([]byte, len(payload)+32)
	copy(input, payload)
	copy(input[len(payload):], solution.SolutionNonce[:])

	salt := challenge.Nonce[:]
	hash := argon2.IDKey(input, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	leadingZeros := countLeadingZeroBits(hash)
	computeTime := time.Since(start)

	if leadingZeros < int(challenge.Difficulty) {
		return ValidationResult{
			Valid:        false,
			Reason:       fmt.Sprintf("insufficient leading zeros: got %d, need %d", leadingZeros, challenge.Difficulty),
			LeadingZeros: leadingZeros,
			ComputeTime:  computeTime,
		}
	}

	v.log.Info("PoW validated successfully",
		"solver", fmt.Sprintf("%x", solution.SolverPubKey[:8]),
		"leading_zeros", leadingZeros,
		"compute_time", computeTime,
	)

	// Record for rate limiting
	v.recordSolution(solution.SolverPubKey)

	return ValidationResult{
		Valid:        true,
		Reason:       "valid",
		LeadingZeros: leadingZeros,
		ComputeTime:  computeTime,
	}
}

// ValidateOffline checks a solution using the nonce cache instead of timestamps.
// This is the NTP-drift-immune validation path for Blackout scenarios.
//
// Steps:
//  1. Check challenge HMAC (not tampered)
//  2. Check nonce in cache (replaces timestamp check)
//  3. Check solver public key (not banned)
//  4. Check rate limit (not flooding)
//  5. Verify Ed25519 signature (solver owns the key)
//  6. Recompute Argon2id and check leading zero bits
func (v *Validator) ValidateOffline(challenge *Challenge, solution *Solution) ValidationResult {
	start := time.Now()

	// Step 1: Verify challenge HMAC
	mac := hmac.New(sha256.New, v.hmacSecret)
	mac.Write(challenge.Payload())
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(expectedMAC, challenge.MAC[:]) {
		return ValidationResult{Valid: false, Reason: "invalid challenge HMAC — possible tampering"}
	}

	// Step 2: Check nonce in cache (NTP-independent)
	if v.nonceCache != nil {
		if err := v.nonceCache.Validate(challenge.Nonce, challenge.Difficulty); err != nil {
			return ValidationResult{Valid: false, Reason: fmt.Sprintf("nonce check failed: %v", err)}
		}
	}

	// Step 3: Check ban list
	v.banMu.RLock()
	_, banned := v.banList[solution.SolverPubKey]
	v.banMu.RUnlock()
	if banned {
		return ValidationResult{Valid: false, Reason: "solver public key is banned"}
	}

	// Step 4: Rate limiting
	if !v.checkRateLimit(solution.SolverPubKey) {
		return ValidationResult{Valid: false, Reason: fmt.Sprintf(
			"rate limit exceeded: max %d solutions/min per pubkey",
			v.MaxSolutionsPerMinute,
		)}
	}

	// Step 5: Verify Ed25519 signature
	payload := challenge.Payload()
	signData := make([]byte, len(payload)+32)
	copy(signData, payload)
	copy(signData[len(payload):], solution.SolutionNonce[:])

	pubKey := ed25519.PublicKey(solution.SolverPubKey[:])
	if !ed25519.Verify(pubKey, signData, solution.Signature[:]) {
		return ValidationResult{Valid: false, Reason: "invalid Ed25519 signature"}
	}

	// Step 6: Recompute Argon2id and verify
	input := make([]byte, len(payload)+32)
	copy(input, payload)
	copy(input[len(payload):], solution.SolutionNonce[:])

	salt := challenge.Nonce[:]
	hash := argon2.IDKey(input, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	leadingZeros := countLeadingZeroBits(hash)
	computeTime := time.Since(start)

	if leadingZeros < int(challenge.Difficulty) {
		return ValidationResult{
			Valid:        false,
			Reason:       fmt.Sprintf("insufficient leading zeros: got %d, need %d", leadingZeros, challenge.Difficulty),
			LeadingZeros: leadingZeros,
			ComputeTime:  computeTime,
		}
	}

	v.log.Info("PoW validated (offline mode)",
		"solver", fmt.Sprintf("%x", solution.SolverPubKey[:8]),
		"leading_zeros", leadingZeros,
		"compute_time", computeTime,
	)

	v.recordSolution(solution.SolverPubKey)

	return ValidationResult{
		Valid:        true,
		Reason:       "valid (offline)",
		LeadingZeros: leadingZeros,
		ComputeTime:  computeTime,
	}
}

// Ban adds a public key to the ban list.
func (v *Validator) Ban(pubKey [32]byte) {
	v.banMu.Lock()
	defer v.banMu.Unlock()
	v.banList[pubKey] = struct{}{}
	v.log.Warn("banned node", "pubkey", fmt.Sprintf("%x", pubKey[:8]))
}

// Unban removes a public key from the ban list.
func (v *Validator) Unban(pubKey [32]byte) {
	v.banMu.Lock()
	defer v.banMu.Unlock()
	delete(v.banList, pubKey)
}

// AdaptiveDifficulty computes the difficulty based on network load.
// When the network is under attack (many join requests), difficulty increases.
// When the network is quiet, difficulty decreases to ease legitimate joins.
func (v *Validator) AdaptiveDifficulty(recentJoinAttempts int, windowDuration time.Duration) uint8 {
	rate := float64(recentJoinAttempts) / windowDuration.Seconds()

	switch {
	case rate > 100: // Heavy attack: >100 joins/sec
		return 24
	case rate > 10: // Moderate load
		return 20
	case rate > 1: // Normal operation
		return 16
	default: // Quiet network
		return 12
	}
}

// --- Rate limiting internals ---

func (v *Validator) checkRateLimit(pubKey [32]byte) bool {
	v.rlMu.Lock()
	defer v.rlMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	// Clean old entries for this pubkey
	times := v.rateLimiter[pubKey]
	var recent []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	// Remove the key entirely if no recent activity (prevents map growth)
	if len(recent) == 0 {
		delete(v.rateLimiter, pubKey)
	} else {
		v.rateLimiter[pubKey] = recent
	}

	return len(recent) < v.MaxSolutionsPerMinute
}

func (v *Validator) recordSolution(pubKey [32]byte) {
	v.rlMu.Lock()
	defer v.rlMu.Unlock()
	v.rateLimiter[pubKey] = append(v.rateLimiter[pubKey], time.Now())
}

// CleanupRateLimiter removes stale entries from the rate limiter map.
// Should be called periodically (e.g., every 5 minutes) to prevent
// unbounded memory growth from many unique pubkeys.
// Returns the number of entries removed.
func (v *Validator) CleanupRateLimiter() int {
	v.rlMu.Lock()
	defer v.rlMu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	removed := 0

	for pubKey, times := range v.rateLimiter {
		// If the most recent entry is older than the cutoff, remove entirely
		if len(times) == 0 {
			delete(v.rateLimiter, pubKey)
			removed++
			continue
		}
		latestTime := times[len(times)-1]
		if latestTime.Before(cutoff) {
			delete(v.rateLimiter, pubKey)
			removed++
		}
	}

	return removed
}
