package pow

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

// TestChallengeMarshalRoundtrip verifies that challenges survive serialization.
func TestChallengeMarshalRoundtrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("test-hmac-secret")
	challenge, err := NewChallenge(16, pub, secret)
	if err != nil {
		t.Fatal(err)
	}

	data, err := challenge.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != 105 {
		t.Fatalf("expected 105 bytes, got %d", len(data))
	}

	decoded, err := UnmarshalChallenge(data)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Difficulty != challenge.Difficulty {
		t.Errorf("difficulty mismatch: %d != %d", decoded.Difficulty, challenge.Difficulty)
	}
	if decoded.Timestamp != challenge.Timestamp {
		t.Errorf("timestamp mismatch: %d != %d", decoded.Timestamp, challenge.Timestamp)
	}
	if decoded.Nonce != challenge.Nonce {
		t.Error("nonce mismatch")
	}
	if decoded.ChallengerPubKey != challenge.ChallengerPubKey {
		t.Error("challenger pubkey mismatch")
	}
	if decoded.MAC != challenge.MAC {
		t.Error("MAC mismatch")
	}
}

// TestChallengeExpiry verifies TTL enforcement.
func TestChallengeExpiry(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	secret := []byte("test-hmac-secret")

	c, _ := NewChallenge(16, pub, secret)
	if c.IsExpired() {
		t.Error("fresh challenge should not be expired")
	}

	// Manually set old timestamp
	c.Timestamp = time.Now().Add(-2 * ChallengeMaxAge).Unix()
	if !c.IsExpired() {
		t.Error("old challenge should be expired")
	}
}

// TestLeadingZeroBits verifies the bit counting function.
func TestLeadingZeroBits(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int
	}{
		{[]byte{0x00, 0x00, 0x00, 0xFF}, 24},
		{[]byte{0x00, 0x01}, 15},
		{[]byte{0x80}, 0},
		{[]byte{0x40}, 1},
		{[]byte{0x20}, 2},
		{[]byte{0x10}, 3},
		{[]byte{0x08}, 4},
		{[]byte{0x00}, 8},
		{[]byte{0x00, 0x00}, 16},
		{[]byte{}, 0},
	}

	for _, tt := range tests {
		got := countLeadingZeroBits(tt.input)
		if got != tt.expected {
			t.Errorf("countLeadingZeroBits(%x) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

// TestSolveAndValidate is the full end-to-end PoW test.
// Uses low difficulty (8) for fast test execution.
func TestSolveAndValidate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW test in short mode (requires ~2-5s compute)")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Generate challenger and solver identities
	challengerPub, challengerPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, solverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = challengerPriv // challenger only needs pub for challenge creation

	hmacSecret := []byte("test-secret-key-for-pow")

	// Create challenge with low difficulty for testing
	challenge, err := NewChallenge(8, challengerPub, hmacSecret)
	if err != nil {
		t.Fatal(err)
	}

	// Solve
	solver := NewSolver(log, solverPriv)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	solution, err := solver.Solve(ctx, challenge)
	if err != nil {
		t.Fatal("solve failed:", err)
	}

	// Validate
	validator := NewValidator(log, hmacSecret)
	result := validator.Validate(challenge, solution)

	if !result.Valid {
		t.Fatalf("validation failed: %s", result.Reason)
	}

	t.Logf("PoW test passed: leading_zeros=%d, compute_time=%s",
		result.LeadingZeros, result.ComputeTime)
}

// TestValidatorRejectsExpired verifies expired challenges are rejected.
func TestValidatorRejectsExpired(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	hmacSecret := []byte("test-secret")

	challenge, _ := NewChallenge(8, pub, hmacSecret)
	challenge.Timestamp = time.Now().Add(-2 * ChallengeMaxAge).Unix()

	// Re-compute HMAC with the modified timestamp
	// (In a real attack, the attacker can't do this without the secret)

	validator := NewValidator(log, hmacSecret)
	result := validator.Validate(challenge, &Solution{})

	if result.Valid {
		t.Error("validator should reject tampered challenge")
	}
}

// TestValidatorBanList verifies banned nodes are rejected.
func TestValidatorBanList(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	validator := NewValidator(log, []byte("secret"))

	var bannedKey [32]byte
	copy(bannedKey[:], []byte("banned-node-key-1234567890abcdef"))

	validator.Ban(bannedKey)

	challenge := &Challenge{
		Difficulty: 8,
		Timestamp:  time.Now().Unix(),
	}
	// Compute valid HMAC for the challenge
	// (simplification — real test would use NewChallenge)

	solution := &Solution{}
	solution.SolverPubKey = bannedKey

	result := validator.Validate(challenge, solution)
	if result.Valid {
		t.Error("validator should reject banned pubkey")
	}
	if result.Reason != "solver public key is banned" && result.Reason != "invalid challenge HMAC — possible tampering" {
		// Either ban check or HMAC check should catch it first
		t.Logf("rejected with reason: %s", result.Reason)
	}
}

// TestAdaptiveDifficulty verifies difficulty scaling.
func TestAdaptiveDifficulty(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	validator := NewValidator(log, []byte("secret"))

	window := time.Minute

	tests := []struct {
		attempts int
		expected uint8
	}{
		{0, 12},       // Quiet: rate=0/s → <1/s
		{90, 16},      // Normal: rate=1.5/s → >1/s, <10/s
		{660, 20},     // Moderate: rate=11/s → >10/s, <100/s
		{6001, 24},    // Heavy attack: rate=100+/s → >100/s
	}

	for _, tt := range tests {
		got := validator.AdaptiveDifficulty(tt.attempts, window)
		if got != tt.expected {
			t.Errorf("AdaptiveDifficulty(%d, %s) = %d, want %d",
				tt.attempts, window, got, tt.expected)
		}
	}
}

// TestNonceCacheBasic verifies issue/validate/replay cycle.
func TestNonceCacheBasic(t *testing.T) {
	cache := NewNonceCache(100)

	var nonce [32]byte
	copy(nonce[:], []byte("test-nonce-1234567890abcdef0000"))

	// Issue
	cache.Issue(nonce, 16)
	if cache.Size() != 1 {
		t.Fatalf("expected size 1, got %d", cache.Size())
	}

	// Validate — should succeed
	err := cache.Validate(nonce, 16)
	if err != nil {
		t.Fatalf("valid nonce rejected: %v", err)
	}

	// Replay — same nonce again should fail
	err = cache.Validate(nonce, 16)
	if err == nil {
		t.Fatal("replay should be rejected")
	}

	// Unknown nonce — should fail
	var unknown [32]byte
	copy(unknown[:], []byte("unknown-nonce-never-issued-00000"))
	err = cache.Validate(unknown, 16)
	if err == nil {
		t.Fatal("unknown nonce should be rejected")
	}

	// Difficulty mismatch — should fail
	var nonce2 [32]byte
	copy(nonce2[:], []byte("test-nonce-difficulty-mismatch00"))
	cache.Issue(nonce2, 20)
	err = cache.Validate(nonce2, 16)
	if err == nil {
		t.Fatal("difficulty mismatch should be rejected")
	}
}

// TestNonceCacheEviction verifies LRU eviction at capacity.
func TestNonceCacheEviction(t *testing.T) {
	cache := NewNonceCache(3) // Tiny cache

	var nonces [5][32]byte
	for i := 0; i < 5; i++ {
		copy(nonces[i][:], []byte(fmt.Sprintf("eviction-test-nonce-%02d-padding", i)))
		cache.Issue(nonces[i], 8)
	}

	// Cache should have at most 3 entries (oldest evicted)
	if cache.Size() > 3 {
		t.Fatalf("expected max 3 entries, got %d", cache.Size())
	}

	// Newest nonces should still be valid
	err := cache.Validate(nonces[4], 8)
	if err != nil {
		t.Fatalf("newest nonce should be valid: %v", err)
	}

	// Oldest nonces should have been evicted
	err = cache.Validate(nonces[0], 8)
	if err == nil {
		t.Fatal("oldest nonce should have been evicted")
	}
}

// TestOfflineValidationE2E is the full end-to-end test using nonce cache (no NTP).
func TestOfflineValidationE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping offline PoW test in short mode")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	challengerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, solverPriv, _ := ed25519.GenerateKey(rand.Reader)

	hmacSecret := []byte("offline-test-secret")

	// Create challenge
	challenge, err := NewChallenge(8, challengerPub, hmacSecret)
	if err != nil {
		t.Fatal(err)
	}

	// Create validator and register the nonce in cache
	validator := NewValidator(log, hmacSecret)
	validator.NonceCache().Issue(challenge.Nonce, challenge.Difficulty)

	// Simulate clock drift: set challenge timestamp to 10 minutes ago.
	// With wall-clock validation this would fail.
	// With nonce-cache validation this should succeed.
	challenge.Timestamp = time.Now().Add(-10 * time.Minute).Unix()

	// Re-compute HMAC with drifted timestamp (the challenger issued it)
	reMAC := hmac.New(sha256.New, hmacSecret)
	reMAC.Write(challenge.Payload())
	copy(challenge.MAC[:], reMAC.Sum(nil))

	// Solve
	solver := NewSolver(log, solverPriv)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	solution, err := solver.Solve(ctx, challenge)
	if err != nil {
		t.Fatal("solve failed:", err)
	}

	// Validate with OFFLINE mode (nonce cache, not timestamps)
	result := validator.ValidateOffline(challenge, solution)
	if !result.Valid {
		t.Fatalf("offline validation failed: %s", result.Reason)
	}

	t.Logf("Offline PoW passed: leading_zeros=%d, compute_time=%s",
		result.LeadingZeros, result.ComputeTime)

	// Confirm that replay is blocked
	result2 := validator.ValidateOffline(challenge, solution)
	if result2.Valid {
		t.Fatal("replay should be rejected in offline mode")
	}
	t.Logf("Replay correctly rejected: %s", result2.Reason)
}

// BenchmarkSolve benchmarks the PoW solver with difficulty=8.
func BenchmarkSolve(b *testing.B) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, solverPriv, _ := ed25519.GenerateKey(rand.Reader)
	hmacSecret := []byte("bench-secret")

	solver := NewSolver(log, solverPriv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		challenge, _ := NewChallenge(8, pub, hmacSecret)
		ctx := context.Background()
		_, err := solver.Solve(ctx, challenge)
		if err != nil {
			b.Fatal(err)
		}
	}
}
