package pow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/argon2"
)

// Solver finds a solution nonce that satisfies the PoW challenge.
type Solver struct {
	log     *slog.Logger
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

// NewSolver creates a new PoW solver with the given Ed25519 identity.
func NewSolver(log *slog.Logger, privKey ed25519.PrivateKey) *Solver {
	return &Solver{
		log:     log,
		privKey: privKey,
		pubKey:  privKey.Public().(ed25519.PublicKey),
	}
}

// Solve attempts to find a solution nonce for the given challenge.
//
// Algorithm:
//   1. Generate random candidate nonce
//   2. Compute: hash = Argon2id(challenge_payload || candidate_nonce)
//   3. Check: leading_zero_bits(hash) >= challenge.Difficulty
//   4. If yes → sign and return solution
//   5. If no → increment nonce and retry
//
// The Argon2id computation is the bottleneck (~1-2 seconds per attempt).
// With difficulty=20, the expected number of attempts is ~1 (since each
// Argon2id hash is essentially random, and 2^20 / 2^256 = negligible).
// The difficulty primarily controls the cost of EACH verification.
//
// For anti-Sybil purposes, even difficulty=1 is effective because the
// memory-hard Argon2id computation takes ~2s regardless.
func (s *Solver) Solve(ctx context.Context, challenge *Challenge) (*Solution, error) {
	// Note: we do NOT reject expired challenges here.
	// TTL enforcement is the validator's responsibility.
	// In offline/Blackout mode, timestamps may be wildly wrong due to NTP drift,
	// but the server-side nonce cache handles validity instead.
	if challenge.IsExpired() {
		s.log.Warn("challenge timestamp appears expired (may be NTP drift)",
			"timestamp", challenge.Timestamp,
		)
	}

	payload := challenge.Payload()
	startTime := time.Now()

	s.log.Info("starting PoW solve",
		"difficulty", challenge.Difficulty,
		"nonce_prefix", fmt.Sprintf("%x", challenge.Nonce[:4]),
	)

	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("solve cancelled after %d attempts: %w", attempt, ctx.Err())
		default:
		}

		attempt++

		// Generate random candidate nonce
		var candidateNonce [32]byte
		if _, err := rand.Read(candidateNonce[:]); err != nil {
			return nil, fmt.Errorf("generate candidate nonce: %w", err)
		}

		// Build input: challenge_payload || candidate_nonce
		input := make([]byte, len(payload)+32)
		copy(input, payload)
		copy(input[len(payload):], candidateNonce[:])

		// Compute Argon2id hash
		// Salt is derived from the challenge nonce for domain separation
		salt := challenge.Nonce[:]
		hash := argon2.IDKey(input, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

		// Check leading zero bits
		zeros := countLeadingZeroBits(hash)
		if zeros >= int(challenge.Difficulty) {
			elapsed := time.Since(startTime)

			s.log.Info("PoW solved",
				"attempts", attempt,
				"duration", elapsed,
				"leading_zeros", zeros,
				"hash_prefix", fmt.Sprintf("%x", hash[:8]),
			)

			// Build solution
			sol := &Solution{}
			copy(sol.SolutionNonce[:], candidateNonce[:])
			copy(sol.SolverPubKey[:], s.pubKey)

			// Sign: Ed25519(privkey, payload || solution_nonce)
			signData := make([]byte, len(payload)+32)
			copy(signData, payload)
			copy(signData[len(payload):], candidateNonce[:])
			sig := ed25519.Sign(s.privKey, signData)
			copy(sol.Signature[:], sig)

			return sol, nil
		}

		if attempt%10 == 0 {
			s.log.Debug("PoW progress",
				"attempts", attempt,
				"elapsed", time.Since(startTime),
				"best_zeros", zeros,
			)
		}
	}
}
