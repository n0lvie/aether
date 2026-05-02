// Package pow implements the Argon2id-based Proof-of-Work system for Sybil resistance.
//
// The PoW mechanism protects the Aether network from state-level DDoS attacks
// and fake node injection. Every node joining the network must solve a
// memory-hard computational puzzle, making it economically infeasible to
// spin up thousands of fake nodes.
//
// Protocol:
//   1. Challenger sends: nonce(32) || difficulty(1) || timestamp(8) || challenger_pubkey(32)
//   2. Solver finds solution_nonce such that:
//      Argon2id(challenge || solution_nonce) has `difficulty` leading zero bits
//   3. Solver returns: solution_nonce(32) || solver_pubkey(32) || signature(64)
//   4. Challenger verifies in O(1): recompute Argon2id and check zero bits
//
// The Argon2id parameters (time=3, memory=64MB, threads=4) are chosen so that:
// - A legitimate node solves the puzzle in ~2-5 seconds
// - GPU/ASIC parallelism provides minimal speedup (memory-hard)
// - Verification is a single Argon2id computation (~2-5 seconds)
package pow

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// Argon2 parameters — tuned for ~2-5 second solve time on modern CPUs.
const (
	Argon2Time    = 3         // Number of passes
	Argon2Memory  = 64 * 1024 // 64 MB in KiB
	Argon2Threads = 4         // Parallelism
	Argon2KeyLen  = 32        // Output hash length
)

// Challenge is the puzzle sent to a node requesting to join the network.
type Challenge struct {
	// Nonce is a random 32-byte value unique to this challenge.
	Nonce [32]byte

	// Difficulty is the number of leading zero bits required in the solution hash.
	// Higher values = harder puzzle. Typical range: 16-24.
	Difficulty uint8

	// Timestamp is when the challenge was created (Unix seconds).
	// Challenges expire after ChallengeMaxAge.
	Timestamp int64

	// ChallengerPubKey is the Ed25519 public key of the node issuing the challenge.
	ChallengerPubKey [32]byte

	// HMAC authenticates the challenge to prevent tampering.
	// HMAC-SHA256(secret, Nonce || Difficulty || Timestamp || ChallengerPubKey)
	MAC [32]byte
}

// ChallengeMaxAge is the maximum age of a valid challenge.
const ChallengeMaxAge = 60 * time.Second

// MarshalBinary encodes a Challenge to its wire format.
// Format: Nonce(32) || Difficulty(1) || Timestamp(8) || ChallengerPubKey(32) || MAC(32)
// Total: 105 bytes
func (c *Challenge) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 105)
	copy(buf[0:32], c.Nonce[:])
	buf[32] = c.Difficulty
	binary.BigEndian.PutUint64(buf[33:41], uint64(c.Timestamp))
	copy(buf[41:73], c.ChallengerPubKey[:])
	copy(buf[73:105], c.MAC[:])
	return buf, nil
}

// UnmarshalChallenge decodes a Challenge from wire format.
func UnmarshalChallenge(data []byte) (*Challenge, error) {
	if len(data) < 105 {
		return nil, fmt.Errorf("challenge too short: %d < 105", len(data))
	}
	c := &Challenge{
		Difficulty: data[32],
		Timestamp:  int64(binary.BigEndian.Uint64(data[33:41])),
	}
	copy(c.Nonce[:], data[0:32])
	copy(c.ChallengerPubKey[:], data[41:73])
	copy(c.MAC[:], data[73:105])
	return c, nil
}

// Payload returns the data portion of the challenge (without MAC).
// This is what gets signed/MAC'd.
func (c *Challenge) Payload() []byte {
	buf := make([]byte, 73)
	copy(buf[0:32], c.Nonce[:])
	buf[32] = c.Difficulty
	binary.BigEndian.PutUint64(buf[33:41], uint64(c.Timestamp))
	copy(buf[41:73], c.ChallengerPubKey[:])
	return buf
}

// IsExpired checks if the challenge has exceeded its TTL.
func (c *Challenge) IsExpired() bool {
	created := time.Unix(c.Timestamp, 0)
	return time.Since(created) > ChallengeMaxAge
}

// Solution is the proof returned by a node that solved the challenge.
type Solution struct {
	// SolutionNonce is the value found by the solver such that
	// Argon2id(challenge_payload || solution_nonce) has sufficient leading zeros.
	SolutionNonce [32]byte

	// SolverPubKey identifies the node that solved the challenge.
	SolverPubKey [32]byte

	// Signature is Ed25519(solver_privkey, challenge_payload || solution_nonce).
	// Proves the solver actually did the work (not replayed from another node).
	Signature [64]byte
}

// MarshalBinary encodes a Solution to wire format.
// Format: SolutionNonce(32) || SolverPubKey(32) || Signature(64)
// Total: 128 bytes
func (s *Solution) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 128)
	copy(buf[0:32], s.SolutionNonce[:])
	copy(buf[32:64], s.SolverPubKey[:])
	copy(buf[64:128], s.Signature[:])
	return buf, nil
}

// UnmarshalSolution decodes a Solution from wire format.
func UnmarshalSolution(data []byte) (*Solution, error) {
	if len(data) < 128 {
		return nil, fmt.Errorf("solution too short: %d < 128", len(data))
	}
	s := &Solution{}
	copy(s.SolutionNonce[:], data[0:32])
	copy(s.SolverPubKey[:], data[32:64])
	copy(s.Signature[:], data[64:128])
	return s, nil
}

// NewChallenge creates a new PoW challenge with the given difficulty.
// The hmacSecret is used to authenticate the challenge and prevent forgery.
func NewChallenge(difficulty uint8, challengerPubKey ed25519.PublicKey, hmacSecret []byte) (*Challenge, error) {
	c := &Challenge{
		Difficulty: difficulty,
		Timestamp:  time.Now().Unix(),
	}

	// Generate random nonce
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Copy challenger public key
	copy(c.ChallengerPubKey[:], challengerPubKey)

	// Compute HMAC
	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(c.Payload())
	copy(c.MAC[:], mac.Sum(nil))

	return c, nil
}

// countLeadingZeroBits counts the number of leading zero bits in a byte slice.
func countLeadingZeroBits(data []byte) int {
	zeros := 0
	for _, b := range data {
		if b == 0 {
			zeros += 8
			continue
		}
		// Count leading zeros in this byte
		for mask := byte(0x80); mask > 0; mask >>= 1 {
			if b&mask == 0 {
				zeros++
			} else {
				return zeros
			}
		}
	}
	return zeros
}
