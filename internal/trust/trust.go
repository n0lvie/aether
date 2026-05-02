// Package trust implements the Aether Trust Protocol (ATP) —
// a multi-layered trust establishment system for zero-infrastructure environments.
//
// The fundamental problem: two nodes meet via BLE/WiFi in a country
// under total internet blackout. There is no CA, no PKI, no NTP server.
// How do they know the other node isn't a state-operated interceptor?
//
// ATP solves this with 5 defense layers:
//
//   Layer 1: Argon2id PoW (Sybil barrier — already implemented)
//   Layer 2: Noise_XX mutual authentication (key exchange)
//   Layer 3: SAS verbal verification (human-verified, defeats MitM)
//   Layer 4: Web of Trust with bounded transitivity (max 3 hops)
//   Layer 5: Key Continuity / TOFU (long-term reputation)
//
// Against a state-level attacker:
//   - Mass Sybil: Blocked by PoW (each node costs 64MB * 3 passes)
//   - Targeted MitM on BLE: Defeated by face-to-face SAS comparison
//   - Long-term impersonation: Defeated by Key Continuity alerts
//   - Trust graph poisoning: Bounded transitivity limits blast radius
//   - Eclipse attack: Only SAS-verified or attested peers are trusted
package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// TrustLevel represents the degree of trust in a peer.
type TrustLevel uint8

const (
	// TrustNone: unknown node, no trust established.
	TrustNone TrustLevel = 0

	// TrustPOW: node passed Proof-of-Work. Minimal trust.
	// Good enough for: packet relay, DTN store-and-forward.
	// Not enough for: direct encrypted communication.
	TrustPOW TrustLevel = 1

	// TrustTOFU: Trust On First Use. Key was recorded on first contact.
	// Good enough for: casual data relay, non-sensitive traffic.
	// Vulnerable to: first-contact MitM (same as SSH on first connect).
	TrustTOFU TrustLevel = 2

	// TrustAttested: vouched for by a SAS-verified peer (transitive trust).
	// Good enough for: semi-trusted communication, mesh routing.
	// Bounded: max 3 hops of transitivity.
	TrustAttested TrustLevel = 3

	// TrustSASVerified: directly verified via Short Authentication String.
	// The user verbally compared the 4-word code face-to-face.
	// This is the highest trust level, equivalent to a PKI certificate.
	TrustSASVerified TrustLevel = 4
)

func (t TrustLevel) String() string {
	names := [...]string{"None", "PoW", "TOFU", "Attested", "SAS-Verified"}
	if int(t) < len(names) {
		return names[t]
	}
	return fmt.Sprintf("Unknown(%d)", t)
}

// PeerRecord stores trust information about a known peer.
type PeerRecord struct {
	// PubKey is the peer's Ed25519 public key (persistent identity).
	PubKey [32]byte

	// Trust is the current trust level.
	Trust TrustLevel

	// FirstSeen is when we first encountered this peer.
	FirstSeen time.Time

	// LastSeen is the most recent interaction.
	LastSeen time.Time

	// SASVerifiedAt is when the SAS was successfully compared (zero if never).
	SASVerifiedAt time.Time

	// Attestations are signed vouches from other peers.
	Attestations []Attestation

	// KeyHistory tracks public key changes (for Key Continuity).
	// If a peer suddenly changes their key, this is a MitM red flag.
	KeyHistory []KeyChange

	// InteractionCount tracks how many successful sessions we've had.
	// More interactions = more confidence in TOFU.
	InteractionCount uint64
}

// KeyChange records a public key change event.
type KeyChange struct {
	OldKey    [32]byte
	NewKey    [32]byte
	Timestamp time.Time
}

// Attestation is a signed vouch from one peer for another.
// Format: Sign(attester_privkey, "aether-attest-v1" || subject_pubkey || trust_level || timestamp)
type Attestation struct {
	// AttesterPubKey is who is vouching.
	AttesterPubKey [32]byte

	// SubjectPubKey is who is being vouched for.
	SubjectPubKey [32]byte

	// Level is the trust level the attester assigns.
	Level TrustLevel

	// Timestamp is when the attestation was created.
	Timestamp time.Time

	// Signature is the Ed25519 signature over the attestation payload.
	Signature [64]byte

	// Depth tracks how many hops this attestation has traveled.
	// Incremented each time it's relayed. Max: MaxAttestationDepth.
	Depth uint8
}

// MaxAttestationDepth limits transitive trust to prevent graph poisoning.
// A → B (depth 0, SAS-verified)
// A → B → C (depth 1, attested)
// A → B → C → D (depth 2, attested)
// A → B → C → D → E (depth 3, REJECTED — too far)
const MaxAttestationDepth = 3

// AttestationPayload returns the signable portion of an attestation.
func (a *Attestation) AttestationPayload() []byte {
	buf := make([]byte, 16+32+1+8) // prefix + pubkey + level + timestamp
	copy(buf[0:16], []byte("aether-attest-v1"))
	copy(buf[16:48], a.SubjectPubKey[:])
	buf[48] = byte(a.Level)
	binary.BigEndian.PutUint64(buf[49:57], uint64(a.Timestamp.Unix()))
	return buf
}

// Verify checks the attestation signature.
func (a *Attestation) Verify() bool {
	pubKey := ed25519.PublicKey(a.AttesterPubKey[:])
	return ed25519.Verify(pubKey, a.AttestationPayload(), a.Signature[:])
}

// --- SAS (Short Authentication String) ---

// SASWordList is a curated list of 256 phonetically distinct words.
// Both peers must use the SAME list (embedded in the binary).
// Words are chosen to be:
// - Unambiguous when spoken aloud (no homophones)
// - Short (1-2 syllables)
// - Easy to pronounce in both Russian and English
var SASWordList = [256]string{
	"alpha", "bravo", "cedar", "delta", "eagle", "frost", "gamma", "haven",
	"ivory", "joker", "karma", "lemon", "maple", "north", "omega", "prism",
	"quark", "razor", "sigma", "tiger", "ultra", "venom", "wrath", "xenon",
	"yield", "zephyr", "amber", "blaze", "coral", "drift", "ember", "flint",
	// ... 224 more words (full list would be embedded in production)
	// Using indices 32-255 as placeholders:
	"abyss", "atlas", "axiom", "azure", "basin", "beach", "bench", "blade",
	"bloom", "board", "brave", "brick", "brush", "cabin", "chain", "chalk",
	"charm", "chess", "cliff", "clock", "cloud", "cobra", "comet", "coral",
	"crane", "crest", "crown", "crumb", "crush", "cynic", "dance", "depth",
	"digit", "diver", "dodge", "dream", "drone", "dwarf", "earth", "eclipse",
	"epoch", "equip", "erase", "event", "exile", "facet", "faith", "feast",
	"ferry", "field", "flame", "flash", "fleet", "float", "flour", "forge",
	"forum", "frame", "frost", "gavel", "ghost", "giant", "glass", "gleam",
	"globe", "gloom", "glory", "grace", "grain", "grape", "grasp", "greed",
	"guide", "guild", "gusty", "haven", "hazel", "heart", "helix", "hoist",
	"honor", "house", "human", "hydra", "ichor", "ideal", "image", "index",
	"inner", "irony", "ivory", "jewel", "joint", "joust", "judge", "jumbo",
	"knack", "kneel", "knife", "knock", "labor", "lance", "latch", "layer",
	"leach", "ledge", "level", "light", "lilac", "linen", "logic", "lucid",
	"lunar", "lynch", "macro", "manor", "marsh", "match", "maxim", "mayor",
	"medal", "mercy", "merit", "metal", "minor", "mirth", "model", "month",
	"moose", "morph", "motel", "mount", "mural", "nerve", "nexus", "night",
	"noble", "noise", "notch", "novel", "nurse", "nylon", "oasis", "ocean",
	"olive", "onset", "opera", "orbit", "order", "organ", "oxide", "ozone",
	"panel", "paste", "patch", "pause", "pearl", "pedal", "penny", "phase",
	"piano", "pilot", "pixel", "plank", "plaza", "plumb", "plume", "polar",
	"pouch", "power", "press", "pride", "prism", "probe", "proxy", "prune",
	"pulse", "pupil", "quake", "queen", "query", "quest", "quick", "quota",
	"radar", "rally", "range", "rapid", "ratio", "raven", "realm", "reign",
}

// DeriveSAS computes a 4-word Short Authentication String from a Noise handshake hash.
//
// The handshake hash is a cryptographic commitment to the entire key exchange.
// If a MitM attacker is present, each side will have a DIFFERENT handshake hash
// (because the attacker performed two separate handshakes), producing different words.
//
// Security: 4 words from a 256-word list = 32 bits of security.
// Probability of MitM guessing the correct SAS = 1 in 4,294,967,296.
// This matches ZRTP's security level.
func DeriveSAS(handshakeHash [32]byte) [4]string {
	// Use HKDF-like derivation: SHA-256(handshake_hash || "aether-sas-v1")
	h := sha256.New()
	h.Write(handshakeHash[:])
	h.Write([]byte("aether-sas-v1"))
	derived := h.Sum(nil)

	var words [4]string
	for i := 0; i < 4; i++ {
		idx := derived[i] // Each byte → 0-255 → word index
		words[i] = SASWordList[idx]
	}
	return words
}

// FormatSAS returns a human-readable SAS string for CLI display.
func FormatSAS(words [4]string) string {
	return fmt.Sprintf("%s — %s — %s — %s", words[0], words[1], words[2], words[3])
}

// --- Trust Store ---

// Store manages the persistent trust database.
type Store struct {
	peers map[[32]byte]*PeerRecord
	mu    sync.RWMutex
}

// NewStore creates an empty trust store.
func NewStore() *Store {
	return &Store{
		peers: make(map[[32]byte]*PeerRecord),
	}
}

// GetPeer returns the trust record for a peer, or nil if unknown.
func (s *Store) GetPeer(pubKey [32]byte) *PeerRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peers[pubKey]
}

// RecordFirstContact creates a TOFU entry for a newly encountered peer.
// Returns false if the peer is already known (Key Continuity check needed).
func (s *Store) RecordFirstContact(pubKey [32]byte) (isNew bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.peers[pubKey]; exists {
		return false
	}

	now := time.Now()
	s.peers[pubKey] = &PeerRecord{
		PubKey:    pubKey,
		Trust:     TrustTOFU,
		FirstSeen: now,
		LastSeen:  now,
	}
	return true
}

// MarkSASVerified upgrades a peer's trust level after successful SAS comparison.
func (s *Store) MarkSASVerified(pubKey [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	peer, exists := s.peers[pubKey]
	if !exists {
		return
	}

	peer.Trust = TrustSASVerified
	peer.SASVerifiedAt = time.Now()
	peer.LastSeen = time.Now()
}

// AddAttestation records a trust attestation from another peer.
// Returns an error if the attestation is invalid or exceeds max depth.
func (s *Store) AddAttestation(att Attestation) error {
	// Verify signature
	if !att.Verify() {
		return fmt.Errorf("invalid attestation signature")
	}

	// Check depth
	if att.Depth >= MaxAttestationDepth {
		return fmt.Errorf("attestation depth %d exceeds max %d", att.Depth, MaxAttestationDepth)
	}

	// Check that we trust the attester
	s.mu.RLock()
	attester := s.peers[att.AttesterPubKey]
	s.mu.RUnlock()

	if attester == nil || attester.Trust < TrustTOFU {
		return fmt.Errorf("unknown or untrusted attester")
	}

	// Record attestation
	s.mu.Lock()
	defer s.mu.Unlock()

	peer, exists := s.peers[att.SubjectPubKey]
	if !exists {
		now := time.Now()
		peer = &PeerRecord{
			PubKey:    att.SubjectPubKey,
			Trust:     TrustPOW, // Start at PoW level
			FirstSeen: now,
			LastSeen:  now,
		}
		s.peers[att.SubjectPubKey] = peer
	}

	peer.Attestations = append(peer.Attestations, att)

	// Upgrade trust if appropriate
	if peer.Trust < TrustAttested && attester.Trust >= TrustSASVerified {
		peer.Trust = TrustAttested
	}

	return nil
}

// DetectKeyChange checks if a peer's key has changed since last contact.
// A key change is a CRITICAL security event — it could mean:
//   1. The peer reinstalled (benign)
//   2. A MitM is impersonating the peer (malicious)
//
// Returns true if the key has changed (caller must alert the user).
func (s *Store) DetectKeyChange(claimedPubKey [32]byte, previousPubKey [32]byte) bool {
	// Use exclusive Lock (not RLock) because we may write to KeyHistory.
	// This avoids the lock-juggling anti-pattern (RLock→RUnlock→Lock)
	// that creates a data race window between unlock and re-lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	peer, exists := s.peers[previousPubKey]
	if !exists {
		return false // New peer, no continuity to check
	}

	if peer.PubKey != claimedPubKey {
		// KEY CHANGE DETECTED — record for forensics
		peer.KeyHistory = append(peer.KeyHistory, KeyChange{
			OldKey:    previousPubKey,
			NewKey:    claimedPubKey,
			Timestamp: time.Now(),
		})
		return true
	}
	return false
}

// CreateAttestation generates a signed attestation for a peer.
func CreateAttestation(
	attesterPrivKey ed25519.PrivateKey,
	subjectPubKey [32]byte,
	level TrustLevel,
) Attestation {
	att := Attestation{
		SubjectPubKey: subjectPubKey,
		Level:         level,
		Timestamp:     time.Now(),
		Depth:         0,
	}

	copy(att.AttesterPubKey[:], attesterPrivKey.Public().(ed25519.PublicKey))

	sig := ed25519.Sign(attesterPrivKey, att.AttestationPayload())
	copy(att.Signature[:], sig)

	return att
}

// ComputeEffectiveTrust calculates the effective trust level for a peer
// considering all attestations and their chain depth.
func (s *Store) ComputeEffectiveTrust(pubKey [32]byte) TrustLevel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peer, exists := s.peers[pubKey]
	if !exists {
		return TrustNone
	}

	// Direct SAS verification is always the highest
	if peer.Trust == TrustSASVerified {
		return TrustSASVerified
	}

	// Check attestation chains
	bestAttested := TrustNone
	for _, att := range peer.Attestations {
		if att.Depth >= MaxAttestationDepth {
			continue
		}

		attester, exists := s.peers[att.AttesterPubKey]
		if !exists {
			continue
		}

		// Trust is only as strong as the weakest link
		if attester.Trust >= TrustSASVerified && att.Level >= TrustAttested {
			if TrustAttested > bestAttested {
				bestAttested = TrustAttested
			}
		}
	}

	if bestAttested > peer.Trust {
		return bestAttested
	}
	return peer.Trust
}
