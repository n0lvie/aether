// Package crypto - Noise Protocol Framework integration.
//
// We use Noise_XX pattern with X25519 + ChaCha20-Poly1305 + SHA-256,
// matching WireGuard's cryptographic choices. The XX pattern provides
// mutual authentication and is suitable for our use case where peers
// may not know each other's static keys in advance.
//
// Future: Kyber-768 hybrid for post-quantum resistance can be added
// by extending the Noise handshake with a KEM encapsulation step.
package crypto

// NoisePattern defines the Noise handshake pattern.
const NoisePattern = "Noise_XX_25519_ChaChaPoly_SHA256"

// NoiseConfig holds parameters for Noise protocol sessions.
type NoiseConfig struct {
	// StaticKeypair is the node's long-term X25519 keypair.
	// Derived deterministically from the Ed25519 identity.
	StaticPrivateKey [32]byte
	StaticPublicKey  [32]byte

	// Prologue is bound into the handshake hash.
	// We use "aether-v1" to domain-separate our protocol.
	Prologue []byte
}

// HandshakeState tracks the state of an in-progress Noise handshake.
type HandshakeState struct {
	Config    NoiseConfig
	Initiator bool

	// Internal state — populated by the Noise library.
	// These fields are placeholders for the actual flynn/noise integration.
	localEphemeral  [32]byte
	remoteEphemeral [32]byte
	remoteStatic    [32]byte
	handshakeHash   [32]byte
	chainKey        [32]byte
	msgIndex        int
}

// CipherState represents the symmetric encryption state after handshake completion.
// Each direction (send/receive) gets its own CipherState with independent nonce counters.
type CipherState struct {
	Key     [32]byte // ChaCha20-Poly1305 key
	Nonce   uint64   // Monotonic counter
}

// SessionKeys holds the split cipher states after handshake completion.
type SessionKeys struct {
	Send    CipherState
	Receive CipherState
	// HandshakeHash can be used for channel binding / session ID derivation
	HandshakeHash [32]byte
}

// NewNoiseConfig creates a Noise configuration from an Ed25519 identity.
// The X25519 static key is derived from the Ed25519 seed using a KDF,
// so a single identity keypair serves both signing and key agreement.
func NewNoiseConfig(identity *Identity) *NoiseConfig {
	cfg := &NoiseConfig{
		Prologue: []byte("aether-v1"),
	}

	// Derive X25519 key from Ed25519 seed.
	// Ed25519 private key = 32-byte seed || 32-byte public key.
	// We use the seed directly with SHA-512 clamping for X25519.
	seed := identity.PrivateKey.Seed()
	copy(cfg.StaticPrivateKey[:], seed)

	// Clamp for X25519 (RFC 7748)
	cfg.StaticPrivateKey[0] &= 248
	cfg.StaticPrivateKey[31] &= 127
	cfg.StaticPrivateKey[31] |= 64

	// TODO: Compute X25519 public key from clamped private key
	// For now, this is a placeholder — real implementation uses
	// curve25519.ScalarBaseMult or the noise library's keypair functions.

	return cfg
}

// NewHandshake initiates a Noise_XX handshake.
func NewHandshake(config *NoiseConfig, initiator bool) *HandshakeState {
	return &HandshakeState{
		Config:    *config,
		Initiator: initiator,
		msgIndex:  0,
	}
}
