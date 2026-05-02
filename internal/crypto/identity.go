// Package crypto provides cryptographic primitives for node identity,
// Noise protocol handshakes, and packet encryption.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Identity represents a node's cryptographic identity (Ed25519 keypair).
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// NodeID returns a short hex-encoded identifier derived from the public key.
// Used for logging and human-readable node identification.
func (id *Identity) NodeID() string {
	return hex.EncodeToString(id.PublicKey[:8])
}

// Sign signs a message with the node's private key.
func (id *Identity) Sign(message []byte) []byte {
	return ed25519.Sign(id.PrivateKey, message)
}

// Verify checks a signature against a public key.
func Verify(pubKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}

// GenerateIdentity creates a new random Ed25519 keypair.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// LoadOrCreateIdentity loads an identity from disk, or creates a new one
// if the file does not exist. This ensures the node has a stable identity
// across restarts — critical for Noise handshakes and PoW reputation.
func LoadOrCreateIdentity(stateDir string) (*Identity, error) {
	keyPath := filepath.Join(stateDir, "node.key")

	// Attempt to load existing key
	data, err := os.ReadFile(keyPath)
	if err == nil {
		return parseIdentity(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	// Generate new identity
	id, err := GenerateIdentity()
	if err != nil {
		return nil, err
	}

	// Persist to disk
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	// Store raw private key (64 bytes = 32 seed + 32 public)
	if err := os.WriteFile(keyPath, id.PrivateKey, 0600); err != nil {
		return nil, fmt.Errorf("write identity file: %w", err)
	}

	return id, nil
}

// parseIdentity reconstructs an Identity from a raw private key file.
func parseIdentity(data []byte) (*Identity, error) {
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key file: expected %d bytes, got %d",
			ed25519.PrivateKeySize, len(data))
	}
	priv := ed25519.PrivateKey(data)
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}
