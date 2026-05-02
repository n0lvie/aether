// Package crypto provides cryptographic primitives for node identity,
// Noise protocol handshakes, and packet encryption.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
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

const (
	scryptN      = 32768
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
)

// LoadOrCreateIdentity loads an identity from disk, or creates a new one
// if the file does not exist. This ensures the node has a stable identity
// across restarts — critical for Noise handshakes and PoW reputation.
func LoadOrCreateIdentity(stateDir string) (*Identity, error) {
	keyPath := filepath.Join(stateDir, "node.key")
	passphrase := os.Getenv("AETHER_KEY_PASS")

	// Attempt to load existing key
	data, err := os.ReadFile(keyPath)
	if err == nil {
		return parseIdentity(data, passphrase)
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

	// Encrypt if passphrase provided
	outData := []byte(id.PrivateKey)
	if passphrase != "" {
		outData, err = encryptKey(outData, passphrase)
		if err != nil {
			return nil, fmt.Errorf("encrypt key: %w", err)
		}
	}

	// Store raw private key (64 bytes = 32 seed + 32 public)
	if err := os.WriteFile(keyPath, outData, 0600); err != nil {
		return nil, fmt.Errorf("write identity file: %w", err)
	}

	return id, nil
}

// parseIdentity reconstructs an Identity from a raw private key file.
func parseIdentity(data []byte, passphrase string) (*Identity, error) {
	// If it has standard unencrypted length
	if len(data) == ed25519.PrivateKeySize {
		priv := ed25519.PrivateKey(data)
		pub := priv.Public().(ed25519.PublicKey)
		return &Identity{
			PrivateKey: priv,
			PublicKey:  pub,
		}, nil
	}

	// Try to decrypt
	if passphrase == "" {
		return nil, fmt.Errorf("encrypted key file found, but AETHER_KEY_PASS is not set")
	}

	decrypted, err := decryptKey(data, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt key: %w", err)
	}

	if len(decrypted) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid decrypted key length")
	}

	priv := ed25519.PrivateKey(decrypted)
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

func encryptKey(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

func decryptKey(data []byte, passphrase string) ([]byte, error) {
	if len(data) < saltLen {
		return nil, fmt.Errorf("data too short")
	}

	salt := data[:saltLen]
	ciphertextWithNonce := data[saltLen:]

	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertextWithNonce) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertextWithNonce[:gcm.NonceSize()]
	ciphertext := ciphertextWithNonce[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
