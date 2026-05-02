package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal("GenerateIdentity failed:", err)
	}

	if len(id.PrivateKey) != 64 {
		t.Errorf("expected 64-byte private key, got %d", len(id.PrivateKey))
	}
	if len(id.PublicKey) != 32 {
		t.Errorf("expected 32-byte public key, got %d", len(id.PublicKey))
	}

	// NodeID should be 16 hex chars (8 bytes encoded)
	nodeID := id.NodeID()
	if len(nodeID) != 16 {
		t.Errorf("expected 16-char NodeID, got %d: %s", len(nodeID), nodeID)
	}
}

func TestSignAndVerify(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("aether test message for signing")
	sig := id.Sign(message)

	if !Verify(id.PublicKey, message, sig) {
		t.Error("valid signature should verify")
	}

	// Tampered message should fail
	tampered := []byte("tampered message")
	if Verify(id.PublicKey, tampered, sig) {
		t.Error("tampered message should not verify")
	}

	// Tampered signature should fail
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	if Verify(id.PublicKey, message, badSig) {
		t.Error("tampered signature should not verify")
	}
}

func TestLoadOrCreateIdentity_NewKey(t *testing.T) {
	dir := t.TempDir()

	id, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal("LoadOrCreateIdentity failed:", err)
	}

	// Key file should exist
	keyPath := filepath.Join(dir, "node.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("key file not created")
	}

	// Reload should return the same identity
	id2, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal("reload failed:", err)
	}

	if !bytes.Equal(id.PublicKey, id2.PublicKey) {
		t.Error("reloaded identity has different public key")
	}
	if !bytes.Equal(id.PrivateKey, id2.PrivateKey) {
		t.Error("reloaded identity has different private key")
	}
}

func TestLoadOrCreateIdentity_CorruptedKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")

	// Write invalid key file (wrong size)
	os.WriteFile(keyPath, []byte("too-short"), 0600)

	_, err := LoadOrCreateIdentity(dir)
	if err == nil {
		t.Fatal("should fail on corrupted key file")
	}
}

func TestNoiseConfig(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	cfg := NewNoiseConfig(id)

	// Public key should NOT be all zeros (it was before the fix)
	allZeros := [32]byte{}
	if cfg.StaticPublicKey == allZeros {
		t.Error("X25519 public key should not be all zeros")
	}

	// Private key should be clamped per RFC 7748
	if cfg.StaticPrivateKey[0]&7 != 0 {
		t.Error("private key byte 0 not properly clamped (lower 3 bits should be 0)")
	}
	if cfg.StaticPrivateKey[31]&128 != 0 {
		t.Error("private key byte 31 not properly clamped (high bit should be 0)")
	}
	if cfg.StaticPrivateKey[31]&64 == 0 {
		t.Error("private key byte 31 not properly clamped (bit 6 should be 1)")
	}

	// Prologue should be set
	if string(cfg.Prologue) != "aether-v1" {
		t.Errorf("expected prologue 'aether-v1', got '%s'", cfg.Prologue)
	}

	// Deterministic: same identity should produce same config
	cfg2 := NewNoiseConfig(id)
	if cfg.StaticPublicKey != cfg2.StaticPublicKey {
		t.Error("X25519 key derivation should be deterministic")
	}
}

func TestHandshakeCreation(t *testing.T) {
	id, _ := GenerateIdentity()
	cfg := NewNoiseConfig(id)

	// Initiator
	hs := NewHandshake(cfg, true)
	if !hs.Initiator {
		t.Error("should be initiator")
	}
	if hs.msgIndex != 0 {
		t.Error("msgIndex should start at 0")
	}

	// Responder
	hs2 := NewHandshake(cfg, false)
	if hs2.Initiator {
		t.Error("should not be initiator")
	}
}

func TestEnvelopeMarshal(t *testing.T) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		t.Fatal(err)
	}

	env := &Envelope{
		Version:   0x01,
		SessionID: sessionID,
		Counter:   42,
		Payload:   []byte("test-payload-data"),
	}

	data, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Expected size: 1 + 16 + 8 + 4 + len(payload) + 16
	expectedSize := 1 + 16 + 8 + 4 + len(env.Payload) + 16
	if len(data) != expectedSize {
		t.Errorf("expected %d bytes, got %d", expectedSize, len(data))
	}

	// Version byte
	if data[0] != 0x01 {
		t.Errorf("expected version 0x01, got 0x%02x", data[0])
	}
}

func TestSeedNodeMarshalRoundtrip(t *testing.T) {
	seed := &SeedNode{
		Transport: TransportTCP,
		Port:      8443,
	}
	copy(seed.PubKey[:], bytes.Repeat([]byte{0xAB}, 32))
	seed.IP = []byte{192, 168, 1, 1}

	data, err := seed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := UnmarshalSeedNode(data, false)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.PubKey != seed.PubKey {
		t.Error("pubkey mismatch")
	}
	if decoded.Transport != seed.Transport {
		t.Error("transport mismatch")
	}
	if decoded.Port != seed.Port {
		t.Errorf("port mismatch: %d != %d", decoded.Port, seed.Port)
	}
	if !decoded.IP.Equal(seed.IP) {
		t.Errorf("IP mismatch: %s != %s", decoded.IP, seed.IP)
	}
}

func TestTransportIDString(t *testing.T) {
	tests := []struct {
		id       TransportID
		expected string
	}{
		{TransportTCP, "TCP"},
		{TransportQUIC, "QUIC"},
		{TransportICMP, "ICMP"},
		{TransportLoRa, "LoRa"},
		{TransportBLE, "BLE"},
		{TransportID(0xFF), "Unknown(0xFF)"},
	}

	for _, tt := range tests {
		if got := tt.id.String(); got != tt.expected {
			t.Errorf("TransportID(%d).String() = %s, want %s", tt.id, got, tt.expected)
		}
	}
}
