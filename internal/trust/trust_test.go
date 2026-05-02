package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"os"
	"testing"
)

func TestDeriveSAS(t *testing.T) {
	// Two nodes with the SAME handshake hash must produce the SAME SAS.
	var hash [32]byte
	copy(hash[:], []byte("test-handshake-hash-1234567890ab"))

	sas1 := DeriveSAS(hash)
	sas2 := DeriveSAS(hash)

	for i := 0; i < 4; i++ {
		if sas1[i] != sas2[i] {
			t.Errorf("SAS word %d mismatch: %s != %s", i, sas1[i], sas2[i])
		}
	}

	t.Logf("SAS: %s", FormatSAS(sas1))

	// Different hash must produce different SAS (with overwhelming probability)
	var hash2 [32]byte
	copy(hash2[:], []byte("different-handshake-hash-0000000"))

	sas3 := DeriveSAS(hash2)
	matches := 0
	for i := 0; i < 4; i++ {
		if sas1[i] == sas3[i] {
			matches++
		}
	}
	if matches == 4 {
		t.Error("different hashes produced identical SAS (collision)")
	}
}

func TestTrustStoreTOFU(t *testing.T) {
	store := NewStore()

	var pubKey [32]byte
	copy(pubKey[:], []byte("test-pubkey-1234567890abcdef00"))

	// First contact → TOFU
	isNew := store.RecordFirstContact(pubKey)
	if !isNew {
		t.Error("expected new peer")
	}

	peer := store.GetPeer(pubKey)
	if peer == nil {
		t.Fatal("peer not found")
	}
	if peer.Trust != TrustTOFU {
		t.Errorf("expected TrustTOFU, got %s", peer.Trust)
	}

	// Second contact → not new
	isNew = store.RecordFirstContact(pubKey)
	if isNew {
		t.Error("expected existing peer, not new")
	}
}

func TestSASVerification(t *testing.T) {
	store := NewStore()

	var pubKey [32]byte
	copy(pubKey[:], []byte("test-pubkey-for-sas-verification"))

	store.RecordFirstContact(pubKey)
	store.MarkSASVerified(pubKey)

	peer := store.GetPeer(pubKey)
	if peer.Trust != TrustSASVerified {
		t.Errorf("expected TrustSASVerified, got %s", peer.Trust)
	}
	if peer.SASVerifiedAt.IsZero() {
		t.Error("SASVerifiedAt should be set")
	}
}

func TestAttestationChain(t *testing.T) {
	store := NewStore()

	// Alice is SAS-verified
	_, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	var alicePub [32]byte
	copy(alicePub[:], alicePriv.Public().(ed25519.PublicKey))

	store.RecordFirstContact(alicePub)
	store.MarkSASVerified(alicePub)

	// Bob is unknown
	var bobPub [32]byte
	copy(bobPub[:], []byte("bob-pubkey-1234567890abcdef0000"))

	// Alice attests for Bob
	att := CreateAttestation(alicePriv, bobPub, TrustAttested)

	err := store.AddAttestation(att)
	if err != nil {
		t.Fatal("attestation should be accepted:", err)
	}

	// Bob should now be TrustAttested
	effectiveTrust := store.ComputeEffectiveTrust(bobPub)
	if effectiveTrust != TrustAttested {
		t.Errorf("expected TrustAttested, got %s", effectiveTrust)
	}
}

func TestAttestationDepthLimit(t *testing.T) {
	store := NewStore()

	_, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	var alicePub [32]byte
	copy(alicePub[:], alicePriv.Public().(ed25519.PublicKey))
	store.RecordFirstContact(alicePub)
	store.MarkSASVerified(alicePub)

	var bobPub [32]byte
	copy(bobPub[:], []byte("bob-deep-attestation-test-pubkey"))

	// Create attestation at max depth → should be rejected
	att := CreateAttestation(alicePriv, bobPub, TrustAttested)
	att.Depth = MaxAttestationDepth // At the limit

	err := store.AddAttestation(att)
	if err == nil {
		t.Error("attestation at max depth should be rejected")
	}
}

func TestAttestationSignatureVerification(t *testing.T) {
	_, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	var bobPub [32]byte
	copy(bobPub[:], []byte("bob-signature-test-pubkey-000000"))

	att := CreateAttestation(alicePriv, bobPub, TrustAttested)

	// Valid signature
	if !att.Verify() {
		t.Error("valid attestation should verify")
	}

	// Tamper with subject → signature should fail
	att.SubjectPubKey[0] ^= 0xFF
	if att.Verify() {
		t.Error("tampered attestation should not verify")
	}
}

func TestEffectiveTrustComputation(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	_ = log

	store := NewStore()

	var unknownPub [32]byte
	copy(unknownPub[:], []byte("totally-unknown-node-0123456789"))

	// Unknown node → TrustNone
	trust := store.ComputeEffectiveTrust(unknownPub)
	if trust != TrustNone {
		t.Errorf("expected TrustNone, got %s", trust)
	}

	// TOFU node → TrustTOFU
	var tofuPub [32]byte
	copy(tofuPub[:], []byte("tofu-node-pubkey-0123456789abcd"))
	store.RecordFirstContact(tofuPub)
	trust = store.ComputeEffectiveTrust(tofuPub)
	if trust != TrustTOFU {
		t.Errorf("expected TrustTOFU, got %s", trust)
	}
}

// TestDetectKeyChange verifies Key Continuity detection.
// This test also validates the lock juggling fix (BUG-1):
// the old code used RLock→RUnlock→Lock which created a data race window.
func TestDetectKeyChange(t *testing.T) {
	store := NewStore()

	var originalKey [32]byte
	copy(originalKey[:], []byte("original-key-1234567890abcdef0"))

	var newKey [32]byte
	copy(newKey[:], []byte("new-key-after-reinstall-0000000"))

	// Register peer
	store.RecordFirstContact(originalKey)

	// Same key → no change
	changed := store.DetectKeyChange(originalKey, originalKey)
	if changed {
		t.Error("same key should not trigger change detection")
	}

	// Different key → change detected
	changed = store.DetectKeyChange(newKey, originalKey)
	if !changed {
		t.Error("different key should trigger change detection")
	}

	// Verify KeyHistory was recorded
	peer := store.GetPeer(originalKey)
	if peer == nil {
		t.Fatal("peer should exist")
	}
	if len(peer.KeyHistory) != 1 {
		t.Fatalf("expected 1 key change, got %d", len(peer.KeyHistory))
	}
	if peer.KeyHistory[0].OldKey != originalKey {
		t.Error("old key mismatch in history")
	}
	if peer.KeyHistory[0].NewKey != newKey {
		t.Error("new key mismatch in history")
	}
}

// TestDetectKeyChange_UnknownPeer verifies that unknown peers don't trigger alerts.
func TestDetectKeyChange_UnknownPeer(t *testing.T) {
	store := NewStore()

	var unknownKey [32]byte
	copy(unknownKey[:], []byte("never-seen-before-key-000000000"))

	var claimedKey [32]byte
	copy(claimedKey[:], []byte("some-other-key-00000000000000000"))

	changed := store.DetectKeyChange(claimedKey, unknownKey)
	if changed {
		t.Error("unknown peer should not trigger change detection")
	}
}

// TestDetectKeyChange_Concurrent verifies thread safety of the fixed implementation.
// This test would panic/race with the old lock-juggling code.
func TestDetectKeyChange_Concurrent(t *testing.T) {
	store := NewStore()

	var key1 [32]byte
	copy(key1[:], []byte("concurrent-test-key-1-000000000"))
	var key2 [32]byte
	copy(key2[:], []byte("concurrent-test-key-2-000000000"))

	store.RecordFirstContact(key1)

	// Run concurrent DetectKeyChange calls — this would race under the old code
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			store.DetectKeyChange(key2, key1)
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			store.GetPeer(key1) // Concurrent read
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
