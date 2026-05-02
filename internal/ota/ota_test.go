package ota

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"os"
	"testing"
)

// setupDevKeys creates a test developer keyring with N keys.
func setupDevKeys(t *testing.T, n int) (*DeveloperKeys, []ed25519.PrivateKey) {
	t.Helper()

	dk := &DeveloperKeys{
		Keys:   make([][32]byte, n),
		Quorum: QuorumSize,
	}

	privKeys := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		copy(dk.Keys[i][:], pub)
		privKeys[i] = priv
	}

	return dk, privKeys
}

// createTestUpdate creates a model update with test payload.
func createTestUpdate(version uint64, payload []byte) *ModelUpdate {
	update := &ModelUpdate{
		Version: version,
		Payload: payload,
	}
	update.ComputeHash()
	return update
}

func TestVerifyQuorum_FullQuorum(t *testing.T) {
	devKeys, privKeys := setupDevKeys(t, 5)

	update := createTestUpdate(1, []byte("test-model-weights-v1"))

	// Sign with 3 developers (exactly quorum)
	for i := 0; i < 3; i++ {
		SignUpdate(update, privKeys[i])
	}

	validCount, signers, err := VerifyQuorum(update, devKeys)
	if err != nil {
		t.Fatalf("quorum should pass with 3/5 sigs: %v", err)
	}

	if validCount != 3 {
		t.Errorf("expected 3 valid sigs, got %d", validCount)
	}

	if len(signers) != 3 {
		t.Errorf("expected 3 signers, got %d", len(signers))
	}
}

func TestVerifyQuorum_InsufficientSigs(t *testing.T) {
	devKeys, privKeys := setupDevKeys(t, 5)

	update := createTestUpdate(1, []byte("test-model-weights-v1"))

	// Sign with only 2 developers (below quorum)
	for i := 0; i < 2; i++ {
		SignUpdate(update, privKeys[i])
	}

	_, _, err := VerifyQuorum(update, devKeys)
	if err == nil {
		t.Fatal("quorum should FAIL with only 2/5 sigs")
	}
}

func TestVerifyQuorum_UnknownSigner(t *testing.T) {
	devKeys, _ := setupDevKeys(t, 5)

	update := createTestUpdate(1, []byte("test-model-weights-v1"))

	// Sign with 3 UNKNOWN keys (not in devKeys)
	for i := 0; i < 3; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		SignUpdate(update, priv)
	}

	_, _, err := VerifyQuorum(update, devKeys)
	if err == nil {
		t.Fatal("quorum should FAIL with unknown signers")
	}
}

func TestVerifyQuorum_TamperedPayload(t *testing.T) {
	devKeys, privKeys := setupDevKeys(t, 5)

	update := createTestUpdate(1, []byte("legitimate-model-weights"))

	// Sign legitimately
	for i := 0; i < 3; i++ {
		SignUpdate(update, privKeys[i])
	}

	// Tamper with payload AFTER signing (poisoning attack)
	update.Payload = []byte("poisoned-model-weights-from-gov")

	_, _, err := VerifyQuorum(update, devKeys)
	if err == nil {
		t.Fatal("quorum should FAIL with tampered payload")
	}
}

func TestVerifyQuorum_DuplicateSigners(t *testing.T) {
	devKeys, privKeys := setupDevKeys(t, 5)

	update := createTestUpdate(1, []byte("test-model-weights"))

	// Sign with same key 3 times (replay attack)
	for i := 0; i < 3; i++ {
		SignUpdate(update, privKeys[0]) // Same key!
	}

	validCount, _, err := VerifyQuorum(update, devKeys)
	if err == nil {
		t.Fatal("quorum should FAIL with duplicate signers")
	}
	if validCount != 1 {
		t.Errorf("expected only 1 unique valid sig, got %d", validCount)
	}
}

func TestCanaryVerification(t *testing.T) {
	tests := []struct {
		name          string
		oldBlocked    int
		newBlocked    int
		total         int
		expectVerdict CanaryVerdict
	}{
		{
			name:       "new model is better",
			oldBlocked: 5, newBlocked: 2, total: 100,
			expectVerdict: CanaryPass,
		},
		{
			name:       "new model is same",
			oldBlocked: 10, newBlocked: 10, total: 100,
			expectVerdict: CanaryPass,
		},
		{
			name:       "new model slightly worse (within threshold)",
			oldBlocked: 10, newBlocked: 25, total: 100,
			expectVerdict: CanaryPass, // 15% increase < 20% threshold
		},
		{
			name:       "POISONED: new model much worse",
			oldBlocked: 5, newBlocked: 50, total: 100,
			expectVerdict: CanaryFail, // 45% increase > 20% threshold
		},
		{
			name:       "too few probes for conclusion",
			oldBlocked: 1, newBlocked: 3, total: 5,
			expectVerdict: CanaryInconclusive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvaluateCanary(tt.oldBlocked, tt.newBlocked, tt.total)
			if result.Verdict != tt.expectVerdict {
				t.Errorf("expected %s, got %s", tt.expectVerdict, result.Verdict)
			}
		})
	}
}

func TestGossipConsensus_Positive(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ga := NewGossipAggregator(log)

	// 10 peers report: 8 positive, 2 negative (20% < 30% threshold)
	for i := 0; i < 10; i++ {
		var pubKey [32]byte
		pubKey[0] = byte(i)

		report := PeerReport{
			ReporterPubKey: pubKey,
			UpdateVersion:  42,
			Works:          i < 8, // 8 positive, 2 negative
			BlockRate:      0.05,
		}
		ga.AddReport(report)
	}

	result := ga.Evaluate(42)
	if result.ShouldQuarantine {
		t.Error("should NOT quarantine with only 20% negative reports")
	}
	if !result.ShouldApply {
		t.Error("should recommend applying update")
	}
	if result.PositiveCount != 8 {
		t.Errorf("expected 8 positive, got %d", result.PositiveCount)
	}
}

func TestGossipConsensus_Poisoned(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ga := NewGossipAggregator(log)

	// 10 peers report: 4 positive, 6 negative (60% > 30% threshold)
	for i := 0; i < 10; i++ {
		var pubKey [32]byte
		pubKey[0] = byte(i)

		report := PeerReport{
			ReporterPubKey: pubKey,
			UpdateVersion:  42,
			Works:          i < 4, // Only 4 positive
			BlockRate:      0.5,
		}
		ga.AddReport(report)
	}

	result := ga.Evaluate(42)
	if !result.ShouldQuarantine {
		t.Error("MUST quarantine with 60% negative reports")
	}
	if result.ShouldApply {
		t.Error("should NOT apply quarantined update")
	}
}

func TestGossipConsensus_DuplicateReports(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ga := NewGossipAggregator(log)

	// Same peer sends 100 positive reports (vote stuffing)
	var pubKey [32]byte
	pubKey[0] = 0x42

	for i := 0; i < 100; i++ {
		report := PeerReport{
			ReporterPubKey: pubKey,
			UpdateVersion:  42,
			Works:          true,
		}
		ga.AddReport(report)
	}

	result := ga.Evaluate(42)
	if result.TotalReports != 1 {
		t.Errorf("expected 1 report (deduped), got %d", result.TotalReports)
	}
}

func TestFullPipeline_E2E(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	devKeys, privKeys := setupDevKeys(t, 5)
	um := NewUpdateManager(log, devKeys)

	// Create legitimate update
	payload := []byte("legitimate-ml-model-weights-v1-production-grade")
	update := createTestUpdate(1, payload)

	// 3 developers sign
	for i := 0; i < 3; i++ {
		SignUpdate(update, privKeys[i])
	}

	// Layer 1+2: Quorum + Integrity
	stage, err := um.VerifyUpdate(update)
	if err != nil {
		t.Fatalf("verification should pass: %v", err)
	}
	if stage != StageQuorumPassed {
		t.Errorf("expected StageQuorumPassed, got %s", stage)
	}

	// Layer 3: Canary (simulated)
	canary := EvaluateCanary(5, 3, 100) // New model is better
	if canary.Verdict != CanaryPass {
		t.Fatal("canary should pass")
	}

	// Layer 4: Gossip (simulated positive consensus)
	for i := 0; i < 10; i++ {
		var pubKey [32]byte
		pubKey[0] = byte(i)
		um.Gossip().AddReport(PeerReport{
			ReporterPubKey: pubKey,
			UpdateVersion:  1,
			Works:          true,
			BlockRate:      0.02,
		})
	}
	consensus := um.Gossip().Evaluate(1)
	if consensus.ShouldQuarantine {
		t.Fatal("should not quarantine legitimate update")
	}

	// Apply
	err = um.ApplyUpdate(update)
	if err != nil {
		t.Fatal("apply should succeed:", err)
	}

	if um.CurrentVersion() != 1 {
		t.Errorf("expected version 1, got %d", um.CurrentVersion())
	}
}

func TestAntiDowngrade(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	devKeys, privKeys := setupDevKeys(t, 5)

	um := NewUpdateManager(log, devKeys)

	// Apply v2
	update2 := createTestUpdate(2, []byte("model-v2"))
	for i := 0; i < 3; i++ {
		SignUpdate(update2, privKeys[i])
	}
	um.VerifyUpdate(update2)
	um.ApplyUpdate(update2)

	// Try to downgrade to v1
	update1 := createTestUpdate(1, []byte("model-v1-downgrade"))
	for i := 0; i < 3; i++ {
		SignUpdate(update1, privKeys[i])
	}

	stage, err := um.VerifyUpdate(update1)
	if err == nil {
		t.Fatal("downgrade should be REJECTED")
	}
	if stage != StageQuarantined {
		t.Errorf("expected StageQuarantined, got %s", stage)
	}
}

func TestRollback(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	devKeys, privKeys := setupDevKeys(t, 5)

	um := NewUpdateManager(log, devKeys)

	// Apply v1
	v1 := createTestUpdate(1, []byte("model-v1"))
	for i := 0; i < 3; i++ {
		SignUpdate(v1, privKeys[i])
	}
	um.VerifyUpdate(v1)
	um.ApplyUpdate(v1)

	// Manually push v1 to history for rollback
	um.mu.Lock()
	um.history = append(um.history, *v1)
	um.mu.Unlock()

	// Apply v2
	v2 := createTestUpdate(2, []byte("model-v2-poisoned"))
	for i := 0; i < 3; i++ {
		SignUpdate(v2, privKeys[i])
	}
	um.VerifyUpdate(v2)
	um.ApplyUpdate(v2)

	if um.CurrentVersion() != 2 {
		t.Fatalf("expected version 2, got %d", um.CurrentVersion())
	}

	// Rollback to v1 (e.g., canary detected poisoning)
	rolledTo, err := um.Rollback()
	if err != nil {
		t.Fatal("rollback should succeed:", err)
	}
	if rolledTo != 1 {
		t.Errorf("expected rollback to v1, got v%d", rolledTo)
	}
	if um.CurrentVersion() != 1 {
		t.Errorf("current version should be 1 after rollback, got %d", um.CurrentVersion())
	}
}
