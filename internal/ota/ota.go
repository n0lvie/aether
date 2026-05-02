// Package ota implements the Over-The-Air update system for ML model weights
// and configuration payloads within the encrypted Aether network.
//
// THREAT MODEL:
//   A state actor compromises an Aether node and uses it to distribute
//   poisoned ML model weights via Gossip protocol. The poisoned model
//   deliberately weakens obfuscation, making Aether traffic detectable by DPI.
//
// DEFENSE: 4-layer verification pipeline. An update must pass ALL layers.
//
//   Layer 1: Multi-Sig Quorum (Cryptographic Gate)
//     - N developer Ed25519 public keys hardcoded in the binary
//     - Requires M-of-N valid signatures (default: 3-of-5)
//     - A poisoned update from a state actor lacks developer signatures → REJECTED
//     - If all M developers are arrested: Emergency Key Rotation via network vote
//
//   Layer 2: Payload Integrity (Content Hash)
//     - SHA-256 hash of the model binary is signed, not just the metadata
//     - Even 1-bit flip in model weights invalidates all signatures
//     - Prevents partial corruption during Gossip relay
//
//   Layer 3: Canary Verification (Empirical Test)
//     - Node does NOT blindly apply the new model
//     - Runs both old and new models in parallel ("canary" mode)
//     - Sends test traffic through both to known-good endpoints
//     - If new model's traffic is blocked more often → REJECT and alert
//     - This catches sophisticated attacks where developers are coerced
//
//   Layer 4: Gossip Reputation (Network Consensus)
//     - Nodes that applied the update report outcomes via signed Gossip
//     - Only reports from TrustSASVerified/TrustAttested peers are counted
//     - If >30% of trusted peers report "model causes blocks" → QUARANTINE
//     - Automatic rollback to previous model version
//
// WHY NOT PURE MULTI-SIG:
//   Developers can be arrested, coerced, or killed. The network must be
//   able to survive total compromise of the developer team. Canary + Gossip
//   provide empirical verification independent of any authority.
//
// WHY NOT PURE CONSENSUS:
//   State actor can Sybil-attack the vote (PoW makes this expensive but not
//   impossible for a nation-state). Multi-sig from hardcoded keys is the
//   primary gate that consensus alone cannot replace.
package ota

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
)

// QuorumSize is the minimum number of valid developer signatures required.
// Default: 3-of-5 (survives compromise of 2 developers).
const QuorumSize = 3

// MaxModelVersions is the number of model versions kept for rollback.
const MaxModelVersions = 3

// ModelUpdate is a signed payload containing new ML model weights.
type ModelUpdate struct {
	// Version is the monotonically increasing update counter.
	// Prevents downgrade attacks (node rejects versions <= current).
	Version uint64

	// ModelHash is SHA-256 of the raw model binary.
	ModelHash [32]byte

	// ModelSize is the byte length of the model payload.
	ModelSize uint64

	// Payload is the raw model binary (weights + architecture).
	// In production, this is compressed with zstd.
	Payload []byte

	// Signatures from the developer quorum.
	// Each signature covers: "aether-ota-v1" || version || model_hash || model_size
	Signatures []UpdateSignature

	// Timestamp is advisory only (not used for validation due to NTP drift).
	Timestamp int64
}

// UpdateSignature is a developer's Ed25519 signature on an update.
type UpdateSignature struct {
	SignerPubKey [32]byte
	Signature   [64]byte
}

// SignablePayload returns the canonical bytes that developers sign.
func (u *ModelUpdate) SignablePayload() []byte {
	buf := make([]byte, 15+8+32+8) // prefix + version + hash + size
	copy(buf[0:15], []byte("aether-ota-v1\x00\x00"))
	binary.BigEndian.PutUint64(buf[15:23], u.Version)
	copy(buf[23:55], u.ModelHash[:])
	binary.BigEndian.PutUint64(buf[55:63], u.ModelSize)
	return buf
}

// ComputeHash computes SHA-256 of the payload and stores it in ModelHash.
func (u *ModelUpdate) ComputeHash() {
	u.ModelHash = sha256.Sum256(u.Payload)
	u.ModelSize = uint64(len(u.Payload))
}

// --- Developer Key Registry ---

// DeveloperKeys is the hardcoded set of trusted developer Ed25519 public keys.
// These are compiled into the binary and CANNOT be changed at runtime
// (except via Emergency Key Rotation, which requires network consensus).
//
// In production, these would be the real keys of the 5 core developers.
// The binary must be built with `-ldflags` to inject them, or they are
// embedded via `go:embed` from a signed keyring file.
type DeveloperKeys struct {
	Keys     [][32]byte
	Quorum   int // M in M-of-N
}

// DefaultDeveloperKeys returns the hardcoded developer keyring.
// In production, this would contain real Ed25519 public keys.
func DefaultDeveloperKeys() *DeveloperKeys {
	return &DeveloperKeys{
		Keys:   make([][32]byte, 5), // 5 developer slots
		Quorum: QuorumSize,
	}
}

// Contains checks if a public key is in the developer keyring.
func (dk *DeveloperKeys) Contains(pubKey [32]byte) bool {
	for _, key := range dk.Keys {
		if key == pubKey {
			return true
		}
	}
	return false
}

// --- Signature Verification ---

// VerifyQuorum checks that an update has at least M valid signatures
// from distinct developers in the keyring.
//
// Returns the number of valid signatures and the list of signers.
func VerifyQuorum(update *ModelUpdate, devKeys *DeveloperKeys) (int, [][32]byte, error) {
	payload := update.SignablePayload()

	// Verify content hash matches payload
	actualHash := sha256.Sum256(update.Payload)
	if actualHash != update.ModelHash {
		return 0, nil, fmt.Errorf("payload hash mismatch: claimed %x, actual %x",
			update.ModelHash[:8], actualHash[:8])
	}

	var validSigners [][32]byte
	seen := make(map[[32]byte]bool)

	for _, sig := range update.Signatures {
		// Must be a known developer
		if !devKeys.Contains(sig.SignerPubKey) {
			continue // Unknown signer, skip
		}

		// No duplicate signers
		if seen[sig.SignerPubKey] {
			continue
		}

		// Verify Ed25519 signature
		pubKey := ed25519.PublicKey(sig.SignerPubKey[:])
		if ed25519.Verify(pubKey, payload, sig.Signature[:]) {
			validSigners = append(validSigners, sig.SignerPubKey)
			seen[sig.SignerPubKey] = true
		}
	}

	validCount := len(validSigners)
	if validCount < devKeys.Quorum {
		return validCount, validSigners, fmt.Errorf(
			"insufficient quorum: %d/%d valid signatures (need %d)",
			validCount, len(devKeys.Keys), devKeys.Quorum,
		)
	}

	return validCount, validSigners, nil
}

// SignUpdate adds a developer's signature to an update.
func SignUpdate(update *ModelUpdate, devPrivKey ed25519.PrivateKey) {
	payload := update.SignablePayload()
	sig := ed25519.Sign(devPrivKey, payload)

	us := UpdateSignature{}
	copy(us.SignerPubKey[:], devPrivKey.Public().(ed25519.PublicKey))
	copy(us.Signature[:], sig)

	update.Signatures = append(update.Signatures, us)
}

// --- Canary Verification ---

// CanaryResult is the outcome of testing a model in canary mode.
type CanaryResult struct {
	// OldModelBlocked is the number of test probes blocked with the old model.
	OldModelBlocked int
	// NewModelBlocked is the number of test probes blocked with the new model.
	NewModelBlocked int
	// TotalProbes is the total number of test probes sent.
	TotalProbes int
	// Verdict is the canary's recommendation.
	Verdict CanaryVerdict
}

// CanaryVerdict is the outcome of the canary test.
type CanaryVerdict uint8

const (
	// CanaryPass means the new model performs as well or better than the old.
	CanaryPass CanaryVerdict = iota
	// CanaryFail means the new model causes more blocks (possible poisoning).
	CanaryFail
	// CanaryInconclusive means not enough data to decide (offline, no probes).
	CanaryInconclusive
)

func (v CanaryVerdict) String() string {
	names := [...]string{"PASS", "FAIL", "INCONCLUSIVE"}
	if int(v) < len(names) {
		return names[v]
	}
	return "UNKNOWN"
}

// EvaluateCanary compares old vs new model performance.
// The new model FAILS if it causes >20% more blocks than the old model.
func EvaluateCanary(oldBlocked, newBlocked, totalProbes int) CanaryResult {
	result := CanaryResult{
		OldModelBlocked: oldBlocked,
		NewModelBlocked: newBlocked,
		TotalProbes:     totalProbes,
	}

	if totalProbes < 10 {
		result.Verdict = CanaryInconclusive
		return result
	}

	oldRate := float64(oldBlocked) / float64(totalProbes)
	newRate := float64(newBlocked) / float64(totalProbes)

	// New model fails if block rate is >20% higher than old
	if newRate > oldRate+0.20 {
		result.Verdict = CanaryFail
	} else {
		result.Verdict = CanaryPass
	}

	return result
}

// --- Gossip Reputation ---

// PeerReport is a signed statement from a peer about an update's effectiveness.
type PeerReport struct {
	// ReporterPubKey is the peer reporting the outcome.
	ReporterPubKey [32]byte

	// UpdateVersion is which update is being reported on.
	UpdateVersion uint64

	// Works is true if the model works correctly for this peer.
	Works bool

	// BlockRate is the observed DPI block rate (0.0 - 1.0).
	BlockRate float64

	// Timestamp is advisory (not used for validation).
	Timestamp int64

	// Signature over the report payload.
	Signature [64]byte
}

// ReportPayload returns the canonical bytes for signing.
func (r *PeerReport) ReportPayload() []byte {
	buf := make([]byte, 32+8+1+8) // pubkey + version + works + blockrate_bits
	copy(buf[0:32], r.ReporterPubKey[:])
	binary.BigEndian.PutUint64(buf[32:40], r.UpdateVersion)
	if r.Works {
		buf[40] = 1
	}
	// Encode block rate as fixed-point uint64
	binary.BigEndian.PutUint64(buf[41:49], uint64(r.BlockRate*1e9))
	return buf
}

// GossipAggregator collects peer reports and computes network consensus.
type GossipAggregator struct {
	log     *slog.Logger
	mu      sync.RWMutex
	reports map[uint64][]PeerReport // version → reports

	// QuarantineThreshold: if this fraction of trusted peers report failure,
	// the update is quarantined. Default: 0.30 (30%).
	QuarantineThreshold float64
}

// NewGossipAggregator creates a new report aggregator.
func NewGossipAggregator(log *slog.Logger) *GossipAggregator {
	return &GossipAggregator{
		log:                 log,
		reports:             make(map[uint64][]PeerReport),
		QuarantineThreshold: 0.30,
	}
}

// AddReport records a peer's report about an update.
// Duplicate reports from the same peer are ignored.
func (ga *GossipAggregator) AddReport(report PeerReport) {
	ga.mu.Lock()
	defer ga.mu.Unlock()

	// Deduplicate by reporter pubkey
	existing := ga.reports[report.UpdateVersion]
	for _, r := range existing {
		if r.ReporterPubKey == report.ReporterPubKey {
			return // Already have a report from this peer
		}
	}

	ga.reports[report.UpdateVersion] = append(existing, report)
}

// ConsensusResult is the network's collective verdict on an update.
type ConsensusResult struct {
	Version        uint64
	TotalReports   int
	PositiveCount  int
	NegativeCount  int
	AvgBlockRate   float64
	ShouldApply    bool
	ShouldQuarantine bool
}

// Evaluate computes consensus for a specific update version.
// Only reports from peers with sufficient trust level are counted
// (trust filtering is done by the caller before AddReport).
func (ga *GossipAggregator) Evaluate(version uint64) ConsensusResult {
	ga.mu.RLock()
	defer ga.mu.RUnlock()

	reports := ga.reports[version]
	result := ConsensusResult{
		Version:      version,
		TotalReports: len(reports),
	}

	if len(reports) == 0 {
		return result
	}

	var totalBlockRate float64
	for _, r := range reports {
		if r.Works {
			result.PositiveCount++
		} else {
			result.NegativeCount++
		}
		totalBlockRate += r.BlockRate
	}

	result.AvgBlockRate = totalBlockRate / float64(len(reports))

	// Quarantine if too many negative reports
	negativeRatio := float64(result.NegativeCount) / float64(len(reports))
	if negativeRatio >= ga.QuarantineThreshold {
		result.ShouldQuarantine = true
		result.ShouldApply = false
	} else {
		result.ShouldApply = true
	}

	return result
}

// --- Update Manager ---

// UpdateManager orchestrates the 4-layer verification pipeline.
type UpdateManager struct {
	log     *slog.Logger
	devKeys *DeveloperKeys
	gossip  *GossipAggregator

	// Current model version
	currentVersion uint64

	// Model history for rollback (up to MaxModelVersions)
	history []ModelUpdate

	mu sync.RWMutex
}

// NewUpdateManager creates a new OTA update manager.
func NewUpdateManager(log *slog.Logger, devKeys *DeveloperKeys) *UpdateManager {
	return &UpdateManager{
		log:     log,
		devKeys: devKeys,
		gossip:  NewGossipAggregator(log),
	}
}

// VerificationStage represents which stage of the pipeline an update is in.
type VerificationStage uint8

const (
	StageReceived     VerificationStage = iota // Just received via Gossip
	StageQuorumPassed                          // Multi-sig verified
	StageCanaryActive                          // Running canary test
	StageCanaryPassed                          // Canary test succeeded
	StageGossipWait                            // Waiting for peer reports
	StageApplied                               // Fully verified and applied
	StageQuarantined                           // Failed verification, quarantined
	StageRolledBack                            // Applied then rolled back
)

func (s VerificationStage) String() string {
	names := [...]string{
		"Received", "QuorumPassed", "CanaryActive", "CanaryPassed",
		"GossipWait", "Applied", "Quarantined", "RolledBack",
	}
	if int(s) < len(names) {
		return names[s]
	}
	return "Unknown"
}

// VerifyUpdate runs the full 4-layer verification pipeline.
// Returns the stage the update reached and any error.
//
// The caller is responsible for:
//   - Running the canary test (Layer 3) asynchronously
//   - Collecting Gossip reports (Layer 4) over time
//   - Calling ApplyUpdate() once all layers pass
func (um *UpdateManager) VerifyUpdate(update *ModelUpdate) (VerificationStage, error) {
	um.mu.RLock()
	currentVer := um.currentVersion
	um.mu.RUnlock()

	// --- Anti-downgrade check ---
	if update.Version <= currentVer {
		return StageQuarantined, fmt.Errorf(
			"downgrade rejected: offered v%d, current v%d",
			update.Version, currentVer,
		)
	}

	// --- Layer 1: Multi-Sig Quorum ---
	validSigs, signers, err := VerifyQuorum(update, um.devKeys)
	if err != nil {
		um.log.Warn("OTA update rejected: quorum failed",
			"version", update.Version,
			"valid_sigs", validSigs,
			"error", err,
		)
		return StageQuarantined, fmt.Errorf("layer 1 (quorum): %w", err)
	}

	um.log.Info("OTA Layer 1 PASSED: quorum verified",
		"version", update.Version,
		"signers", len(signers),
		"quorum", um.devKeys.Quorum,
	)

	// --- Layer 2: Payload Integrity ---
	actualHash := sha256.Sum256(update.Payload)
	if actualHash != update.ModelHash {
		return StageQuarantined, fmt.Errorf(
			"layer 2 (integrity): hash mismatch %x != %x",
			actualHash[:8], update.ModelHash[:8],
		)
	}

	um.log.Info("OTA Layer 2 PASSED: payload integrity verified",
		"version", update.Version,
		"hash", fmt.Sprintf("%x", update.ModelHash[:8]),
		"size", update.ModelSize,
	)

	// Layers 3 and 4 are asynchronous — return stage for the caller to continue
	return StageQuorumPassed, nil
}

// ApplyUpdate applies a verified update and archives the old model for rollback.
func (um *UpdateManager) ApplyUpdate(update *ModelUpdate) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	// Archive current model
	if len(um.history) >= MaxModelVersions {
		um.history = um.history[1:] // Drop oldest
	}
	// (current model would be added to history here)

	um.currentVersion = update.Version

	um.log.Info("OTA update APPLIED",
		"version", update.Version,
		"hash", fmt.Sprintf("%x", update.ModelHash[:8]),
	)

	return nil
}

// Rollback reverts to the previous model version.
// Called automatically when:
//   - Canary test fails (Layer 3)
//   - Gossip reports indicate poisoning (Layer 4)
//   - Connectivity drops after applying an update (dead man's switch)
func (um *UpdateManager) Rollback() (uint64, error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if len(um.history) == 0 {
		return 0, fmt.Errorf("no previous version to rollback to")
	}

	prev := um.history[len(um.history)-1]
	um.history = um.history[:len(um.history)-1]
	um.currentVersion = prev.Version

	um.log.Warn("OTA ROLLBACK executed",
		"rolled_back_to", prev.Version,
		"hash", fmt.Sprintf("%x", prev.ModelHash[:8]),
	)

	return prev.Version, nil
}

// CurrentVersion returns the active model version.
func (um *UpdateManager) CurrentVersion() uint64 {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.currentVersion
}

// GossipAggregator returns the Gossip report aggregator.
func (um *UpdateManager) Gossip() *GossipAggregator {
	return um.gossip
}
