package orchestrator

import (
	"context"
	"fmt"

	"github.com/aether-project/aether/internal/hwscan"
)

// Vector is the interface that all connectivity strategies must implement.
// Each vector represents one method of establishing a tunnel to the Aether network.
//
// Vectors are organized into tiers (0-4) representing escalation levels:
//   Tier 0: Kernel-level (eBPF stealth, ICMP tunnels, AT commands)
//   Tier 1: Obfuscated internet (ECH, LLM mimicry, WebRTC cover)
//   Tier 2: Decentralized discovery (DoH, Domain Fronting, blockchain)
//   Tier 3: Local swarm (AWDL, Wi-Fi Aware, BLE Mesh, Ultrasonic, DTN)
//   Tier 4: Hardware fallback (LoRa, SDR, Softmodem)
type Vector interface {
	// Name returns a unique identifier for this vector.
	Name() string

	// Tier returns the escalation tier (0-4).
	Tier() int

	// Priority returns a priority value within the tier.
	// Lower values = higher priority. Used to order vectors during Happy Eyeballs.
	Priority() int

	// RequiresHardware returns the hardware types needed for this vector.
	// The Orchestrator checks the CapabilityMatrix before attempting a probe.
	// Returns empty slice if no special hardware is needed.
	RequiresHardware() []hwscan.HardwareType

	// Probe attempts to establish a connection using this vector.
	// It should respect the context deadline and return as soon as possible.
	// Returns a Connection on success or an error describing the failure.
	Probe(ctx context.Context) (*Connection, error)

	// Maintain keeps an established connection alive.
	// It runs continuously until the context is cancelled or the connection dies.
	// Returns an error when the connection is no longer viable.
	Maintain(ctx context.Context, conn *Connection) error
}

// VectorRegistry holds all registered connectivity vectors.
type VectorRegistry struct {
	vectors []Vector
}

// NewVectorRegistry creates a new empty registry.
func NewVectorRegistry() *VectorRegistry {
	return &VectorRegistry{}
}

// Register adds a vector to the registry.
func (r *VectorRegistry) Register(v Vector) {
	r.vectors = append(r.vectors, v)
}

// Available returns vectors that can run given the current hardware capabilities.
// Vectors are sorted by tier (ascending) then priority (ascending).
func (r *VectorRegistry) Available(caps *hwscan.CapabilityMatrix) []Vector {
	var available []Vector
	for _, v := range r.vectors {
		requirements := v.RequiresHardware()
		if len(requirements) == 0 {
			available = append(available, v)
			continue
		}

		// Check all hardware requirements are met
		allMet := true
		for _, req := range requirements {
			if !caps.Has(req) {
				allMet = false
				break
			}
		}
		if allMet {
			available = append(available, v)
		}
	}

	// Sort: tier ascending, then priority ascending
	sortVectors(available)
	return available
}

// ByTier returns available vectors filtered by a specific tier.
func (r *VectorRegistry) ByTier(tier int, caps *hwscan.CapabilityMatrix) []Vector {
	var result []Vector
	for _, v := range r.Available(caps) {
		if v.Tier() == tier {
			result = append(result, v)
		}
	}
	return result
}

// sortVectors sorts vectors by tier then priority (insertion sort — small N).
func sortVectors(vecs []Vector) {
	for i := 1; i < len(vecs); i++ {
		for j := i; j > 0; j-- {
			if vecs[j].Tier() < vecs[j-1].Tier() ||
				(vecs[j].Tier() == vecs[j-1].Tier() && vecs[j].Priority() < vecs[j-1].Priority()) {
				vecs[j], vecs[j-1] = vecs[j-1], vecs[j]
			} else {
				break
			}
		}
	}
}

// FormatVectorList returns a human-readable list of vectors with their status.
func FormatVectorList(vectors []Vector) string {
	result := ""
	for _, v := range vectors {
		result += fmt.Sprintf("  [T%d P%d] %s\n", v.Tier(), v.Priority(), v.Name())
	}
	return result
}
