// Package orchestrator implements the core state machine (FSM) and
// Aggressive Happy Eyeballs vector racing for Project Aether.
package orchestrator

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/aether-project/aether/internal/crypto"
)

// State represents a discrete state in the Orchestrator's finite state machine.
type State uint8

const (
	// StateColdStart is the initial state: load/generate identity, read config.
	StateColdStart State = iota

	// StateHardwareScan: discover available hardware (COM, USB, audio, network).
	StateHardwareScan

	// StateSeedDiscovery: obtain bootstrap node addresses through available oracles.
	StateSeedDiscovery

	// StateVectorRace: Aggressive Happy Eyeballs — race all available vectors.
	StateVectorRace

	// StateConnected: at least one vector has established a working tunnel.
	StateConnected

	// StateDegraded: connectivity partially lost, attempting recovery.
	StateDegraded

	// StateHumanRequired: all programmatic vectors exhausted, need physical intervention.
	StateHumanRequired

	// StateTerminated: graceful shutdown complete.
	StateTerminated
)

// String returns the human-readable state name.
func (s State) String() string {
	names := [...]string{
		"ColdStart",
		"HardwareScan",
		"SeedDiscovery",
		"VectorRace",
		"Connected",
		"Degraded",
		"HumanRequired",
		"Terminated",
	}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("Unknown(%d)", s)
}

// StateConfig defines the behavior and constraints for each state.
type StateConfig struct {
	// Timeout is the maximum time the FSM will spend in this state
	// before forcing a transition.
	Timeout time.Duration

	// MaxRetries is the number of times the state can retry its operation
	// before escalating to the next state.
	MaxRetries int

	// NextOnSuccess is the state to transition to on success.
	NextOnSuccess State

	// NextOnFailure is the state to transition to on failure/timeout.
	NextOnFailure State
}

// DefaultStateConfigs returns the default FSM configuration.
func DefaultStateConfigs() map[State]StateConfig {
	return map[State]StateConfig{
		StateColdStart: {
			Timeout:       10 * time.Second,
			MaxRetries:    1,
			NextOnSuccess: StateHardwareScan,
			NextOnFailure: StateTerminated, // Can't even load identity → fatal
		},
		StateHardwareScan: {
			Timeout:       30 * time.Second,
			MaxRetries:    2,
			NextOnSuccess: StateSeedDiscovery,
			NextOnFailure: StateHumanRequired, // No hardware at all → ask human
		},
		StateSeedDiscovery: {
			Timeout:       60 * time.Second,
			MaxRetries:    3,
			NextOnSuccess: StateVectorRace,
			NextOnFailure: StateHumanRequired,
		},
		StateVectorRace: {
			Timeout:       120 * time.Second,
			MaxRetries:    5,
			NextOnSuccess: StateConnected,
			NextOnFailure: StateHumanRequired,
		},
		StateConnected: {
			Timeout:       0, // No timeout — stay connected
			MaxRetries:    0,
			NextOnSuccess: StateConnected,   // Self-loop: still connected
			NextOnFailure: StateDegraded,
		},
		StateDegraded: {
			Timeout:       60 * time.Second,
			MaxRetries:    3,
			NextOnSuccess: StateConnected,
			NextOnFailure: StateHumanRequired,
		},
		StateHumanRequired: {
			Timeout:       0, // Wait indefinitely for human
			MaxRetries:    0,
			NextOnSuccess: StateHardwareScan, // Human attached hardware → rescan
			NextOnFailure: StateTerminated,
		},
		StateTerminated: {
			Timeout:       5 * time.Second,
			MaxRetries:    0,
			NextOnSuccess: StateTerminated,
			NextOnFailure: StateTerminated,
		},
	}
}

// Transition represents a state change event.
type Transition struct {
	From      State
	To        State
	Reason    string
	Timestamp time.Time
}

// Connection represents an established connectivity tunnel.
type Connection struct {
	// VectorName identifies which vector created this connection.
	VectorName string

	// Tier is the tier level of the vector (0-4).
	Tier int

	// RemoteNode is the peer node we're connected to.
	RemoteNode crypto.SeedNode

	// Session holds the Noise session keys for this connection.
	Session *crypto.SessionKeys

	// Conn is the underlying network connection (may be nil for non-IP transports).
	Conn net.Conn

	// RawIO is the raw read/write interface for non-IP transports (LoRa, BLE, Audio).
	RawIO io.ReadWriteCloser

	// EstablishedAt is when this connection was established.
	EstablishedAt time.Time

	// Quality tracks connection quality metrics.
	Quality ConnectionQuality

	// Cancel stops this connection's maintenance goroutine.
	Cancel context.CancelFunc
}

// ConnectionQuality tracks real-time quality metrics.
type ConnectionQuality struct {
	RTT          time.Duration // Round-trip time
	PacketLoss   float64       // 0.0 - 1.0
	Bandwidth    uint64        // Bytes per second estimate
	LastProbeAt  time.Time
	ConsecFails  int           // Consecutive failed probes
}

// IsHealthy returns true if the connection is usable.
func (q *ConnectionQuality) IsHealthy() bool {
	return q.ConsecFails < 3 && q.PacketLoss < 0.5
}
