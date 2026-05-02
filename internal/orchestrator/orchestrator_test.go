package orchestrator

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aether-project/aether/internal/hwscan"
)

// mockVector implements the Vector interface for testing.
type mockVector struct {
	name string
	tier int
	prio int
}

func (v *mockVector) Name() string                            { return v.name }
func (v *mockVector) Tier() int                               { return v.tier }
func (v *mockVector) Priority() int                           { return v.prio }
func (v *mockVector) RequiresHardware() []hwscan.HardwareType { return nil }
func (v *mockVector) Probe(ctx context.Context) (*Connection, error) {
	select {
	case <-time.After(10 * time.Millisecond):
		return &Connection{VectorName: v.name, Tier: v.tier, EstablishedAt: time.Now()}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (v *mockVector) Maintain(ctx context.Context, conn *Connection) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestOrchestrator_FullCycle(t *testing.T) {
	// Setup temp dir for state
	tmpDir, err := os.MkdirTemp("", "aether_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Setup mock vector registry
	registry := NewVectorRegistry()
	registry.Register(&mockVector{name: "mock_tunnel", tier: 0, prio: 10})

	// Override state configs to run tests faster
	configs := DefaultStateConfigs()
	configs[StateColdStart] = StateConfig{MaxRetries: 0, Timeout: 1 * time.Second}
	configs[StateVectorRace] = StateConfig{MaxRetries: 0, Timeout: 5 * time.Second}

	cfg := Config{
		StateDir:     tmpDir,
		StateConfigs: configs,
	}

	orch := New(cfg, registry)

	// Run the orchestrator with a short timeout to prevent hanging tests
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- orch.Run(ctx)
	}()

	// Give it time to progress through the states
	time.Sleep(500 * time.Millisecond)

	// Cancel to trigger shutdown
	cancel()
	err = <-errCh

	// The run context was cancelled, so the error should be context.DeadlineExceeded
	// or context.Canceled. Both are normal shutdown behaviors.
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Errorf("expected context cancellation error, got: %v", err)
	}

	// Verify transitions
	transitions := orch.Transitions()
	if len(transitions) == 0 {
		t.Fatal("expected state transitions, got none")
	}

	// Check if it reached at least Connected state
	reachedConnected := false
	for _, tr := range transitions {
		t.Logf("Transition: %s -> %s", tr.From, tr.To)
		if tr.To == StateConnected {
			reachedConnected = true
		}
	}

	if !reachedConnected {
		t.Errorf("Orchestrator never reached StateConnected")
	}

	// Verify connections
	conns := orch.ActiveConnections()
	if len(conns) == 0 {
		t.Errorf("expected at least 1 active connection, got 0")
	} else if conns[0].VectorName != "mock_tunnel" {
		t.Errorf("expected connection from 'mock_tunnel', got %s", conns[0].VectorName)
	}
}
