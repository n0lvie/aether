package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/aether-project/aether/internal/cli"
	"github.com/aether-project/aether/internal/crypto"
	"github.com/aether-project/aether/internal/hwscan"
)

// Orchestrator is the central FSM that manages the daemon's lifecycle.
// It coordinates hardware discovery, seed resolution, vector racing,
// connection maintenance, and human operator interaction.
type Orchestrator struct {
	log      *slog.Logger
	stateDir string

	// FSM
	currentState State
	stateConfigs map[State]StateConfig
	transitions  []Transition
	mu           sync.RWMutex

	// Subsystems
	identity *crypto.Identity
	hwCaps   *hwscan.CapabilityMatrix
	registry *VectorRegistry
	scanner  *hwscan.Scanner
	operator *cli.Operator

	// Active connections (may have multiple for redundancy)
	connections []*Connection
	connMu      sync.RWMutex

	// Seed nodes discovered through oracles
	seeds   []crypto.SeedNode
	seedsMu sync.RWMutex

	// Lifecycle
	cancel context.CancelFunc
	done   chan struct{}
}

// Config holds configuration for the Orchestrator.
type Config struct {
	StateDir     string // Directory for persistent state (keys, cache)
	LogLevel     slog.Level
	StateConfigs map[State]StateConfig // Override default state configs
}

// New creates a new Orchestrator with the given configuration.
func New(cfg Config, registry *VectorRegistry) *Orchestrator {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	stateConfigs := DefaultStateConfigs()
	if cfg.StateConfigs != nil {
		for k, v := range cfg.StateConfigs {
			stateConfigs[k] = v
		}
	}

	return &Orchestrator{
		log:          log,
		stateDir:     cfg.StateDir,
		currentState: StateColdStart,
		stateConfigs: stateConfigs,
		registry:     registry,
		scanner:      hwscan.NewScanner(log),
		operator:     cli.NewOperator(log),
		done:         make(chan struct{}),
	}
}

// Run starts the FSM main loop. Blocks until shutdown or fatal error.
func (o *Orchestrator) Run(ctx context.Context) error {
	ctx, o.cancel = context.WithCancel(ctx)
	defer close(o.done)

	o.log.Info("=== PROJECT AETHER ===")
	o.log.Info("orchestrator starting", "state", o.currentState)

	for {
		select {
		case <-ctx.Done():
			o.transitionTo(StateTerminated, "context cancelled")
			return ctx.Err()
		default:
		}

		// Execute current state
		nextState, err := o.executeState(ctx)
		if err != nil {
			o.log.Error("state execution error",
				"state", o.currentState,
				"error", err,
			)
		}

		// Terminal state
		if o.currentState == StateTerminated {
			o.log.Info("orchestrator terminated")
			return nil
		}

		// Transition
		if nextState != o.currentState {
			o.transitionTo(nextState, fmt.Sprintf("from %s", o.currentState))
		}
	}
}

// Shutdown initiates a graceful shutdown.
func (o *Orchestrator) Shutdown() {
	o.log.Info("shutdown requested")
	if o.cancel != nil {
		o.cancel()
	}
	<-o.done
}

// State returns the current FSM state.
func (o *Orchestrator) State() State {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.currentState
}

// Transitions returns the history of state transitions.
func (o *Orchestrator) Transitions() []Transition {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return append([]Transition{}, o.transitions...)
}

// executeState runs the logic for the current state and returns the next state.
func (o *Orchestrator) executeState(ctx context.Context) (State, error) {
	cfg := o.stateConfigs[o.currentState]

	// Apply state timeout (if configured)
	var stateCtx context.Context
	var cancel context.CancelFunc
	if cfg.Timeout > 0 {
		stateCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
	} else {
		stateCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	switch o.currentState {
	case StateColdStart:
		return o.execColdStart(stateCtx)
	case StateHardwareScan:
		return o.execHardwareScan(stateCtx)
	case StateSeedDiscovery:
		return o.execSeedDiscovery(stateCtx)
	case StateVectorRace:
		return o.execVectorRace(stateCtx)
	case StateConnected:
		return o.execConnected(stateCtx)
	case StateDegraded:
		return o.execDegraded(stateCtx)
	case StateHumanRequired:
		return o.execHumanRequired(stateCtx)
	case StateTerminated:
		return StateTerminated, nil
	default:
		return StateTerminated, fmt.Errorf("unknown state: %d", o.currentState)
	}
}

// --- State Implementations ---

// execColdStart loads/generates the node identity and reads configuration.
func (o *Orchestrator) execColdStart(ctx context.Context) (State, error) {
	o.log.Info("cold start: loading identity")

	id, err := crypto.LoadOrCreateIdentity(o.stateDir)
	if err != nil {
		o.log.Error("failed to initialize identity", "error", err)
		return StateTerminated, err
	}

	o.identity = id
	o.log.Info("identity ready",
		"node_id", id.NodeID(),
		"pubkey_hex", fmt.Sprintf("%x", id.PublicKey[:16]),
	)

	return StateHardwareScan, nil
}

// execHardwareScan discovers available hardware devices.
func (o *Orchestrator) execHardwareScan(ctx context.Context) (State, error) {
	o.log.Info("scanning hardware capabilities")

	caps := o.scanner.Scan(ctx)
	o.hwCaps = caps

	if caps.Mask == hwscan.HWNone {
		o.log.Warn("no hardware detected — will attempt software-only vectors")
	}

	// Log available vectors given current hardware
	available := o.registry.Available(caps)
	o.log.Info("available vectors",
		"count", len(available),
		"list", FormatVectorList(available),
	)

	if len(available) == 0 {
		return StateHumanRequired, fmt.Errorf("no vectors available with current hardware")
	}

	return StateSeedDiscovery, nil
}

// execSeedDiscovery attempts to discover bootstrap nodes through all available oracles.
func (o *Orchestrator) execSeedDiscovery(ctx context.Context) (State, error) {
	o.log.Info("discovering seed nodes")

	// TODO: Run seed discovery oracles in parallel:
	// - DNS TXT records via DoH/DoT
	// - Domain Fronting requests
	// - AT-command SMS/USSD queries
	// - Blockchain smart contract reads
	// - ICMP probe sequences
	//
	// For now, proceed to VectorRace with any hardcoded/cached seeds.

	o.seedsMu.RLock()
	seedCount := len(o.seeds)
	o.seedsMu.RUnlock()

	if seedCount == 0 {
		o.log.Warn("no seed nodes found — vectors will attempt blind discovery")
	} else {
		o.log.Info("seed nodes available", "count", seedCount)
	}

	return StateVectorRace, nil
}

// execVectorRace runs the Aggressive Happy Eyeballs algorithm.
func (o *Orchestrator) execVectorRace(ctx context.Context) (State, error) {
	available := o.registry.Available(o.hwCaps)
	if len(available) == 0 {
		return StateHumanRequired, fmt.Errorf("no vectors available")
	}

	racer := NewHappyEyeballs(o.log, available)
	result, err := racer.RaceWithFallback(ctx, 3)
	if err != nil {
		o.log.Error("vector race failed", "error", err)
		return StateHumanRequired, err
	}

	// Store the winning connection
	o.connMu.Lock()
	o.connections = append(o.connections, result.Connection)
	o.connMu.Unlock()

	o.log.Info("tunnel established",
		"vector", result.Vector.Name(),
		"tier", result.Vector.Tier(),
		"latency", result.Duration,
	)

	// Start connection maintenance in background
	go o.maintainConnection(result.Vector, result.Connection)

	return StateConnected, nil
}

// execConnected monitors active connections and triggers degradation if quality drops.
func (o *Orchestrator) execConnected(ctx context.Context) (State, error) {
	o.log.Info("connected — monitoring link quality")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return StateTerminated, ctx.Err()
		case <-ticker.C:
			o.connMu.RLock()
			healthy := false
			for _, conn := range o.connections {
				if conn.Quality.IsHealthy() {
					healthy = true
					break
				}
			}
			o.connMu.RUnlock()

			if !healthy {
				o.log.Warn("all connections degraded")
				return StateDegraded, nil
			}
		}
	}
}

// execDegraded attempts to recover connectivity by racing additional vectors.
func (o *Orchestrator) execDegraded(ctx context.Context) (State, error) {
	o.log.Warn("degraded mode — attempting recovery")

	// Try to establish new connections while keeping existing ones alive
	available := o.registry.Available(o.hwCaps)
	racer := NewHappyEyeballs(o.log, available)

	result, err := racer.Race(ctx)
	if err != nil {
		return StateHumanRequired, err
	}

	o.connMu.Lock()
	o.connections = append(o.connections, result.Connection)
	o.connMu.Unlock()

	go o.maintainConnection(result.Vector, result.Connection)

	return StateConnected, nil
}

// execHumanRequired requests physical intervention from the operator.
func (o *Orchestrator) execHumanRequired(ctx context.Context) (State, error) {
	o.log.Warn("all programmatic vectors exhausted — requesting human intervention")

	// Build a list of possible actions based on missing hardware
	actions := o.buildHumanActions()

	if len(actions) == 0 {
		// Suggest generic actions
		actions = append(actions, cli.HumanAction{
			ID:          "generic_network",
			Priority:    cli.PriorityHigh,
			Description: "Обеспечьте любое сетевое подключение (Wi-Fi, Ethernet, USB-tethering)",
			Deadline:    0, // Wait forever
		})
	}

	// Request action from operator (blocks until human responds or context cancelled)
	for _, action := range actions {
		err := o.operator.Request(ctx, action)
		if err != nil {
			if ctx.Err() != nil {
				return StateTerminated, ctx.Err()
			}
			continue
		}

		// Human confirmed action — rescan hardware
		return StateHardwareScan, nil
	}

	return StateTerminated, fmt.Errorf("operator did not respond")
}

// --- Helper methods ---

// transitionTo changes the FSM state and records the transition.
func (o *Orchestrator) transitionTo(next State, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	t := Transition{
		From:      o.currentState,
		To:        next,
		Reason:    reason,
		Timestamp: time.Now(),
	}
	o.transitions = append(o.transitions, t)
	o.currentState = next

	o.log.Info("state transition",
		"from", t.From,
		"to", t.To,
		"reason", t.Reason,
	)
}

// maintainConnection runs the maintenance loop for a single connection.
func (o *Orchestrator) maintainConnection(v Vector, conn *Connection) {
	ctx, cancel := context.WithCancel(context.Background())
	conn.Cancel = cancel

	err := v.Maintain(ctx, conn)
	if err != nil {
		o.log.Warn("connection maintenance ended",
			"vector", v.Name(),
			"error", err,
		)
	}

	// Mark connection as unhealthy
	conn.Quality.ConsecFails = 999
}

// buildHumanActions generates context-aware actions based on missing hardware.
func (o *Orchestrator) buildHumanActions() []cli.HumanAction {
	var actions []cli.HumanAction

	if !o.hwCaps.Has(hwscan.HWLoRa) {
		actions = append(actions, cli.HumanAction{
			ID:          "attach_lora",
			Priority:    cli.PriorityHigh,
			Description: "Подключите LoRa/Meshtastic трансивер к USB-порту",
			Hardware:    hwscan.HWLoRa,
			Deadline:    5 * time.Minute,
		})
	}

	if !o.hwCaps.Has(hwscan.HWCellModem) {
		actions = append(actions, cli.HumanAction{
			ID:          "attach_modem",
			Priority:    cli.PriorityNormal,
			Description: "Подключите USB-модем с SIM-картой",
			Hardware:    hwscan.HWCellModem,
			Deadline:    5 * time.Minute,
		})
	}

	if !o.hwCaps.Has(hwscan.HWPhoneLine) {
		actions = append(actions, cli.HumanAction{
			ID:          "connect_phone",
			Priority:    cli.PriorityNormal,
			Description: "Подключите аналоговую телефонную линию к модему",
			Hardware:    hwscan.HWPhoneLine,
			Deadline:    10 * time.Minute,
		})
	}

	if !o.hwCaps.Has(hwscan.HWSDR) {
		actions = append(actions, cli.HumanAction{
			ID:          "attach_sdr",
			Priority:    cli.PriorityNormal,
			Description: "Подключите SDR-приёмник (RTL-SDR/HackRF) к USB-порту",
			Hardware:    hwscan.HWSDR,
			Deadline:    5 * time.Minute,
		})
	}

	return actions
}

// AddSeeds adds discovered seed nodes to the Orchestrator's seed pool.
func (o *Orchestrator) AddSeeds(seeds ...crypto.SeedNode) {
	o.seedsMu.Lock()
	defer o.seedsMu.Unlock()
	o.seeds = append(o.seeds, seeds...)
}

// ActiveConnections returns a snapshot of all active connections.
func (o *Orchestrator) ActiveConnections() []*Connection {
	o.connMu.RLock()
	defer o.connMu.RUnlock()
	return append([]*Connection{}, o.connections...)
}
