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

// MaxTransitionHistory is the maximum number of FSM transitions kept in memory.
// Prevents unbounded growth in long-running daemons (months of uptime).
// 1000 transitions × ~100 bytes each ≈ 100KB hard cap.
const MaxTransitionHistory = 1000

// Orchestrator is the central FSM that manages the daemon's lifecycle.
// It coordinates hardware discovery, seed resolution, vector racing,
// connection maintenance, and human operator interaction.
type Orchestrator struct {
	log      *slog.Logger
	stateDir string

	// FSM
	currentState State
	stateConfigs map[State]StateConfig
	// Ring buffer for transition history (bounded at MaxTransitionHistory).
	// Prevents memory leak reported in review: in long-running daemons,
	// the old slice-based approach would grow without bound.
	transitions []Transition
	transHead   int // Next write position in ring buffer
	transCount  int // Total transitions recorded (including overwritten)
	mu          sync.RWMutex

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
	runCtx context.Context // Stored from Run() for child goroutines
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
		transitions:  make([]Transition, MaxTransitionHistory),
		registry:     registry,
		scanner:      hwscan.NewScanner(log),
		operator:     cli.NewOperator(log),
		done:         make(chan struct{}),
	}
}

// Run starts the FSM main loop. Blocks until shutdown or fatal error.
func (o *Orchestrator) Run(ctx context.Context) error {
	ctx, o.cancel = context.WithCancel(ctx)
	o.runCtx = ctx // Store for maintainConnection child goroutines
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

// Transitions returns the history of state transitions in chronological order.
// Returns at most MaxTransitionHistory entries.
func (o *Orchestrator) Transitions() []Transition {
	o.mu.RLock()
	defer o.mu.RUnlock()

	count := o.transCount
	if count > MaxTransitionHistory {
		count = MaxTransitionHistory
	}

	result := make([]Transition, 0, count)
	for i := 0; i < count; i++ {
		idx := (o.transHead - count + i + MaxTransitionHistory) % MaxTransitionHistory
		result = append(result, o.transitions[idx])
	}
	return result
}

// executeState runs the logic for the current state with retry support.
// Respects StateConfig.MaxRetries and StateConfig.NextOnFailure.
func (o *Orchestrator) executeState(ctx context.Context) (State, error) {
	cfg := o.stateConfigs[o.currentState]

	maxAttempts := cfg.MaxRetries + 1 // MaxRetries=0 means 1 attempt
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Apply state timeout (if configured)
		var stateCtx context.Context
		var cancel context.CancelFunc
		if cfg.Timeout > 0 {
			stateCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		} else {
			stateCtx, cancel = context.WithCancel(ctx)
		}

		nextState, err := o.dispatchState(stateCtx)
		cancel()

		if err == nil {
			return nextState, nil
		}

		lastErr = err

		// Don't retry if context was cancelled (shutdown)
		if ctx.Err() != nil {
			return StateTerminated, ctx.Err()
		}

		if attempt < maxAttempts {
			o.log.Warn("state execution failed, retrying",
				"state", o.currentState,
				"attempt", attempt,
				"max_attempts", maxAttempts,
				"error", err,
			)
			// Brief pause between retries (backoff: 1s, 2s, 4s, ...)
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return StateTerminated, ctx.Err()
			}
		}
	}

	// All retries exhausted → use NextOnFailure from config
	o.log.Error("state retries exhausted",
		"state", o.currentState,
		"retries", cfg.MaxRetries,
		"error", lastErr,
		"next", cfg.NextOnFailure,
	)
	return cfg.NextOnFailure, lastErr
}

// dispatchState routes to the appropriate state handler.
func (o *Orchestrator) dispatchState(ctx context.Context) (State, error) {
	switch o.currentState {
	case StateColdStart:
		return o.execColdStart(ctx)
	case StateHardwareScan:
		return o.execHardwareScan(ctx)
	case StateSeedDiscovery:
		return o.execSeedDiscovery(ctx)
	case StateVectorRace:
		return o.execVectorRace(ctx)
	case StateConnected:
		return o.execConnected(ctx)
	case StateDegraded:
		return o.execDegraded(ctx)
	case StateHumanRequired:
		return o.execHumanRequired(ctx)
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

// SeedOracle is an interface for seed node discovery mechanisms.
// Each oracle independently queries one source (DNS, SMS, blockchain, etc.)
// and returns any discovered seed nodes.
type SeedOracle interface {
	// Name returns the oracle identifier for logging.
	Name() string
	// Discover queries the oracle and returns discovered seeds.
	// Must respect context cancellation.
	Discover(ctx context.Context) ([]crypto.SeedNode, error)
}

// execSeedDiscovery runs all available oracles in parallel and collects results.
// Uses goroutines + shared results channel (same pattern as Happy Eyeballs).
func (o *Orchestrator) execSeedDiscovery(ctx context.Context) (State, error) {
	o.log.Info("discovering seed nodes via parallel oracles")

	// Collect registered oracles
	oracles := o.buildSeedOracles()

	if len(oracles) == 0 {
		o.log.Warn("no seed oracles configured — using cached seeds only")
	} else {
		// Run all oracles in parallel
		type oracleResult struct {
			name  string
			seeds []crypto.SeedNode
			err   error
		}

		results := make(chan oracleResult, len(oracles))
		var wg sync.WaitGroup

		for _, oracle := range oracles {
			wg.Add(1)
			go func(orc SeedOracle) {
				defer wg.Done()
				seeds, err := orc.Discover(ctx)
				results <- oracleResult{
					name:  orc.Name(),
					seeds: seeds,
					err:   err,
				}
			}(oracle)
		}

		// Close results channel when all oracles finish
		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect all discovered seeds
		for res := range results {
			if res.err != nil {
				o.log.Debug("oracle failed",
					"oracle", res.name,
					"error", res.err,
				)
				continue
			}
			if len(res.seeds) > 0 {
				o.log.Info("oracle discovered seeds",
					"oracle", res.name,
					"count", len(res.seeds),
				)
				o.AddSeeds(res.seeds...)
			}
		}
	}

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

// buildSeedOracles returns the available seed discovery oracles.
// In production, these would be populated from configuration.
func (o *Orchestrator) buildSeedOracles() []SeedOracle {
	return []SeedOracle{
		NewDoHOracle("seeds.aether.network"),
	}
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

	// Periodic cleanup to prevent stale connection accumulation
	cleanupTicker := time.NewTicker(60 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return StateTerminated, ctx.Err()
		case <-cleanupTicker.C:
			o.pruneDeadConnections()
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

// transitionTo changes the FSM state and records the transition in the ring buffer.
func (o *Orchestrator) transitionTo(next State, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	t := Transition{
		From:      o.currentState,
		To:        next,
		Reason:    reason,
		Timestamp: time.Now(),
	}

	// Write to ring buffer (O(1), bounded memory)
	o.transitions[o.transHead] = t
	o.transHead = (o.transHead + 1) % MaxTransitionHistory
	o.transCount++

	o.currentState = next

	o.log.Info("state transition",
		"from", t.From,
		"to", t.To,
		"reason", t.Reason,
	)
}

// maintainConnection runs the maintenance loop for a single connection.
// The goroutine is derived from the orchestrator's run context, ensuring
// it is cancelled on shutdown (fixes orphaned goroutine bug).
func (o *Orchestrator) maintainConnection(v Vector, conn *Connection) {
	// Guard: if Run() hasn't been called yet, runCtx may be nil.
	if o.runCtx == nil {
		o.log.Error("maintainConnection called before Run() — cannot start maintenance",
			"vector", v.Name(),
		)
		conn.Quality.ConsecFails = 999
		return
	}

	// Derive from runCtx so shutdown cancels all maintenance goroutines.
	// Previously used context.Background() which leaked goroutines.
	ctx, cancel := context.WithCancel(o.runCtx)
	conn.Cancel = cancel

	err := v.Maintain(ctx, conn)
	if err != nil && ctx.Err() == nil {
		// Only log if not shutdown-triggered
		o.log.Warn("connection maintenance ended",
			"vector", v.Name(),
			"error", err,
		)
	}

	// Mark connection as unhealthy
	conn.Quality.ConsecFails = 999
}

// pruneDeadConnections removes connections that are no longer healthy
// from the connections slice. This prevents unbounded memory growth
// in long-running daemons.
func (o *Orchestrator) pruneDeadConnections() {
	o.connMu.Lock()
	defer o.connMu.Unlock()

	alive := make([]*Connection, 0, len(o.connections))
	pruned := 0
	for _, conn := range o.connections {
		if conn.Quality.ConsecFails >= 999 {
			// Cancel the maintenance goroutine if still running
			if conn.Cancel != nil {
				conn.Cancel()
			}
			pruned++
			continue
		}
		alive = append(alive, conn)
	}
	o.connections = alive

	if pruned > 0 {
		o.log.Info("pruned dead connections", "count", pruned, "remaining", len(alive))
	}
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
