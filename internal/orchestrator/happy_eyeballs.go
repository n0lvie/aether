package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// RaceResult is the outcome of a single vector probe during Happy Eyeballs.
type RaceResult struct {
	Vector     Vector
	Connection *Connection
	Error      error
	Duration   time.Duration
}

// DefaultTierDelay is the default delay between launching each tier of vectors.
// Gives higher-priority vectors a head start without blocking lower tiers.
const DefaultTierDelay = 2 * time.Second

// HappyEyeballs implements the Aggressive Happy Eyeballs algorithm.
//
// Unlike RFC 8305 which staggers connection attempts with 250ms delays,
// our implementation launches ALL available vectors simultaneously across
// all tiers. The first vector to establish a connection wins; all others
// are cancelled via context cancellation.
//
// Additionally, it implements tiered cascading: if all vectors in the current
// tier fail, it immediately promotes vectors from the next tier. This ensures
// we don't wait for high-tier timeouts before trying lower-level transports.
type HappyEyeballs struct {
	log     *slog.Logger
	vectors []Vector

	// TierDelay is the stagger delay between launching each tier.
	// Configurable to allow the resource scheduler to adjust based on power budget.
	TierDelay time.Duration
}

// NewHappyEyeballs creates a racer with the given set of available vectors.
func NewHappyEyeballs(log *slog.Logger, vectors []Vector) *HappyEyeballs {
	return &HappyEyeballs{
		log:       log,
		vectors:   vectors,
		TierDelay: DefaultTierDelay,
	}
}

// Race launches all vectors in parallel and returns the first successful connection.
//
// Algorithm:
// 1. Group vectors by tier (0-4)
// 2. Launch all vectors in Tier 0 immediately
// 3. After tierDelay, launch next tier (regardless of Tier 0 status)
// 4. First successful connection wins → cancel all others
// 5. If all vectors fail → return aggregate error
//
// The tierDelay provides a small head-start to higher-priority vectors
// without blocking the entire pipeline.
func (he *HappyEyeballs) Race(ctx context.Context) (*RaceResult, error) {
	if len(he.vectors) == 0 {
		return nil, fmt.Errorf("no vectors available for racing")
	}

	// Channel for results (buffered to avoid goroutine leaks)
	results := make(chan RaceResult, len(he.vectors))

	// Master context: cancelling this stops all probes
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	// Group by tier
	tiers := he.groupByTier()

	he.log.Info("starting vector race",
		"total_vectors", len(he.vectors),
		"tiers", len(tiers),
	)

	// Launch all tiers with staggered delays
	var wg sync.WaitGroup

	for tierIdx, tierVectors := range tiers {
		delay := time.Duration(tierIdx) * he.TierDelay

		for _, v := range tierVectors {
			wg.Add(1)
			go func(v Vector, delay time.Duration) {
				defer wg.Done()

				// Wait for tier delay (or cancellation)
				if delay > 0 {
					select {
					case <-time.After(delay):
					case <-raceCtx.Done():
						return
					}
				}

				he.log.Debug("launching vector probe",
					"vector", v.Name(),
					"tier", v.Tier(),
				)

				start := time.Now()
				conn, err := v.Probe(raceCtx)
				dur := time.Since(start)

				results <- RaceResult{
					Vector:     v,
					Connection: conn,
					Error:      err,
					Duration:   dur,
				}
			}(v, delay)
		}
	}

	// Close results channel when all probes complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var errors []RaceResult
	for result := range results {
		if result.Error != nil {
			he.log.Warn("vector probe failed",
				"vector", result.Vector.Name(),
				"tier", result.Vector.Tier(),
				"error", result.Error,
				"duration", result.Duration,
			)
			errors = append(errors, result)
			continue
		}

		// Winner!
		he.log.Info("vector probe succeeded — WINNER",
			"vector", result.Vector.Name(),
			"tier", result.Vector.Tier(),
			"duration", result.Duration,
		)

		// Cancel all other probes
		raceCancel()

		return &result, nil
	}

	// All vectors failed
	return nil, fmt.Errorf("all %d vectors failed: %s",
		len(errors), summarizeErrors(errors))
}

// RaceWithFallback runs Happy Eyeballs with automatic tier escalation.
// If the initial race fails, it retries with progressively longer timeouts.
func (he *HappyEyeballs) RaceWithFallback(ctx context.Context, maxAttempts int) (*RaceResult, error) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Exponential backoff on timeout: 30s, 60s, 120s, ...
		timeout := time.Duration(30<<(attempt-1)) * time.Second
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)

		he.log.Info("race attempt",
			"attempt", attempt,
			"max_attempts", maxAttempts,
			"timeout", timeout,
		)

		result, err := he.Race(attemptCtx)
		cancel()

		if err == nil {
			return result, nil
		}

		he.log.Warn("race attempt failed",
			"attempt", attempt,
			"error", err,
		)

		// Brief pause between attempts
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("exhausted %d race attempts", maxAttempts)
}

// groupByTier organizes vectors into tier-ordered slices.
func (he *HappyEyeballs) groupByTier() [][]Vector {
	tierMap := make(map[int][]Vector)
	maxTier := 0

	for _, v := range he.vectors {
		t := v.Tier()
		tierMap[t] = append(tierMap[t], v)
		if t > maxTier {
			maxTier = t
		}
	}

	result := make([][]Vector, 0, maxTier+1)
	for t := 0; t <= maxTier; t++ {
		if vecs, ok := tierMap[t]; ok {
			result = append(result, vecs)
		}
	}
	return result
}

// summarizeErrors creates a compact error summary from failed probes.
func summarizeErrors(results []RaceResult) string {
	summary := ""
	for i, r := range results {
		if i > 0 {
			summary += "; "
		}
		summary += fmt.Sprintf("%s: %v", r.Vector.Name(), r.Error)
	}
	return summary
}
