// Package resource implements the adaptive Resource Scheduler for Project Aether.
//
// PROBLEM:
//
//	In a Blackout scenario, Aether runs on battery-powered devices:
//	smartphones (Android/iOS), laptops, routers on power banks.
//	The daemon's aggressive behavior — parallel vector racing, Argon2id
//	computation, ML inference, Gossip protocol — drains batteries fast.
//	A dead device is a dead mesh node. Kill too many nodes → topology collapse.
//
// SOLUTION:
//
//	The Resource Scheduler reads system metrics (battery, CPU, memory, thermal)
//	and dynamically adjusts the daemon's behavior across 5 Power Tiers.
//	Each tier throttles specific subsystems to extend device lifetime.
//
// DESIGN PRINCIPLES:
//  1. The daemon MUST NOT kill its host. Self-preservation of the device
//     takes absolute priority over network participation.
//  2. Graceful degradation: shed load gradually, don't cliff-edge.
//  3. Role demotion: Relay → Client → Hibernate. Never the reverse unless
//     power is restored (charger connected, solar panel, etc.).
//  4. State persistence: save state to disk before emergency shutdown
//     so the node can resume instantly when power returns.
package resource

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// --- Node Roles ---

// NodeRole determines the level of network participation.
type NodeRole uint8

const (
	// RoleRelay: full participation. Relay packets for others, serve PoW
	// challenges, run Gossip protocol, accept OTA updates, run ML inference.
	// Power cost: HIGH (~500mW continuous on mobile).
	RoleRelay NodeRole = iota

	// RoleClient: maintain own connection only. No relaying, reduced Gossip,
	// no PoW serving. Accept incoming connections but don't initiate for others.
	// Power cost: MEDIUM (~150mW continuous).
	RoleClient

	// RoleLowPower: minimal client. Single best vector only, no Gossip,
	// no ML inference (use static obfuscation), reduced keepalive frequency.
	// Power cost: LOW (~50mW continuous).
	RoleLowPower

	// RoleHibernate: near-zero activity. Periodic heartbeat only (every 5min).
	// Wake on external event (BLE advertisement, incoming TCP, USB hotplug).
	// Power cost: MINIMAL (~5mW).
	RoleHibernate

	// RoleEmergencyShutdown: save state to disk and exit cleanly.
	// This is not a role but a terminal action.
	RoleEmergencyShutdown
)

func (r NodeRole) String() string {
	names := [...]string{"Relay", "Client", "LowPower", "Hibernate", "EmergencyShutdown"}
	if int(r) < len(names) {
		return names[r]
	}
	return fmt.Sprintf("Unknown(%d)", r)
}

// --- Power Tiers ---

// PowerTier maps battery percentage to operational constraints.
type PowerTier struct {
	// MinBattery is the minimum battery percentage for this tier (inclusive).
	MinBattery int

	// Role is the maximum allowed role in this tier.
	Role NodeRole

	// MaxParallelVectors limits Happy Eyeballs concurrency.
	// Fewer vectors = less CPU/network, slower but more power-efficient.
	MaxParallelVectors int

	// GossipInterval is the time between Gossip rounds.
	// Higher = less network activity = less power.
	GossipInterval time.Duration

	// KeepaliveInterval is the time between connection keepalive probes.
	KeepaliveInterval time.Duration

	// AllowMLInference enables/disables ML-based traffic obfuscation.
	// When disabled, falls back to static XOR/padding obfuscation.
	AllowMLInference bool

	// AllowRelay enables/disables packet relaying for other nodes.
	AllowRelay bool

	// AllowPoWServing enables/disables serving PoW challenges to joiners.
	AllowPoWServing bool

	// HardwareScanInterval is the time between hardware rescans.
	HardwareScanInterval time.Duration
}

// DefaultPowerTiers returns the 5-tier power management configuration.
//
// These values are calibrated for a typical smartphone (3000-5000 mAh):
//   - Tier 1 (>80%): ~6-8 hours as Relay
//   - Tier 2 (50-80%): ~10-14 hours as Client
//   - Tier 3 (20-50%): ~24-36 hours as LowPower
//   - Tier 4 (5-20%): ~48+ hours in Hibernate
//   - Tier 5 (<5%): Emergency shutdown (save state)
func DefaultPowerTiers() []PowerTier {
	return []PowerTier{
		{
			MinBattery:           80,
			Role:                 RoleRelay,
			MaxParallelVectors:   8,
			GossipInterval:       30 * time.Second,
			KeepaliveInterval:    30 * time.Second,
			AllowMLInference:     true,
			AllowRelay:           true,
			AllowPoWServing:      true,
			HardwareScanInterval: 60 * time.Second,
		},
		{
			MinBattery:           50,
			Role:                 RoleClient,
			MaxParallelVectors:   4,
			GossipInterval:       2 * time.Minute,
			KeepaliveInterval:    60 * time.Second,
			AllowMLInference:     true,
			AllowRelay:           false,
			AllowPoWServing:      false,
			HardwareScanInterval: 5 * time.Minute,
		},
		{
			MinBattery:           20,
			Role:                 RoleLowPower,
			MaxParallelVectors:   2,
			GossipInterval:       5 * time.Minute,
			KeepaliveInterval:    2 * time.Minute,
			AllowMLInference:     false, // Static obfuscation only
			AllowRelay:           false,
			AllowPoWServing:      false,
			HardwareScanInterval: 30 * time.Minute,
		},
		{
			MinBattery:           5,
			Role:                 RoleHibernate,
			MaxParallelVectors:   1,
			GossipInterval:       30 * time.Minute,
			KeepaliveInterval:    5 * time.Minute,
			AllowMLInference:     false,
			AllowRelay:           false,
			AllowPoWServing:      false,
			HardwareScanInterval: 0, // No rescans
		},
		{
			MinBattery:           0,
			Role:                 RoleEmergencyShutdown,
			MaxParallelVectors:   0,
			GossipInterval:       0,
			KeepaliveInterval:    0,
			AllowMLInference:     false,
			AllowRelay:           false,
			AllowPoWServing:      false,
			HardwareScanInterval: 0,
		},
	}
}

// --- System Metrics ---

// HostMetrics represents the current state of the host device.
type HostMetrics struct {
	// BatteryPercent is the current battery level (0-100).
	// -1 means "unknown" (e.g., desktop with no battery).
	BatteryPercent int

	// IsCharging is true if the device is connected to external power.
	IsCharging bool

	// CPUUsagePercent is the system-wide CPU utilization (0-100).
	CPUUsagePercent int

	// MemoryUsagePercent is the system-wide memory utilization (0-100).
	MemoryUsagePercent int

	// ThermalThrottling is true if the device is thermally throttled.
	// On mobile, sustained computation causes thermal throttling which
	// both slows the CPU and accelerates battery drain.
	ThermalThrottling bool

	// UptimeSeconds is how long the device has been running.
	UptimeSeconds int64

	// Timestamp is when these metrics were collected.
	Timestamp time.Time
}

// --- Metrics Provider Interface ---

// MetricsProvider abstracts platform-specific system metric collection.
//
// Implementations:
//   - LinuxMetricsProvider:   reads /sys/class/power_supply/, /proc/stat
//   - AndroidMetricsProvider: reads Battery API via JNI bridge
//   - DarwinMetricsProvider:  reads IOKit battery info
//   - FallbackProvider:       assumes desktop (unlimited power)
type MetricsProvider interface {
	// Collect reads current system metrics. Thread-safe.
	Collect() (HostMetrics, error)

	// Platform returns the platform name for logging.
	Platform() string
}

// FallbackMetricsProvider is used on platforms where battery info is unavailable.
// It assumes unlimited power (desktop/server) and always returns RoleRelay.
type FallbackMetricsProvider struct{}

func (f *FallbackMetricsProvider) Collect() (HostMetrics, error) {
	return HostMetrics{
		BatteryPercent:     -1, // Unknown
		IsCharging:         true,
		CPUUsagePercent:    0,
		MemoryUsagePercent: 0,
		ThermalThrottling:  false,
		Timestamp:          time.Now(),
	}, nil
}

func (f *FallbackMetricsProvider) Platform() string { return "fallback" }

// LinuxMetricsProvider reads battery info from /sys/class/power_supply/.
//
// Paths:
//
//	/sys/class/power_supply/BAT0/capacity         → battery percent
//	/sys/class/power_supply/BAT0/status            → "Charging", "Discharging", "Full"
//	/sys/class/thermal/thermal_zone0/temp           → CPU temperature (millidegrees)
//
// On OpenWrt routers without battery:
//
//	Falls back to FallbackMetricsProvider behavior.
type LinuxMetricsProvider struct {
	batteryPath string // e.g., "/sys/class/power_supply/BAT0"
}

func NewLinuxMetricsProvider() *LinuxMetricsProvider {
	return &LinuxMetricsProvider{
		batteryPath: "/sys/class/power_supply/BAT0",
	}
}

func (l *LinuxMetricsProvider) Platform() string { return "linux" }

func (l *LinuxMetricsProvider) Collect() (HostMetrics, error) {
	// TODO: Implementation
	// 1. Read /sys/class/power_supply/BAT0/capacity → int
	// 2. Read /sys/class/power_supply/BAT0/status → string
	// 3. Read /proc/stat → compute CPU usage
	// 4. Read /proc/meminfo → compute memory usage
	// 5. Read /sys/class/thermal/thermal_zone0/temp → check throttle threshold
	//
	// If battery path doesn't exist (router), return BatteryPercent=-1
	return HostMetrics{
		BatteryPercent: -1,
		IsCharging:     true,
		Timestamp:      time.Now(),
	}, nil
}

// --- Resource Scheduler ---

// Scheduler monitors host resources and dynamically adjusts daemon behavior.
type Scheduler struct {
	log      *slog.Logger
	provider MetricsProvider
	tiers    []PowerTier

	mu          sync.RWMutex
	currentRole NodeRole
	currentTier *PowerTier
	lastMetrics HostMetrics
	callbacks   []RoleChangeCallback

	// Override: if set, the role is locked regardless of battery state.
	// Used when the operator manually forces a role via CLI.
	roleOverride *NodeRole

	// Hysteresis: prevent rapid role oscillation when battery is at a threshold.
	// Role demotion happens immediately; promotion requires sustained charge
	// above the threshold for this duration.
	PromotionDelay time.Duration

	// Track when we last crossed a promotion threshold
	promotionEligibleSince time.Time
}

// RoleChangeCallback is called when the node's role changes.
type RoleChangeCallback func(oldRole, newRole NodeRole, metrics HostMetrics)

// NewScheduler creates a new resource scheduler.
func NewScheduler(log *slog.Logger, provider MetricsProvider) *Scheduler {
	if provider == nil {
		provider = &FallbackMetricsProvider{}
	}

	tiers := DefaultPowerTiers()

	return &Scheduler{
		log:            log,
		provider:       provider,
		tiers:          tiers,
		currentRole:    RoleRelay, // Start optimistic
		currentTier:    &tiers[0],
		PromotionDelay: 5 * time.Minute, // Require 5min of sustained charge before promoting
	}
}

// OnRoleChange registers a callback for role change events.
func (s *Scheduler) OnRoleChange(cb RoleChangeCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callbacks = append(s.callbacks, cb)
}

// ForceRole overrides the automatic role selection.
// Pass nil to clear the override and resume automatic management.
func (s *Scheduler) ForceRole(role *NodeRole) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.roleOverride = role
	if role != nil {
		s.log.Warn("role override set",
			"forced_role", role.String(),
		)
	} else {
		s.log.Info("role override cleared — resuming automatic management")
	}
}

// Evaluate reads current metrics and adjusts the role if needed.
// This should be called periodically (e.g., every 30 seconds).
// Returns the current PowerTier constraints for the orchestrator to use.
func (s *Scheduler) Evaluate() (*PowerTier, error) {
	metrics, err := s.provider.Collect()
	if err != nil {
		return s.CurrentTier(), fmt.Errorf("collect metrics: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastMetrics = metrics

	// If role is overridden, skip evaluation
	if s.roleOverride != nil {
		return s.currentTier, nil
	}

	// Determine target tier based on battery
	targetTier := s.determineTier(metrics)

	// If charging, allow full relay (override battery-based demotion)
	if metrics.IsCharging && metrics.BatteryPercent > 10 {
		targetTier = &s.tiers[0] // Full relay when plugged in
	}

	// Unknown battery (desktop/router) → always relay
	if metrics.BatteryPercent < 0 {
		targetTier = &s.tiers[0]
	}

	// Apply thermal throttle override: if device is overheating,
	// demote by one tier regardless of battery level.
	// NodeRole enum: Relay(0) < Client(1) < LowPower(2) < Hibernate(3) < Shutdown(4).
	// We only demote if current target is more aggressive than LowPower.
	if metrics.ThermalThrottling && targetTier.Role < RoleLowPower {
		demotedRole := targetTier.Role + 1
		for i := range s.tiers {
			if s.tiers[i].Role == demotedRole {
				s.log.Warn("thermal throttle: demoting role",
					"from", targetTier.Role,
					"to", s.tiers[i].Role,
					"cpu_temp", "throttled",
				)
				targetTier = &s.tiers[i]
				break
			}
		}
	}

	oldRole := s.currentRole
	newRole := targetTier.Role

	// Hysteresis: demotions are immediate, promotions require sustained improvement.
	// NOTE: Higher NodeRole enum value = more conservative (Relay=0 < Hibernate=3).
	// So newRole > oldRole means DEMOTION (moving to power-saving mode).
	if newRole > oldRole {
		// Demotion (more conservative): apply immediately (battery is draining, act fast)
		s.currentRole = newRole
		s.currentTier = targetTier
		s.promotionEligibleSince = time.Time{} // Reset promotion timer

		s.log.Warn("power tier DEMOTION",
			"from", oldRole,
			"to", newRole,
			"battery", metrics.BatteryPercent,
			"charging", metrics.IsCharging,
		)

		// Notify callbacks
		for _, cb := range s.callbacks {
			cb(oldRole, newRole, metrics)
		}
	} else if newRole < oldRole {
		// Promotion (more aggressive): require sustained improvement
		if s.promotionEligibleSince.IsZero() {
			s.promotionEligibleSince = time.Now()
			s.log.Debug("promotion eligible, waiting for hysteresis",
				"target", newRole,
				"delay", s.PromotionDelay,
			)
		} else if time.Since(s.promotionEligibleSince) >= s.PromotionDelay {
			// Sustained — promote
			s.currentRole = newRole
			s.currentTier = targetTier
			s.promotionEligibleSince = time.Time{}

			s.log.Info("power tier PROMOTION",
				"from", oldRole,
				"to", newRole,
				"battery", metrics.BatteryPercent,
				"charging", metrics.IsCharging,
			)

			for _, cb := range s.callbacks {
				cb(oldRole, newRole, metrics)
			}
		}
	}

	return s.currentTier, nil
}

// determineTier finds the appropriate power tier for the given battery level.
func (s *Scheduler) determineTier(metrics HostMetrics) *PowerTier {
	for i := range s.tiers {
		if metrics.BatteryPercent >= s.tiers[i].MinBattery {
			return &s.tiers[i]
		}
	}
	// Fallback to most conservative tier
	return &s.tiers[len(s.tiers)-1]
}

// CurrentRole returns the current node role.
func (s *Scheduler) CurrentRole() NodeRole {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentRole
}

// CurrentTier returns the current power tier constraints.
func (s *Scheduler) CurrentTier() *PowerTier {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentTier
}

// LastMetrics returns the most recent host metrics.
func (s *Scheduler) LastMetrics() HostMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastMetrics
}

// ShouldShutdown returns true if the device must perform emergency shutdown.
func (s *Scheduler) ShouldShutdown() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentRole == RoleEmergencyShutdown
}

// --- Power Budget ---

// PowerBudget provides per-subsystem resource limits based on the current tier.
// The orchestrator reads these before executing expensive operations.
type PowerBudget struct {
	// MaxConcurrentVectors for Happy Eyeballs.
	MaxConcurrentVectors int

	// GossipInterval between Gossip rounds.
	GossipInterval time.Duration

	// KeepaliveInterval between keepalive probes.
	KeepaliveInterval time.Duration

	// AllowMLInference enables ML-based obfuscation.
	AllowMLInference bool

	// AllowRelay enables packet relaying for other nodes.
	AllowRelay bool

	// AllowPoWServing enables serving PoW challenges.
	AllowPoWServing bool

	// Role is the current node role.
	Role NodeRole
}

// Budget returns the current power budget for the orchestrator.
func (s *Scheduler) Budget() PowerBudget {
	tier := s.CurrentTier()
	return PowerBudget{
		MaxConcurrentVectors: tier.MaxParallelVectors,
		GossipInterval:       tier.GossipInterval,
		KeepaliveInterval:    tier.KeepaliveInterval,
		AllowMLInference:     tier.AllowMLInference,
		AllowRelay:           tier.AllowRelay,
		AllowPoWServing:      tier.AllowPoWServing,
		Role:                 tier.Role,
	}
}
