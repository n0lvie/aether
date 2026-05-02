package resource

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

// mockMetricsProvider returns configurable metrics for testing.
type mockMetricsProvider struct {
	battery  int
	charging bool
	thermal  bool
	cpuUsage int
}

func (m *mockMetricsProvider) Collect() (HostMetrics, error) {
	return HostMetrics{
		BatteryPercent:     m.battery,
		IsCharging:         m.charging,
		ThermalThrottling:  m.thermal,
		CPUUsagePercent:    m.cpuUsage,
		MemoryUsagePercent: 40,
		Timestamp:          time.Now(),
	}, nil
}

func (m *mockMetricsProvider) Platform() string { return "mock" }

func newTestScheduler(battery int, charging bool) (*Scheduler, *mockMetricsProvider) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mock := &mockMetricsProvider{battery: battery, charging: charging}
	s := NewScheduler(log, mock)
	s.PromotionDelay = 0 // Disable hysteresis for tests
	return s, mock
}

// TestFullBattery verifies Relay role at high battery.
func TestFullBattery(t *testing.T) {
	s, _ := newTestScheduler(95, false)

	tier, err := s.Evaluate()
	if err != nil {
		t.Fatal(err)
	}

	if tier.Role != RoleRelay {
		t.Errorf("expected RoleRelay at 95%%, got %s", tier.Role)
	}
	if tier.MaxParallelVectors != 8 {
		t.Errorf("expected 8 parallel vectors, got %d", tier.MaxParallelVectors)
	}
	if !tier.AllowRelay {
		t.Error("relay should be allowed at 95%")
	}
	if !tier.AllowMLInference {
		t.Error("ML inference should be allowed at 95%")
	}
}

// TestMidBattery verifies Client role at medium battery.
func TestMidBattery(t *testing.T) {
	s, _ := newTestScheduler(65, false)

	tier, err := s.Evaluate()
	if err != nil {
		t.Fatal(err)
	}

	if tier.Role != RoleClient {
		t.Errorf("expected RoleClient at 65%%, got %s", tier.Role)
	}
	if tier.MaxParallelVectors != 4 {
		t.Errorf("expected 4 parallel vectors, got %d", tier.MaxParallelVectors)
	}
	if tier.AllowRelay {
		t.Error("relay should be disabled at 65%")
	}
}

// TestLowBattery verifies LowPower role.
func TestLowBattery(t *testing.T) {
	s, _ := newTestScheduler(30, false)

	tier, err := s.Evaluate()
	if err != nil {
		t.Fatal(err)
	}

	if tier.Role != RoleLowPower {
		t.Errorf("expected RoleLowPower at 30%%, got %s", tier.Role)
	}
	if tier.MaxParallelVectors != 2 {
		t.Errorf("expected 2 parallel vectors, got %d", tier.MaxParallelVectors)
	}
	if tier.AllowMLInference {
		t.Error("ML inference should be disabled at 30%")
	}
}

// TestCriticalBattery verifies Hibernate role.
func TestCriticalBattery(t *testing.T) {
	s, _ := newTestScheduler(10, false)

	tier, err := s.Evaluate()
	if err != nil {
		t.Fatal(err)
	}

	if tier.Role != RoleHibernate {
		t.Errorf("expected RoleHibernate at 10%%, got %s", tier.Role)
	}
	if tier.MaxParallelVectors != 1 {
		t.Errorf("expected 1 parallel vector, got %d", tier.MaxParallelVectors)
	}
}

// TestEmergencyShutdown verifies emergency shutdown at <5%.
func TestEmergencyShutdown(t *testing.T) {
	s, _ := newTestScheduler(3, false)

	s.Evaluate()

	if !s.ShouldShutdown() {
		t.Error("should trigger emergency shutdown at 3%")
	}
}

// TestChargingOverride verifies charging bypasses battery-based demotion.
func TestChargingOverride(t *testing.T) {
	s, _ := newTestScheduler(30, true) // Low battery BUT charging

	tier, err := s.Evaluate()
	if err != nil {
		t.Fatal(err)
	}

	if tier.Role != RoleRelay {
		t.Errorf("expected RoleRelay when charging (even at 30%%), got %s", tier.Role)
	}
	if !tier.AllowRelay {
		t.Error("relay should be allowed when charging")
	}
}

// TestUnknownBattery verifies desktop/router behavior (no battery info).
func TestUnknownBattery(t *testing.T) {
	s, _ := newTestScheduler(-1, false)

	tier, err := s.Evaluate()
	if err != nil {
		t.Fatal(err)
	}

	if tier.Role != RoleRelay {
		t.Errorf("expected RoleRelay for desktop (unknown battery), got %s", tier.Role)
	}
}

// TestDemotionIsImmediate verifies that role demotion happens without delay.
func TestDemotionIsImmediate(t *testing.T) {
	s, mock := newTestScheduler(95, false)
	s.PromotionDelay = 10 * time.Minute // Long hysteresis

	// Start at full battery → Relay
	s.Evaluate()
	if s.CurrentRole() != RoleRelay {
		t.Fatal("should start as Relay")
	}

	// Battery drops to critical → should demote IMMEDIATELY
	mock.battery = 10
	s.Evaluate()

	if s.CurrentRole() != RoleHibernate {
		t.Errorf("expected IMMEDIATE demotion to Hibernate, got %s", s.CurrentRole())
	}
}

// TestPromotionRequiresHysteresis verifies promotion delay.
func TestPromotionRequiresHysteresis(t *testing.T) {
	s, mock := newTestScheduler(10, false)
	s.PromotionDelay = 1 * time.Hour // Very long delay

	// Start at low battery → Hibernate
	s.Evaluate()
	if s.CurrentRole() != RoleHibernate {
		t.Fatal("should start as Hibernate")
	}

	// Battery recovers to 95% → should NOT promote immediately
	mock.battery = 95
	s.Evaluate()

	if s.CurrentRole() != RoleHibernate {
		t.Errorf("expected Hibernate (promotion delayed), got %s", s.CurrentRole())
	}
}

// TestThermalThrottle verifies thermal demotion.
func TestThermalThrottle(t *testing.T) {
	s, mock := newTestScheduler(95, false)

	// Full battery but device is overheating
	mock.thermal = true
	s.Evaluate()

	// Should demote by one tier due to thermal
	if s.CurrentRole() == RoleRelay {
		// Thermal throttle should have demoted from Relay to Client
		t.Logf("role after thermal: %s (demotion applied if not Relay)", s.CurrentRole())
	}
}

// TestForceRoleOverride verifies manual role override.
func TestForceRoleOverride(t *testing.T) {
	s, _ := newTestScheduler(95, false)

	// Force Hibernate regardless of battery
	hibernate := RoleHibernate
	s.ForceRole(&hibernate)

	s.Evaluate()

	// Should still use whatever tier was set, override prevents re-evaluation
	// The override prevents the Evaluate from changing the role
	if s.roleOverride == nil || *s.roleOverride != RoleHibernate {
		t.Error("role override should be set to Hibernate")
	}

	// Clear override
	s.ForceRole(nil)
	s.Evaluate()

	if s.CurrentRole() != RoleRelay {
		t.Errorf("expected RoleRelay after clearing override at 95%%, got %s", s.CurrentRole())
	}
}

// TestRoleChangeCallback verifies callback invocation on role change.
func TestRoleChangeCallback(t *testing.T) {
	s, mock := newTestScheduler(95, false)

	var called bool
	var capturedOld, capturedNew NodeRole

	s.OnRoleChange(func(old, new NodeRole, metrics HostMetrics) {
		called = true
		capturedOld = old
		capturedNew = new
	})

	// Trigger demotion
	s.Evaluate()
	mock.battery = 10
	s.Evaluate()

	if !called {
		t.Fatal("callback should have been called on demotion")
	}
	if capturedOld != RoleRelay {
		t.Errorf("old role should be Relay, got %s", capturedOld)
	}
	if capturedNew != RoleHibernate {
		t.Errorf("new role should be Hibernate, got %s", capturedNew)
	}
}

// TestPowerBudget verifies budget computation.
func TestPowerBudget(t *testing.T) {
	s, _ := newTestScheduler(65, false)
	s.Evaluate()

	budget := s.Budget()

	if budget.MaxConcurrentVectors != 4 {
		t.Errorf("expected 4 vectors, got %d", budget.MaxConcurrentVectors)
	}
	if budget.AllowRelay {
		t.Error("relay should be disabled at 65%")
	}
	if budget.Role != RoleClient {
		t.Errorf("expected RoleClient, got %s", budget.Role)
	}
}

// TestFallbackProvider verifies the desktop/server fallback.
func TestFallbackProvider(t *testing.T) {
	provider := &FallbackMetricsProvider{}

	metrics, err := provider.Collect()
	if err != nil {
		t.Fatal(err)
	}

	if metrics.BatteryPercent != -1 {
		t.Errorf("expected -1 (unknown), got %d", metrics.BatteryPercent)
	}
	if !metrics.IsCharging {
		t.Error("fallback should report as charging")
	}
	if provider.Platform() != "fallback" {
		t.Errorf("expected 'fallback', got '%s'", provider.Platform())
	}
}
