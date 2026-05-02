// Package cli implements the Human Operator Interface.
//
// When all programmatic connectivity vectors are exhausted, the Orchestrator
// transitions to HumanRequired state and uses this package to request physical
// intervention through the terminal. The operator is asked to perform
// specific hardware actions (e.g., plug in a LoRa antenna, enable hotspot).
//
// Design principles:
// - Output goes to stderr (so stdout can be piped)
// - Supports non-interactive mode (auto-detect hardware hotplug)
// - Localized prompts (RU/EN)
// - Color-coded priority levels via ANSI escape codes
package cli

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aether-project/aether/internal/hwscan"
)

// ActionPriority defines the urgency of a human action request.
type ActionPriority int

const (
	PriorityNormal   ActionPriority = 0
	PriorityHigh     ActionPriority = 1
	PriorityCritical ActionPriority = 2
)

// HumanAction describes a physical action the operator must perform.
type HumanAction struct {
	ID          string              // Unique identifier (e.g., "attach_lora")
	Priority    ActionPriority      // Visual urgency level
	Description string              // Human-readable instruction
	Hardware    hwscan.HardwareType // Expected hardware (for auto-detection)
	Deadline    time.Duration       // 0 = wait indefinitely
	Callback    func() bool         // Optional: auto-verify action was performed
}

// Operator manages the CLI interface for human interaction.
type Operator struct {
	log    *slog.Logger
	reader *bufio.Reader
	lang   Language
}

// Language for CLI prompts.
type Language int

const (
	LangEN Language = iota
)

// NewOperator creates a new CLI operator interface.
func NewOperator(log *slog.Logger) *Operator {
	return &Operator{
		log:    log,
		reader: bufio.NewReader(os.Stdin),
		lang:   LangEN, // Default: English
	}
}

// SetLanguage changes the CLI language.
func (o *Operator) SetLanguage(lang Language) {
	o.lang = lang
}

// Request displays an action request to the operator and waits for confirmation.
//
// Behavior:
// 1. Print a formatted, color-coded prompt to stderr
// 2. If a Callback is provided, poll it every 2s (auto-detection)
// 3. Otherwise, wait for Enter key on stdin
// 4. Respect context cancellation and deadline
func (o *Operator) Request(ctx context.Context, action HumanAction) error {
	// Apply deadline if set
	if action.Deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, action.Deadline)
		defer cancel()
	}

	// Display the prompt
	o.printPrompt(action)

	// If we have a callback, try auto-detection first
	if action.Callback != nil {
		return o.waitWithAutoDetect(ctx, action)
	}

	// Otherwise, wait for manual confirmation
	return o.waitForConfirmation(ctx, action)
}

// waitWithAutoDetect polls the callback and also accepts manual confirmation.
func (o *Operator) waitWithAutoDetect(ctx context.Context, action HumanAction) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Also listen for manual input in a goroutine
	inputCh := make(chan struct{}, 1)
	go func() {
		o.reader.ReadString('\n')
		inputCh <- struct{}{}
	}()

	for {
		select {
		case <-ctx.Done():
			o.printTimeout(action)
			return ctx.Err()
		case <-inputCh:
			o.printConfirmed(action)
			return nil
		case <-ticker.C:
			if action.Callback() {
				o.printAutoDetected(action)
				return nil
			}
		}
	}
}

// waitForConfirmation waits for the operator to press Enter.
func (o *Operator) waitForConfirmation(ctx context.Context, action HumanAction) error {
	inputCh := make(chan string, 1)
	go func() {
		line, _ := o.reader.ReadString('\n')
		inputCh <- strings.TrimSpace(line)
	}()

	select {
	case <-ctx.Done():
		o.printTimeout(action)
		return ctx.Err()
	case input := <-inputCh:
		if input == "q" || input == "quit" || input == "exit" {
			return fmt.Errorf("operator aborted")
		}
		o.printConfirmed(action)
		return nil
	}
}

// --- Output formatting ---

func (o *Operator) printPrompt(action HumanAction) {
	prompts := GetPrompt(o.lang)
	fmt.Fprintf(os.Stderr, "REQ: %s\n", action.ID)
	
	desc := action.Description
	if localizedDesc, ok := prompts.HardwareActions[action.ID]; ok {
		desc = localizedDesc
	}
	fmt.Fprintf(os.Stderr, "DESC: %s\n", desc)

	if action.Deadline > 0 {
		fmt.Fprintf(os.Stderr, "TIMEOUT: %s\n", action.Deadline)
	}

	if action.Hardware != hwscan.HWNone {
		fmt.Fprintf(os.Stderr, "HW_EXPECT: %s\n", action.Hardware.String())
	}

	if action.Callback != nil {
		fmt.Fprintf(os.Stderr, "AUTO_DETECT: ENABLED\n")
	}

	fmt.Fprintf(os.Stderr, "AWAIT: CONFIRM\n")
}

func (o *Operator) printConfirmed(action HumanAction) {
	fmt.Fprintf(os.Stderr, "STATUS: CONFIRMED\n")
}

func (o *Operator) printAutoDetected(action HumanAction) {
	fmt.Fprintf(os.Stderr, "STATUS: HW_AUTO_DETECTED\n")
}

func (o *Operator) printTimeout(action HumanAction) {
	fmt.Fprintf(os.Stderr, "STATUS: TIMEOUT\n")
}
