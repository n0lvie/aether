// aetherd is the main entry point for the Project Aether daemon.
//
// Usage:
//
//	aetherd [flags]
//
// The daemon operates as a zero-config autonomous agent that establishes
// and maintains network connectivity through any available means.
// It runs as a finite state machine (FSM) with parallel vector racing
// (Aggressive Happy Eyeballs) to find the fastest working connection.
//
// When all programmatic approaches fail, it prompts the operator via CLI
// for physical hardware intervention (e.g., connecting a LoRa antenna).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/aether-project/aether/internal/orchestrator"
	"github.com/aether-project/aether/internal/vectors"
)

const version = "0.1.0-alpha"

var (
	cleanupHooks []func()
	cleanupMu    sync.Mutex
)

// RegisterCleanupHook registers a function to be called on shutdown or panic.
// Hooks are executed in reverse order of registration (LIFO).
func RegisterCleanupHook(hook func()) {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	cleanupHooks = append(cleanupHooks, hook)
}

// runCleanupHooks executes all registered cleanup hooks.
func runCleanupHooks() {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	for i := len(cleanupHooks) - 1; i >= 0; i-- {
		// Run securely without panicking during cleanup
		func() {
			defer func() { recover() }()
			cleanupHooks[i]()
		}()
	}
}

func main() {
	// Global Watchdog: ensure critical cleanup (like eBPF detach) runs even on panic
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n[WATCHDOG PANIC] %v\n", r)
			fmt.Fprintf(os.Stderr, "[WATCHDOG] Executing emergency cleanup hooks...\n")
			runCleanupHooks()
			os.Exit(2)
		}
	}()

	defer runCleanupHooks()

	// Parse flags
	var (
		stateDir string
		logLevel string
		showVer  bool
	)

	flag.StringVar(&stateDir, "state-dir", defaultStateDir(), "Directory for persistent state (keys, cache)")
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.BoolVar(&showVer, "version", false, "Print version and exit")
	flag.Parse()

	if showVer {
		fmt.Printf("aetherd v%s\n", version)
		os.Exit(0)
	}

	// Parse log level
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		fmt.Fprintf(os.Stderr, "invalid log level: %s\n", logLevel)
		os.Exit(1)
	}

	// Banner
	printBanner()

	// Register all connectivity vectors
	registry := orchestrator.NewVectorRegistry()
	vectors.RegisterAllVectors(registry)

	// Create orchestrator
	orch := orchestrator.New(orchestrator.Config{
		StateDir: stateDir,
		LogLevel: level,
	}, registry)

	// Handle OS signals for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "\n[SIGNAL] %s received — initiating shutdown...\n", sig)
		cancel()
	}()

	// Run the daemon
	if err := orch.Run(ctx); err != nil {
		if ctx.Err() != nil {
			// Normal shutdown via signal
			fmt.Fprintf(os.Stderr, "[AETHER] Shutdown complete.\n")
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "[FATAL] %v\n", err)
		os.Exit(1)
	}
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".aether"
	}
	return filepath.Join(home, ".aether")
}

func printBanner() {
	fmt.Fprintf(os.Stderr, "[SYS] aetherd v%s initializing...\n", version)
}
