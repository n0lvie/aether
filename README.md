# Project Aether

**Autonomous Zero-Config Connectivity Daemon**

Project Aether is a self-healing network connectivity daemon designed to maintain internet access under conditions of total censorship, DPI-based blocking, and network blackouts. It operates as a benign network agent that exploits every available hardware and software capability to establish a resilient tunnel.

## Architecture

The daemon is built as a **Finite State Machine (FSM)** with **Aggressive Happy Eyeballs** — all available connectivity vectors are launched in parallel, and the first successful connection wins.

### Tiers (Escalation Levels)

| Tier | Name | Description |
|------|------|-------------|
| 0 | Kernel Stealth | eBPF/XDP packet manipulation, ICMP tunnels, AT-command SMS seeds |
| 1 | Generative Obfuscation | ECH + HTTP/3, LLM API mimicry, WebRTC cover traffic |
| 2 | Decentralized Oracles | DoH/DoT DNS, Domain Fronting, blockchain smart contracts |
| 3 | Swarm Mesh | BLE Mesh, Wi-Fi Aware, AWDL, Ultrasonic, DTN |
| 4 | Hardware Fallback | LoRa/Meshtastic, SDR, Softmodem (analog phone lines) |

### FSM States

```
ColdStart → HardwareScan → SeedDiscovery → VectorRace → Connected → Degraded → HumanRequired → Terminated
```

## Building

### Prerequisites

- Go 1.21+
- Rust nightly (for eBPF, optional)
- `bpf-linker` (for eBPF, optional)

### Build

```bash
# Build the daemon
go build -o aetherd ./cmd/aetherd

# Run tests
go test ./... -v -race

# Run PoW benchmark
go test ./internal/pow/ -bench=BenchmarkSolve -benchmem

# Build eBPF programs (Linux only, requires nightly Rust)
cd ebpf && cargo build --release --target bpfel-unknown-none
```

## Running

```bash
# Start with defaults
./aetherd

# Custom state directory and debug logging
./aetherd --state-dir /var/lib/aether --log-level debug
```

## Security Model

- **Noise Protocol Framework** (XX pattern) for all inter-node communication
- **Ed25519** identities with persistent key storage
- **Argon2id Proof-of-Work** for Sybil resistance (memory-hard, GPU-resistant)
- **ChaCha20-Poly1305** for data encryption
- Adaptive PoW difficulty scaling under attack

## License

MIT
