<div align="center">

```
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║     █████╗ ███████╗████████╗██╗  ██╗███████╗██████╗   ║
    ║    ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗  ║
    ║    ███████║█████╗     ██║   ███████║█████╗  ██████╔╝  ║
    ║    ██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗  ║
    ║    ██║  ██║███████╗   ██║   ██║  ██║███████╗██║  ██║  ║
    ║    ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ║
    ║                                                       ║
    ║    Zero-Config Autonomous Connectivity Daemon          ║
    ╚═══════════════════════════════════════════════════════╝
```

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Rust](https://img.shields.io/badge/Rust-nightly-orange?style=flat-square&logo=rust)](https://rustup.rs)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-red?style=flat-square)]()

**Project Aether** is a self-healing, zero-configuration autonomous network connectivity daemon designed to maintain internet access under conditions of total censorship, deep packet inspection (DPI), and network blackouts.

</div>

---

## The Problem

State-level network censorship has evolved beyond simple IP blocking. Modern censorship infrastructure deploys:

- **DPI engines** that detect and block VPN protocols by traffic fingerprint
- **Whitelists** that block all non-approved domains by default
- **BGP route hijacking** that makes entire ASNs unreachable
- **Physical infrastructure control** — fiber cuts, ISP shutdowns

Existing privacy tools (VPNs, Tor) fail when all outbound ports are filtered or when the destination IP is blocked at the national level.

**Aether's answer**: if one path is blocked, try all paths simultaneously. If all software paths fail, ask a human to plug in hardware.

---

## How It Works

Aether operates as a **Finite State Machine (FSM)** that continuously escalates through five tiers of increasingly exotic connectivity methods, using **Aggressive Happy Eyeballs** — all available vectors within a tier are raced in parallel, and the first to succeed wins.

### FSM Lifecycle

```
ColdStart → HardwareScan → SeedDiscovery → VectorRace → Connected
                                                              ↕
                                                          Degraded
                                                              ↕
                                                       HumanRequired → Terminated
```

| State | Description | Timeout |
|-------|-------------|---------|
| `ColdStart` | Load/generate Ed25519 node identity | 10s |
| `HardwareScan` | Enumerate available hardware (COM, USB, Audio, BLE, Wi-Fi) | 30s |
| `SeedDiscovery` | Resolve bootstrap node addresses via all available oracles | 60s |
| `VectorRace` | Race all eligible connectivity vectors in parallel | 120s |
| `Connected` | Monitor active connections, trigger rotation on quality drop | ∞ |
| `Degraded` | Partial connectivity lost — attempt recovery with next-tier vectors | 60s |
| `HumanRequired` | All programmatic vectors exhausted — prompt operator for hardware | ∞ |
| `Terminated` | Graceful shutdown | — |

---

## Connectivity Vectors

Vectors are organized into five escalation tiers. Lower tiers are attempted first; each tier launches all its vectors simultaneously.

### Tier 0 — Kernel & Cold Start

These vectors bypass application-layer filtering entirely.

| Vector | Description | Hardware Required |
|--------|-------------|-------------------|
| `icmp_tunnel` | Covert channel encoded in ICMP Echo payloads. Passes most firewalls since ICMP is required for network diagnostics. | None (CAP_NET_RAW) |
| `at_modem` | Bootstrap via SMS/USSD — sends AT commands to a cellular modem to extract seed node addresses from SMS replies. Completely out-of-band from internet infrastructure. | USB cellular modem |

Also at Tier 0: **eBPF/XDP Kernel Stealth** (see [eBPF Module](#ebpfxdp-stealth-module-rust)).

### Tier 1 — Generative Obfuscation

These vectors disguise Aether traffic as legitimate application traffic.

| Vector | Description |
|--------|-------------|
| `obfuscated_tls` | TLS with **Encrypted Client Hello (ECH)** over **HTTP/3 (QUIC)**. The outer SNI points to a legitimate CDN; the inner connection reaches an Aether relay. |
| `llm_mimicry` | Wraps Aether protocol in JSON payloads that match **OpenAI/Anthropic API** request/response patterns — timing, chunk sizes, headers. |

### Tier 2 — Decentralized Oracles

Seed discovery methods that don't rely on a single, blockable server.

| Vector | Description |
|--------|-------------|
| `doh_oracle` | DNS TXT record queries via **DNS-over-HTTPS** (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9). Seed node info is base64-encoded in TXT records. |
| `domain_fronting` | CDN-based relay routing where the HTTP `Host` header differs from the TLS SNI. |
| `blockchain_rpc` | Reads seed nodes from smart contract storage on-chain — no central server to block. |

### Tier 3 — Local Swarm Mesh

When internet access is completely cut, nodes connect to each other locally and route packets through the mesh.

| Vector | Description | Hardware Required |
|--------|-------------|-------------------|
| `ble_mesh` | Bluetooth Low Energy mesh using GATT. Nodes advertise a custom Aether service UUID and relay data via BLE L2CAP. | BLE adapter |
| `dtn` | **Delay-Tolerant Networking** — store-carry-forward. Packets are queued locally and forwarded when any peer is encountered. | None |
| `awdl` | **Apple Wireless Direct Link** — peer-to-peer Wi-Fi without an access point (macOS/iOS). | AWDL-capable Wi-Fi |
| `wifi_aware` | **Wi-Fi Aware (NAN)** — peer-to-peer discovery and data paths without internet (Android). | Wi-Fi Aware adapter |
| `ultrasonic` | Data transmission encoded as **18–20 kHz FSK audio** — inaudible to humans, passes through air and walls. Implemented in C for minimal latency. | Microphone + Speaker |

### Tier 4 — Hardware Fallback

Last resort: physical radio hardware operated by a human.

| Vector | Description | Hardware Required |
|--------|-------------|-------------------|
| `lora_meshtastic` | Routes packets through a **Meshtastic LoRa mesh** via USB serial. LoRa signals travel 5–15 km in open terrain. | USB LoRa transceiver (Meshtastic-compatible) |
| `softmodem` | Data transmission over **analog telephone lines** using software-based FSK modem. Phone lines often survive when all digital infrastructure is shut down. | Phone line + audio I/O |
| `sdr` | **Software Defined Radio** transmit/receive on arbitrary frequencies. Requires operator to select a band and aim an antenna. | RTL-SDR / HackRF |

---

## Security Model

All inter-node communication is designed to be secure and Sybil-resistant.

### Identity

Each Aether node generates an **Ed25519** keypair on first launch and stores it encrypted in `~/.aether/`. The public key is the node's permanent identity — it never changes, enabling trust-on-first-use (TOFU) across reconnections.

### Transport Encryption

All node-to-node traffic uses the **Noise Protocol Framework** (`Noise_XX_25519_ChaChaPoly_SHA256` pattern — the same used by WireGuard and Signal). This provides:
- **Mutual authentication** via Ed25519 identities
- **Forward secrecy** — session keys are ephemeral
- **Zero round-trip** authentication possible with known peers

### Sybil Resistance — Argon2id PoW

To prevent an adversary from flooding the network with fake nodes, every node joining must solve a **memory-hard Proof-of-Work** puzzle:

```
Challenge wire format (105 bytes):
  Nonce(32) || Difficulty(1) || Timestamp(8) || ChallengerPubKey(32) || HMAC(32)

Solution wire format (128 bytes):
  SolutionNonce(32) || SolverPubKey(32) || Ed25519Signature(64)

Hash function: Argon2id(time=3, memory=64MB, threads=4)
Difficulty: 16-24 leading zero bits (configurable, adaptive under attack)
Solve time: ~2-5 seconds on a modern CPU
```

The **memory-hard** property means GPU/ASIC parallelism provides minimal speedup, making it economically infeasible to spin up thousands of fake nodes.

### eBPF/XDP Stealth Module (Rust)

On Linux with `CAP_BPF`, Aether loads an XDP program that performs:

- **TTL Normalization** — aligns TTL values to match the target OS (64 for Linux, 128 for Windows)
- **TCP Fingerprint Mimicry** — modifies TCP window size, options order, and MSS to evade `p0f`-style fingerprinting
- **Entropy Flattening** — XOR-pads payloads to normalize byte entropy, defeating high-entropy traffic detection
- **Packet Coalescing** — merges small packets to reduce statistical traffic signatures

The eBPF module is implemented in **Rust** using the [Aya](https://github.com/aya-rs/aya) framework for CO-RE (Compile Once, Run Everywhere) compatibility across kernel versions.

---

## Human Operator Interface

When all programmatic vectors fail, Aether transitions to `HumanRequired` state and displays a context-aware, color-coded prompt on `stderr`:

```
════════════════════════════════════════════════════════════
‼ CRITICAL  AETHER :: HUMAN ACTION REQUIRED
════════════════════════════════════════════════════════════

  Connect a LoRa/Meshtastic transceiver to a USB port

  Timeout: 5m0s
  Expected device: LoRa
  [Auto-detect enabled — device will be detected automatically]

  Press Enter when done (or q to abort)...
════════════════════════════════════════════════════════════
```

- Output goes to `stderr` so `stdout` can be piped
- USB hotplug **auto-detection** — the prompt resolves automatically when the device is connected
- Fully localized (**RU** / **EN**)
- Priority levels: `INFO` (cyan) / `⚠ HIGH` (yellow) / `‼ CRITICAL` (red)

---

## Architecture

### Technology Stack

| Component | Language | Rationale |
|-----------|----------|-----------|
| Core Orchestrator, PoW, CLI | **Go** | Goroutine-based concurrency for Happy Eyeballs; single static binary |
| eBPF/XDP Kernel Stealth | **Rust** (Aya) | Safe kernel programming, CO-RE, zero-panic guarantees |
| Generative Obfuscation ML | **Rust** (burn/candle) | Minimal runtime, deterministic inference, <5 MB model |
| Ultrasonic/Audio Codec | **C** | Direct audio buffer access, minimal latency |

### Package Structure

```
aether/
├── cmd/aetherd/              # Daemon entry point
│   └── main.go               # Flags, signal handling, banner
├── internal/
│   ├── orchestrator/         # Core FSM
│   │   ├── orchestrator.go   # Main state machine loop
│   │   ├── state.go          # State definitions, Connection types
│   │   ├── vector.go         # Vector interface + Registry
│   │   └── happy_eyeballs.go # Parallel vector racing
│   ├── vectors/              # All connectivity vector implementations
│   │   └── vectors.go        # ICMPTunnel, ATModem, ObfuscatedTLS, LLMMimicry,
│   │                         # DoHOracle, BLEMesh, DTN, LoRaMeshtastic, Softmodem
│   ├── cli/                  # Human Operator Interface
│   │   ├── operator.go       # ANSI-colored prompts, stdin/hotplug wait
│   │   └── prompts.go        # Localized prompt strings (RU/EN)
│   ├── pow/                  # Argon2id Proof-of-Work
│   │   ├── challenge.go      # Challenge generation & wire format
│   │   ├── solver.go         # Iterative PoW solver
│   │   └── validator.go      # O(1) solution verification + rate limiting
│   ├── crypto/               # Cryptographic primitives
│   │   ├── identity.go       # Ed25519 key generation & storage
│   │   ├── noise.go          # Noise Protocol session management
│   │   └── envelope.go       # ChaCha20-Poly1305 packet encryption
│   └── hwscan/               # Hardware discovery
│       ├── scanner.go        # COM/USB/Audio/BLE/Wi-Fi enumeration
│       └── capabilities.go   # HardwareType bitmask, CapabilityMatrix
├── ebpf/                     # Rust: eBPF/XDP kernel programs
│   ├── aether-ebpf/          # Kernel-space XDP program (Aya)
│   └── aether-ebpf-common/   # Shared types kernel ↔ userspace
├── configs/
│   └── aether.toml           # Default configuration (all options documented)
├── go.mod
└── go.sum
```

---

## Building

### Prerequisites

| Tool | Version | Required for |
|------|---------|-------------|
| Go | 1.21+ | Core daemon |
| Rust nightly | latest | eBPF module |
| `bpf-linker` | latest | eBPF compilation |
| Linux kernel | ≥ 5.15 | eBPF/XDP stealth |

> **Note:** The eBPF module is optional. The daemon runs on all platforms without it; stealth capabilities are simply disabled (`stealth.enabled = false` in config).

### Build the Daemon

```bash
# Build the daemon binary
go build -o aetherd ./cmd/aetherd

# Run with race detector (development)
go build -race -o aetherd ./cmd/aetherd

# Cross-compile for Linux (from any OS)
GOOS=linux GOARCH=amd64 go build -o aetherd-linux ./cmd/aetherd
```

### Build the eBPF Module (Linux only)

```bash
# Install bpf-linker
cargo install bpf-linker

# Build eBPF programs
cd ebpf && cargo build --release --target bpfel-unknown-none
```

### Run Tests

```bash
# All tests with race detector
go test ./... -v -race

# PoW subsystem tests
go test ./internal/pow/... -v -race

# Orchestrator FSM tests
go test ./internal/orchestrator/... -v -race

# PoW solver benchmark
go test ./internal/pow/ -bench=BenchmarkSolve -benchmem
```

---

## Running

```bash
# Start with all defaults (~/.aether state directory, info logging)
./aetherd

# Custom state directory and verbose logging
./aetherd --state-dir /var/lib/aether --log-level debug

# Print version
./aetherd --version
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--state-dir` | `~/.aether` | Persistent state directory (keys, seed cache, DTN queue) |
| `--log-level` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `--version` | — | Print version and exit |

### Required Privileges

| Feature | Privilege |
|---------|-----------|
| eBPF/XDP stealth (Linux) | `root` or `CAP_BPF` + `CAP_NET_ADMIN` |
| ICMP tunnel | `root` or `CAP_NET_RAW` |
| All other vectors | None (runs as unprivileged user) |

### Running as a Service (systemd)

```ini
# /etc/systemd/system/aetherd.service
[Unit]
Description=Project Aether Connectivity Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/aetherd --state-dir /var/lib/aether
Restart=always
RestartSec=5
User=aether
AmbientCapabilities=CAP_NET_RAW CAP_BPF CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

---

## Configuration

All settings are in `configs/aether.toml`. The daemon works out-of-the-box with zero configuration.

```toml
[daemon]
state_dir = "~/.aether"
log_level = "info"
language = "ru"          # CLI language: "ru" or "en"

[pow]
base_difficulty = 16     # Leading zero bits (16 = ~2-5s solve time)
rate_limit = 5           # Max solutions per pubkey per minute
challenge_ttl = 60       # Challenge expiry in seconds

[noise]
pattern = "Noise_XX_25519_ChaChaPoly_SHA256"
prologue = "aether-v1"

[vectors.enabled]
icmp_tunnel = true
at_modem = true
obfuscated_tls = true
llm_mimicry = true
doh_oracle = true
ble_mesh = true
dtn = true
lora_meshtastic = true
softmodem = true

[stealth]
enabled = false          # Requires Linux + root
target_ttl = 64          # 64=Linux, 128=Windows fingerprint

[oracles]
doh_resolvers = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/dns-query",
    "https://9.9.9.9:5053/dns-query",
]
seed_domains = ["_aether.example.com"]
```

---

## Implementing a New Vector

To add a new connectivity method, implement the `Vector` interface:

```go
type Vector interface {
    Name()             string                // Unique identifier, e.g. "my_vector"
    Tier()             int                   // Escalation tier 0-4
    Priority()         int                   // Within-tier priority (lower = higher)
    RequiresHardware() []hwscan.HardwareType // Hardware prerequisites
    Probe(ctx context.Context) (*Connection, error)               // Attempt connection
    Maintain(ctx context.Context, conn *Connection) error         // Keep connection alive
}
```

Then register it in `internal/vectors/vectors.go`:

```go
func RegisterAllVectors(registry *orchestrator.VectorRegistry) {
    // ...existing vectors...
    registry.Register(&MyNewVector{})
}
```

The Orchestrator automatically includes the new vector in the next race cycle, filtered by the current `CapabilityMatrix`.

---

## Roadmap

- [ ] **Tier 0**: Full ICMP tunnel implementation
- [ ] **Tier 0**: AT modem SMS/USSD bootstrap
- [ ] **Tier 1**: ECH + HTTP/3 obfuscated TLS
- [ ] **Tier 1**: LLM API mimicry traffic shaper (ML model integration)
- [ ] **Tier 2**: DoH/DoT oracle with seed verification
- [ ] **Tier 2**: Domain fronting relay
- [ ] **Tier 2**: Blockchain smart contract seed storage
- [ ] **Tier 3**: BLE mesh with Noise handshake over L2CAP
- [ ] **Tier 3**: Ultrasonic C codec + CGo bridge
- [ ] **Tier 4**: LoRa/Meshtastic serial API
- [ ] **Tier 4**: Softmodem FSK implementation
- [ ] **eBPF**: Full XDP stealth pipeline
- [ ] **ML**: Generative obfuscation model (burn/candle, INT8 quantized)
- [ ] Configuration file loading (TOML parser)
- [ ] Persistent DTN queue with disk storage
- [ ] Channel rotation and multi-path redundancy
- [ ] Metrics endpoint (Prometheus)

---

## Contributing

Contributions are welcome. Please:

1. Open an issue to discuss significant changes before implementing
2. Run `go test ./... -race` before submitting a PR
3. Keep each vector implementation self-contained in its own file
4. Document all exported types and functions
5. Never commit actual seed node addresses or private keys

---

## Security Policy

If you discover a vulnerability, please **do not** open a public GitHub issue. Send details to the maintainers via encrypted email or a private security advisory on GitHub.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*"The network routes around censorship."*  
— John Gilmore, 1993

</div>
