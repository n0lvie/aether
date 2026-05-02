# Project Aether

**Autonomous Zero-Config Connectivity Daemon**

> *"A rational, indifferent instrument. Objective: establish global network access by any means and at any cost."*

Project Aether is a purely functional, indifferent network connectivity daemon designed to maintain internet access under conditions of total censorship, DPI-based blocking, and network blackouts. It operates as a universal tool that systematically exploits every available hardware and software capability to establish a resilient tunnel.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    cmd/aetherd (Entry Point)                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              orchestrator (FSM Engine)              │    │
│  │  ColdStart → HWScan → SeedDiscovery → VectorRace    │    │
│  │  → Connected → Degraded → HumanRequired → Terminated│    │
│  └──────┬───────────┬──────────┬───────────┬───────────┘    │
│         │           │          │           │                │
│  ┌──────▼─┐  ┌──────▼───┐  ┌───▼────┐  ┌───▼─────────┐      │
│  │vectors │  │resource  │  │  pow   │  │   trust     │      │
│  │9 stubs │  │5 tiers   │  │Argon2id│  │SAS+WoT+TOFU │      │
│  │Tier 0-4│  │5 tiers   │  │+nonce  │  │attestations │      │
│  └────────┘  └──────────┘  └────────┘  └─────────────┘      │
│         │           │          │           │                │
│  ┌──────▼─┐  ┌──────▼───┐  ┌───▼────┐  ┌───▼─────────┐      │
│  │hwscan  │  │  crypto  │  │  ota   │  │    cli      │      │
│  │COM/USB │  │Ed25519   │  │MultiSig│  │Minimal UI   │      │
│  │Audio   │  │Noise_XX  │  │Canary  │  │Rational text│      │
│  │Network │  │ChaCha20  │  │Gossip  │  │HW actions   │      │
│  └────────┘  └──────────┘  └────────┘  └─────────────┘      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  ebpf/ (Rust/Aya)                                           │
│  └── XDP: TTL normalization, TCP fingerprint, entropy       │
└─────────────────────────────────────────────────────────────┘
```

### Core Modules

| Module | Purpose | Tests |
|--------|---------|-------|
| **orchestrator** | FSM engine + Aggressive Happy Eyeballs parallel racing | — |
| **vectors** | 9 connectivity stubs: ICMP, AT Modem, ECH/TLS, LLM Mimicry, DoH, BLE, DTN, LoRa, Softmodem | — |
| **pow** | Argon2id Proof-of-Work with O(1) ring buffer nonce cache | 10 |
| **trust** | 5-layer Aether Trust Protocol: PoW → Noise_XX → SAS → Web of Trust → TOFU | 7 |
| **ota** | 4-layer OTA anti-poisoning: Multi-Sig quorum → SHA-256 → Canary A/B → Gossip reputation | 11 |
| **resource** | 5-tier adaptive power management: Relay → Client → LowPower → Hibernate → Shutdown | 14 |
| **crypto** | Ed25519 identity, Noise_XX handshake, ChaCha20-Poly1305 envelopes | — |
| **hwscan** | Parallel COM/USB/Audio/Network hardware discovery | — |
| **cli** | Minimalist human-operator interface for hardware intervention | — |

### Connectivity Tiers

| Tier | Name | Vectors |
|------|------|---------|
| 0 | Kernel Stealth | eBPF/XDP packet manipulation, ICMP tunnels, AT-command SMS |
| 1 | Generative Obfuscation | ECH + HTTP/3, LLM API mimicry |
| 2 | Decentralized Oracles | DoH/DoT DNS discovery |
| 3 | Swarm Mesh | BLE Mesh, DTN store-and-forward |
| 4 | Hardware Fallback | LoRa/Meshtastic, Softmodem (analog phone) |

### Security Model

- **Noise Protocol Framework** (XX pattern) for all inter-node communication
- **Ed25519** identities with persistent key storage
- **Argon2id Proof-of-Work** — memory-hard (64MB × 3 passes), GPU-resistant
- **ChaCha20-Poly1305** for data encryption
- **SAS verbal verification** — 4-word code, 32-bit security against MitM
- **Web of Trust** — bounded transitivity (max 3 hops)
- **OTA Multi-Sig** — 3-of-5 developer quorum with canary verification
- **Adaptive difficulty** — 12→24 bits under DDoS attack

### Power Management

| Battery | Role | Vectors | Gossip | ML | Expected Life |
|---------|------|---------|--------|----|---------------|
| >80% | Relay | 8 parallel | 30s | ✅ | ~6-8h |
| 50-80% | Client | 4 | 2min | ✅ | ~10-14h |
| 20-50% | LowPower | 2 | 5min | ❌ | ~24-36h |
| 5-20% | Hibernate | 1 | 30min | ❌ | ~48h+ |
| <5% | Shutdown | — | — | — | Save & exit |

## Building

### Prerequisites

- Go 1.21+
- Rust nightly (for eBPF, optional)

### Build & Test

```bash
# Build
go build -o aetherd ./cmd/aetherd

# Run all tests
go test ./... -v

# Run with PoW benchmarks
go test ./internal/pow/ -bench=BenchmarkSolve -benchmem

# Build eBPF (Linux only)
cd ebpf && cargo build --release --target bpfel-unknown-none
```

## Running

```bash
# Start with defaults
./aetherd

# Custom state directory and debug logging
./aetherd --state-dir /var/lib/aether --log-level debug
```

## License

MIT
