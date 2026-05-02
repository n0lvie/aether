//! Shared types between kernel-space eBPF programs and user-space Aether daemon.
//!
//! This crate is compiled twice:
//! - For the BPF target (no_std, no alloc)
//! - For the host target (with std, with aya)

#![cfg_attr(not(feature = "user"), no_std)]

/// Actions that the XDP program can take on a packet.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StealthAction {
    /// Pass the packet through unmodified.
    Pass = 0,
    /// Apply TTL normalization.
    NormalizeTTL = 1,
    /// Apply TCP fingerprint mimicry (window size, options).
    MimicTCPFingerprint = 2,
    /// Flatten payload entropy via XOR padding.
    FlattenEntropy = 3,
    /// Drop the packet (used for filtering).
    Drop = 4,
}

/// Configuration passed from userspace to the eBPF program via a BPF map.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct StealthConfig {
    /// Target TTL value to normalize to (e.g., 64 for Linux, 128 for Windows).
    pub target_ttl: u8,

    /// Target TCP window size for fingerprint mimicry.
    pub target_tcp_window: u16,

    /// XOR key for entropy flattening (rotated per-packet).
    pub xor_key: [u8; 16],

    /// Bitmask of enabled stealth actions.
    pub enabled_actions: u32,

    /// Aether protocol magic bytes for identifying our packets.
    /// Only Aether-marked packets are modified; all others pass through.
    pub magic_bytes: [u8; 4],
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            target_ttl: 64, // Linux default
            target_tcp_window: 65535,
            xor_key: [0u8; 16],
            enabled_actions: 0,
            magic_bytes: *b"AETH",
        }
    }
}

/// Statistics exported from the eBPF program to userspace.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct StealthStats {
    /// Total packets seen by the XDP program.
    pub packets_total: u64,
    /// Packets identified as Aether traffic.
    pub packets_aether: u64,
    /// Packets modified by stealth transforms.
    pub packets_modified: u64,
    /// Packets dropped.
    pub packets_dropped: u64,
}
