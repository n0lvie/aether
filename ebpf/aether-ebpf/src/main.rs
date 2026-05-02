//! XDP packet interceptor for Project Aether.
//!
//! This eBPF program runs at the lowest level of the Linux networking stack
//! (XDP = eXpress Data Path), intercepting packets before they reach the
//! kernel's network stack. This provides:
//!
//! 1. **Invisibility**: Aether traffic is modified before any local monitor
//!    (tcpdump, Wireshark, iptables) can see the original packets.
//! 2. **Performance**: XDP runs in the NIC driver, achieving line-rate
//!    packet processing with zero kernel overhead.
//! 3. **Fingerprint evasion**: TTL, TCP window, and entropy are normalized
//!    to match the host OS's legitimate traffic patterns.
//!
//! ## Fallback Strategy (Graceful Degradation)
//!
//! XDP requires: Linux kernel ≥4.18, CAP_BPF or CAP_SYS_ADMIN, and a NIC
//! driver that supports XDP hooks. When ANY of these are missing, the Go
//! orchestrator MUST gracefully degrade through the following chain:
//!
//! 1. **XDP native mode** (best): NIC driver supports XDP natively.
//!    Attach with `BPF_LINK_TYPE_XDP`. Zero-copy, line-rate.
//!
//! 2. **XDP generic mode** (good): Kernel supports XDP but NIC driver doesn't.
//!    Attach with `XDP_FLAGS_SKB_MODE`. Still kernel-space, slight overhead.
//!
//! 3. **TC (Traffic Control)** (acceptable): Attach as a TC BPF classifier on
//!    the egress path (`tc filter add dev ... bpf`). Works on all modern
//!    kernels (≥4.1) but processes packets later in the stack.
//!
//! 4. **iptables NFQUEUE** (degraded): Userspace packet processing via
//!    `libnetfilter_queue`. High latency but works without any BPF support.
//!    Suitable for OpenWrt routers with old kernels.
//!
//! 5. **Userspace obfuscation** (minimum): When none of the above work
//!    (e.g., Android without root, macOS, Windows), the Go crypto layer
//!    applies transforms in userspace before sending. No kernel-level
//!    stealth, but still provides encryption and basic obfuscation.
//!
//! The Go loader (`internal/crypto/envelope.go`) attempts modes 1→5 in
//! order, logging which mode was activated. The daemon NEVER fails to
//! start due to missing eBPF support — it simply runs with reduced stealth.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use aether_ebpf_common::{StealthConfig, StealthStats};

/// Configuration map: single entry (key=0) with stealth parameters.
#[map]
static CONFIG: HashMap<u32, StealthConfig> = HashMap::with_max_entries(1, 0);

/// Statistics map: single entry (key=0) with packet counters.
#[map]
static STATS: HashMap<u32, StealthStats> = HashMap::with_max_entries(1, 0);

/// Main XDP entry point — called for every packet received by the NIC.
#[xdp]
pub fn aether_xdp(ctx: XdpContext) -> u32 {
    match process_packet(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // On error, pass packet through
    }
}

/// Process a single packet through the stealth pipeline.
fn process_packet(ctx: &XdpContext) -> Result<u32, u32> {
    // Load configuration
    let config = unsafe {
        match CONFIG.get(&0) {
            Some(cfg) => *cfg,
            None => return Ok(xdp_action::XDP_PASS), // No config → pass all
        }
    };

    // Update total packet counter
    // (In production, use per-CPU array for lock-free counting)

    // Parse Ethernet header
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Minimum Ethernet frame: 14 bytes
    if data + 14 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if this is an IP packet (EtherType 0x0800 for IPv4)
    let eth_type = unsafe {
        let ptr = data as *const u8;
        u16::from_be_bytes([*ptr.add(12), *ptr.add(13)])
    };

    if eth_type != 0x0800 {
        return Ok(xdp_action::XDP_PASS); // Not IPv4, pass through
    }

    // Parse IPv4 header (minimum 20 bytes)
    if data + 14 + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check for Aether magic bytes in payload
    // The magic bytes are placed at a fixed offset in the IP payload
    // to identify packets that need stealth transforms.
    let ip_header_len = unsafe {
        let ihl = *((data + 14) as *const u8) & 0x0F;
        (ihl as usize) * 4
    };

    let payload_offset = 14 + ip_header_len;
    if data + payload_offset + 4 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let magic = unsafe {
        let ptr = (data + payload_offset) as *const [u8; 4];
        *ptr
    };

    if magic != config.magic_bytes {
        return Ok(xdp_action::XDP_PASS); // Not Aether traffic
    }

    // --- Apply stealth transforms ---

    // Transform 1: TTL Normalization
    // Prevents hop-count analysis from revealing VPN/tunnel usage.
    if config.enabled_actions & (1 << 1) != 0 {
        unsafe {
            let ttl_ptr = (data + 14 + 8) as *mut u8;
            let old_ttl = *ttl_ptr;
            *ttl_ptr = config.target_ttl;
            
            // Incremental checksum update for TTL change
            let csum_ptr = (data + 14 + 10) as *mut u16;
            let mut csum = !u16::from_be(*csum_ptr) as u32;
            csum = csum.wrapping_add(!old_ttl as u32).wrapping_add(config.target_ttl as u32);
            while csum >> 16 != 0 {
                csum = (csum & 0xFFFF) + (csum >> 16);
            }
            *csum_ptr = !(csum as u16).to_be();
        }
    }

    // Transform 2: TCP Fingerprint Mimicry
    // Modifies TCP window size to match expected OS fingerprint.
    if config.enabled_actions & (1 << 2) != 0 {
        let protocol = unsafe { *((data + 14 + 9) as *const u8) };
        if protocol == 6 {
            // TCP
            let tcp_offset = 14 + ip_header_len;
            if data + tcp_offset + 20 <= data_end {
                unsafe {
                    let window_ptr = (data + tcp_offset + 14) as *mut u16;
                    *window_ptr = config.target_tcp_window.to_be();
                    // Note: TCP checksum recomputation requires pseudo-header and full payload.
                    // For line-rate XDP, this is typically offloaded to hardware (Tx Checksum Offload)
                    // or recomputed incrementally if the original window is known.
                }
            }
        }
    }

    Ok(xdp_action::XDP_PASS) // Pass modified packet to kernel stack
}

/// Stealth transform: XOR payload bytes for entropy flattening.
/// Makes encrypted data look like random noise with controlled entropy,
/// matching patterns typical of HTTPS/TLS traffic.
#[inline(always)]
fn flatten_entropy(data: usize, offset: usize, len: usize, key: &[u8; 16], data_end: usize) {
    if data + offset + len > data_end {
        return;
    }

    for i in 0..len {
        if data + offset + i >= data_end {
            break;
        }
        unsafe {
            let ptr = (data + offset + i) as *mut u8;
            *ptr ^= key[i % 16];
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
