---
id: T-016
name: EDR Evasion Suite
category: edr-evasion
tier: S
mitre: [T1562.001, T1562.002, T1620, T1055.001, T1106, T1574.001]
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-001, T-004, T-003]
enables: [T-007, T-012, T-013, T-017, T-005]
vault_references:
  - src/dark_crystal/crowd/src/amsi_hbp.rs
  - src/dark_crystal/crowd/src/amsi_page_guard.rs
  - src/dark_crystal/crowd/src/etw.rs
  - src/dark_crystal/crates/core/src/experimental/pe_header_stomp.rs
implements:
  - file: src/dark_crystal/crowd/src/amsi_hbp.rs
    key_functions: [install_amsi_hbp, install_dr0_bypass, install_page_guard_bypass, exception_handler, resolve_amsi_scan_buffer, enable_breakpoint, clear_breakpoint, dr0_is_occupied, nt_get_context, nt_set_context, get_arg, get_return_address, set_result, adjust_stack_pointer, set_ip, set_bits]
    key_structs: [CONTEXT, EXCEPTION_POINTERS, LdrLoadDllFn]
    key_constants: [EXCEPTION_SINGLE_STEP, EXCEPTION_GUARD_PAGE, AMSI_RESULT_CLEAN, S_OK, EFLAGS_TRAP_FLAG, PAGE_GUARD_RAW, PAGE_EXECUTE_READ_RAW, PAGE_READWRITE_RAW, MEM_COMMIT_RAW, MEM_RESERVE_RAW, CURRENT_PROCESS, CLEAN_STUB_BYTES]
    lines_of_interest: ["L1-L50: doc comments outlining DR0 + Page Guard duality", "L77-L92: set_bits/clear/enable_breakpoint DR7 manipulation", "L113-L137: VEH exception_handler dual-case dispatch (SINGLE_STEP vs GUARD_PAGE)", "L139-L172: nt_get_context/nt_set_context via RecycledGate with extern fallback", "L176-L195: install_dr0_bypass AddVectoredExceptionHandler(1, ...)", "L197-L243: install_page_guard_bypass RW→RX shadow stub + PAGE_GUARD on AmsiScanBuffer page", "L245-L291: resolve_amsi_scan_buffer LdrLoadDll + PE export walk", "L293-L325: install_amsi_hbp public entry with primary→fallback cascade"]
  - file: src/dark_crystal/crowd/src/amsi_page_guard.rs
    key_functions: [install_amsi_page_guard, remove_amsi_page_guard, page_guard_veh_handler, resolve_amsi_scan_buffer, return_address_from_ctx]
    key_structs: [CONTEXT, EXCEPTION_POINTERS]
    key_constants: [EXCEPTION_GUARD_PAGE, AMSI_RESULT_CLEAN, PAGE_EXECUTE_READ, PAGE_GUARD, CURRENT_PROCESS, AMSI_SCAN_BUFFER_ADDR, VEH_HANDLE]
    lines_of_interest: ["L78-L116: page_guard_veh_handler — one-shot hijack returning RAX=0/RIP=caller", "L118-L163: resolve_amsi_scan_buffer LdrLoadDll path", "L165-L213: install_amsi_page_guard — AtomicUsize state + NtProtectVirtualMemory via RecycledGate", "L215-L226: remove_amsi_page_guard — cleanup with swap(0)"]
  - file: src/dark_crystal/crowd/src/etw.rs
    key_functions: [muffle_etw, muffle_etw_providers, patch_etw_via_nt, resolve_etw_event_write, resolve_export_by_hash]
    key_structs: [LdrLoadDllFn (used inline), _ETW_GUID_ENTRY (implicit layout)]
    key_constants: [ETW_PATCH, HASH_ETW_EVENT_WRITE, HASH_ETW_REGISTRATION_LIST, ETW_GUID_ENTRY_GUIDLIST_OFFSET, ETW_GUID_ENTRY_ENABLE_INFO_OFFSET]
    lines_of_interest: ["L30-L33: ETW_PATCH bytes [0x33,0xC0,0xC3] = xor eax,eax;ret", "L36-L50: precomputed DJB2 hashes", "L55-L94: resolve_export_by_hash PE export walker", "L100-L139: muffle_etw_providers LIST_ENTRY walk + write_volatile(IsEnabled=0)", "L141-L172: patch_etw_via_nt — RecycledGate NtProtectVirtualMemory, RW→patch→restore"]
  - file: src/dark_crystal/crates/core/src/experimental/pe_header_stomp.rs
    key_functions: [stomp_pe_header, stomp_own_pe_header, stomp_self_header]
    key_structs: []
    key_constants: [0x5A4D (MZ), 0x0000_4550 (PE\0\0), 0x020B (PE32+), 0x010B (PE32)]
    lines_of_interest: ["L20-L36: stomp_pe_header ptr::write_bytes primitive", "L38-L93: stomp_own_pe_header — full PE header validation + SizeOfHeaders extraction", "L100-L127: stomp_self_header gated by cfg(feature=\"pe_stomp\") — uses gs:[0x60] PEB walk + VirtualProtect"]
min_windows: Win10 RS1 (1607) — EtwRegistrationList path; DR0/PAGE_GUARD/VEH primitives work back to XP
needs_admin: no
tags: [amsi, etw, stack-spoofing, peb-unlink, ntdll-unhook, block-dll, acg, block-handle, advanced-stack, veh, hardware-breakpoint, page-guard, pe-stomp, peb-walk, djb2, recycled-gate]
---

# EDR Evasion Suite (T-016) — Operator Playbook

## TL;DR

A four-pronged evasion bundle that defeats the three pillars of EDR detection — content scanning (AMSI), telemetry (ETW), and memory forensics (pe-sieve/BeaconEye) — without writing a single byte into ntdll or amsi.dll for the primary paths. The AMSI leg uses a DR0 hardware breakpoint on `AmsiScanBuffer` with a VEH handler that returns `AMSI_RESULT_CLEAN`; the ETW leg walks the `EtwRegistrationList` (or falls back to a classic `xor eax,eax; ret` patch on `EtwEventWrite`); PE header stomping removes the MZ/DOS stub so scanners cannot locate the image. Every NT call goes through `crate::recycled` (T-001 RecycledGate), making the entire suite hook-invisible to ring-3 API monitors.

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `crowd/src/amsi_hbp.rs` | DR0 hardware-breakpoint AMSI bypass + PAGE_GUARD fallback | `install_amsi_hbp()`, `install_dr0_bypass()`, `install_page_guard_bypass()`, `exception_handler()` | ~404 lines |
| `crowd/src/amsi_page_guard.rs` | Standalone PAGE_GUARD AMSI bypass with atomic state + cleanup | `install_amsi_page_guard()`, `remove_amsi_page_guard()`, `page_guard_veh_handler()` | ~226 lines |
| `crowd/src/etw.rs` | ETW provider `IsEnabled` zeroing + EtwEventWrite byte-patch fallback | `muffle_etw()`, `muffle_etw_providers()`, `patch_etw_via_nt()` | ~237 lines |
| `crates/core/src/experimental/pe_header_stomp.rs` | PE header zeroing (MZ/NT/section table) | `stomp_pe_header()`, `stomp_own_pe_header()`, `stomp_self_header()` (cfg `pe_stomp`) | ~127 lines |

## How It Works

### AMSI Bypass — DR0 Hardware Breakpoint (Primary)

1. **Resolution** — `resolve_amsi_scan_buffer()` walks the PEB `InLoadOrderModuleList` via `crate::resolve::find_module_base("amsi.dll")`. If null, it loads `amsi.dll` through ntdll's `LdrLoadDll` (no `kernel32!LoadLibraryA` import). It then calls `crate::resolve::resolve_export_by_name(base, "AmsiScanBuffer")` walking the PE export directory (`0x5A4D` MZ check, `e_lfanew` at `+0x3C`, DataDirectory[0] at `+0x88`). Result is cached in the `static mut AMSI_SCAN_BUFFER_PTR`.
2. **DR0 occupancy check** — `install_dr0_bypass()` allocates `CONTEXT { ContextFlags = CONTEXT_ALL }` and calls `nt_get_context()` (NtGetContextThread with `NtCurrentThread = -2` via `recycled::recycled2`). `dr0_is_occupied()` checks `ctx.Dr7 & 0x3` — both L0 and G0 enable bits. If set → bail to `install_page_guard_bypass()`.
3. **VEH registration** — `AddVectoredExceptionHandler(1, Some(exception_handler))` installs the handler at **CALL_FIRST** priority so it intercepts before any user/CLR handler.
4. **DR7/DR0 programming** — `enable_breakpoint(&mut ctx, target, 0)` writes `ctx.Dr0 = target`, clears the condition+size nibbles at `DR7[16+index*4 .. 16+index*4+4]`, and sets L0 (`DR7 |= 1 << 0`). `nt_set_context()` flushes the new context. Size=00, Condition=00 → 1-byte execution breakpoint.
5. **Trigger + hijack** — When PowerShell/CLR calls `AmsiScanBuffer`, the CPU raises `EXCEPTION_SINGLE_STEP (0x80000003)` with `ExceptionAddress == AmsiScanBuffer`. The handler reads arg index 5 (`pResult`) via `get_arg(ctx, 5)` — for the 6th argument this reads `[RSP+0x30]` after the call — writes `AMSI_RESULT_CLEAN = 0` through it, sets `ctx.Rax = S_OK = 0`, sets `ctx.Rip = *(RSP as *const usize)` (caller return address), bumps `ctx.Rsp += 8`, then `clear_breakpoint(ctx, 0)` + `enable_breakpoint(ctx, target, 0)` to re-arm for the next invocation. Returns `EXCEPTION_CONTINUE_EXECUTION`.
6. **Return to caller** — Execution resumes at the instruction following the caller's `call qword ptr [AmsiScanBuffer]` with `RAX=0`. The CLR sees a successful scan with a clean verdict.

### AMSI Bypass — PAGE_GUARD Fallback (in `amsi_hbp.rs`)

7. **Stub allocation** — `install_page_guard_bypass()` calls `crate::recycled::nt_allocate_virtual_memory(CURRENT_PROCESS, …, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`. The 3-byte stub `CLEAN_STUB_BYTES = [0x31, 0xC0, 0xC3]` (`xor eax,eax; ret`) is copied via `ptr::copy_nonoverlapping`.
8. **Stub flip to RX** — `crate::recycled::nt_protect_virtual_memory` flips the page `PAGE_READWRITE → PAGE_EXECUTE_READ`. RWX is never granted at any instant (matches the ACG philosophy of `policy.rs`).
9. **Guard placement** — `nt_protect_virtual_memory` applies `PAGE_EXECUTE_READ | PAGE_GUARD (0x100)` to the **4K page** containing `AmsiScanBuffer`. The page base is computed as `target & !0xFFF`.
10. **Trigger path** — Any execution touching that page raises `EXCEPTION_GUARD_PAGE (0x80000001)`. The handler computes `fault_addr & !0xFFF == page_base`, then sets `ctx.Rip = PAGE_GUARD_SHADOW_STUB` (the xor/eax/ret stub) and sets `EFlags |= EFLAGS_TRAP_FLAG (1<<8)` so the next instruction traps again — at which point the handler re-arms PAGE_GUARD (not shown; the TF re-arm pattern is the standard idiom).

### AMSI Bypass — Standalone PAGE_GUARD (`amsi_page_guard.rs`)

11. **State** — Two `AtomicUsize` globals: `AMSI_SCAN_BUFFER_ADDR` (target), `VEH_HANDLE` (cleanup). Resolution is identical to `amsi_hbp.rs` — `crate::resolve::find_module_base` + `resolve_export_by_name`.
12. **VEH dispatch** — `page_guard_veh_handler()` only handles `EXCEPTION_GUARD_PAGE`. It computes the page-aligned target via `& !0xFFF`. On match, it writes `*(pResult) = 0` (arg 6 read from `[RSP+0x30]` after `RSP += 8` arithmetic — note the `add(6)` indexing), sets `ctx.Rax = 0`, `ctx.Rip = return_address_from_ctx(ctx)`, `ctx.Rsp += 8`. Returns `EXCEPTION_CONTINUE_EXECUTION`.
13. **One-shot semantics** — Windows auto-clears PAGE_GUARD on the triggering access, so no re-arming is needed. The comment explicitly notes this is "sufficient: the first call is the CLR's initialization scan."
14. **Cleanup** — `remove_amsi_page_guard()` does `VEH_HANDLE.swap(0, AcqRel)` and `RemoveVectoredExceptionHandler`. The page is already back to `PAGE_EXECUTE_READ` so no protection restoration is needed.

### ETW Muffling — Primary (Provider EnableFlags Zeroing)

15. **Resolution** — `resolve_etw_event_write()` uses `crate::resolve::ntdll_base_and_name_hashes()` to get ntdll base, then `resolve_export_by_hash(ntdll, HASH_ETW_REGISTRATION_LIST = 0xC34BFDEC)`. The export walker validates `0x5A4D`, reads `e_lfanew @ +0x3C`, walks the EXPORT directory at `DataDirectory[0] @ +0x88` — iterating `AddressOfNames/AddressOfNameOrdinals/AddressOfFunctions` and recomputing DJB2 (`h = (h<<5)+h+b`).
16. **Provider zeroing** — `muffle_etw_providers()` walks the `EtwRegistrationList` LIST_ENTRY from `head->Flink`, capping at 512 entries. For each entry, it computes `entry_base = current - ETW_GUID_ENTRY_GUIDLIST_OFFSET (0x00)` and writes `0` to `entry_base + ETW_GUID_ENTRY_ENABLE_INFO_OFFSET (0x38)` via `ptr::write_volatile`. The volatile prevents the compiler from eliding the write.
17. **Acknowledged limitation** — The comment block at L107-L116 explicitly admits that `EtwRegistrationList` is **NOT** an exported symbol on most ntdll builds, so the primary path usually falls through to the byte-patch fallback. `mega_dbg!` logs this.

### ETW Muffling — Fallback (EtwEventWrite Byte-Patch)

18. **RW transition** — `patch_etw_via_nt()` resolves `EtwEventWrite` via the same hash walk (DJB2 = `0x24A8D022`), then calls `crate::recycled::invoke(hash_of_NtProtectVirtualMemory, 5, &args)` with `PAGE_READWRITE (0x04)` — **never RWX (0x40)**, the comment emphasizes.
19. **Patch + restore** — After `ptr::copy_nonoverlapping(ETW_PATCH = [0x33, 0xC0, 0xC3], etw_addr, 3)`, a second `recycled::invoke` restores the original protection. `xor eax,eax; ret` makes `EtwEventWrite` return `STATUS_SUCCESS = 0` without emitting any event.
20. **Public entry** — `muffle_etw()` tries primary first; if it returns `false`, calls `patch_etw_via_nt()`. Returns `true` only if at least one path succeeded.

### PE Header Stomping

21. **Primitive** — `stomp_pe_header(base, size)` is a one-liner: `ptr::write_bytes(base, 0u8, size)`. No syscall, no protection flip — the caller is responsible for the page already being writable.
22. **Self-derived size** — `stomp_own_pe_header(base)` validates `dos_magic == 0x5A4D`, reads `e_lfanew` (bounds-checked `0..0x1000`), verifies `nt_sig == 0x4550` ("PE\0\0"), reads `OptionalHeader.Magic` at `nt+4+20` and dispatches on `0x020B` (PE32+) vs `0x010B` (PE32) — `SizeOfHeaders` is at `optional+56` for **both**. Bounds check `0 < size_of_headers < 0x10000`. Then calls `stomp_pe_header`.
23. **Self-stomp** — `stomp_self_header()` is `cfg(feature = "pe_stomp")` gated. It reads `PEB` via `mov {}, gs:[0x60]`, dereferences `ImageBaseAddress` at `+0x10`, calls `VirtualProtect(…, 0x1000, PAGE_EXECUTE_READWRITE, &mut old)`, calls `stomp_own_pe_header(image_base)`, then restores the original protection. **Note**: this uses `windows::Win32` (not RecycledGate) — it's the experimental crate, not the hardened `crowd` crate.

## Code Architecture

### Call Graph

```
fsm::ExecutionContext (T-022 architecture)
  └── amsi_hbp::patch_fsm()              ← FSM phase hook
        └── install_amsi_hbp()
              ├── resolve_amsi_scan_buffer()
              │     ├── crate::resolve::find_module_base()           ← T-004 PEB Walker
              │     ├── crate::resolve::ntdll_base_and_name_hashes() ← T-004
              │     └── crate::resolve::resolve_export_by_name()      ← T-004
              ├── install_dr0_bypass()
              │     ├── AddVectoredExceptionHandler(1, exception_handler)  ← Win32
              │     ├── nt_get_context() → recycled::recycled2()         ← T-001
              │     └── nt_set_context() → recycled::recycled2()        ← T-001
              └── install_page_guard_bypass()
                    ├── recycled::nt_allocate_virtual_memory()         ← T-001
                    ├── recycled::nt_protect_virtual_memory()          ← T-001 (RW→RX)
                    └── recycled::nt_protect_virtual_memory()          ← T-001 (PAGE_GUARD)

etw::muffle_etw()
  ├── muffle_etw_providers() → resolve_export_by_hash()               ← T-004 DJB2 hash walk
  └── patch_etw_via_nt()
        ├── resolve_etw_event_write() → resolve_export_by_hash()     ← T-004
        └── recycled::invoke(hash, 5, &args) × 2                       ← T-001

pe_header_stomp::stomp_self_header()  (cfg = "pe_stomp")
  ├── gs:[0x60] PEB read                                              ← T-004 inline
  ├── windows::Win32::VirtualProtect()                                ← NOT RecycledGate
  └── stomp_own_pe_header() → stomp_pe_header() (ptr::write_bytes)
```

### Data Flow

- **State**: `amsi_hbp.rs` uses three `static mut` globals (`AMSI_SCAN_BUFFER_PTR`, `PAGE_GUARD_SHADOW_STUB`, `PAGE_GUARD_ACTIVE`) — `#[allow(static_mut_refs)]` acknowledges the latent soundness hole. `amsi_page_guard.rs` modernizes this to `AtomicUsize` (`AMSI_SCAN_BUFFER_ADDR`, `VEH_HANDLE`) with `Ordering::Release`/`AcqRel` for safe cross-thread visibility.
- **CONTEXT manipulation**: The VEH handlers receive `EXCEPTION_POINTERS` and mutate `ctx.Rip`, `ctx.Rsp`, `ctx.Rax`, `ctx.Dr0`/`ctx.Dr7`, `ctx.EFlags` directly through `*mut CONTEXT`.
- **PEB module enumeration** is shared across all three files via `crate::resolve` — single source of truth for module base resolution.
- **RecycledGate SSN/gadget lookup**: `crate::syscall_map::get_ssn_and_gadget(hash)` returns `(ssn: u32, gadget: usize)`. If `gadget == 0`, the function falls back to a direct `extern "system"` block (e.g., `NtGetContextThread`) — a safety net for boot-time SSN map population failures.

### Type Hierarchy

- `CONTEXT` (winapi) — 64-bit CPU context, mutated to redirect execution.
- `EXCEPTION_POINTERS` (winapi) — `{ ExceptionRecord, ContextRecord }` pair passed to VEH.
- `LdrLoadDllFn` — local type alias for `unsafe extern "system" fn(*const u16, *mut u32, *mut [usize; 2], *mut *const u8) -> i32`. The `*mut [usize; 2]` is an inline `UNICODE_STRING` representation: `Length | (MaxLength << 16)` in slot 0, buffer pointer in slot 1. For `"amsi.dll"` the values are `Length=16, MaxLength=18` (8 wchars + null).

### Feature Gates

- `crates/core/src/experimental/pe_header_stomp.rs::stomp_self_header` is `#[cfg(feature = "pe_stomp")]` — excluded from default builds to allow operator discretion (self-stomping can break post-load TLS callbacks if not sequenced).
- The `#![allow(static_mut_refs)]`, `#![allow(non_snake_case)]`, `#![allow(dead_code)]` attributes signal that `amsi_hbp.rs` is a "god-tier" prototype preserved for behavior, not for Rust purity.

## Operational Profile

### When to Use

- **Engagements against EDRs that rely on AMSI for content scanning** (Defender for Endpoint, SentinelOne with AMSI integration, CrowdStrike Falcon with AMSI): the DR0 path is invisible to most ETW-TI sensors because debug-register state is kernel-only.
- **.NET/PowerShell-heavy post-ex**: any `Assembly.Load` / `Invoke-PS` workflow where the runtime unconditionally invokes `AmsiScanBuffer` on every script and assembly.
- **Sacrificial processes for ETW muffling**: `muffle_etw()` should be invoked in the loader process before any reflective load or injection — zeroing provider `IsEnabled` before the EDR has a chance to register a `Microsoft-Windows-Threat-Intelligence` provider means the kernel never sees your syscall sequence.
- **Long-dwell implants**: `stomp_own_pe_header()` on the loader image post-IAT-fixup defeats pe-sieve and BeaconEye memory scanners that look for `MZ` signatures.
- **Concurrent VEH use**: AMSI HBP and KiUserException StepOver (T-016 sibling) share the DR register pool. Use `dr0_is_occupied()` to coordinate — DR1/DR2/DR3 are still available if DR0 is taken by KiStepOver.

### When NOT to Use

- **Defender for Endpoint standalone (no AMSI)**: if AMSI is already disabled at policy level, `install_amsi_hbp()` is dead weight; the function correctly no-ops when `amsi.dll` cannot be loaded (`return` silently).
- **CrashDump-capturing environments**: any process with `WerFault` post-mortem enabled — a VEH handler installed at CALL_FIRST will intercept the crash dump's `EXCEPTION_BREAKPOINT` first, potentially infinite-looping the dump. This is not handled in `exception_handler`.
- **Hyper-protected ETW-TI sensors** (Elastic Endpoint, Microsoft Defender for Endpoint with kernel telemetry): the fallback byte-patch on `EtwEventWrite` writes 3 bytes to a `PAGE_EXECUTE_READ` ntdll page — that protect flip via `NtProtectVirtualMemory` is observable by `MiProtoset` hooks even through RecycledGate. Prefer the primary provider-zeroing path; if that fails, abort rather than patch.
- **Don't `stomp_self_header()` before `LdrpCallTlsCallbacks`**: TLS callbacks (T-017 layer 4) read the PE header to find the TLS directory. The cfg gate `pe_stomp` exists for exactly this sequencing reason.
- **Heavy .NET host with already-loaded AMSI Assemblies**: `install_amsi_hbp()` only intercepts the **first** call to `AmsiScanBuffer` per DR0 re-arm cycle. Heavily cached `AmsiScan` results in `System.Management.Automation` can defeat the bypass if PowerShell has already pre-scanned your payload signature into the in-memory allowlist.

### Kill Chain Position

```
T-004 (PEB walker)         ─┐
T-003 (Hell's Gate SSNs)   ─┤
T-001 (RecycledGate)       ─┼──► T-016 (THIS)
                              │
                              ├──► AMSI bypass — pre-execution, before IEX/Assembly.Load
                              ├──► ETW muffling — at loader init, before any injection
                              └──► PE header stomp — post-IAT-fixup, post-TLS, pre-scanner run

Then enables:
T-012 (Early Cascade) — needs ETW dark
T-007 (Pool Party / Threadless) — needs Block-DLL policy active
T-005 (Ekko ROP sleep) — needs ntdll unhooked (sibling of T-016)
T-017 (Persistence) — needs AMSI off to register WMI subscribers via PS
```

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` Blocks — Catalog

| File:Function | Unsafe Purpose | Mechanism |
|---|---|---|
| `amsi_hbp.rs::exception_handler` | VEH callback; reads/writes raw `*mut CONTEXT` and `*mut EXCEPTION_RECORD` | `*(*exceptions).ContextRecord` deref, `*scan_result_ptr = AMSI_RESULT_CLEAN` write, DR7 bit manipulation |
| `amsi_hbp.rs::nt_get_context` | Syscall invocation via RecycledGate | `crate::recycled::recycled2(ssn, gadget, -2, ctx)`, fallback to `extern "system" NtGetContextThread` |
| `amsi_hbp.rs::nt_set_context` | Same as above for NtSetContextThread | `recycled2` + extern fallback |
| `amsi_hbp.rs::install_dr0_bypass` | Mutates global state and CONTEXT | `static mut AMSI_SCAN_BUFFER_PTR` read, VEH registration, `nt_set_context` |
| `amsi_hbp.rs::install_page_guard_bypass` | RW→RX page protection flip; guard placement | `recycled::nt_allocate_virtual_memory`, `ptr::copy_nonoverlapping`, `recycled::nt_protect_virtual_memory` ×2 |
| `amsi_hbp.rs::resolve_amsi_scan_buffer` | PEB + PE export walk; LdrLoadDll invocation | `crate::resolve::find_module_base`, `resolve_export_by_name`, `mem::transmute::<*mut u8, LdrLoadDllFn>` |
| `amsi_hbp.rs::install_amsi_hbp` | Top-level orchestrator | Calls the above |
| `etw.rs::resolve_export_by_hash` | PE header arithmetic + raw pointer reads | `*(base as *const u16) == 0x5A4D`, `*(base.add(0x3C) as *const u32)`, `slice::from_raw_parts(cstr, len)` |
| `etw.rs::muffle_etw_providers` | LIST_ENTRY walk on `_ETW_GUID_ENTRY` | `*head` Flink deref, `current.wrapping_sub(0x38)`, `ptr::write_volatile(enable_byte, 0u8)` |
| `etw.rs::patch_etw_via_nt` | RW flip + byte patch + restore | `recycled::invoke(hash, 5, &args)`, `ptr::copy_nonoverlapping(ETW_PATCH, etw_addr, 3)` |
| `pe_header_stomp.rs::stomp_pe_header` | Bulk zero-fill write | `ptr::write_bytes(base, 0u8, size)` |
| `pe_header_stomp.rs::stomp_own_pe_header` | PE header arithmetic | Multiple `*(base.add(N) as *const T)` reads with bounds checks |
| `pe_header_stomp.rs::stomp_self_header` | Inline PEB read + VirtualProtect + stomp | `asm!("mov {}, gs:[0x60]", out(reg) peb)`, VirtualProtect, stomp_own_pe_header |

### `core::arch::asm!` Usage

Only `pe_header_stomp.rs::stomp_self_header` uses inline asm:

```rust
std::arch::asm!(
    "mov {}, gs:[0x60]",
    out(reg) peb,
    options(nostack, preserves_flags)
);
```

- **Register constraint**: `out(reg)` lets the compiler pick an arbitrary general-purpose register.
- **gs:[0x60]**: x64 TEB→PEB indirection. `gs:[0x60]` is the canonical PEB pointer on Windows x64.
- **options(nostack)**: no stack adjustment — this is a pure read.
- **options(preserves_flags)**: `mov` doesn't touch EFLAGS.
- **No clobbers**: declared.

This is the same PEB read pattern used by `crate::resolve` (T-004 PEB walker). The experimental crate duplicates it inline rather than depending on `crowd`, indicating that `crates/core` and `crowd` are sibling crates without a shared utility layer.

### FFI Patterns

- **`extern "system"` blocks** are used as fallbacks in `nt_get_context`/`nt_set_context` (`amsi_hbp.rs` L155-L158, L170-L173) when the SSN/gadget map is unavailable. This is a **soundness risk**: if `crate::syscall_map::get_ssn_and_gadget` returns `(0, 0)`, the function falls back to direct `extern "system"` linkage — which means a normal IAT entry to `ntdll!NtGetContextThread` will be emitted by the linker, defeating the indirect-syscall promise.
- **`std::mem::transmute::<*mut u8, LdrLoadDllFn>`** in `resolve_amsi_scan_buffer` and `amsi_page_guard.rs` — converts a raw pointer resolved from the export table into a typed function pointer. Standard pattern; the type alias `LdrLoadDllFn` makes the signature explicit.
- **UNICODE_STRING inline construction**: `[usize; 2]` with `Length | (MaxLength << 16)` in slot 0 — this is an in-memory cast trick that avoids pulling in the `winapi::shared::ntdef::UNICODE_STRING` struct.

### Initialization Patterns

- **`static mut AMSI_SCAN_BUFFER_PTR: Option<*mut u8>`** in `amsi_hbp.rs` — lazy-init, written once on first `resolve_amsi_scan_buffer()` call. The `#[allow(static_mut_refs)]` is honest about the latent unsoundness.
- **`AtomicUsize` for state** in `amsi_page_guard.rs` — modern alternative pattern. `Ordering::Release` on store, `Ordering::Relaxed`/`AcqRel` for read. The VEH handler reads with `Relaxed` — acceptable since VEH installation happens-before via the `AddVectoredExceptionHandler` fence.
- **`OnceLock`** is not used; if a future revision is needed, the `static mut` should migrate to `OnceLock<*mut u8>` or `atomic::AtomicPtr<u8>`.
- **`cfg(feature = "pe_stomp")`** is the only feature gate in these four files; default builds omit `stomp_self_header` to keep the experimental surface off.

### Error Handling

- `amsi_hbp.rs::install_amsi_hbp()`: **silently swallows all failures**. The doc comment explicitly states "AMSI is optional hardening, not a hard requirement" — matches the operator principle of never crashing on evasion failure.
- `amsi_hbp.rs::install_dr0_bypass()`: returns `Result<(), String>` with string error messages — used to drive the fallback cascade in `install_amsi_hbp()` via `match`.
- `amsi_page_guard.rs::install_amsi_page_guard()`: returns `anyhow::Result<bool>` — `Ok(false)` for "amsi.dll not loaded", `Ok(true)` for installed, `Err` for syscall failure. Cleanup is **explicitly invoked** on the syscall-failure path (removes the VEH handler).
- `etw.rs::muffle_etw()`: returns `bool`. The `mega_dbg!` macro logs failure but the function does not propagate errors — operator must inspect debug logs.
- `pe_header_stomp.rs::stomp_own_pe_header()`: returns `anyhow::Result<usize>` with **defensive bounds checking**: null check, `e_lfanew` range `0..0x1000`, `SizeOfHeaders` range `0..0x10000`, optional magic validation. Returns `Ok(0)` for "already stomped" (not a fatal error).

### Memory Layout

- **`CONTEXT`** size: 1232 bytes on x64 (winapi `CONTEXT_ALL` includes `DebugRegisters` at `Dr0`/`Dr1`/`Dr2`/`Dr3`/`Dr6`/`Dr7`, `EFlags`, and XMM state).
- **`EXCEPTION_POINTERS`** size: 16 bytes (2 pointers).
- **`UNICODE_STRING`** inline representation: 16 bytes (2 `usize` slots).
- **`_ETW_GUID_ENTRY`** (per code comments): `+0x00 LIST_ENTRY GuidList`, `+0x10 LIST_ENTRY RegList`, `+0x20 ULONG64 Luid`, `+0x28 GUID ProviderId (16 bytes)`, `+0x38 ETW_PROVIDER_ENABLE_INFO EnableInfo`. The `EnableInfo.IsEnabled` byte is at offset `0x38`.
- **PE header layout (stomp)**: MZ @ `+0x00` (2B), `e_lfanew` @ `+0x3C` (4B), NT sig `PE\0\0` @ `e_lfanew+0`, FileHeader 20B, OptionalHeader Magic @ `e_lfanew+4+20` (2B), `SizeOfHeaders` @ `e_lfanew+4+20+56` for both PE32 and PE32+ (4B).

### Syscall Numbers

- `NtGetContextThread` — resolved via `crate::syscall_map::get_ssn_and_gadget(crate::resolve::compute_hash("NtGetContextThread"))`.
- `NtSetContextThread` — same path.
- `NtAllocateVirtualMemory` — via `crate::recycled::nt_allocate_virtual_memory` wrapper.
- `NtProtectVirtualMemory` — via `crate::recycled::nt_protect_virtual_memory` wrapper (used 4× across the suite: stub RW→RX, guard placement, ETW patch RW, ETW patch restore).
- All syscall numbers are runtime-resolved via the T-001/T-002/T-003 SSN cascade (Hell's Gate → Halo's Gate → Tartarus Gate). The gadget pointer is found by `crate::recycled` walking ntdll `.text` for a `syscall; ret` pattern.

## Cross-References Found in Code

| Reference | Connection |
|---|---|
| `amsi_hbp.rs::nt_get_context` → `crate::syscall_map::get_ssn_and_gadget` | **T-004 Syscall Dispatch** — SSN+gadget lookup |
| `amsi_hbp.rs::nt_get_context` → `crate::recycled::recycled2` | **T-001 RecycledGate** — indirect syscall |
| `amsi_hbp.rs::install_page_guard_bypass` → `crate::recycled::nt_allocate_virtual_memory` | **T-001 RecycledGate** — NT wrapper |
| `amsi_hbp.rs::install_page_guard_bypass` → `crate::recycled::nt_protect_virtual_memory` | **T-001 RecycledGate** — NT wrapper |
| `amsi_hbp.rs::resolve_amsi_scan_buffer` → `crate::resolve::find_module_base` | **T-004 PEB Walker** — module enumeration |
| `amsi_hbp.rs::resolve_amsi_scan_buffer` → `crate::resolve::resolve_export_by_name` | **T-004 PEB Walker** — export resolution |
| `amsi_hbp.rs::resolve_amsi_scan_buffer` → `crate::resolve::ntdll_base_and_name_hashes` | **T-004 PEB Walker** — ntdll base |
| `amsi_hbp.rs::patch_fsm` → `crate::fsm::ExecutionContext` | **T-022 Architecture** — FSM integration |
| `amsi_hbp.rs::exception_handler` (DR0 path) | **Sibling in T-016**: shares DR register pool with `ki_step_over.rs` |
| `etw.rs::patch_etw_via_nt` → `crate::recycled::invoke(hash, 5, &args)` | **T-001 RecycledGate** — variadic indirect syscall |
| `etw.rs::resolve_export_by_hash` → `crate::resolve::compute_hash` | **T-004 PEB Walker** — DJB2 hash |
| `etw.rs::patch_etw_via_nt` (PAGE_READWRITE never RWX) | **Sibling in T-016**: aligns with `policy.rs` ACG philosophy |
| `pe_header_stomp.rs::stomp_self_header` → `gs:[0x60]` PEB read | **T-004 PEB Walker** — inline variant |
| `pe_header_stomp.rs::stomp_self_header` → `VirtualProtect` (Win32) | **NOT** via RecycledGate — experimental crate uses raw Win32; operator porting should swap to `crate::recycled::nt_protect_virtual_memory` |
| Doc comment: "Synergy: combine with Module Overloading (MEM_IMAGE) + Sleep Obfuscation for the MEMORY TRIAD chain (darkcrystal.html score 9.5/10)" | References **T-013 Module/Func Stomp** + **T-005 Ekko ROP Sleep** |
| Doc comment: "pe-sieve/BeaconEye can't parse/dump but .text execution continues" | References external memory scanners (Hunt-Sleeping-Beacons, pe-sieve) |

## Edge Cases & Failure Modes

1. **DR0 already occupied by debugger / EDR / KiStepOver HBP**
   - *Code path*: `install_dr0_bypass()` → `dr0_is_occupied()` returns `true` → returns `Err("DR0 is occupied — falling back to Page Guard")` → `install_amsi_hbp()` catches `Err(_)` and calls `install_page_guard_bypass()`.
   - *Symptom*: silent fallback; debug log will indicate "Page Guard" path.
   - *Workaround*: PAGE_GUARD fallback is automatic. The DR0 path is also re-armable for the next AMSI scan via `enable_breakpoint()` in the handler.

2. **amsi.dll not loaded** (e.g., native Win32 process without CLR)
   - *Code path*: `resolve_amsi_scan_buffer()` → `find_module_base("amsi.dll")` is null → attempts `LdrLoadDll`. If amsi.dll is not on the system (Server Core without .NET), LdrLoadDll fails.
   - *Symptom*: `install_amsi_hbp()` silently returns. No error propagated. The `patch_fsm` wrapper returns `true` regardless — FSM proceeds.
   - *Workaround*: none needed; AMSI is absent and content scanning is moot.

3. **`AddVectoredExceptionHandler` returns null** (rare: low memory or the VEH chain is corrupted)
   - *Code path*: `install_dr0_bypass()` returns `Err("AddVectoredExceptionHandler failed")` → falls through to Page Guard, which also calls `AddVectoredExceptionHandler`. If that also fails, `install_amsi_page_guard()` returns the `Err` which is silently dropped by the outer `let _ =`.
   - *Symptom*: AMSI bypass does not install. Runtime AMSI scans will see real content.
   - *Workaround*: none in code. 

4. **`EtwRegistrationList` not an exported symbol** (per code comments, this is the common case on Win10/11 retail builds)
   - *Code path*: `muffle_etw_providers()` → `resolve_export_by_hash(ntdll, HASH_ETW_REGISTRATION_LIST)` returns null → `mega_dbg!` logs "symbol is private/unexported" → returns `false` → `muffle_etw()` falls back to `patch_etw_via_nt()`.
   - *Symptom*: ETW provider zeroing is effectively never the active path on production Windows. The byte-patch on EtwEventWrite is the de-facto technique.
   - *Workaround*: maintain an offset table per Windows build for `EtwRegistrationList` (it lives at a known RVA inside ntdll .data) — this would let the primary path succeed.

5. **Calling `stomp_own_pe_header()` on an already-stomped image**
   - *Code path*: `dos_magic != 0x5A4D` → returns `Ok(0)` (no error).
   - *Symptom*: idempotent. Safe to call repeatedly.

6. **`stomp_own_pe_header()` on a non-PE mapped region** (e.g., shellcode)
   - *Code path*: `dos_magic != 0x5A4D` → returns `Ok(0)`. Safe.
   - *Symptom*: no crash, no zeroing. The caller can detect "0 bytes zeroed" to know the region was not a PE.

7. **`stomp_own_pe_header()` on a PE with `e_lfanew > 0x1000`** (unusual, possibly malicious)
   - *Code path*: bounds check fails → returns `Err("invalid e_lfanew")`.
   - *Symptom*: caller (e.g., `stomp_self_header`) propagates the error via `?`. The `VirtualProtect` flip has already happened — **the page is now RWX but not restored**. Memory leak + OPSEC regression.
   - *Workaround*: the `stomp_self_header` finally block should restore protection even on `Err`. This is a **bug** in the current code.

8. **VEH handler infinite loop** (TF bit set without a corresponding TF-clear)
   - In `amsi_hbp.rs::exception_handler` CASE 2, `ctx.EFlags |= EFLAGS_TRAP_FLAG` is set to re-arm PAGE_GUARD on next instruction. If the next instruction is also on the same page (e.g., the shadow stub itself is on the same page), the TF exception fires again, the handler sees a non-GUARD_PAGE exception (it's EXCEPTION_SINGLE_STEP from TF), and falls through to `EXCEPTION_CONTINUE_SEARCH` — which may crash if no other handler exists.
   - *Symptom*: process terminates with unhandled EXCEPTION_SINGLE_STEP.
   - *Workaround*: allocate the shadow stub on a **different 4K page** than AmsiScanBuffer (which it is — `nt_allocate_virtual_memory` with `0` alignment is anywhere). The risk is only if the allocator happens to return a nearby address; with `size=3` the stub is in a fresh 4K page in practice.

9. **Concurrent invocation during VEH install** (multithreaded loader)
   - `amsi_page_guard.rs` uses `AtomicUsize` for `AMSI_SCAN_BUFFER_ADDR` and `VEH_HANDLE`, but the VEH handler reads both with `Relaxed`. If the handler fires between the `VEH_HANDLE.store` and the `NtProtectVirtualMemory` call, the handler returns `EXCEPTION_CONTINUE_SEARCH` because `target == 0` (already cleared on retry path). No infinite loop.
   - *Symptom*: clean fallback semantics.

## OPSEC Notes

### Artifacts Left

- **VEH chain entry** — `AddVectoredExceptionHandler(1, ...)` inserts at CALL_FIRST. EDRs that inspect the VEH list (Process Hacker's "VEH" tab) will see the entry. Not patched in code.
- **DR0 register set** — `NtSetContextThread` writes DR0/DR7. Some EDRs intercept `NtSetContextThread` and log debug-register changes (this is rare; most EDRs only hook `NtSetContextThread` cross-process, not self-target with -2).
- **PAGE_GUARD attribute on amsi.dll's page** — `NtProtectVirtualMemory` with `PAGE_GUARD` on a `MEM_IMAGE` page is unusual. Memory scanning tools that enumerate region protections will flag it. The PAGE_GUARD fallback is detectable; the DR0 path is preferred.
- **Allocated RW→RX stub region** — `install_page_guard_bypass` allocates 3 bytes in a fresh 4K page and flips to RX. A 3-byte RX region in the process's address space is a clear anomaly (typical RX regions are whole PE images).
- **ETW byte-patch** — 3 bytes `0x33 0xC0 0xC3` written to `EtwEventWrite` in ntdll .text. ntdll integrity scanners (e.g., `pe-sieve --refs ntdll`) detect this immediately.
- **PE header zeroed** — `stomp_own_pe_header` removes MZ/NT headers. pe-sieve's `MEM_IMAGE` scan will skip the region as "not a PE" — desired effect. But scanners that compare the in-memory image to the on-disk image will note the header mismatch.

### Telemetry Surface

- **NtGetContextThread / NtSetContextThread** via RecycledGate — if the EDR hooks these syscalls (rare, even for kernel-CAPI EDRs, because legitimate debuggers use them constantly), the SSN+gadget pattern is observable. The fallback to `extern "system"` direct call (in `nt_get_context`) emits an IAT entry — **this is a soundness regression** if the operator relies on the no-imports principle.
- **NtProtectVirtualMemory** with `PAGE_GUARD` on a `MEM_IMAGE` page — observable via `MiProtectSystemImage` kernel callback (the kernel re-flips PAGE_GUARD on image pages to PAGE_EXECUTE_READ in some versions, which silently disables the bypass).
- **NtAllocateVirtualMemory** for the shadow stub — observable but benign (every loader allocates).
- **`AddVectoredExceptionHandler`** is `kernel32!KernelBase` — emits a normal IAT entry to `kernel32.dll`. RecycledGate does not cover this call (the code uses raw `winapi::um::errhandlingapi::AddVectoredExceptionHandler`).

### Cleanup Performed

- `amsi_page_guard.rs::remove_amsi_page_guard()` — full cleanup: `RemoveVectoredExceptionHandler` + atomic state clear.
- `amsi_hbp.rs` — **no uninstall function**. The DR0 breakpoint persists for the process lifetime. The VEH handler remains registered. 
- `etw.rs` — no uninstall; the byte-patch persists. `EtwEventWrite` returns 0 forever. For OPSEC cleanup, restore the original 3 bytes (`0x4C 0x8B 0xDC` typically — `mov r11, rsp`, the actual prologue) from a fresh ntdll read.
- `pe_header_stomp.rs::stomp_self_header` — restores the page protection (`PAGE_EXECUTE_READ` typically) but does NOT restore the headers. Intentional — the stomp is irreversible.

## Reusable Patterns

### Pattern: DR7 Bit Manipulation via Generic `set_bits`
- **Use when**: manipulating debug control register fields without clobbering other DRs.
- **Code ref**: `amsi_hbp.rs::set_bits(dw, low_bit, bits, new_value)`
- **How**: `(dw & !((mask) << low_bit)) | (new_value << low_bit)`. Used for both the L/G enable bits at `index*2` and the condition+size nibbles at `16+index*4`. Avoids the common mistake of `|=` which doesn't clear existing bits.

### Pattern: VEH Handler Dual-Case Dispatch
- **Use when**: a single VEH handler needs to service multiple exception types (HW breakpoint + PAGE_GUARD + ACCESS_VIOLATION in one handler).
- **Code ref**: `amsi_hbp.rs::exception_handler()` L113-L172
- **How**: `if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP && exception_record.ExceptionAddress == target { ... }` followed by `if PAGE_GUARD_ACTIVE && exception_record.ExceptionCode == EXCEPTION_GUARD_PAGE { ... }`. Falls through to `EXCEPTION_CONTINUE_SEARCH` for unhandled cases.

### Pattern: AtomicUsize for VEH State
- **Use when**: VEH handler reads from a global and the install/remove paths may run concurrently.
- **Code ref**: `amsi_page_guard.rs` (`AMSI_SCAN_BUFFER_ADDR`, `VEH_HANDLE`)
- **How**: `AtomicUsize` with `Ordering::Release` on store (publishes the value before the VEH is registered), `Ordering::Relaxed` in the handler (the VEH registration is the actual fence), `Ordering::AcqRel` on `swap(0)` for cleanup.

### Pattern: RW→RX Staged Allocation (Never RWX)
- **Use when**: allocating executable stubs without tripping ACG policy or W^X memory scanners.
- **Code ref**: `amsi_hbp.rs::install_page_guard_bypass` L197-L230
- **How**: `nt_allocate_virtual_memory` with `PAGE_READWRITE`, `ptr::copy_nonoverlapping` the bytes, then `nt_protect_virtual_memory` to `PAGE_EXECUTE_READ`. RWX (0x40) is explicitly avoided in comments — matches `policy.rs` ACG philosophy.

### Pattern: Inline UNICODE_STRING Cast
- **Use when**: needing `LdrLoadDll` or other `PCUNICODE_STRING` parameters without pulling in the `ntdef` crate.
- **Code ref**: `amsi_hbp.rs::resolve_amsi_scan_buffer` L265-L275
- **How**: `let mut us: [usize; 2] = [length | (maxlength << 16), buffer_ptr_as_usize];` then pass `&mut us as *mut [usize; 2]`. The `LdrLoadDllFn` type alias declares the parameter as `*mut [usize; 2]` which matches the in-memory layout of `UNICODE_STRING` on x64.

### Pattern: DJB2 Export-Table Walker
- **Use when**: resolving NT functions by hash without `GetProcAddress` in the import table.
- **Code ref**: `etw.rs::resolve_export_by_hash` L60-L94
- **How**: Validate `0x5A4D` magic → read `e_lfanew` → read `DataDirectory[0]` (EXPORT) at `nt+0x88` → iterate `AddressOfNames` computing DJB2 for each → on match, follow `AddressOfNameOrdinals` to get the ordinal, then `AddressOfFunctions[ord]` to get the RVA. Returns `base + rva`.

### Pattern: PE Header Validation Cascade
- **Use when**: validating a mapped PE before header arithmetic.
- **Code ref**: `pe_header_stomp.rs::stomp_own_pe_header` L48-L93
- **How**: null check → `dos_magic == 0x5A4D` → `e_lfanew` in `0..0x1000` → `nt_sig == 0x0000_4550` → `OptionalHeader.Magic` in `{0x020B, 0x010B}` → `SizeOfHeaders` in `0..0x10000`. Each check fails fast with `anyhow::anyhow!` describing the exact violation. This is the canonical "safe PE arithmetic" pattern.

### Pattern: Idempotent Stomp
- **Use when**: an operation may be called multiple times and should not error on the second call.
- **Code ref**: `pe_header_stomp.rs::stomp_own_pe_header` L57-L60
- **How**: `if dos_magic != 0x5A4D { return Ok(0); }` — already-stomped images return success without writing. Enables re-runs of the stomp call without tracking state.

### Pattern: `patch_fsm` Always-True Hook
- **Use when**: a technique is optional hardening that should never block the FSM.
- **Code ref**: `amsi_hbp.rs::patch_fsm` L295-L298
- **How**: `pub fn patch_fsm(_ctx: &mut ExecutionContext) -> bool { install_amsi_hbp(); true }`. Returns `true` unconditionally regardless of whether AMSI was actually patched. The FSM proceeds even on failure. Matches the operator principle: evasion techniques must be best-effort, never blocking.
