---
id: T-015
name: PPID Spoofing
category: process-injection
tier: S
mitre:
  - T1134.004
  - T1106
  - T1055
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires:
  - T-001
enables:
  - T-007
  - T-009
  - T-010
  - T-012
  - T-013
  - T-016
vault_references:
  - dark_crystal/crowd/src/ppid.rs
implements:
  - file: dark_crystal/crowd/src/ppid.rs
    key_functions:
      - find_pid_by_name
      - spawn_with_ppid_spoof
      - spawn_background_with_ppid
    key_structs:
      - PsAttribute
      - PsAttributeList
      - PsCreateInfo
      - PsCreateInfoInit
      - ObjectAttributes
      - PBI
    key_constants:
      - PS_ATTRIBUTE_PARENT_PROCESS
      - PS_ATTRIBUTE_IMAGE_NAME
      - PS_STD_HANDLE_STATE_ENABLED
      - PROCESS_CREATE_PROCESS
      - PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
      - CREATE_SUSPENDED
      - EXTENDED_STARTUPINFO_PRESENT
    lines_of_interest:
      - "L43-L48: PS_ATTRIBUTE_* constants (NT-internal)"
      - "L50-L75: PsAttribute / PsAttributeList / PsCreateInfo structs (defined but unused in current path)"
      - "L82-L121: find_pid_by_name() — Toolhelp32 walk + RecycledGate nt_close"
      - "L123-L192: spawn_with_ppid_spoof() — actual implementation via CreateProcessW + STARTUPINFOEX"
      - "L195-L218: spawn_background_with_ppid() — NtQueryInformationProcess PID retrieval"
min_windows: "6.0 (Vista) — STARTUPINFOEXW + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
needs_admin: "no (same-user parent only); conditional for cross-user"
tags:
  - ppid
  - process-creation
  - parent-spoofing
  - nt-api
  - createprocessw
  - startupinfoex
  - proc-thread-attribute
  - handle-hygiene
---

# PPID Spoofing — Operator Playbook

## TL;DR
Launches a child process with a forged parent PID (typically `explorer.exe`) so that the new process inherits the parent's lineage, security context, and trust markings. The implementation actually uses `CreateProcessW` with a `STARTUPINFOEXW` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` attribute list rather than the `NtCreateUserProcess` syscall that the file's header comment advertises — both reach the same outcome, but the Win32 path emits more ETW noise. All parent-handle and toolhelp-snapshot cleanup is routed through `crate::recycled::nt_close` (T-001 RecycledGate) instead of `CloseHandle`, preserving the syscall-stack indirection story even though the process create call itself is Win32.

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `dark_crystal/crowd/src/ppid.rs` | Single-file PPID-spoof module: PID resolution, parent handle acquisition, attribute-list construction, suspended-or-resumed spawn, and post-spawn PID retrieval | `find_pid_by_name()`, `spawn_with_ppid_spoof()`, `spawn_background_with_ppid()` | ~9K |

## How It Works

1. **Target parent PID resolution** — `find_pid_by_name("explorer.exe")` opens a `TH32CS_SNAPPROCESS` snapshot via `CreateToolhelp32Snapshot` (Win32 Toolhelp, *not* NT-direct), iterates with `Process32FirstW` / `Process32NextW`, and string-matches `PROCESSENTRY32W.szExeFile` case-insensitively. The snapshot handle is closed with `crate::recycled::nt_close` — *not* `CloseHandle` — to keep the syscall stack on the indirect path. On miss it returns `None`.

2. **Parent handle acquisition** — In `spawn_with_ppid_spoof()`, the code calls `crate::recycled::nt_open_process(...)` with `PROCESS_CREATE_PROCESS = 0x0080` and an inline `ObjectAttributes` struct whose `Length` field is the correct `u32` (Windows ABI). The `CLIENT_ID` array `[pid, 0]` is passed as the CID pointer. Returns `h_parent` as a `HANDLE` on success, or an `anyhow` error containing the `NTSTATUS` hex on failure.

3. **Attribute-list construction (Win32 path)** — `InitializeProcThreadAttributeList` is called twice: first with `null_mut()` to query required size, then with the allocated `Vec<u8>` buffer to initialize. `UpdateProcThreadAttribute` is then called with attribute `0x00020000` (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) and a *copy* of the parent handle (`let mut h_parent_copy = h_parent;`) — this is required because the API duplicates rather than borrows.

4. **STARTUPINFOEX population** — `STARTUPINFOEXW` is zero-initialized and its `StartupInfo.cb` set to `size_of::<STARTUPINFOEXW>()`. The `lpAttributeList` field is set to the constructed attribute list pointer.

5. **Spawn with optional suspend** — `CreateProcessW` is called with:
   - `lpApplicationName = null_mut()`
   - `lpCommandLine = wide_cmd` (UTF-16, NUL-terminated image path)
   - `dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT | (0x4 if suspend)"`
   - `lpStartupInfo = &mut si.StartupInfo` (note: the EX variant is passed via its embedded `StartupInfo` field; `EXTENDED_STARTUPINFO_PRESENT` tells the kernel to read the larger struct)
   - `lpProcessInformation = &mut pi`

6. **Cleanup ordering** — `DeleteProcThreadAttributeList` is invoked *immediately* after `CreateProcessW` returns (the kernel has already consumed the attribute list by this point). Then `crate::recycled::nt_close(h_parent_usize)` releases the spoofed-parent handle. The resulting `(pi.hProcess, pi.hThread)` are returned to the caller, who owns both.

7. **PID retrieval (background variant)** — `spawn_background_with_ppid` calls `crate::recycled::nt_query_information_process(h_proc, 0, ...)` with `ProcessBasicInformation` (`InfoClass=0`) and an inline `PBI` struct. The `unique_pid` field at offset `[usize;4]` is read out as the new PID, then both process and thread handles are released via `nt_close`.

## Code Architecture

### Call Graph

```
spawn_with_ppid_spoof()
  ├─ find_pid_by_name()            [if parent_pid == 0]
  │     ├─ CreateToolhelp32Snapshot     (Win32)
  │     ├─ Process32FirstW / NextW      (Win32)
  │     └─ crate::recycled::nt_close() (T-001 RecycledGate)
  ├─ crate::recycled::nt_open_process()  (T-001 RecycledGate)
  ├─ InitializeProcThreadAttributeList   (Win32)
  ├─ UpdateProcThreadAttribute           (Win32)
  ├─ CreateProcessW                      (Win32)
  ├─ DeleteProcThreadAttributeList       (Win32)
  └─ crate::recycled::nt_close()         (T-001 RecycledGate)

spawn_background_with_ppid()
  ├─ spawn_with_ppid_spoof()
  ├─ crate::recycled::nt_query_information_process()  (T-001)
  ├─ crate::recycled::nt_close() x2                   (T-001)
```

### Data Flow
- `image_path: &str` → UTF-16 encode → `wide_cmd: Vec<u16>` → `CreateProcessW` lpCommandLine
- `parent_pid: u32` → `CLIENT_ID [pid, 0]` → `nt_open_process` → `h_parent_usize: usize` → cast to `HANDLE` → copied into attribute list → consumed by `CreateProcessW`
- `pi: PROCESS_INFORMATION` → returned as `(HANDLE, HANDLE)` tuple — caller owns both

### Type Hierarchy
- `PsAttribute` (defined, unused) — 4 × `usize` = 32 bytes on x64
- `PsAttributeList` (defined, unused) — `total_length + [PsAttribute; 3]` = 104 bytes
- `PsCreateInfo` (defined, unused) — `size + state + init_union` ≈ 24 bytes with padding
- `PsCreateInfoInit` (defined, unused) — `union { flags: u32, ptr: usize }`
- `ObjectAttributes` (inline in fn, used) — `[u32 length][u32 pad][5 × usize]` ≈ 48 bytes
- `PBI` (inline in fn, used) — `[_pad: usize;4][unique_pid][uninherited]` = 48 bytes, unique_pid at offset 32

### Feature Gates
None. `#![allow(dead_code, non_snake_case)]` at module top permits the unused NT-direct scaffolding to compile without warnings.

## Operational Profile

### When to Use
- Spawning sacrificial processes for injection chains where the implant should appear to descend from `explorer.exe` (browser-like lineage) or `svchost.exe` (service-like lineage) rather than the loader's own (often suspicious) parent.
- Preparing a suspended child for `T-012 Early Cascade` APC injection or `T-009 Process Ghosting` follow-up.
- Burning handle forensics: a child spawned from `explorer.exe` will not raise the typical "unknown parent spawned suspicious child" EDR rule.
- Long-lived background helpers (use `spawn_background_with_ppid`) where you don't need continued handle ownership.

### When NOT to Use
- Operations requiring the *minimum* ETW footprint — the current implementation uses `CreateProcessW`, which is one of the most heavily hooked/instrumented Win32 calls. Wait for the NT-direct variant (currently scaffolded but unwired) or pivot to `T-014 NtCreateUserProcess`.
- Cross-user parent spoofing (e.g., making your process look like it descended from `winlogon.exe` running as SYSTEM) without `SeDebugPrivilege` — `NtOpenProcess` with `PROCESS_CREATE_PROCESS` on a higher-integrity process will return `STATUS_ACCESS_DENIED (0xC0000022)`.
- Scenarios where you must avoid `STARTUPINFOEX` artifacts in ETW `Kernel.Process` events — the extended-startupinfo flag is a known EDR heuristic.

### Kill Chain Position
PPID spoof is a *process creation* primitive — it sits at the front of any chain that needs a sacrificial or camouflage process:

```
T-004 (PEB walk) → T-001 (RecycledGate) → T-015 (PPID Spoof, this) → T-012 (Early Cascade APC) → T-005 (Ekko sleep)
                                                                              → T-016 (Block-DLL / ACG on child)
                                                                              → T-017 (persistence)
```

It also chains *into* ghosting/herpaderping chains when the spoofed parent must be `explorer.exe` but the spawned image is delete-pending:

```
T-015 (PPID Spoof + CREATE_SUSPENDED) → T-009 (Process Ghosting image content swap) → NtResumeThread
```

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` blocks (3 total)

1. **`find_pid_by_name`** (`ppid.rs:find_pid_by_name`) — wraps the entire Toolhelp32 snapshot lifecycle: `CreateToolhelp32Snapshot`, the iteration loop, string extraction from `szExeFile`, and `crate::recycled::nt_close`. The unsafe boundary is reasonable since all of these are FFI calls.

2. **`spawn_with_ppid_spoof`** (`ppid.rs:spawn_with_ppid_spoof`) — the large block covering parent-handle acquisition (`nt_open_process`), the `InitializeProcThreadAttributeList` size query + actual init, `UpdateProcThreadAttribute`, `CreateProcessW`, and cleanup. All Win32 FFI requires `unsafe`.

3. **`spawn_background_with_ppid`** (two blocks) — one for the `NtQueryInformationProcess` call with the inline `PBI` struct, one for the `nt_close` pair. Split because the PID retrieval block is logically separate from cleanup.

### `core::arch::asm!` usage
None in this file. The asm stubs live in `sys_recycled.rs` (T-001) and are reached indirectly via `crate::recycled::nt_*`.

### FFI patterns
- `winapi` + `ntapi` crate bindings (older style — consistent with the rest of `crowd`).
- Inline `#[repr(C)]` structs (`ObjectAttributes`, `PBI`) to avoid pulling in extra crates and to control exact byte layout. `ObjectAttributes._pad` and `_pad2` are explicit alignment fields — the Windows `OBJECT_ATTRIBUTES` struct has a 4-byte `Length` followed by a 4-byte pad before the pointer fields on x64.
- `HANDLE` ownership: the parent handle is `usize` for the RecycledGate FFI boundary, cast to `HANDLE` for Win32 APIs. The caller of `spawn_with_ppid_spoof` owns the returned `(h_process, h_thread)` and must close them.

### Initialization patterns
- `std::mem::zeroed::<PROCESSENTRY32W>()` then manual `dwSize` set (correct — Win32 requires `dwSize` to be set before first call).
- Re-zeroed `entry` between iterations (suboptimal but safe; preserves `dwSize`).
- `InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size)` → allocate `Vec<u8>` of `size` → re-call with buffer (standard size-query pattern).
- `zeroed::<STARTUPINFOEXW>()` then `StartupInfo.cb = size_of::<STARTUPINFOEXW>()` (mandatory for `STARTUPINFOEXW` to be recognized).

### Error handling
- `anyhow::Result` everywhere with `anyhow!()` context including the failing NTSTATUS hex.
- Every error path releases the parent handle via `crate::recycled::nt_close(h_parent_usize)` and the attribute list via `DeleteProcThreadAttributeList(p_attr_list)` before returning `Err`.
- `spawn_background_with_ppid` returns `pid = 0` if `NtQueryInformationProcess` fails — *not* an error, just a degraded return. Caller should check for 0.

### Memory layout
- `PsAttribute`: 4 × `usize` = 32 bytes, naturally aligned.
- `PsAttributeList`: `usize (total_length) + [PsAttribute; 3]` = 8 + 96 = 104 bytes.
- `PsCreateInfo`: `usize (size) + u32 (state) + union (8B)` → with default alignment, 24 bytes. Layout matches ReactOS `PS_CREATE_INFO`.
- `ObjectAttributes` (inline, used): `u32 + u32 + 5 × usize` = 8 + 40 = 48 bytes — correct x64 layout.
- `PBI` (inline, used): `[usize; 4] + usize + usize` = 48 bytes, `unique_pid` at offset 32. Matches `PROCESS_BASIC_INFORMATION` x64 layout (skipping `Reserved1`, `PebBaseAddress`, `InheritedFromUniqueProcessId` to reach `UniqueProcessId`).

### Syscall numbers
Not resolved in this file — all NT calls delegate to `crate::recycled::*` (T-001 RecycledGate) which itself delegates to `sys_indirect` / `sys_recycled` for SSN+gadget resolution. From this file's perspective, `nt_open_process`, `nt_close`, and `nt_query_information_process` are opaque `usize`-in / `NTSTATUS`-out functions.

## Cross-References Found in Code

- `ppid.rs:find_pid_by_name()` → calls `crate::recycled::nt_close()` (T-001 RecycledGate, snapshot handle cleanup)
- `ppid.rs:spawn_with_ppid_spoof()` → calls `crate::recycled::nt_open_process()` (T-001 RecycledGate, parent handle acquisition)
- `ppid.rs:spawn_with_ppid_spoof()` → calls `crate::recycled::nt_close()` (T-001 RecycledGate, parent handle release)
- `ppid.rs:spawn_background_with_ppid()` → calls `crate::recycled::nt_query_information_process()` (T-001 RecycledGate, PID retrieval via ProcessBasicInformation)
- `ppid.rs:spawn_background_with_ppid()` → calls `crate::recycled::nt_close()` ×2 (T-001 RecycledGate, child handle cleanup)
- The `CREATE_SUSPENDED` flag (0x4) emitted from `spawn_with_ppid_spoof(suspend=true)` is consumed by `T-012 Early Cascade` (the suspended process becomes the APC target before `LdrInitializeThunk`).
- The `(HANDLE, HANDLE)` return from `spawn_with_ppid_spoof()` is the standard input to most `T-007 Process Injection` methods (write + resume pattern).

## Edge Cases & Failure Modes

1. **Scenario**: `parent_pid == 0` and `explorer.exe` is not running (e.g., Server Core, RDP session 0 only).
   **Failure path**: `find_pid_by_name("explorer.exe")` returns `None` → `ok_or_else(|| anyhow!("explorer.exe not found for PPID spoof"))`.
   **Symptom**: Hard error, caller receives `Err`.
   **Workaround**: Caller passes explicit `parent_pid` of any running user-mode process (`svchost.exe`, `sihost.exe`, `RuntimeBroker.exe`). Library does not auto-fallback.

2. **Scenario**: Caller lacks permission to open parent with `PROCESS_CREATE_PROCESS` (cross-user, no `SeDebugPrivilege`).
   **Failure path**: `crate::recycled::nt_open_process(...)` returns `STATUS_ACCESS_DENIED (0xC0000022)` → `Err(anyhow!("NtOpenProcess(parent PID={}) failed: 0x{:x}", ...))`.
   **Symptom**: Error containing the NTSTATUS hex.
   **Workaround**: Caller must enable `SeDebugPrivilege` first (not handled here — escalate via `T-017 escalation/uac.rs`).

3. **Scenario**: `InitializeProcThreadAttributeList` size query returns 0 (rare — typically low-memory or out-of-quota).
   **Failure path**: `if size == 0 { nt_close(h_parent_usize); return Err(...); }`.
   **Symptom**: Hard error before any allocation.
   **Workaround**: Retry with backoff; the parent handle is correctly closed first.

4. **Scenario**: `UpdateProcThreadAttribute` fails (e.g., bad attribute value, attribute list already finalized).
   **Failure path**: `DeleteProcThreadAttributeList(p_attr_list); nt_close(h_parent_usize); return Err(...)`.
   **Symptom**: Hard error.
   **Workaround**: Audit the `0x00020000` literal — should match `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`; verify the handle copy is `usize`-sized.

5. **Scenario**: `CreateProcessW` fails (e.g., bad image path, image not found, signature-policy rejection, sandbox policy).
   **Failure path**: `DeleteProcThreadAttributeList` is called *before* checking `success`, then `nt_close(h_parent_usize)`, then `Err(anyhow!("CreateProcessW failed with EXTENDED_STARTUPINFO_PRESENT"))`.
   **Symptom**: Hard error, no handle leak (good).
   **Caveat**: The error message does *not* include `GetLastError()` — operator debugging is harder. Modify to capture `GetLastError()` into the error context.

6. **Scenario**: `spawn_background_with_ppid` — `NtQueryInformationProcess` fails (e.g., handle already closed, invalid InfoClass buffer size).
   **Failure path**: `if st == 0 { pbi.unique_pid as u32 } else { 0u32 }` — silently returns 0.
   **Symptom**: PID 0 returned, no error.
   **Workaround**: Caller must check `pid == 0` and treat as failure. No logging.

7. **Scenario**: Caller forgets to close the handles returned by `spawn_with_ppid_spoof`.
   **Symptom**: Handle leak (process + thread) accumulates per call.
   **Workaround**: Use `spawn_background_with_ppid` for fire-and-forget; for the owned-handle variant, wrap in a `Drop`-implementing RAII guard.

## OPSEC Notes

### Artifacts left
- **Toolhelp snapshot**: `CreateToolhelp32Snapshot` in `find_pid_by_name` is itself an ETW event (`Microsoft-Windows-Kernel-Process`). Visible to EDR even though the snapshot handle is closed via RecycledGate.
- **Parent handle open**: `NtOpenProcess(PROCESS_CREATE_PROCESS)` on `explorer.exe` is an unusual access mask — `PROCESS_CREATE_PROCESS (0x80)` is rare in benign software. EDRs that filter on this mask will flag it.
- **Extended attribute list presence**: `EXTENDED_STARTUPINFO_PRESENT` in the `dwCreationFlags` is a known heuristic. Combined with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, it is the textbook PPID-spoof fingerprint.
- **Win32-layer `CreateProcessW` call**: full `Microsoft-Windows-Kernel-Process` event with `ParentImage` field that will *not* match the spoofed parent's image path (only the PPID is spoofed, not the parent's image name in the kernel event payload). EDRs correlating PPID→Image against the actual parent's image will detect the mismatch.
- **`STARTUPINFOEXW.cb` = full struct size**: benign code often passes `sizeof(STARTUPINFOEXW)` even when not using the extended fields — not a strong signal alone, but combined with the attribute list it is.

### Cleanup performed
- Toolhelp snapshot: closed via `crate::recycled::nt_close` (good — not `CloseHandle`).
- Parent handle: closed via `crate::recycled::nt_close` immediately after `CreateProcessW` returns (good — no handle-leak forensic trace).
- Attribute list: `DeleteProcThreadAttributeList` called before returning from `spawn_with_ppid_spoof` regardless of success/failure (good — no leaked attribute list memory).
- `spawn_background_with_ppid` closes both child handles after extracting the PID (good — minimal handle footprint).

### What is NOT cleaned
- The `CreateProcessW` event itself (cannot be retroactively cleared without kernel-mode intervention).
- The kernel's `EPROCESS->InheritedFromUniqueProcessId` field — once spoofed, it stays spoofed for the lifetime of the child. This is the *intent* of the technique, not a leak.
- Prefetch entries for the spawned image (e.g., `svchost.exe` prefetch will record the launch).
- Shimcache / Amcache entries for the spawned image if it is a non-system binary.

## Reusable Patterns

### Pattern: Win32 size-query-then-allocate for variable-length structs
- **Use when**: Calling Windows APIs that require caller-allocated buffers of runtime-determined size (`InitializeProcThreadAttributeList`, `NtQueryInformationProcess`, `RegQueryInfoKey`, etc.).
- **Code ref**: `ppid.rs:spawn_with_ppid_spoof` (lines around `InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size)`).
- **How**: Call with `null_mut()` buffer to populate `size`, then `vec![0; size]`, then call again with the buffer pointer. Wrap each call in error handling that releases any prior-allocated resources.

### Pattern: Inline `#[repr(C)]` NT struct definitions
- **Use when**: An NT-internal struct is not exported by `ntapi` or you need to control exact field visibility / alignment.
- **Code ref**: `ppid.rs:spawn_with_ppid_spoof` (the `ObjectAttributes` struct) and `ppid.rs:spawn_background_with_ppid` (the `PBI` struct).
- **How**: Define the struct locally with `#[repr(C)]` and explicit `_pad` fields to match Windows x64 alignment. Compute `Length` field via `size_of::<Struct>() as u32` at runtime. Cast pointers across the FFI boundary with `as *mut std::ffi::c_void`.

### Pattern: Handle ownership transfer via tuple
- **Use when**: A function returns multiple kernel handles (`HANDLE`) that the caller must close.
- **Code ref**: `ppid.rs:spawn_with_ppid_spoof -> Result<(HANDLE, HANDLE)>`.
- **How**: Document in the doc comment that "ambos handles son propiedad del caller" (both handles are caller-owned). Provide a sibling function (`spawn_background_with_ppid`) that closes them internally for callers who don't need continued ownership. This pattern avoids the Rust anti-pattern of returning RAII guards from `unsafe` code.

### Pattern: Same-module fallback chain for parameter defaults
- **Use when**: A function accepts an optional parameter with a sensible default that requires computation.
- **Code ref**: `ppid.rs:spawn_with_ppid_spoof` — `if parent_pid == 0 { parent_pid = find_pid_by_name("explorer.exe")...? }`.
- **How**: Use a sentinel (`0`, `usize::MAX`, `Option::None`) and resolve it inside the function. The resolution path uses the same module's primitives, keeping the dependency closure small. Pair with `ok_or_else(|| anyhow!(...))` for explicit error context.

### Pattern: FFI cleanup-before-return in every error branch
- **Use when**: An `unsafe` function holds multiple OS resources (handles, attribute lists, allocations) that must be released on every error path.
- **Code ref**: `ppid.rs:spawn_with_ppid_spoof` — every `return Err(...)` is preceded by `DeleteProcThreadAttributeList(p_attr_list)` and/or `crate::recycled::nt_close(h_parent_usize)`.
- **How**: Repeat the cleanup at each error site rather than using `goto`/`defer`-style patterns. Verbose but easy to audit. Consider an RAII guard struct with `Drop` to reduce duplication if the function grows.
