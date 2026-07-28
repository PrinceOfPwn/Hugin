---
id: T-013
name: Additional Injection Methods (Reflective PE Loader, Hypnosis, WaitingThread, Reflection)
category: process-injection
tier: mixed
mitre: [T1055, T1055.001, T1055.012, T1055.014]
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-001, T-004, T-002]
enables: [T-005, T-009, T-016, T-017, T-019]
vault_references:
  - src/dark_crystal/crowd/src/pe_loader.rs
  - src/dark_crystal/crowd/src/hypnosis.rs
  - src/dark_crystal/crowd/src/waiting_thread.rs
  - src/dark_crystal/crates/core/src/experimental/injection/process_reflection.rs
  - src/dark_crystal/crates/core/src/pe.rs
implements:
  - file: src/dark_crystal/crowd/src/pe_loader.rs
    key_functions: [PE::parse, PE::load, PE::execute, PE::run, PE::process_relocations, PE::resolve_imports, PE::invoke_tls_callbacks, PE::set_section_permissions]
    key_structs: [PE, BaseRelocationEntry, ExeFn, DllFn]
    key_constants: [NT_CURRENT_PROCESS, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_LOW, IMAGE_REL_BASED_ABSOLUTE]
    lines_of_interest: ["L113-L160: PE struct definition", "L165-L230: PE::parse validation", "L240-L320: PE::load allocation and section mapping", "L335-L360: PE::execute DllMain/Main entry dispatch", "L378-L435: process_relocations DIR64/HIGHLOW/HIGH/LOW", "L445-L510: resolve_imports IAT fixup", "L520-L545: invoke_tls_callbacks", "L560-L605: set_section_permissions"]
  - file: src/dark_crystal/crowd/src/hypnosis.rs
    key_functions: [hypnotize_and_inject, hypnotize_default]
    key_structs: [STARTUPINFOW, PROCESS_INFORMATION, DEBUG_EVENT, DebugEventUnion, CREATE_PROCESS_DEBUG_INFO]
    key_constants: [DEBUG_ONLY_THIS_PROCESS, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXCEPTION_BREAKPOINT, DBG_CONTINUE, EVENTS_BEFORE_INJECT, PAGE_READWRITE, PAGE_EXECUTE_READ]
    lines_of_interest: ["L26-L36: debug event constants", "L40-L92: Win32 debug structs", "L100-L108: extern CreateProcessW/WaitForDebugEvent/ContinueDebugEvent/DebugActiveProcessStop", "L115-L185: hypnotize_and_inject main loop", "L187-L200: CreateProcessW DEBUG_ONLY_THIS_PROCESS call", "L213-L245: lpStartAddress capture from CREATE_PROCESS_DEBUG_INFO", "L247-L300: RW flip + NtWriteVirtualMemory + RX restore via RecycledGate", "L312-L320: DebugActiveProcessStop detach"]
  - file: src/dark_crystal/crowd/src/waiting_thread.rs
    key_functions: [nt_open_thread, nt_query_information_thread, query_process_threads, find_waiting_thread, inject, wait_reason_name]
    key_structs: [ThreadBasicInformation, SystemThreadInformation, WaitCandidate]
    key_constants: [WAIT_REASON_DELAY_EXECUTION, WAIT_REASON_WR_USER_REQUEST, WAIT_REASON_WR_LPC_REPLY, WAIT_REASON_WR_QUEUE, WAIT_REASON_WR_ALERT_BY_THREAD, SAFE_WAIT_REASONS, THREAD_STATE_WAITING, SPI_HEADER_SIZE, SYSTEM_PROCESS_INFORMATION_CLASS, THREAD_ALL_ACCESS]
    lines_of_interest: ["L42-L65: KWAIT_REASON constants and SAFE_WAIT_REASONS array", "L90-L130: SystemThreadInformation layout", "L140-L175: nt_open_thread/nt_query_information_thread RecycledGate wrappers", "L185-L260: query_process_threads NtQuerySystemInformation walk", "L275-L310: find_waiting_thread longest-WaitTime selection", "L320-L420: NtCreateSection + dual map (local RW, remote RX)", "L425-L470: NtSuspendThread + NtGetContextThread + RIP swap + NtSetContextThread + NtResumeThread"]
  - file: src/dark_crystal/crates/core/src/experimental/injection/process_reflection.rs
    key_functions: [try_process_reflection]
    key_structs: [ClientId, RtlpProcessReflectionInformation]
    key_constants: [RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE, RtlCreateProcessReflectionFn]
    lines_of_interest: ["L20-L35: ClientId and RtlpProcessReflectionInformation structs", "L37-L48: RtlCreateProcessReflectionFn type alias", "L50-L52: RTL_CLONE flags", "L54-L155: try_process_reflection VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → RtlCreateProcessReflection"]
  - file: src/dark_crystal/crates/core/src/pe.rs
    key_functions: [PE::new, PE::run, PE::prepare, PE::fixing_iat, PE::realoc_image, PE::fixing_memory, PE::fixing_arguments, PE::export_function_address, NtCurrentPeb, __readgsqword, __readfsdword]
    key_structs: [PE, BASE_RELOCATION_ENTRY]
    key_constants: [IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_LOW, IMAGE_REL_BASED_ABSOLUTE, IMAGE_ORDINAL_FLAG64, IMAGE_FILE_DLL]
    lines_of_interest: ["L36-L66: PE struct with args/export/exception fields", "L78-L130: PE::new validation", "L140-L200: PE::run export resolution + RtlAddFunctionTable + TLS + entry dispatch", "L210-L260: PE::prepare VirtualAlloc + section copy + IAT + reloc + permissions", "L270-L330: fixing_iat LoadLibraryA + GetProcAddress", "L340-L390: realoc_image DIR64/HIGHLOW/HIGH/LOW", "L400-L445: fixing_memory section protection matrix", "L455-L485: fixing_arguments PEB CommandLine patching", "L495-L545: export_function_address by name/ordinal", "L555-L575: NtCurrentPeb gs:[0x60] inline asm", "L585-L600: __readgsqword core::arch::asm!"]
min_windows: Windows 7 SP1 (x64)
needs_admin: conditional
tags: [injection, hollowing, hypnosis, fiber, callback, mapping, module-stomp, func-stomp, vectored-overloading, reflective-pe-loader, process-reflection, wait-state-hijack, PEB-invisible, manual-mapping, relocations, IAT-fixup, TLS-callbacks]
---

# T-013 Additional Injection Methods — Operator Playbook

## TL;DR
A grab-bag of eight-plus injection primitives that escape the `CreateRemoteThread`/`VirtualAllocEx` heuristic net. The four files analyzed here cover the S-tier **Reflective PE Loader** (`pe_loader.rs`, `pe.rs`) — full in-memory PE mapping with PEB invisibility, the A-tier **Process Hypnosis** (`hypnosis.rs`) — debug-event mediated write to `lpStartAddress`, the A-tier **WaitingThread Hijack** (`waiting_thread.rs`) — RIP swap on the longest-sleeping KTHREAD in a process, and the **Process Reflection** experimental adapter (`process_reflection.rs`) — `RtlCreateProcessReflection` clone-and-execute. Together they span the spectrum from "no allocation at all" (Hypnosis) to "no NtWriteVirtualMemory at all" (WaitingThread via section mapping) to "no LoadLibrary at all" (Reflective PE).

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `crowd/src/pe_loader.rs` | Reflective PE loader (PEB-invisible manual mapping) | `PE::parse`, `PE::load`, `PE::execute`, `PE::run` | ~25K |
| `crowd/src/hypnosis.rs` | Process Hypnosis — debug-API shellcode injection | `hypnotize_and_inject`, `hypnotize_default` | ~14K |
| `crowd/src/waiting_thread.rs` | WAIT-state thread hijack with mapping injection | `inject`, `find_waiting_thread`, `query_process_threads` | ~22K |
| `crates/core/src/experimental/injection/process_reflection.rs` | Process reflection via `RtlCreateProcessReflection` | `try_process_reflection` | ~6K |
| `crates/core/src/pe.rs` | Extended PE loader w/ PEB arg patch + exports + exceptions | `PE::new`, `PE::run`, `PE::prepare`, `NtCurrentPeb` | ~22K |

## How It Works

### A. Reflective PE Loader — `pe_loader.rs` (`PE::load` / `PE::execute`)

1. **Parse (L165-L230)**: `PE::parse` validates `IMAGE_DOS_SIGNATURE` (0x5A4D) at `*dos_header`, follows `e_lfanew` to `IMAGE_NT_HEADERS64`, verifies `IMAGE_NT_SIGNATURE` (0x50450000 "PE\0\0"), bounds-checks section table layout via `checked_add` against `buffer.len()`. Stores raw pointers `nt_header`, `section_header` into `self.buffer` (note: `unsafe impl Send for PE` is hand-asserted because of this self-referential pattern).
2. **Allocate (L248-L263)**: First attempt `VirtualAlloc(Some(self.image_base as *const c_void), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)` — try preferred `ImageBase`. On null (preferred base unavailable), retry with `None` base. RW chosen because subsequent `VirtualProtect` per-section will tighten.
3. **Copy headers (L266-L273)**: `std::ptr::copy_nonoverlapping(self.buffer.as_ptr(), base, headers_size)` where `headers_size = (*self.nt_header).OptionalHeader.SizeOfHeaders`.
4. **Map sections (L276-L302)**: For each `IMAGE_SECTION_HEADER`: read `VirtualAddress`, `PointerToRawData`, `SizeOfRawData`; bounds-check `raw_end` against `buffer.len()`; `copy_nonoverlapping` raw → virtual slot.
5. **Relocations (L304-L308 → L378-L435)**: If `delta = base - image_base != 0` and `reloc_data.VirtualAddress != 0`, call `process_relocations`. Walks `IMAGE_BASE_RELOCATION` blocks until `VirtualAddress == 0` or `SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)`. For each `BaseRelocationEntry` (packed `u16`): type = high 4 bits, offset = low 12 bits. Match arms:
   - `IMAGE_REL_BASED_DIR64` (type 10): `*target += delta as i64`
   - `IMAGE_REL_BASED_HIGHLOW` (type 3): `*target += delta as u32`
   - `IMAGE_REL_BASED_HIGH` (type 1): high 16 bits
   - `IMAGE_REL_BASED_LOW` (type 2): low 16 bits
   - `IMAGE_REL_BASED_ABSOLUTE` (type 0): no-op (padding)
   - Unknown → `bail!`
6. **Imports (L310-L314 → L445-L510)**: Walk `IMAGE_IMPORT_DESCRIPTOR` array until null entry. For each: `LoadLibraryA(dll_name_ptr)`. Walk `IMAGE_THUNK_DATA64` pairs (OriginalFirstThunk for lookup, FirstThunk for patching) until `u1.Function == 0`. For ordinal imports (bit 63 set): `GetProcAddress(h_module, PCSTR(ordinal as *const u8))`. For name imports: dereference `IMAGE_IMPORT_BY_NAME` and call `GetProcAddress`. Write resolved address into `(*first_thunk).u1.Function`.
7. **TLS callbacks (L316-L320 → L520-L545)**: If `tls_data.Size != 0`, walk `IMAGE_TLS_DIRECTORY64.AddressOfCallBacks` (null-terminated array of `PIMAGE_TLS_CALLBACK`). Each callback invoked with `(base, DLL_PROCESS_ATTACH, null)`.
8. **Section permissions (L322-L326 → L560-L605)**: For each section, decode `(IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE)` and pick matching `PAGE_*` constant from an 8-entry match table. `VirtualProtect` per-section.
9. **I-cache flush (L328-L333)**: `NtFlushInstructionCache(NT_CURRENT_PROCESS, base, size)` via raw `#[link(name = "ntdll")]`. `NT_CURRENT_PROCESS = -1isize as *mut c_void`.
10. **Execute (L335-L360)**: `entry = base.offset(self.entry_point)`. If `is_dll` (`IMAGE_FILE_DLL` characteristic): transmute to `DllFn`, call `DllMain(HINSTANCE(base), DLL_PROCESS_ATTACH, null)`. Else transmute to `ExeFn` and call `Main()`.

### B. Process Hypnosis — `hypnosis.rs` (`hypnotize_and_inject`)

1. **Wide-string setup (L187-L194)**: `target_exe.encode_utf16().chain(once(0))` for `CreateProcessW` `lpCommandLine`.
2. **STARTUPINFO allocation (L196-L201)**: `Vec<u8>` of `size_of::<winapi::um::processthreadsapi::STARTUPINFOW>()`, sets `cb` field at offset 0.
3. **CreateProcessW with DEBUG_ONLY_THIS_PROCESS (L203-L218)**: `dwCreationFlags = 0x00000002`. This attaches the current thread as a debugger to the new process — but only this process, not children.
4. **Debug event loop (L223-L290)**: Loop `EVENTS_BEFORE_INJECT = 7` times. Each iteration: `WaitForDebugEvent(&mut dbg, 5000)` with 5s timeout. Match on `dwDebugEventCode`:
   - `CREATE_PROCESS_DEBUG_EVENT (3)`: extract `dbg.u.CreateProcessInfo.lpStartAddress` — this is the target's own entry point, not allocated by us.
   - `CREATE_THREAD_DEBUG_EVENT (2)`, `LOAD_DLL_DEBUG_EVENT (6)`, `EXCEPTION_DEBUG_EVENT (1)`: log only.
5. **On final event (L247-L300)**:
   - `crate::recycled::nt_protect_virtual_memory(hProcess, &mut base_addr, &mut region_size, PAGE_READWRITE, &mut old_protect)` — flip RX → RW. (RecycledGate syscall — T-001.)
   - `crate::recycled::nt_write_virtual_memory(hProcess, start_address, shellcode.as_ptr(), shellcode.len(), &mut written)` — write payload at original entry point.
   - `crate::recycled::nt_protect_virtual_memory(..., PAGE_EXECUTE_READ, ...)` — restore RX.
6. **Detach (L312)**: `DebugActiveProcessStop(pi.dwProcessId)`. The process resumes at its `lpStartAddress` — which now contains our shellcode.
7. **Cleanup (L317-L321)**: `crate::recycled::nt_close(pi.hProcess)` and `nt_close(pi.hThread)`.
8. **Fallback paths**: All error paths invoke `DebugActiveProcessStop` + `nt_close` × 2 — RAII-style.

### C. WaitingThread Hijack — `waiting_thread.rs` (`inject`)

1. **Open target process (L325-L339)**: `crate::recycled::nt_open_process(&mut h_proc, 0x1FFFFF, oa, cid)` where `0x1FFFFF = PROCESS_ALL_ACCESS`. `CLIENT_ID = [pid, 0]`, `OBJECT_ATTRIBUTES[6]` with `Length` set.
2. **Enumerate threads (L341-L350 → L185-L260 → `query_process_threads`)**: `crate::recycled::nt_query_system_information(SYSTEM_PROCESS_INFORMATION_CLASS = 5, buf, buf_size, &mut ret_len)`. Starts with 1 MB buffer, doubles on `STATUS_INFO_LENGTH_MISMATCH = 0xC0000004`, capped at 256 MB. Walks `NextEntryOffset`-chained `SYSTEM_PROCESS_INFORMATION` entries. Reads `UniqueProcessId` at offset `0x50`. For matching PID: parses `SYSTEM_THREAD_INFORMATION` array starting at `offset + SPI_HEADER_SIZE (0x100)` with stride `size_of::<SystemThreadInformation>()`.
3. **Filter candidates (L235-L245)**: Keep only threads where `thread_state == THREAD_STATE_WAITING (5)` AND `wait_reason ∈ SAFE_WAIT_REASONS = [4, 13, 15, 17, 36]` (DelayExecution, WrUserRequest, WrQueue, WrLpcReply, WrAlertByThreadId).
4. **Select (L302-L308 → `find_waiting_thread`)**: `candidates.iter().max_by_key(|c| c.wait_time)` — pick the longest-sleeping thread (lowest crash risk).
5. **Open the thread (L310-L325)**: `nt_open_thread(&mut h_thread, THREAD_ALL_ACCESS = 0x1FFFFF, oa, cid)` where `cid = [0, tid]` (only UniqueThread matters; UniqueProcess=0 means "current process lookup by TID").
6. **Mapping injection (L357-L415)**:
   - `nt_create_section(&mut h_section, 0xF001F /* SECTION_ALL_ACCESS */, null, &mut max_size, 0x04 /* PAGE_READWRITE */, 0x08000000 /* SEC_COMMIT */, 0)`.
   - Local map: `nt_map_view_of_section(h_section, NtCurrentProcess = -1isize, &mut local_base, 0, 0, null, &mut local_size, 1 /* ViewUnmap */, 0, 0x04 /* RW */)`.
   - `copy_nonoverlapping(shellcode.as_ptr(), local_base, sc_size)`.
   - `nt_unmap_view_of_section(NtCurrentProcess, local_base)`.
   - Remote map: `nt_map_view_of_section(h_section, h_proc, &mut remote_base, 0, 0, null, &mut remote_size, 1, 0, 0x20 /* PAGE_EXECUTE_READ */)`.
   - `nt_close(h_section)` — section object persists via the remote view.
7. **Hijack RIP (L417-L460)**:
   - `nt_suspend_thread(h_thread, &mut prev_suspend_count)`.
   - `ctx.ContextFlags = CONTEXT_FULL`; `nt_get_context_thread(h_thread, &mut ctx)`.
   - Save `_original_rip = ctx.Rip` (comment: "not restoring — shellcode takes over").
   - `ctx.Rip = remote_base as u64`.
   - `nt_set_context_thread(h_thread, &mut ctx)`. On failure: restore original RIP, resume, cleanup.
   - `nt_resume_thread(h_thread, &mut prev_suspend_count)` — wakes from wait, jumps to shellcode.
8. **Cleanup (L462-L464)**: `nt_close(h_thread)`, `nt_close(h_proc)`.

### D. Process Reflection — `process_reflection.rs` (`try_process_reflection`)

1. `OpenProcess(PROCESS_ALL_ACCESS, false, pid)`.
2. `VirtualAllocEx(h_process, None, payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)` — RWX remote allocation.
3. `WriteProcessMemory(h_process, remote_mem, payload, payload.len(), &mut written)`.
4. `VirtualProtectEx(h_process, remote_mem, payload.len(), PAGE_EXECUTE_READ, &mut old)` — harden to RX.
5. `GetModuleHandleA(PCSTR(b"ntdll.dll\0"))` then `GetProcAddress(ntdll, PCSTR(b"RtlCreateProcessReflection\0"))`.
6. `transmute` to `RtlCreateProcessReflectionFn`. Call with `flags = RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES (0x2) | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE (0x4)`, `start_routine = remote_mem`, `start_context = null`, `event_handle = default`.
7. If `status == STATUS_SUCCESS`: close `reflection_process_handle`, `reflection_thread_handle`, free remote memory, close process handle. Return `true`.
8. Else: free memory + close handle, return `false`.

### E. Extended PE Loader — `pe.rs`

Same skeleton as `pe_loader.rs` plus:

- **Exception table (L160-L175)**: `RtlAddFunctionTable(function_entry, address as u64)` if `exception.Size != 0`. Creates `IMAGE_RUNTIME_FUNCTION_ENTRY` slice from `exception.VirtualAddress` with count `exception.Size / size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>()`. Required for x64 SEH/unwind in the mapped module.
- **Export resolution (L150-L156 → L495-L545)**: `export_function_address(address)` walks `IMAGE_EXPORT_DIRECTORY`: supports ordinal (parse `self.export` as `u32`, bounds-check against `Base`/`NumberOfFunctions`) and by-name (linear scan of `AddressOfNames` + `AddressOfNameOrdinals` + `AddressOfFunctions`).
- **Export execution (L196-L205)**: If DLL has a named export, after `DllMain(DLL_PROCESS_ATTACH)` it `CreateThread` + `WaitForSingleObject(INFINITE)` on the export. Useful for calling a DLL export directly.
- **PEB argument patching (L209-L212 → L455-L485 → `fixing_arguments`)**: Reads `NtCurrentPeb()` (gs:[0x60] on x64, fs:[0x30] on x86), dereferences `ProcessParameters`, zeroes `CommandLine.Buffer`, writes `"current_exe" args\0` as UTF-16, updates `Length`/`MaximumLength`. Makes the host process's `GetCommandLineW()` return our spoofed string — defeats `ProcessHacker` / `GetCommandLineW`-based detection.
- **Relocations (L340-L390)**: Same four types as `pe_loader.rs` but uses `BASE_RELOCATION_ENTRY` with `type_()` and `offset()` methods (note trailing underscore to avoid keyword). Loops until `(*base_relocation).VirtualAddress == 0` (simpler termination than `pe_loader`'s size check).

## Code Architecture

### Call Graph (cross-file)

```
crowd/src/waiting_thread.rs::inject()
   ├── crate::recycled::nt_open_process          (T-001 RecycledGate)
   ├── crate::recycled::nt_query_system_information
   ├── crate::recycled::nt_open_thread           (via nt_open_thread wrapper, DJB2 hash)
   │     └── crate::resolve::compute_hash("NtOpenThread")   (T-004 PEB walker + DJB2)
   ├── crate::recycled::nt_create_section
   ├── crate::recycled::nt_map_view_of_section   (×2: local RW + remote RX)
   ├── crate::recycled::nt_unmap_view_of_section
   ├── crate::recycled::nt_suspend_thread
   ├── crate::recycled::nt_get_context_thread
   ├── crate::recycled::nt_set_context_thread
   ├── crate::recycled::nt_resume_thread
   └── crate::recycled::nt_close                 (×3)

crowd/src/hypnosis.rs::hypnotize_and_inject()
   ├── extern CreateProcessW                      (direct, DEBUG_ONLY_THIS_PROCESS)
   ├── extern WaitForDebugEvent
   ├── extern ContinueDebugEvent
   ├── crate::recycled::nt_protect_virtual_memory (×2: RW flip + RX restore)
   ├── crate::recycled::nt_write_virtual_memory
   ├── extern DebugActiveProcessStop
   ├── crate::recycled::nt_close                 (×2)
   └── crate::mega_dbg!                          (debug logging macro)

crowd/src/pe_loader.rs::PE::load()
   ├── VirtualAlloc                              (windows crate, preferred base then fallback)
   ├── std::ptr::copy_nonoverlapping             (headers + sections)
   ├── self::process_relocations                 (DIR64/HIGHLOW/HIGH/LOW/ABSOLUTE)
   ├── self::resolve_imports                     (LoadLibraryA + GetProcAddress)
   ├── self::invoke_tls_callbacks                (PIMAGE_TLS_CALLBACK walk)
   ├── self::set_section_permissions             (8-entry match table → VirtualProtect)
   └── extern "system" NtFlushInstructionCache   (#[link(name = "ntdll")])

crates/core/src/pe.rs::PE::run()
   ├── self::prepare()                           (allocate + sections + IAT + reloc + permissions)
   │     ├── VirtualAlloc
   │     ├── self::fixing_iat                    (LoadLibraryA + GetProcAddress)
   │     ├── self::realoc_image                  (BASE_RELOCATION_ENTRY walk)
   │     └── self::fixing_memory                 (VirtualProtect per-section)
   ├── self::export_function_address             (IMAGE_EXPORT_DIRECTORY walk)
   ├── RtlAddFunctionTable                       (exception directory)
   ├── TLS callback walk                         (IMAGE_TLS_DIRECTORY64.AddressOfCallBacks)
   ├── self::fixing_arguments()                  (NtCurrentPeb() → PEB.ProcessParameters.CommandLine patch)
   │     └── NtCurrentPeb() → __readgsqword(0x60) (T-004 PEB walk via gs:[0x60])
   ├── CreateThread + WaitForSingleObject(INFINITE)  (for DLL export execution)
   └── DllMain(base, DLL_PROCESS_ATTACH, null)  or  Main()

crates/core/src/experimental/injection/process_reflection.rs::try_process_reflection()
   ├── OpenProcess(PROCESS_ALL_ACCESS)            (windows crate)
   ├── VirtualAllocEx(MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
   ├── WriteProcessMemory
   ├── VirtualProtectEx(PAGE_EXECUTE_READ)       (hardening)
   ├── GetModuleHandleA("ntdll.dll")
   ├── GetProcAddress("RtlCreateProcessReflection")
   └── RtlCreateProcessReflection(...)            (cloned process executes payload as start_routine)
```

### Data Flow

- **pe_loader.rs / pe.rs**: `Vec<u8>` file bytes → `PE` struct (raw pointers into `self.buffer`) → `load()` returns `*mut u8` base → `execute(base)`.
- **hypnosis.rs**: `&str target_exe` → wide string → `CreateProcessW` → `PROCESS_INFORMATION` (raw `usize` fields) → DEBUG_EVENT union → `lpStartAddress` (intercepted) → `crate::recycled` syscall calls.
- **waiting_thread.rs**: `target_pid` → `query_process_threads` returns `Vec<WaitCandidate>` → `find_waiting_thread` selects `max_by_key(wait_time)` → returns `(tid, h_thread)` → `inject` opens process, creates section, maps twice, swaps RIP.
- **process_reflection.rs**: `pid` + `&[u8]` → `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `GetProcAddress` → `RtlCreateProcessReflection` clones and starts.

### Type Hierarchy

- `PE` struct (pe_loader.rs and pe.rs are sibling implementations; pe.rs adds `args`, `export`, `exception`, `export_data` fields and replaces `reloc_data`/`entry_point`/`image_base`/`size_of_image` with the `IMAGE_NT_HEADERS64` direct access)
- `BaseRelocationEntry` (pe_loader) vs `BASE_RELOCATION_ENTRY` (pe.rs) — same layout, different naming convention
- `SystemThreadInformation` (waiting_thread.rs) — `#[repr(C)]` match for `SYSTEM_THREAD_INFORMATION` from `ntddk.h`
- `WaitCandidate` (waiting_thread.rs) — internal selection struct
- `RtlpProcessReflectionInformation` (process_reflection.rs) — minimal ntdll struct with only the three fields we touch (`reflection_process_handle`, `reflection_thread_handle`, `reflection_client_id`)

### Feature Gates

No `cfg` flags in these four files. The crate-level `lib.rs` gates them via `#[cfg(feature = "...")]` for selective compilation. The `#[cfg(target_arch = "x86_64")]` and `#[cfg(target_arch = "x86")]` in `pe.rs` provide architecture-specific PEB access (`gs:[0x60]` vs `fs:[0x30]`).

## Operational Profile

### When to Use

- **Reflective PE Loader** (`pe_loader.rs` / `pe.rs`): Execute a fully-formed EXE/DLL without `LoadLibrary`. PEB-invisible — invisible to `NtQueryInformationProcess(ProcessMappedModules)`, `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`, `EnumProcessModules`. Pick this when you need the loaded module's TLS callbacks, exception tables, and full IAT to behave as if loaded normally. The `pe.rs` variant is preferred when you also need to spoof `GetCommandLineW()` output or invoke a specific DLL export.
- **Process Hypnosis** (`hypnosis.rs`): When you need an existing-process context (e.g., to inherit a token, drop history into a known executable's audit trail) but cannot afford `VirtualAllocEx`/`CreateRemoteThread`. The debug interface bypasses userland hooks on `NtWriteVirtualMemory` because the call originates from `ntdll!DbgUiRemoteConnectin` semantics via the debug subsystem. Use for notepad.exe / svchost.exe camouflage.
- **WaitingThread Hijack** (`waiting_thread.rs`): When the target process already has many sleeping threads (service hosts, browser content processes, COM servers). Zero new threads, zero `NtWriteVirtualMemory`. Pairs beautifully with a RecycledGate syscall backend for full ETW-TI invisibility.
- **Process Reflection** (`process_reflection.rs`): When `RtlCreateProcessReflection` is exported by the running Windows build (Windows 10 1607+). The reflection is a true clone — same token, same handles (with `INHERIT_HANDLES`), same image. Use when the payload must run with the target's exact privileges and the original process must continue unaffected.

### When NOT to Use

- **Reflective PE Loader**: Don't use for huge DLLs with bound imports — `LoadLibraryA` is called per imported DLL, which IS visible to EDR via `LdrLoadDll` ETW events. For sensitive imports, consider resolving them via `pe.rs::export_function_address` against manually-mapped dependencies.
- **Process Hypnosis**: Don't use against hardened targets that hook `CreateProcessW` with `DEBUG_ONLY_THIS_PROCESS`. Don't use if the target exe's `lpStartAddress` is in a non-writable page (the code does flip RW→write→RX, but if `NtProtectVirtualMemory` is hooked you're caught). Also avoid if the target has anti-debug checks (`IsDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort)`).
- **WaitingThread Hijack**: Don't use on processes with no idle threads (foreground GUI apps in active use, busy worker pools). The candidate filter rejects non-WAIT threads, so you'll just get `Err`. Also avoid single-threaded processes — hijacking the only thread is a DoS.
- **Process Reflection**: Don't use on Windows builds pre-1607. The `RtlCreateProcessReflection` export is missing on older systems. Also avoid on processes with a huge working set — clone is expensive.

### Kill Chain Position

Example chain with these techniques:

**Scenario A — Long-haul C2 in service host:**
T-004 (PEB walk) → T-001 (RecycledGate) → **T-013 WaitingThread** (hijack `svchost.exe` sleeper) → T-005 (Ekko sleep) → T-019 (Edo Dead Drop) → T-017 (PhantomPersist)

**Scenario B — Reflective module payload:**
T-002 (Hell's Gate SSN resolution) → T-001 (RecycledGate) → **T-013 Reflective PE Loader** (drop encrypted stage-2 DLL) → T-009 (EDR evasion: AMSI + ETW patch) → T-023 (client capabilities: screen capture, keylogger)

**Scenario C — Token inheritance via debug:**
T-004 (PEB walk) → T-001 (RecycledGate) → **T-013 Process Hypnosis** (notepad.exe with DEBUG_ONLY_THIS_PROCESS) → T-016 (stack spoofing) → T-022 (NT sockets networking)

**Scenario D — Privilege reflection:**
T-018 (BYOVD for kernel primitive) → **T-013 Process Reflection** (clone `winlogon.exe` for SYSTEM token) → T-023 (credential harvest from clone) → T-019 (Edo Dead Drop exfil)

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` Blocks — Inventory

| File:Function | Purpose | What It Does |
|---|---|---|
| `pe_loader.rs:PE::parse` | Header validation | Casts `*mut u8` to `*mut IMAGE_DOS_HEADER` / `*mut IMAGE_NT_HEADERS64`, dereferences `e_magic`, `Signature`, `e_lfanew`, `NumberOfSections`, `Characteristics`, `DataDirectory[]` |
| `pe_loader.rs:PE::load` | Memory mapping | `VirtualAlloc`, `copy_nonoverlapping`, calls `process_relocations`/`resolve_imports`/`invoke_tls_callbacks`/`set_section_permissions`, `NtFlushInstructionCache` |
| `pe_loader.rs:PE::execute` | Entry dispatch | `transmute::<*mut u8, DllFn>` or `transmute::<*mut u8, ExeFn>` — calling a function pointer derived from a raw byte offset |
| `pe_loader.rs:PE::process_relocations` | Reloc fixup | `read_unaligned`/`write_unaligned` at `*mut i64`, `*mut u32`, `*mut u16` with `wrapping_add` |
| `pe_loader.rs:PE::resolve_imports` | IAT patching | `CStr::from_ptr(dll_name_ptr)`, `LoadLibraryA`, `GetProcAddress`, writes `(*first_thunk).u1.Function = addr as u64` |
| `pe_loader.rs:PE::invoke_tls_callbacks` | TLS walk | `*callbacks_ptr.offset(idx)` until `None`, calls `cb(base, DLL_PROCESS_ATTACH, null)` |
| `pe_loader.rs:PE::set_section_permissions` | Per-section VirtualProtect | 8-entry match on `(is_exec, is_read, is_write)` flags |
| `hypnosis.rs:hypnotize_and_inject` | Debug API + RecycledGate | `CreateProcessW`, `WaitForDebugEvent`, `ContinueDebugEvent`, `DebugActiveProcessStop`, `crate::recycled::nt_*` syscalls |
| `waiting_thread.rs:nt_open_thread` / `nt_query_information_thread` | Syscall dispatch | `crate::recycled::invoke(crate::resolve::compute_hash("NtOpenThread"), 4, &args)` |
| `waiting_thread.rs:query_process_threads` | SPI buffer walk | `*(entry_ptr as *const u32)` for `NextEntryOffset`/`NumberOfThreads`; `*(entry_ptr.add(0x50) as *const usize)` for `UniqueProcessId`; `&*(buf.as_ptr().add(t_off) as *const SystemThreadInformation)` cast |
| `waiting_thread.rs:find_waiting_thread` | Thread open | `std::mem::zeroed()` for `OBJECT_ATTRIBUTES`, `nt_open_thread` |
| `waiting_thread.rs:inject` | Full sequence | All `crate::recycled::nt_*` calls + `winapi::um::winnt::CONTEXT` zeroed + `ctx.Rip = remote_base as u64` |
| `process_reflection.rs:try_process_reflection` | Reflection | `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `std::mem::transmute` of `GetProcAddress` return to `RtlCreateProcessReflectionFn` |
| `pe.rs:PE::new` | Header parse | Same as `pe_loader.rs` plus `IMAGE_DIRECTORY_ENTRY_EXCEPTION`/`IMAGE_DIRECTORY_ENTRY_EXPORT` |
| `pe.rs:PE::run` | Full lifecycle | `RtlAddFunctionTable`, TLS walk, `fixing_arguments`, `CreateThread`+`WaitForSingleObject`, `DllMain`/`Main` dispatch |
| `pe.rs:PE::fixing_arguments` | PEB CommandLine patch | `NtCurrentPeb()`, `(*peb).ProcessParameters`, `write_bytes(buf, 0, len)`, `copy_nonoverlapping` of new wide string |
| `pe.rs:__readgsqword` / `__readfsdword` | PEB access | `core::arch::asm!` with `gs:[offset]` / `fs:[offset]` |

### `core::arch::asm!` Usage

`pe.rs` lines ~585-600 (line numbers approximated):

```rust
#[cfg(target_arch = "x86_64")]
pub unsafe fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    core::arch::asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}
```

- `lateout(reg) out` — output to any free GPR; the `{:e}` placeholder forces 32-bit address size prefix on `offset` (the `in(reg)` operand is u64 but the `:e` formatter takes the low 32 bits).
- `options(nostack, pure, readonly)` — `nostack` = no stack spills, `pure` = compiler may CSE/elide, `readonly` = no memory writes. Required because PEB is process-global read-only.
- x86 variant `__readfsdword` uses `fs:[0x30]` instead of `gs:[0x60]`. Both return `*const PEB`.

### FFI Patterns

- **`#[link(name = "ntdll")]` + `extern "system"`** in `pe_loader.rs` for `NtFlushInstructionCache`. Not routed through RecycledGate because it's a one-shot post-load call; using the link! macro keeps it visible in the IAT as a `ntdll!NtFlushInstructionCache` import — a minor OPSEC cost.
- **Raw `extern "system"` declarations** in `hypnosis.rs` for `CreateProcessW`, `WaitForDebugEvent`, `ContinueDebugEvent`, `DebugActiveProcessStop` — avoids the `windows` crate's bloat and lets the linker resolve against `kernel32.dll` directly.
- **`crate::recycled::invoke(hash, argc, &args)`** in `waiting_thread.rs` — the universal syscall dispatcher takes a DJB2 hash (resolved at runtime via `crate::resolve::compute_hash("NtOpenThread")`), an argument count, and a `&[usize]` of arguments. The actual SSN+gadget lookup happens inside `crate::recycled` (T-001 RecycledGate).
- **`std::mem::transmute` of `GetProcAddress` result** to `RtlCreateProcessReflectionFn` in `process_reflection.rs` — classic GetProcAddress-as-FFI pattern; the function pointer type signature must exactly match the Win32 declaration or you'll get UB at the call site.
- **Handle ownership**: `process_reflection.rs` and `hypnosis.rs` use `let _ = CloseHandle(h)` / `crate::recycled::nt_close(h)` at every error path — manual RAII since there's no `OwnedHandle` wrapper. The `windows` crate's `Handle` would be safer but introduces Drop bomb complexity.

### Initialization Patterns

- `OnceLock` not used in these four files. `pe.rs` and `pe_loader.rs` construct `PE` via `new`/`parse` (stateless).
- `waiting_thread.rs` uses `std::mem::zeroed()` for `OBJECT_ATTRIBUTES` (`oa: [usize; 6]`) — matches the `Length` field at offset 0 to `size_of::<[usize; 6]>()`. The unused fields remain zero, which is what `OBJECT_ATTRIBUTES` requires for `RootDirectory=NULL`, `SecurityDescriptor=NULL`, `Attributes=0`.
- `hypnosis.rs` allocates `STARTUPINFOW` as `Vec<u8>` of correct size, sets `cb` at offset 0 — avoids manual struct definition while respecting the Win32 layout.

### Error Handling

- `pe_loader.rs` uses `anyhow::{Result, bail, Context}`. `bail!` on every bounds check; `.context("...")` on every fallible sub-call. The `PE::parse` function returns `Ok(Self { ... })` only after all validation passes.
- `pe.rs` uses `windows::core::Result` with `Error::new(E_FAIL, "...")` — these errors propagate through the `windows` crate's `HRESULT` machinery.
- `hypnosis.rs` returns `Result<u32, String>` — `String`-based errors (not `anyhow`), formatted with `format!`. Resource cleanup (`DebugActiveProcessStop`, `nt_close`) runs at every error branch.
- `waiting_thread.rs` uses `anyhow::{Result, anyhow, Context}`. Crucially, on `NtSetContextThread` failure, it **restores the original RIP** before resuming — a defensive pattern that prevents leaving the target thread in a corrupted state.
- `process_reflection.rs` returns `bool` — no error context. Failures are silent except for the cleanup paths.

### Memory Layout

- `SystemThreadInformation` (`waiting_thread.rs`): `#[repr(C)]`, sized `0x50` on x64. Layout matches `SYSTEM_THREAD_INFORMATION` from `ntddk.h` exactly (KernelTime/UserTime/CreateTime = 24B, WaitTime = 4B + 4B pad, StartAddress = 8B, ClientId = 16B, Priority/BasePriority = 8B, ContextSwitches = 4B, ThreadState = 4B, WaitReason = 4B, 4B pad).
- `ThreadBasicInformation`: `0x30` bytes, matches `THREAD_BASIC_INFORMATION`. Note: the code does NOT actually use this struct (the comment documents it) — wait info comes from `SystemThreadInformation` via `NtQuerySystemInformation` instead.
- `DEBUG_EVENT` (`hypnosis.rs`): `#[repr(C)]` with `union DebugEventUnion` containing a `_raw: [u8; 160]` fallback to absorb unknown event variants. `CREATE_PROCESS_DEBUG_INFO` is `#[derive(Copy, Clone)]` so it can be read out of the union safely.
- `BaseRelocationEntry` (`pe_loader.rs`) and `BASE_RELOCATION_ENTRY` (`pe.rs`): both `#[repr(C)]` `data: u16`. Two-bitfield accessors: `offset() = data & 0x0FFF`, `reloc_type()/type_() = (data >> 12) & 0xF`.
- `PE` struct (both variants): raw pointers (`*mut IMAGE_NT_HEADERS64`, `*mut IMAGE_SECTION_HEADER`) into `self.buffer: Vec<u8>`. `unsafe impl Send for PE {}` in `pe_loader.rs` acknowledges the self-referential hazard.

### Syscall Numbers / Resolution

- `waiting_thread.rs` does NOT hardcode SSNs. All syscalls go through `crate::recycled::invoke(crate::resolve::compute_hash("Nt*"), argc, &args)`. The `crate::resolve::compute_hash` is the DJB2 hash function (T-004 PEB walker). The actual SSN+gadget resolution happens inside `crate::recycled` (T-001 RecycledGate).
- `hypnosis.rs` does NOT use direct syscalls for the Win32 debug APIs (`CreateProcessW`, etc.). It DOES use `crate::recycled::nt_protect_virtual_memory`, `nt_write_virtual_memory`, `nt_close` — meaning the RecycledGate path for NT syscalls but direct Win32 for the debug subsystem.
- `pe_loader.rs` uses `NtFlushInstructionCache` via `#[link(name = "ntdll")]` — direct ntdll import, visible in IAT.

## Cross-References Found in Code

- `crowd/src/waiting_thread.rs:nt_open_thread()` → calls `crate::recycled::invoke(crate::resolve::compute_hash("NtOpenThread"), 4, &args)` (T-001 RecycledGate + T-004 PEB walker/DJB2)
- `crowd/src/waiting_thread.rs:nt_query_information_thread()` → `crate::resolve::compute_hash("NtQueryInformationThread")` (T-004 DJB2 hash)
- `crowd/src/waiting_thread.rs:inject()` → `crate::recycled::nt_open_process`, `nt_create_section`, `nt_map_view_of_section`, `nt_unmap_view_of_section`, `nt_suspend_thread`, `nt_get_context_thread`, `nt_set_context_thread`, `nt_resume_thread`, `nt_close`, `nt_query_system_information` (T-001 RecycledGate)
- `crowd/src/hypnosis.rs:hypnotize_and_inject()` → `crate::recycled::nt_protect_virtual_memory`, `nt_write_virtual_memory`, `nt_close` (T-001 RecycledGate)
- `crowd/src/hypnosis.rs` → uses `crate::mega_dbg!` macro (debug logging — T-020 anti-analysis utility or shared crate macro)
- `crowd/src/pe_loader.rs:PE::resolve_imports()` → `LoadLibraryA`, `GetProcAddress` — direct Win32 calls for IAT resolution. This is a known OPSEC gap; T-004 PEB walker would be the stealth alternative.
- `crowd/src/pe_loader.rs` → `NtFlushInstructionCache` via `#[link(name = "ntdll")]` — could be replaced with RecycledGate (T-001) for IAT invisibility.
- `crates/core/src/pe.rs:NtCurrentPeb()` → `__readgsqword(0x60)` on x64, `__readfsdword(0x30)` on x86 (T-004 PEB walk primitive — same technique family)
- `crates/core/src/pe.rs:PE::fixing_arguments()` → patches `PEB.ProcessParameters.CommandLine` — related to T-016 EDR evasion (arg spoofing / PEB manipulation)
- `crates/core/src/experimental/injection/process_reflection.rs:try_process_reflection()` → `RtlCreateProcessReflection` from ntdll — related to T-011 Dirty Vanity (which is a sibling technique using `RtlCreateProcessReflection` with start_routine=shellcode)
- `crowd/src/waiting_thread.rs` → uses `winapi::um::winnt::CONTEXT` for `NtGetContextThread`/`NtSetContextThread` — same pattern as `crowd/src/process_hollow.rs` (sibling injection in T-013 card)
- `crates/core/src/pe.rs:PE::fixing_arguments()` writes to `(*process_parameters).CommandLine.Buffer.0` — the `.0` field access implies this is the `windows` crate's `PWSTR` newtype, not raw `*mut u16`.

## Edge Cases & Failure Modes

1. **Reflective PE — preferred base collision**
   - Scenario: `ImageBase` is already taken by another DLL.
   - Failure: `VirtualAlloc(Some(image_base), ...)` returns null.
   - Symptom: Loader silently falls back to `VirtualAlloc(None, ...)` and applies relocations — correct, but the relocation pass needs `reloc_data.Size != 0`. If the PE was compiled with `/DYNAMICBASE:NO /HIGHENTROPYVA:NO` and has no reloc directory, the load silently uses the wrong base for absolute addresses → crash on first import call.
   - Workaround: Always ensure payload PE has relocation directory. The `pe_loader.rs:process_relocations` guard `if delta != 0 && self.reloc_data.VirtualAddress != 0 && self.reloc_data.Size != 0` will skip silently if reloc table is missing — bug or feature, depending on perspective.

2. **Hypnosis — debug event count drift**
   - Scenario: Target process (`notepad.exe`) loads extra DLLs early (e.g., `uicore.dll`, `textinputframework.dll`) before reaching the breakpoint.
   - Failure: The hardcoded `EVENTS_BEFORE_INJECT = 7` triggers on the 7th event regardless of type. If 7th event is `LOAD_DLL` of an unrelated DLL, `start_address` may still be null (if `CREATE_PROCESS` event was event #3 and `lpStartAddress` was captured, OK; if the 7th event is before `CREATE_PROCESS`, we miss it).
   - Symptom: `lpStartAddress is null` error path triggered, cleanup runs, no injection.
   - Workaround: Make the loop track `CREATE_PROCESS` event explicitly and inject when 4-5 subsequent `LOAD_DLL` events have fired, not on a fixed count.

3. **Hypnosis — RX write protection**
   - Scenario: Target entry point is in `PAGE_EXECUTE_READ` (typical).
   - Failure: `NtWriteVirtualMemory` would return `STATUS_ACCESS_VIOLATION (0xC0000005)`.
   - Symptom: Without the `NtProtectVirtualMemory` RW flip, you'd hit the status check `if status < 0` and bail.
   - Workaround: The code already implements this — see lines flagged "BUG FIX: Change page protection to PAGE_READWRITE before writing." If the page is `PAGE_EXECUTE_WRITECOPY` (typical for .text in mapped images), some Windows builds allow direct write without the flip; this implementation always flips for safety.

4. **WaitingThread — no waiting threads in target**
   - Scenario: Target process is busy (e.g., a service in the middle of a request burst).
   - Failure: `query_process_threads` returns `Vec::new()` because no thread has `thread_state == THREAD_STATE_WAITING && wait_reason ∈ SAFE_WAIT_REASONS`.
   - Symptom: `find_waiting_thread` returns `Err(anyhow!("no thread in WAIT state found for PID {}", pid))`. The `inject` function propagates this after cleaning up the process handle.
   - Workaround: Retry with backoff, or fall back to a different injection primitive. No fallback exists in this file.

5. **WaitingThread — RIP not restored on success**
   - Scenario: Shellcode crashes or returns without restoring original RIP.
   - Failure: `_original_rip = ctx.Rip` is saved but never written back. Comment: "not restoring — shellcode takes over".
   - Symptom: Target thread dies after shellcode exits. The host process loses one thread silently — if it was a critical worker thread, the process may hang.
   - Workaround: Have the shellcode itself `jmp` back to the original RIP (passed via a stage-0 stub) or `ExitThread` cleanly. Modify `inject()` to prepend a trampoline that saves RIP and returns to it after shellcode returns.

6. **Process Reflection — `RtlCreateProcessReflection` not exported**
   - Scenario: Windows build older than 1607 or ntdll stripped.
   - Failure: `GetProcAddress(ntdll, "RtlCreateProcessReflection")` returns `None`.
   - Symptom: Silent `false` return. Caller has no diagnostic.
   - Workaround: Check the Windows build number before calling. Fall back to `NtCreateProcessEx` (T-014) or `CreateProcessAsUser` + `WriteProcessMemory`.

7. **Process Reflection — handle inheritance leak**
   - Scenario: `RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES` set, target has many open handles.
   - Failure: Cloned process inherits all handles — including potentially sensitive ones (e.g., LSASS handles in the target).
   - Symptom: Handle count inflation in the clone. If the clone runs untrusted shellcode, it can abuse inherited handles.
   - Workaround: Drop `RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES` if you don't need handle inheritance.

8. **PE loader — `LoadLibraryA` visibility**
   - Scenario: Payload imports `user32.dll`.
   - Failure: `resolve_imports` calls `LoadLibraryA("user32.dll")` for IAT fixup.
   - Symptom: EDR sees `LdrLoadDll` event for `user32.dll` originating from a process that shouldn't be loading it (based on its static IAT). Detection heuristic: process X loads DLL Y but Y isn't in X's static imports.
   - Workaround: Use `pe.rs` variant with `export_function_address` against manually-mapped dependencies, or resolve imports via PEB walker (T-004) + `LdrGetProcedureAddress`.

## OPSEC Notes

### Artifacts Left

- **`pe_loader.rs`**: `LoadLibraryA` per imported dependency leaves `LdrLoadDll` ETW events (mitigated only by T-009 ETW muffling). `NtFlushInstructionCache` import in IAT (via `#[link(name = "ntdll")]`). `VirtualAlloc` with `MEM_COMMIT | MEM_RESERVE` for image-sized region.
- **`pe.rs`**: Same as above + `RtlAddFunctionTable` registers unwind info in the kernel — visible to debuggers and `RtlLookupFunctionEntry` queries. PEB `CommandLine` patch is detectable by comparing `PEB.ProcessParameters.CommandLine` against the image's path in `PEB.ImageBaseAddress`-resolved module list.
- **`hypnosis.rs`**: `CreateProcessW(DEBUG_ONLY_THIS_PROCESS)` is a distinct flag combo — EDRs can alert on debug-mode process creation. `WaitForDebugEvent`/`ContinueDebugEvent`/`DebugActiveProcessStop` triple is unusual outside of legitimate debuggers. Process object lingers briefly during detach — `NtQuerySystemInformation(SystemHandleInformation)` may show the debug port assignment.
- **`waiting_thread.rs`**: `NtMapViewOfSection(remote, PAGE_EXECUTE_READ)` is detectable — memory scanners look for foreign-mapped executable sections. The hijacked thread's call stack will show a foreign return address (the shellcode's base) when it first executes — until the shellcode sets up its own stack.
- **`process_reflection.rs`**: `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` are the classic triad — every EDR hooks these. `RtlCreateProcessReflection` is less commonly hooked but exists in ntdll's export table. The cloned process's parent PID is the cloning process, not the original target's parent — anomalous lineage.

### Cleanup

- All four files close handles via `nt_close` (RecycledGate) or `CloseHandle`. No orphaned handle leaks in the happy path.
- `hypnosis.rs` explicitly calls `DebugActiveProcessStop` to clear the debug port assignment before returning — important because a lingering debug attachment keeps the target process in a debug-quasi-suspended state.
- `process_reflection.rs` closes both `reflection_process_handle` and `reflection_thread_handle` — the reflected process itself persists and continues running with the payload.
- `waiting_thread.rs` does NOT unmap the remote section view — the shellcode lives in the target's address space indefinitely. If the shellcode exits without self-cleanup, the mapped section remains as a foreign RX region in the target's VAD tree (visible to `NtQueryVirtualMemory` walks).

### Telemetry Sources

- **ETW-TI** (kernel threat intelligence): `NtMapViewOfSection`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtSetContextThread` all generate ETW-TI events. The `crate::recycled` indirection makes them appear to originate from `ntdll` (not the calling module) — defeats userland stack-based detection but kernel callbacks still see the actual callsite.
- **Kernel callbacks**: `PsSetCreateProcessNotifyRoutineEx` fires on `CreateProcessW(DEBUG_ONLY_THIS_PROCESS)` and on the reflected process creation. `ObRegisterCallbacks` (if EDR has handle filters) sees the `PROCESS_ALL_ACCESS` open in `waiting_thread.rs` and `process_reflection.rs`.
- **Memory scanners**: Periodic `VirtualQuery` walks will find foreign RX mappings from `waiting_thread.rs` and the allocated image region from `pe_loader.rs`. The `pe.rs` `fixing_arguments` patch is detectable by snapshotting PEB before/after.
- **Sysmon EID 1 (Process Create)**: Fires for the hypnosis child process and the reflected clone. `ParentImage` for the hypnosis child will be the current process; `ParentImage` for the reflection clone will also be the current process — anomalous when the cloning process shouldn't be spawning children.

## Reusable Patterns

### Pattern: Self-Referential Struct with `unsafe impl Send`

- **Use when**: A struct holds raw pointers into its own `Vec<u8>` field.
- **Code ref**: `pe_loader.rs:PE` struct + `unsafe impl Send for PE {}`
- **How**: The struct owns a `Vec<u8>` and stores `*mut IMAGE_NT_HEADERS64` pointing into that buffer. The `Vec`'s heap allocation is stable across moves (its data lives on the heap, only the stack `Vec` header moves). The `unsafe impl Send` is sound as long as no `Sync` is implemented and the struct isn't shared across threads. Document the invariant in a comment.

### Pattern: Packed Bitfield Accessors via `data & mask`

- **Use when**: Parsing Win32 packed structures (relocations, section flags).
- **Code ref**: `pe_loader.rs:BaseRelocationEntry` (`offset() = data & 0x0FFF`, `reloc_type() = (data >> 12) & 0xF`)
- **How**: Define a `#[repr(C)] struct Foo { data: u16 }`, then write `#[inline(always)]` accessor methods. The `#[inline(always)]` is critical because these are called in tight loops over thousands of relocations.

### Pattern: Bounds-Checked Buffer Walks with `checked_add`

- **Use when**: Parsing untrusted PE bytes from network or filesystem.
- **Code ref**: `pe_loader.rs:PE::parse` (L195-L220)
- **How**: Replace `offset + size` with `offset.checked_add(size).ok_or_else(|| anyhow!("overflow"))?` to prevent `usize` overflow panics on adversarial input. Pair with `> buffer.len()` checks. This is the difference between a parse error (recoverable) and a Rust panic (process abort).

### Pattern: RAII Cleanup via Error-Path Repetition

- **Use when**: No `Drop` guard is available (raw handles, FFI resources).
- **Code ref**: `hypnosis.rs:hypnotize_and_inject` (every error branch repeats `DebugActiveProcessStop` + `nt_close(hProcess)` + `nt_close(hThread)`)
- **How**: At each error point, explicitly close all open handles before `return Err`. Verbose but bullet-proof. A `bail_close!` macro (referenced in the technique card for `process_hollow.rs`) would deduplicate this.

### Pattern: KWAIT_REASON Filtering for Safe Hijack Targets

- **Use when**: Thread hijacking with minimal crash risk.
- **Code ref**: `waiting_thread.rs:SAFE_WAIT_REASONS = &[4, 13, 15, 17, 36]`
- **How**: Only hijack threads in `WrDelayExecution`, `WrUserRequest`, `WrQueue`, `WrLpcReply`, `WrAlertByThreadId` — these are deeply idle threads not executing user code. Combined with `max_by_key(|c| c.wait_time)` to pick the longest sleeper. Avoids `WrSuspended` (5) — those are paused for a reason; avoids `WrExecutive` (7) — kernel wait, hijacking from kernel mode is undefined.

### Pattern: PEB Direct Access via `gs:[0x60]` Inline ASM

- **Use when**: Need PEB without going through `NtCurrentTeb()->ProcessEnvironmentBlock` (which is itself a function call into ntdll).
- **Code ref**: `pe.rs:__readgsqword(0x60)` via `core::arch::asm!`
- **How**: On x64, TEB is at `gs:[0x30]`, PEB pointer is at TEB+0x60, so `gs:[0x60]` is the PEB. On x86, TEB is at `fs:[0x18]` (self-pointer) or `fs:[0x30]` (PEB directly). `options(nostack, pure, readonly)` lets the compiler hoist the read out of loops.

### Pattern: Mapping Injection — Local Write, Remote Execute

- **Use when**: Avoiding `NtWriteVirtualMemory` in a remote process.
- **Code ref**: `waiting_thread.rs:inject` (L357-L415)
- **How**: `NtCreateSection(SEC_COMMIT, RW)` → `NtMapViewOfSection(local, RW)` → `memcpy` shellcode → `NtUnmapViewOfSection(local)` → `NtMapViewOfSection(remote, RX)`. The section object is the carrier — no remote write syscall ever fires. The remote view inherits RX protection directly. Note `ViewUnmap = 1` (not `ViewShare = 0`) — `ViewShare` would propagate the mapping to child processes (the card mentions this bugfix explicitly for `mapping_inject.rs`).
