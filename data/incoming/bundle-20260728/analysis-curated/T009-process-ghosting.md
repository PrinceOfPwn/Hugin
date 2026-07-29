---
id: T-009
name: Process Ghosting
category: process-injection
tier: S
mitre: T1055.012
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-001, T-021]
enables: []
vault_references:
  - dark_crystal/crowd/src/ghost.rs
  - dark_crystal/crates/core/src/experimental/process_ghosting.rs
implements:
  - file: dark_crystal/crowd/src/ghost.rs
    key_functions:
      - spawn_ghosted
      - create_section_from_delete_pending
      - setup_process_parameters
      - get_entry_point_rva
      - find_pid_by_name
    key_structs:
      - FileDispositionInfo (anonymous #[repr(C)])
    key_constants:
      - PROCESS_CREATE_PROCESS (0x0080)
      - FILE_SUPERSEDE
      - FILE_SYNCHRONOUS_IO_NONALERT
      - SEC_IMAGE
      - SECTION_ALL_ACCESS
      - OBJ_CASE_INSENSITIVE (0x40)
      - RTL_USER_PROC_PARAMS_NORMALIZED
      - PROCESS_CREATE_FLAGS_INHERIT_HANDLES
      - MEM_COMMIT|MEM_RESERVE (0x00003000)
      - PAGE_READWRITE (0x04)
    lines_of_interest:
      - "L97-L154: spawn_ghosted — top-level orchestration"
      - "L159-L228: create_section_from_delete_pending — the ghost primitive (delete-pending + SEC_IMAGE)"
      - "L186-L195: NtSetInformationFile FileDispositionInformation marking file delete-pending before payload write"
      - "L201-L213: NtWriteFile into the unscannable file"
      - "L216-L226: NtCreateSection SEC_IMAGE + immediate NtClose — file vanishes, section persists"
      - "L232-L353: setup_process_parameters — VA-hint allocation to keep internal UNICODE_STRING pointers valid"
      - "L312-L326: PEB.ProcessParameters field offset arithmetic via addr_of!"
      - "L366-L386: get_entry_point_rva — PE64 entry point extraction"
  - file: dark_crystal/crates/core/src/experimental/process_ghosting.rs
    key_functions:
      - Ghosting::new
      - Ghosting::run
      - Ghosting::prepare
      - Ghosting::create_section
      - Ghosting::params
      - try_process_ghosting
    key_structs:
      - Ghosting
      - IMAGE_FILE_HEADER (local redecl)
      - IMAGE_OPTIONAL_HEADER64 (local redecl)
      - IMAGE_NT_HEADERS64 (local redecl)
      - EnvGuard (RAII guard for CreateEnvironmentBlock/DestroyEnvironmentBlock)
    key_constants:
      - OBJ_CASE_INSENSITIVE (0x40)
      - FILE_DISPOSITION_INFORMATION_CLASS (13)
      - RTL_USER_PROC_PARAMS_NORMALIZED
      - PROCESS_CREATE_FLAGS_INHERIT_HANDLES
      - PAGE_EXECUTE_READ
    lines_of_interest:
      - "L86-L130: Ghosting::run — entry-point protect + NtCreateThreadEx"
      - "L132-L160: Ghosting::prepare — NtCreateProcessEx with parent=-1 (current process)"
      - "L169-L227: Ghosting::create_section — NtOpenFile → delete-pending → NtWriteFile → SEC_IMAGE → NtClose"
      - "L247-L425: Ghosting::params — full RTL_USER_PROCESS_PARAMETERS relocation with kernel-chosen base"
      - "L312-L322: relocation closures (relocate_ptr / relocate_unicode) fixing all 10 UNICODE_STRING pointers"
      - "L295-L302: NtAllocateVirtualMemory with null hint (kernel-chosen) — the correct approach vs the crowd version's hint-based one"
      - "L435-L447: try_process_ghosting — OPSEC-broken convenience wrapper that writes payload to disk before ghosting"
min_windows: Windows Vista+
needs_admin: conditional
tags: [injection, ghosting, delete-pending, sec-image, ppid-spoof, nt-api, masquerade]
---

# Process Ghosting — Operator Playbook

## TL;DR
Spawn a process backed by a `SEC_IMAGE` section created from a **delete-pending** file: the file is marked for deletion *before* the payload is written, so it never exists on disk in a scannable state, yet a valid image section survives in kernel memory and serves as the substrate for `NtCreateProcessEx`. The result is a fully legitimate-looking process (real PEB, real image section, real loader thunk) with zero on-disk forensic footprint and zero RWX-anonymous-memory footprint — the two things Moneta and pe-sieve flag. Two implementations live in the vault: a hardened operator-grade version in `crowd/src/ghost.rs` (PPID spoof + RecycledGate-routed syscalls + masquerade path) and an experimental reference version in `crates/core/src/experimental/process_ghosting.rs` (full pointer relocation but no PPID and an OPSEC-broken convenience wrapper).

## Source File Map

| File | Role | Key Exports | Size |
|---|---|---|---|
| `dark_crystal/crowd/src/ghost.rs` | Operator-grade ghosting: PPID spoof, masquerade path, RecycledGate-routed memory ops, public `find_pid_by_name` helper for PPID auto-acquisition | `spawn_ghosted()`, `find_pid_by_name()` | ~390 LOC |
| `dark_crystal/crates/core/src/experimental/process_ghosting.rs` | Experimental reference: `Ghosting` struct, full pointer relocation, `crate::obf!` string obfuscation, explicit `NtProtectVirtualMemory` on entry-point region, `try_process_ghosting` convenience wrapper | `Ghosting::new`, `Ghosting::run`, `Ghosting::prepare`, `Ghosting::create_section`, `Ghosting::params`, `try_process_ghosting` | ~450 LOC |

## How It Works

The ghost primitive is the same in both implementations; only the parameter-block setup differs. Steps below cite `crowd/src/ghost.rs` first (operator path), then call out divergences from `process_ghosting.rs`.

1. **Temp path generation** (`ghost.rs:104-121`). `GetTempPathA` + `GetTempFileNameA(prefix="TH")` produces a path like `C:\Users\...\Temp\TH1234.tmp`. The path is then converted to NT form `\\??\\C:\...` (line 124). The experimental version (`Ghosting::new`, L60-L78) uses `std::env::temp_dir()` + `GetTempFileNameW(prefix="TT")` and the same `\\??\\` prefix.

2. **File creation with DELETE disposition** (`ghost.rs:170-186`, `create_section_from_delete_pending`). The crowd version uses `NtCreateFile` with `DELETE | SYNCHRONIZE | FILE_GENERIC_WRITE | FILE_GENERIC_READ` access, `FILE_SUPERSEDE` disposition, `FILE_SYNCHRONOUS_IO_NONALERT` options. The experimental version uses `NtOpenFile` with `GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE` and the same disposition/options. `FILE_SUPERSEDE` on `NtOpenFile` is technically unusual (supersede is a create-disposition), but the kernel tolerates it because the file already exists from `GetTempFileName*`.

3. **Mark delete-pending — the crux of the technique** (`ghost.rs:188-200`). A stack-allocated `FileDispositionInfo { delete_file: 1 }` is written via `NtSetInformationFile` with info class `FileDispositionInformation` (= 13, hardcoded as `FILE_DISPOSITION_INFORMATION_CLASS` in the experimental file at L24). From this moment, the file is *unscannable*: any external `NtOpenFile` for read access returns `STATUS_DELETE_PENDING` (0xC0000056). But our handle is still valid for write and section creation.

4. **Write payload into the unscannable file** (`ghost.rs:202-213`, `NtWriteFile`). ByteOffset is `NULL` to use the current file position (synchronous I/O mode set in step 2). The payload is the decrypted PE bytes already in memory — never touches disk in plaintext.

5. **Create the SEC_IMAGE section** (`ghost.rs:216-222`). `NtCreateSection(SEC_IMAGE, PAGE_READONLY, h_file)` causes the kernel to parse the PE, validate it as a proper image, and create a section object backed by the file. At this exact instant the file content is "captured" — the section can outlive the file.

6. **Close the file handle** (`ghost.rs:223`, `NtClose(h_file)`). The filesystem sees no more handles and silently deletes the file. The section persists, now backed by the paging file rather than the (deleted) source file.

7. **Resolve parent handle for PPID spoofing** (`ghost.rs:127-167`). If `ppid > 0`, the operator-supplied PID is opened with `OpenProcess(PROCESS_CREATE_PROCESS=0x0080, ...)`. If that fails (e.g., PPL-protected or insufficient privilege), the code silently degrades to *no spoof*. If `ppid == 0`, the code opens the *current* process with `NtOpenProcess(PROCESS_CREATE_PROCESS, cid=self)` so the kernel sees a legitimate parent relationship. The experimental version (`Ghosting::prepare`, L137-L156) skips this entirely — `NtCreateProcessEx` is called with `ParentProcess = -1isize as HANDLE` (= NtCurrentProcess, the pseudo-handle).

8. **NtCreateProcessEx from the section** (`ghost.rs:170-184`). `NtCreateProcessEx(h_process, PROCESS_ALL_ACCESS, NULL, effective_parent, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, h_section, NULL, NULL, 0)`. The kernel sets up an EPROCESS, allocates the address space by mapping the section, creates the PEB, sets up the loader data structures, and prepares `LdrInitializeThunk` — but does **not** start any thread yet. The section handle is closed immediately afterwards (`NtClose(h_section)`).

9. **Query PEB base of the ghosted process** (`ghost.rs:192-203`). `NtQueryInformationProcess(ProcessBasicInformation)` returns a `PROCESS_BASIC_INFORMATION` whose `PebBaseAddress` field points into the ghosted process's address space.

10. **Read remote PEB** (`ghost.rs:205-216`). `NtReadVirtualMemory(h_process, pbi.PebBaseAddress, &mut remote_peb, size_of::<PEB>())`. We need `ImageBaseAddress` (the kernel-determined base where the section was mapped) and `ProcessParameters` field offset.

11. **Build RTL_USER_PROCESS_PARAMETERS with masquerade path** (`ghost.rs:setup_process_parameters`, L243-L281). `RtlCreateProcessParametersEx` is called with `ImagePathName = masquerade_path` (e.g. `C:\Windows\System32\svchost.exe`), `DllPath = C:\Windows\System32`, `CurrentDirectory = parent dir of masquerade_path`, `WindowTitle = masquerade_path`, `DesktopInfo` inherited from the current process's PEB via `NtCurrentPeb()->ProcessParameters->DesktopInfo` (avoids a black screen on interactive spawns). `RTL_USER_PROC_PARAMS_NORMALIZED` flag tells RtlCreateProcessParametersEx to return pointers in absolute form, not self-relative.

12. **Allocate remote memory and write params** (`ghost.rs:283-L326` for crowd version; `process_ghosting.rs:Ghosting::params` L295-L327 for the experimental version).
    - **Crowd version (fragile)**: `crate::recycled::nt_allocate_virtual_memory(h_process, &mut remote_addr = params as *mut _, 0, region_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)` — passes the *local* `params` pointer as the allocation hint, betting that the remote process will accept the same VA. The code explicitly verifies `remote_addr == params as *mut _` and bails if the hint is rejected. This works reliably only when ASLR places the two processes at overlapping bases (e.g., sibling svchost children).
    - **Experimental version (correct)**: `NtAllocateVirtualMemory(h_process, &mut base_address = NULL, 0, ...)` — lets the kernel pick the base, then walks every embedded pointer (`ImagePathName.Buffer`, `CommandLine.Buffer`, `DesktopInfo.Buffer`, `Environment`, etc.) via the `relocate_ptr` / `relocate_unicode` closures and rewrites them to point inside the new remote region. This is the textbook-correct approach.

13. **Patch PEB.ProcessParameters** (`ghost.rs:308-L326`). The code computes the field offset with `addr_of!((*peb_ptr).ProcessParameters) as usize - peb_ptr as usize` (NOT a direct deref, since `peb_ptr` is remote). Then writes `params as usize` into `pbi.PebBaseAddress + offset` via `crate::recycled::nt_write_virtual_memory`. The experimental version uses `offset_of!(PEB, ProcessParameters)` directly (L408-L420) — same semantics, cleaner API.

14. **Calculate entry point and spawn initial thread** (`ghost.rs:349-L375`).
    - `get_entry_point_rva(payload)` parses `IMAGE_DOS_HEADER` → `IMAGE_NT_HEADERS64` (validates `e_magic == IMAGE_DOS_SIGNATURE` and `Signature == IMAGE_NT_SIGNATURE`) and returns `OptionalHeader.AddressOfEntryPoint`.
    - `entry_point = remote_peb.ImageBaseAddress + ep_rva`.
    - The experimental version additionally calls `crate::sys_indirect::nt::nt_protect_virtual_memory(h_process, base_addr=entry_point, region_size=4096, PAGE_EXECUTE_READ, &mut old_protect)` (L101-L110) — hardens the EP page from RW to RX before thread start. The crowd version skips this and relies on the loader's default protections.
    - `NtCreateThreadEx(h_thread, THREAD_ALL_ACCESS, NULL, h_process, entry_point, NULL, flags=0, 0, 0, 0, NULL)`. Flags=0 means "start immediately." For `SEC_IMAGE` processes, the kernel runs `LdrInitializeThunk` first (resolves imports, runs TLS callbacks, applies relocations), then jumps to the entry point — exactly like a normal process birth.

15. **Cleanup** (`ghost.rs:377-L378`). `crate::recycled::nt_close(h_thread)` + `crate::recycled::nt_close(h_process)`. The ghosted process is now running with no outstanding handles from the spawner. The temp file is gone; the section is owned by the kernel; the parent (if spoofed) was closed in step 8.

## Code Architecture

### Call graph (operator path, `crowd/src/ghost.rs`)

```
spawn_ghosted(payload, masquerade_path, ppid)
├── GetTempPathA / GetTempFileNameA                       [Win32]
├── create_section_from_delete_pending(nt_path, payload)
│   ├── RtlInitUnicodeString                              [ntapi]
│   ├── InitializeObjectAttributes                         [winapi]
│   ├── NtCreateFile  ← (FILE_SUPERSEDE)                 [ntapi]
│   ├── NtSetInformationFile ← FileDispositionInformation [ntapi]
│   ├── NtWriteFile                                       [ntapi]
│   ├── NtCreateSection ← SEC_IMAGE, PAGE_READONLY        [ntapi]
│   └── NtClose(h_file)                                   [ntapi]
├── OpenProcess(PPID, PROCESS_CREATE_PROCESS)             [Win32]   (if ppid > 0)
├── NtOpenProcess(self, PROCESS_CREATE_PROCESS)          [ntapi]   (fallback if ppid == 0)
├── NtCreateProcessEx(h_section, effective_parent, …)     [ntapi]
├── NtClose(h_section) / crate::recycled::nt_close(parent) [T-001]
├── NtQueryInformationProcess(ProcessBasicInformation)   [ntapi]
├── NtReadVirtualMemory(remote_peb)                      [ntapi]
├── setup_process_parameters(h_process, &pbi, masquerade_path)
│   ├── RtlCreateProcessParametersEx                       [ntapi]
│   ├── CreateEnvironmentBlock / DestroyEnvironmentBlock    [Win32 userenv]
│   ├── crate::recycled::nt_allocate_virtual_memory         [T-001]
│   ├── crate::recycled::nt_write_virtual_memory (params)   [T-001]
│   ├── crate::recycled::nt_write_virtual_memory (env)       [T-001]
│   └── crate::recycled::nt_write_virtual_memory (PEB.ProcessParameters) [T-001]
├── get_entry_point_rva(payload)                          [local PE parse]
└── NtCreateThreadEx(entry_point, flags=0)                [ntapi]
    └── crate::recycled::nt_close(h_thread / h_process)   [T-001]
```

### Call graph (experimental, `crates/core/src/experimental/process_ghosting.rs`)

```
Ghosting::new(file, args)
├── std::env::temp_dir / GetTempFileNameW(prefix="TT")
└── std::fs::read(file)         ← payload loaded from disk

Ghosting::run(&self)
├── Ghosting::prepare()
│   ├── Ghosting::create_section()
│   │   ├── RtlInitUnicodeString / InitializeObjectAttributes
│   │   ├── NtOpenFile (FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT)
│   │   ├── NtSetInformationFile (FileDispositionInformation)
│   │   ├── NtWriteFile (payload)
│   │   ├── NtCreateSection (SEC_IMAGE, PAGE_READWRITE)   ← note: PAGE_READWRITE vs crowd's PAGE_READONLY
│   │   └── NtClose(h_file)
│   ├── NtCreateProcessEx(parent = -1isize as HANDLE)     ← pseudo-handle, no PPID
│   └── Ghosting::params(h_process)
│       ├── crate::obf!("C:\\Windows\\System32")         ← T-021 obfuscation
│       ├── RtlCreateProcessParametersEx
│       ├── NtQueryInformationProcess(ProcessBasicInformation)
│       ├── NtReadVirtualMemory(remote PEB)
│       ├── NtAllocateVirtualMemory (NULL hint, kernel-chosen)   ← correct approach
│       ├── relocate_ptr / relocate_unicode closures       ← fix 10 embedded UNICODE_STRING pointers
│       ├── NtWriteVirtualMemory (params + env blob)
│       └── NtWriteVirtualMemory (PEB.ProcessParameters field)
├── crate::sys_indirect::nt::nt_protect_virtual_memory (entry point → PAGE_EXECUTE_READ)  [T-001/T-004]
└── NtCreateThreadEx(entry_point, flags=0)

try_process_ghosting(payload: &[u8])                     ← OPSEC-broken wrapper
├── std::fs::write(temp_dir/cc_ghost_payload.exe, payload)   ← writes payload to disk in plaintext!
├── Ghosting::new(...) / .run()
└── std::fs::remove_file(...)
```

### Type hierarchy

- `Ghosting { buffer: Vec<u8>, temp_name: String, args: String }` (experimental only) — RAII-style owner of the payload bytes and NT path string.
- `EnvGuard(*mut c_void)` (experimental, anonymous in `Ghosting::params`) — RAII guard that calls `DestroyEnvironmentBlock` on drop. This is the canonical Rust pattern for kernel-owned environment blobs.
- `FileDispositionInfo { delete_file: u8 }` (crowd, anonymous `#[repr(C)]` struct) — local re-declaration because `ntapi::ntioapi::FILE_DISPOSITION_INFORMATION` (used by the experimental version) wasn't imported.

### Feature gates

- `crowd/src/ghost.rs` has `#[cfg(debug_assertions)]` debug-prints at lines 134, 137, and 381 — they emit PID, masquerade, and entry-point info to stderr. Strip in release.
- `process_ghosting.rs` uses `crate::obf!` macro for `C:\Windows\System32` and `C:\Windows\System32\Notepad.exe` literals — the strings exist only in encrypted form in the binary and are decrypted at runtime. Direct dependency on T-021.
- `process_ghosting.rs` imports `windows_sys::Wdk::*` paths (e.g. `Wdk::Storage::FileSystem::FILE_DISPOSITION_INFORMATION`) — requires the `Wdk` feature on `windows-sys`, which is Windows 10+ only as a Cargo feature but produces binaries that run on Vista+.

## Operational Profile

### When to Use
- You have a decrypted PE payload in memory and need to execute it as a real process with a legitimate-looking PEB, image section, and loader thunk chain (vs. manual mapping which Moneta flags as unsigned).
- EDR does image-section-based parent/child correlation and you need a `SEC_IMAGE`-backed process to pass those heuristics.
- You want PPID spoofing AND a clean process birth in a single syscall — `NtCreateProcessEx` accepts the parent handle and the section in the same call.
- You need the spawned process to host further technique stacks (Ekko sleep, Edo Tensei resurrection callbacks, persistence monitors) that require a real loader-initialized environment.

### When NOT to Use
- Target has kernel-mode callbacks (`PsSetCreateProcessNotifyRoutineEx`) that veto process creation from sections — some EDRs block `NtCreateProcessEx` outright when the section was created from a delete-pending file (this is the documented mitigation).
- You're executing pure position-independent shellcode (no PE header) — ghosting needs a valid PE.
- You can't write the payload to even a delete-pending file (e.g., FS-filter that blocks `FILE_DISPOSITION_INFORMATION` on `*.tmp` in user-writable dirs).
- The crowd version's VA-hint allocation will fail on processes with divergent ASLR slides — see Edge Case 1.

### Kill Chain Position
Ghosting is a delivery primitive — it sits in the **post-decrypt / pre-execution** slot. It consumes a decrypted PE and produces a running process; everything downstream runs inside that process.

Example chain:
```
T-004 (PEB walk for ntdll) → T-002 (FreshyCalls SSN resolution) → T-001 (RecycledGate) →
T-021 (decrypt payload in memory) → T-009 (Process Ghosting) →
T-015 (PPID spoof built-in) → T-005 (Ekko sleep inside ghost) →
T-017 (TLS callback / NTFS EA persistence) → T-018 (Edo Tensei resurrection callbacks)
```

Compare with `T-012 Early Cascade` (also a delivery primitive but injects into a legitimately-spawned suspended process via APC) — ghosting's advantage is no on-disk payload exposure *at all*, even briefly; its disadvantage is that the spawned process has a section-from-deleted-file provenance that some EDRs flag.

### Trade-offs

## Rust Implementation Deep Dive

### `unsafe` blocks

1. **`ghost.rs:97 spawn_ghosted`** — entire function body is `unsafe`. Justified: every NT call dereferences raw `HANDLE`s, writes to remote process memory, and uses FFI to ntapi. No safe abstraction exists for `NtCreateProcessEx`.
2. **`ghost.rs:159 create_section_from_delete_pending`** — entire helper is `unsafe`. Holds the file handle live between the delete-pending mark and the section creation — a 4-syscall critical section.
3. **`ghost.rs:231 setup_process_parameters`** — `unsafe` for the `RtlCreateProcessParametersEx` FFI, the remote VA hint arithmetic, and the `addr_of!((*peb_ptr).ProcessParameters)` field offset computation. The latter is safe-as-written (no deref) but Rust still requires `unsafe`.
4. **`ghost.rs:366 get_entry_point_rva`** — `unsafe` for `IMAGE_DOS_HEADER` / `IMAGE_NT_HEADERS64` pointer casts. Validates `e_magic` and `Signature` before returning the RVA.
5. **`ghost.rs:386 find_pid_by_name`** — `unsafe` for `CreateToolhelp32Snapshot` + `Process32First/Next` FFI and `CStr::from_ptr` on `szExeFile`.
6. **`process_ghosting.rs:Ghosting::create_section` L169-L227** — `unsafe` block spanning the entire file-create/delete/write/section sequence. Uses `zeroed::<UNICODE_STRING>()` and `zeroed::<IO_STATUS_BLOCK>()` for initialization.
7. **`process_ghosting.rs:Ghosting::params` L247-L425** — `unsafe` block spanning the entire params setup. Most subtle part: the `relocate_ptr` / `relocate_unicode` closures capture `local_base` and `span_end` by reference and mutate the `remote_params_ptr` buffer in place.
8. **`process_ghosting.rs:EnvGuard::drop`** — `unsafe` for `DestroyEnvironmentBlock` FFI.

### `core::arch::asm!` usage
None. Both implementations route syscalls through `ntapi` (crowd) or `crate::wrappers` / `crate::sys_indirect` (experimental). Inline asm is delegated to T-001 RecycledGate (`crate::recycled::*`) and T-004 syscall dispatch (`crate::sys_indirect`).

### FFI patterns

- **`ntapi::*` in crowd/ghost.rs**: directly uses `ntapi_base::CLIENT_ID`, `ntioapi::*`, `ntmmapi::NtCreateSection`, `ntobapi::NtClose`, `ntpebteb::PEB`, `ntpsapi::*`, `ntrtl::*`. Returns `NTSTATUS` (i32) checked via `NT_SUCCESS` macro from `winapi::shared::ntdef`. This is the "raw ntapi" pattern.
- **`winapi::*` in crowd/ghost.rs**: used only for `OBJECT_ATTRIBUTES`, `UNICODE_STRING`, `IMAGE_DOS_HEADER`/`IMAGE_NT_HEADERS64`, Win32 helpers (`GetTempFileNameA`, `OpenProcess`, `CreateToolhelp32Snapshot`, `CreateEnvironmentBlock`). Mixed because ntapi doesn't expose all of these.
- **`windows_sys::Wdk::*` in experimental**: uses the WDK-flavored bindings (`Wdk::Storage::FileSystem::*`, `Wdk::Foundation::OBJECT_ATTRIBUTES`). This is the newer Microsoft-blessed binding path; the comment on L25 ("OBJ_CASE_INSENSITIVE constant removed from windows-sys::Win32::System::Kernel in v0.61") documents a binding churn workaround.
- **`crate::recycled::*` calls**: `nt_close(handle: usize)`, `nt_allocate_virtual_memory(h_process: usize, base_addr: *mut *mut c_void, zero, size: *mut usize, alloc_type, protect)`, `nt_write_virtual_memory(h_process, addr, src, size, written: *mut usize)`. Note the `usize` handle convention — RecycledGate uses numeric handles internally to avoid lifetime issues with raw `HANDLE` aliases. Returns `NTSTATUS` (i32) — caller checks `< 0` for failure (different convention from `NT_SUCCESS` macro!).
- **`crate::sys_indirect::nt::nt_protect_virtual_memory`** (experimental only): called as `crate::sys_indirect::nt::nt_protect_virtual_memory(h_process as usize, &mut base_addr as *mut *mut c_void, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect)`. Routes through the universal syscall dispatcher — uses whatever SSN resolution is active (Hell's/Halo's/Tartarus per T-002).

### Initialization patterns

- **No `OnceLock` / `LazyCell` in either file.** Ghosting is a one-shot operation; no cached state. SSN resolution and PEB walks happen at the syscall layer below.
- **`include_str!` / build-time embedding**: not in these files. The payload arrives as `&[u8]` from upstream (T-021 crypto pipeline) or via `std::fs::read(file)` in the experimental version.
- **`#[cfg(debug_assertions)]`**: 3 sites in `crowd/src/ghost.rs` (L134, L137, L381) — debug-only `eprintln!` for PPID-open failures and final spawn confirmation.

### Error handling

Both implementations use `anyhow::Result` (crowd) or `Box<dyn Error>` (experimental). Failure modes:

- **NT call failure**: returns `Err(anyhow!("... failed: 0x{:08x}", status as u32))` — preserves NTSTATUS for triage.
- **Crowd version cleanup**: on failure after `NtCreateProcessEx`, calls `NtTerminateProcess(h_process, 0)` + `crate::recycled::nt_close(h_process)`. **Does NOT terminate the process if `setup_process_parameters` or `NtCreateThreadEx` succeeds but a later step fails** — see Edge Case 2.
- **Experimental version**: does not terminate the ghosted process on failure — leaves zombie processes. Worse OPSEC than crowd version.
- **`EnvGuard`** (experimental): RAII guard ensures `DestroyEnvironmentBlock` runs even on early return. Crowd version manually calls `DestroyEnvironmentBlock(env_block)` at every failure point — more error-prone.

### Memory layout

- `PEB` (from `ntpebteb::PEB` in crowd, `windows_sys::Win32::System::Threading::PEB` in experimental): the field `ProcessParameters` lives at a fixed offset; crowd version computes it via `addr_of!` arithmetic, experimental via `offset_of!`.
- `RTL_USER_PROCESS_PARAMETERS`: contains 10 `UNICODE_STRING` fields (`ImagePathName`, `CommandLine`, `WindowTitle`, `DesktopInfo`, `ShellInfo`, `RuntimeData`, `CurrentDirectory.DosPath`, `DllPath`, `RedirectionDllName`, `HeapPartitionName`) plus 3 raw pointers (`Environment`, `PackageDependencyData`, `DefaultThreadpoolCpuSetMasks`) plus a 32-element `CurrentDirectories` array — all of which may point inside the same allocation. The experimental version's relocation logic at L316-L322 handles every one; the crowd version assumes the VA-hint trick makes relocation unnecessary.
- `FileDispositionInfo` (crowd): 1-byte struct, packed via `#[repr(C)]`. The experimental version uses `FILE_DISPOSITION_INFORMATION { DeleteFile: BOOLEAN }` from windows-sys where `BOOLEAN = u8`.
- `IMAGE_NT_HEADERS64` (experimental local redecl at L36-L44): only declares `Signature` (4 bytes) + `FileHeader` (20 bytes padded) + first 16 bytes of `OptionalHeader` + `AddressOfEntryPoint` (4 bytes). This is a *minimal* slice of the real header — saves having to import the full `IMAGE_NT_HEADERS64` from windows-sys. The crowd version uses the full `winapi::um::winnt::IMAGE_NT_HEADERS64` and indexes `(*nt).OptionalHeader.AddressOfEntryPoint`.

### Syscall numbers

This technique **does not resolve SSNs itself**. All syscalls go through one of:
- `ntapi::*` (statically linked to ntdll exports) — crowd version
- `crate::wrappers::*` (windows_targets::link! macros, also ntdll-static) — experimental version
- `crate::recycled::*` (RecycledGate indirect syscalls via ntdll gadget, **T-001**) — crowd's `nt_close`, `nt_allocate_virtual_memory`, `nt_write_virtual_memory`
- `crate::sys_indirect::nt::nt_protect_virtual_memory` (**T-004** syscall dispatcher with Hell's/Halo's/Tartarus Gate SSN resolution from **T-002**)

The split is intentional: state-mutating syscalls on a *remote* process handle go through RecycledGate (so the call stack looks like ntdll); state-querying syscalls on local handles go through ntapi (acceptable because they don't change process state).

## Cross-References Found in Code

- `crowd/src/ghost.rs:127-167` → calls `crate::recycled::nt_close` (T-001 RecycledGate) for closing parent handle, h_thread, h_process. Reason: avoid `NtClose` ETW trap-stack from ntdll direct call.
- `crowd/src/ghost.rs:303-L326` → calls `crate::recycled::nt_allocate_virtual_memory` and `crate::recycled::nt_write_virtual_memory` (T-001) for all memory ops on the ghosted process. Reason: every remote memory write is high-risk telemetry; routing through RecycledGate makes the call stack originate from a `MEM_IMAGE` ntdll gadget instead of an anonymous stack.
- `crowd/src/ghost.rs:386-415 find_pid_by_name` → uses `CreateToolhelp32Snapshot` + `Process32First/Next` + closes the snapshot via `crate::recycled::nt_close` (T-001). The helper exists to support **T-015 PPID Spoofing** flows (e.g., `spawn_ghosted(payload, "C:\\Windows\\System32\\svchost.exe", find_pid_by_name("explorer.exe").unwrap_or(0))`).
- `crowd/src/ghost.rs:170` → `NtCreateProcessEx(effective_parent, ...)` is itself a **T-015 PPID spoofing** primitive (the same syscall used by the standalone `ppid.rs` module per the manifest).
- `process_ghosting.rs:246-249` → uses `crate::obf!("C:\\Windows\\System32")` and `crate::obf!("C:\\Windows\\System32\\Notepad.exe")` (T-021 String Obfuscation proc macro). Reason: hide the masquerade target paths from static string extraction.
- `process_ghosting.rs:101-110` → calls `crate::sys_indirect::nt::nt_protect_virtual_memory` (T-001/T-004 syscall dispatch). Reason: harden the entry-point page to `PAGE_EXECUTE_READ` before thread creation — avoids a brief RW window.
- `process_ghosting.rs:imports` → pulls `crate::wrappers::*` which the manifest tags as "NT API bindings via windows_targets::link!" — this is the FFI layer used by multiple injection modules. No T-XXX card explicitly covers it (it's utility infrastructure).
- Neither file references T-005 (Ekko sleep), T-017 (persistence), or T-018 (Edo Tensei) directly, but the spawned process is the natural host for all of these — see "Kill Chain Position" above.

## Edge Cases & Failure Modes

1. **VA-hint allocation rejected (crowd version)**
   - **Scenario**: Two processes with sufficiently different ASLR base addresses; `params` lands at a VA in the spawner that's already occupied in the ghosted process.
   - **Failure path**: `crowd/src/ghost.rs:setup_process_parameters` L297-L302 — `crate::recycled::nt_allocate_virtual_memory(h_process, &mut remote_addr = params as *mut _, ...)` returns `STATUS_CONFLICTING_ADDRESSES` (0xC0000018) or accepts a different VA. The check at L305-L308 catches the latter and errors out; the former is caught by `alloc_status < 0`.
   - **Symptom**: Ghosted process is created (kernel sees the EPROCESS) but is immediately terminated in the cleanup path. Operator sees `"NtAllocateVirtualMemory(params hint=0x...) failed"` in stderr (debug only).
   - **Workaround**: Use the experimental version's `Ghosting::params` (kernel-chosen base + full relocation) — explicitly commented at L290-L294 as the correct approach. Alternatively, port the `relocate_ptr`/`relocate_unicode` closures into the crowd version. The crowd version's comment at L292 ("Critical: hint = params address so internal UNICODE_STRING pointers stay valid") documents the bet being made.

2. **Zombie ghosted process on failure (experimental version)**
   - **Scenario**: `Ghosting::params` fails after `NtCreateProcessEx` succeeds.
   - **Failure path**: `process_ghosting.rs:Ghosting::prepare` L141-L156 returns `Err` but the process is already alive (no thread yet, but EPROCESS exists). No cleanup path calls `NtTerminateProcess`.
   - **Symptom**: Suspended ghosted process lingers in `System` PID 4's child list with no image path. Highly visible to EDR.
   - **Workaround**: Wrap `Ghosting::prepare` in a guard that calls `NtTerminateProcess` on drop. The crowd version does this correctly at every failure point.

3. **Payload written to disk in plaintext (experimental `try_process_ghosting`)**
   - **Scenario**: Operator calls the convenience wrapper `try_process_ghosting(payload)`.
   - **Failure path**: `process_ghosting.rs:try_process_ghosting` L435-L447 — `std::fs::write(&tmp_path, payload)` writes the decrypted PE to `temp_dir/cc_ghost_payload.exe` *before* `Ghosting::new` reads it back. The file exists on disk in normal, scannable state for the duration of the I/O.
   - **Symptom**: AV signature scan or EDR image-load event fires on the payload file.
   - **Workaround**: Never use `try_process_ghosting`. Use `spawn_ghosted(payload, masquerade, ppid)` directly with in-memory payload — the crowd version is correct.

4. **`NtOpenFile` with `FILE_SUPERSEDE` (experimental version)**
   - **Scenario**: `Ghosting::create_section` L184-L191 calls `NtOpenFile` with `FILE_SUPERSEDE` in `CreateOptions`. `FILE_SUPERSEDE` is a *CreateDisposition*, not a *CreateOption* — semantically misplaced.
   - **Failure path**: On strict kernel builds, this may return `STATUS_INVALID_PARAMETER`. Tested empirically to work on Win10/11, but not guaranteed on hardened configurations.
   - **Symptom**: `NtOpenFile Failed With Status: 0xC000000D` (STATUS_INVALID_PARAMETER).
   - **Workaround**: Use `NtCreateFile` with `FILE_SUPERSEDE` as `CreateDisposition` (5th parameter) like the crowd version does (L172-L186).

5. **PPID OpenProcess failure**
   - **Scenario**: Operator-supplied `ppid` belongs to a PPL-protected process or one in a different session.
   - **Failure path**: `crowd/src/ghost.rs:131-137` — `OpenProcess(PROCESS_CREATE_PROCESS, 0, ppid)` returns NULL. The code sets `parent_handle = null_mut()` and falls through to the `effective_parent` block, which then opens the current process as parent. **Silent degradation, not an error.**
   - **Symptom**: Ghosted process appears as a child of the spawner, not the requested PPID.
   - **Workaround**: Pre-validate the PPID with `find_pid_by_name` + a probe `OpenProcess` before calling `spawn_ghosted`, or pass `ppid=0` to use current-process-as-parent intentionally.

6. **Non-PE payload**
   - **Scenario**: Operator passes raw shellcode or a corrupted PE.
   - **Failure path**: `crowd/src/ghost.rs:get_entry_point_rva` L366-L386 returns `None` if `e_magic != IMAGE_DOS_SIGNATURE` or `Signature != IMAGE_NT_SIGNATURE`. `spawn_ghosted` then returns `Err("Process Ghost: PE inválido — sin AddressOfEntryPoint")`.
   - **Symptom**: Section is created (kernel's `SEC_IMAGE` parser may reject the file earlier, in which case `NtCreateSection` returns `STATUS_INVALID_IMAGE_NOT_MZ` 0xC000012F or similar).
   - **Workaround**: Validate the PE header in the operator harness before calling ghost.

7. **Masquerade path doesn't exist on disk**
   - **Scenario**: `masquerade_path = "C:\\Windows\\System32\\svchost.exe"` is set as ImagePathName, but the actual file doesn't exist (e.g., stripped Windows build).
   - **Failure path**: No immediate failure — `RtlCreateProcessParametersEx` doesn't verify the path. But the loader inside the ghosted process will fail to resolve imports if the payload expects them at a different base.
   - **Symptom**: Ghosted process crashes on `LdrInitializeThunk` with `STATUS_DLL_NOT_FOUND`.
   - **Workaround**: Pick a masquerade path that exists on the target host. Use `find_pid_by_name` to enumerate real running processes and pick one whose path is verifiable.

## OPSEC Notes

### Artifacts left
- **`NtCreateProcessEx` ETW event** (Microsoft-Windows-Kernel-Process). No `CreateProcessW`/`RtlCreateUserProcess` event. EDR that correlates these two will see a process born with no preceding Win32 API — immediate red flag.
- **Section object with no backing file path** (post-step-6). Querying `NtQueryInformationSection(SectionImageInformation)` succeeds and returns the PE info, but `NtQueryInformationFile` on the (now-deleted) source returns `STATUS_INVALID_HANDLE`.
- **Temp file briefly visible in directory enumeration**: between step 1 (`GetTempFileNameA`) and step 3 (`NtSetInformationFile` delete-pending), the file is visible in `FindFirstFile`/`FindNextFile` enumeration. This is a ~1ms window but filesystem filters may snapshot it.
- **`NtCreateThreadEx` on the EP** (step 14): the thread's `StartAddress` is the payload's EP, not a loader thunk. Visible via `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`.
- **PPID handle leak if `OpenProcess` succeeds and `parent_handle` is later overwritten** — actually the crowd version correctly routes through `crate::recycled::nt_close(parent_handle)` at L184. No leak.
- **`stderr` debug output** in `#[cfg(debug_assertions)]` build at L134, L137, L381 — never ship a debug build.

### Cleanup performed
- File handle closed at `crowd/src/ghost.rs:223` immediately after `NtCreateSection` — file vanishes.
- Section handle closed at L184 after `NtCreateProcessEx` — no leak.
- Parent handle closed via `crate::recycled::nt_close(parent_handle)` at L184 — no leak.
- Thread + process handles closed at L377-L378 — spawner retains no handles into the ghost.
- Environment block destroyed via `DestroyEnvironmentBlock(env_block)` at every failure exit in `crowd/src/ghost.rs:setup_process_parameters` and via `EnvGuard` RAII in experimental version.

### Telemetry mitigations
- Routing `nt_close` / `nt_allocate_virtual_memory` / `nt_write_virtual_memory` through `crate::recycled::*` (T-001) ensures the call stack originates from a `MEM_IMAGE` ntdll gadget — defeats stack-trace-based ETW-TI rules.
- PPID spoofing inside the same `NtCreateProcessEx` call (vs. a separate `NtSetInformationProcess(ProcessParent)`) means there's no intermediate process with the wrong parent.
- Masquerade path in `RTL_USER_PROCESS_PARAMETERS` makes `Process Explorer`, `tasklist`, and EDR UI display the ghost as `svchost.exe` (or whatever operator chose).

### Telemetry gaps
- `NtCreateProcessEx` itself is not suppressed — would need T-016 ETW muffling (`crowd/src/etw.rs`) for full cover.
- The `NtCreateThreadEx` start address is the EP, not a loader thunk — visible to `ThreadQuerySetWin32StartAddress` queries.

## Reusable Patterns

### Pattern: VA-hint allocation for pointer relocation shortcut
- **Use when**: You need to copy a self-referential structure (with internal pointers) from your process into a remote process at the *same* virtual address, so embedded pointers stay valid without relocation.
- **Code ref**: `crowd/src/ghost.rs:setup_process_parameters` L295-L302
- **How**: Pass the local pointer as the `BaseAddress` hint to `NtAllocateVirtualMemory` (here via `crate::recycled::nt_allocate_virtual_memory`). The kernel attempts to map at that exact VA in the remote process. Verify `remote_addr == hint` after the call — if not, the bet failed and you must fall back to full relocation. **Caveat**: This is fragile under ASLR. The experimental version (`process_ghosting.rs:Ghosting::params` L295-L327) shows the correct alternative: let the kernel pick the base, then walk every embedded pointer and fix it up via a relocation closure.

### Pattern: Field-offset computation without dereferencing remote pointers
- **Use when**: You need to compute the address of a field in a structure that lives in a *remote* process — you have a remote base pointer but cannot safely dereference it locally.
- **Code ref**: `crowd/src/ghost.rs:setup_process_parameters` L309-L312 and `process_ghosting.rs:Ghosting::params` L408-L410
- **How**: Cast the remote base to a `*const T` (without dereferencing), use `addr_of!((*ptr).Field) as usize - ptr as usize` (Rust std pattern) or `offset_of!(T, Field)` (nightly / `memoffset` crate) to compute the byte offset, then add the offset to the remote base address. This is safe because no actual memory access happens — only pointer arithmetic. Used here to compute `PEB.ProcessParameters` VA in the ghosted process.

### Pattern: RAII guard for kernel-allocated environment blobs
- **Use when**: Calling `CreateEnvironmentBlock` (or any Win32 allocator that requires a matching `Destroy*` call) where you might early-return on error.
- **Code ref**: `process_ghosting.rs:EnvGuard` (anonymous struct in `Ghosting::params` L279-L289)
- **How**: Declare a local struct wrapping the raw pointer, implement `Drop` to call `DestroyEnvironmentBlock` if non-null. Bind a local variable of this type immediately after the allocating call. Every `?` early-return triggers the drop, which cleans up. The crowd version (`ghost.rs:setup_process_parameters`) does this manually at every error site — error-prone; the RAII pattern is strictly better.

### Pattern: Relocation closure for remote structure fixup
- **Use when**: You've allocated a structure in a remote process at a kernel-chosen VA (not a hint), and the structure contains internal pointers that must be adjusted to point inside the new allocation.
- **Code ref**: `process_ghosting.rs:Ghosting::params` L312-L322 (`relocate_ptr` and `relocate_unicode` closures)
- **How**: Capture `local_base` and `span_end` (the bounds of the local buffer). Define `relocate_ptr(ptr)` that returns `remote_base + (ptr - local_base)` if `ptr` is in `[local_base, span_end)`, else `ptr` unchanged (pointers to non-relocated data like DLL paths stay absolute). Then iterate every embedded pointer field — for `UNICODE_STRING` fields, mutate `.Buffer`; for raw pointers, mutate the pointer directly. Snapshot the local buffer into a `Vec<u8>`, apply relocations to the snapshot, then write the snapshot remotely in one `NtWriteVirtualMemory` call. The experimental version lists all 10 `UNICODE_STRING` fields plus 3 raw pointers plus the `CurrentDirectories[32]` array — comprehensive coverage is essential.

### Pattern: Syscall routing split — local state queries via ntapi, remote state mutations via RecycledGate
- **Use when**: You're doing a mix of local-handle syscalls (read your own PEB) and remote-handle syscalls (write into another process) and want maximum stealth on the high-risk operations.
- **Code ref**: `crowd/src/ghost.rs:spawn_ghosted` (entire function)
- **How**: Use `ntapi::*` directly for syscalls that only touch your own process (`NtCurrentPeb`, `NtQueryInformationProcess(self)`). Route through `crate::recycled::*` (T-001 RecycledGate) for syscalls that mutate a remote process (`nt_allocate_virtual_memory`, `nt_write_virtual_memory`, `nt_close` on remote handles). The split reflects telemetry risk: remote mutations are what EDR cares about; local queries are noise.

### Pattern: PPID auto-acquisition via toolhelp snapshot
- **Use when**: You want to inject as a child of a named process (e.g., `explorer.exe`) without hardcoding a PID.
- **Code ref**: `crowd/src/ghost.rs:find_pid_by_name` L386-L415
- **How**: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32First`/`Process32Next` walk. Match `szExeFile` case-insensitively. Return the first match's `th32ProcessID`. Close the snapshot via `crate::recycled::nt_close` to avoid the `NtClose` ETW event from ntdll-direct. Use as `spawn_ghosted(payload, "C:\\Windows\\System32\\svchost.exe", find_pid_by_name("explorer.exe").unwrap_or(0))`.
