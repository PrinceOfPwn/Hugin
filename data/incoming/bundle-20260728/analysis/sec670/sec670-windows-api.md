---
id: RTO-winapi-foundations
name: Windows API Foundations
source: Red Team Ops / SANS SEC670
category: winapi
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-014, T-015, T-013, T-007, T-016, T-004]
tags: [win32-api, createprocess, handles, error-handling, process-enumeration, windows-internals, foundational]
---

# Windows API Foundations — Training Reference

## TL;DR
SEC670's "Windows API" module is foundational Win32 plumbing: `CreateProcessW`, `CreateToolhelp32Snapshot`, the object/handle model, and error-handling idioms (`GetLastError`/`FormatMessage`, HRESULT/LSTATUS/BOOL/HANDLE conventions). For an operator already working with the vault's syscall gates and injection suite, this material is **prerequisite context** — it documents the *legitimate* API surface that vault techniques (T-014 NtCreateUserProcess, T-007 injection suite, T-016 handle blocking) deliberately route around or manipulate. Read it as the substrate, not the tradecraft.

## Key Concepts

1. **CreateProcessW — the Win32 process creation façade**
   Nine parameters; BOOL return is misleading because the kernel returns as soon as the primary thread is created — real success/failure is in `lpProcessInformation` (hProcess/hThread/dwProcessId/dwThreadId). `lpApplicationName` does not use the search path and requires an extension; `lpCommandLine` (LPWSTR, mutable — must live in RW memory, not const segment) auto-appends `.exe` and triggers DLL-style search order: (1) calling exe dir, (2) CWD, (3) `GetSystemDirectory`, (4) `GetWindowsDirectory`, (5) `%PATH%`. `dwCreationFlags` supports `CREATE_SUSPENDED` (used by classical process hollowing and Early Bird APC injection). The vault's T-014 NtCreateUserProcess bypasses this entire wrapper and goes straight to the syscall, avoiding kernel32!CreateProcessW telemetry hooks entirely.

2. **STARTUPINFOEX is the bridge to PPID spoofing and attribute lists**
   The training notes that `lpStartupInfo` accepts either `STARTUPINFO` or `STARTUPINFOEX` (the extended form). This is the exact structure the vault's T-015 PPID Spoofing extends with `InitializeProcThreadAttributeList` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. The training mentions the structure but never operationalizes attribute lists — that is left to the vault.

3. **CreateToolhelp32Snapshot — process enumeration**
   `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` returns a snapshot handle; iterate with `Process32First` / `Process32Next` against a `PROCESSENTRY32` (must set `dwSize = sizeof(PROCESSENTRY32)` first). The same API also snapshots heaps, threads, and loaded modules (relevant for module-stomping detection and PEB-walk-free enumeration). The vault's T-004 PEB Walker deliberately does *not* use this API — it walks `gs:[0x60]` → PEB → Ldr → InLoadOrderModuleList to avoid the snapshot API and its ETW/EDR telemetry.

4. **Windows Object Manager — kernel/executive/user objects**
   Objects (process, thread, section, token, mutex, key, desktop, ~4000+ types) are kernel data structures wrapped in a uniform object header (type, name, directory, security descriptor, handle count) + a type-specific body. The object manager does access checks against security descriptors when handles are requested. Understanding this matters because:
   - The vault's T-016 EDR Evasion Suite includes `block_handle` — denying external handle access to your process object — which is literally denying the object manager's `OpenProcess` walk.
   - The vault's T-007 injection suite manipulates thread/process/section objects directly via NT syscalls, skipping the Win32 wrapper that calls the object manager through user-mode intermediaries.

5. **Handle tables — multi-level, per-process**
   Each process has its own opaque handle table (lowest level created at init, additional levels allocated on demand up to ~16M entries). Handle value is an index; on x86 each entry is 8 bytes (32-bit pointer + 32-bit access mask + lock/inheritable/audit/protect-from-close bits); on x64 it's 12 bytes (64-bit pointer + 32-bit access). Handle values are always multiples of 4 (first valid = 4, never 0). `NtSetInformationObject` can set the `protect from close` flag. `GetCurrentProcess()`/`GetCurrentThread()` return pseudo-handles `(HANDLE)-1` / `(HANDLE)-2` — the kernel grants `PROCESS_ALL_ACCESS` / `THREAD_ALL_ACCESS` after internal checks.

6. **Access rights as the OPSEC lever**
   `PROCESS_ALL_ACCESS` / `THREAD_ALL_ACCESS` / `PROCESS_CREATE_PROCESS` / `PROCESS_CREATE_THREAD` / `PROCESS_DUP_HANDLE` flag the access mask handed back with a handle. The training explicitly warns: calling `OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId())` from a SYSTEM service creates an inheritable, fully-permissive handle — the kind of bug James Forshaw weaponizes. The basic `CreateRemoteThread` example on slide 175 (`VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`) is the canonical "bad OPSEC" pattern the entire vault's injection suite (T-007, T-008 Threadless, T-007 Pool Party, T-012 Early Cascade) exists to replace.

7. **Error return-type taxonomy — pick the right check**
   - **BOOL** (0/non-0): `GetLastError()` immediately after — any intervening call clobbers it.
   - **HANDLE**: `NULL` or `INVALID_HANDLE_VALUE (-1)` depending on API (CreateFile returns INVALID_HANDLE_VALUE; CreateThread returns NULL).
   - **HRESULT**: `< 0` = failure, `>= 0` = success; use `SUCCEEDED()` / `FAILED()` macros. 32-bit layout: severity(1) + reserved(3) + facility(11) + code(16). Use `HRESULT_FACILITY()` / `HRESULT_SEVERITY()` for field extraction.
   - **LSTATUS**: returns the error code itself; check `!= ERROR_SUCCESS (0)`. Used by all `Reg*` APIs.

8. **GetLastError + FormatMessage — error stringification**
   `GetLastError()` must be called immediately — last-error is per-thread and overwritten by any subsequent Win32 call. `FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ErrorCode, 0, (LPSTR)&messageBuffer, 0, NULL)` returns a system message string; caller must `LocalFree(messageBuffer)`. The `IGNORE_INSERTS` flag is *mandatory* for system lookups or the function fails with `ERROR_INVALID_PARAMETER (87)` because system messages contain `%1`-style insertions and the caller provides none.

## Operational Techniques

### CreateProcessW with CREATE_SUSPENDED (textbook hollowing prep)
- **What**: Spin up a process with its primary thread suspended, ready for hollowing/APC injection.
- **When to use**: Never, on a modern engagement — this is the *detection signature* EDRs were built to catch. Included here for context only.
- **How**:
  1. `STARTUPINFO si = { sizeof(si) }; PROCESS_INFORMATION pi;`
  2. `CreateProcessW(NULL, L"notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)`
  3. Use `pi.hProcess` / `pi.hThread` for downstream injection primitives.
  4. `CloseHandle(pi.hThread); CloseHandle(pi.hProcess)` when done.
- **Vault link**: T-014 NtCreateUserProcess — go straight to `NtCreateProcessEx` / `NtCreateUserProcess` via indirect syscall (T-001 RecycledGate) and skip kernel32 entirely. The vault's hollowing adapter lives in `dark_crystal/framework/adapters/deferred/process_hollowing/`. The `CREATE_SUSPENDED` + `CreateRemoteThread` pattern is the *baseline* T-013 Remaining Injection enumerates and immediately supersedes.
- **Tool/code**: `kernel32!CreateProcessW`, `CREATE_SUSPENDED (0x4)`
- **OPSEC**: HIGH detection risk. `CREATE_SUSPENDED` + cross-process `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` is one of the most heavily fingerprinted call sequences in EDR rule sets. Use only for lab verification.

### CreateToolhelp32Snapshot Process Walking
- **What**: Enumerate running processes by name/PID without touching the PEB.
- **When to use**: Reconnaissance where EDR density is low or where PEB-walk semantics are too brittle (e.g., manipulating a foreign process whose PEB layout you can't directly read).
- **How**:
  1. `HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);`
  2. `PROCESSENTRY32 pe = { sizeof(pe) };`
  3. `if (Process32First(snap, &pe)) do { /* pe.szExeFile, pe.th32ProcessID */ } while (Process32Next(snap, &pe));`
  4. `CloseHandle(snap);`
- **Vault link**: T-004 PEB Walker is the OPSEC alternative — self-only enumeration via `gs:[0x60]` → PEB → Ldr lists, no API call, no ETW provider hit. The training's snapshot API is appropriate for foreign-process enumeration (PEB walker can't enumerate other processes), so they complement each other.
- **Tool/code**: `kernel32!CreateToolhelp32Snapshot`, `TH32CS_SNAPPROCESS (0x2)`, `Process32First/Next`, `PROCESSENTRY32` (`tlhelp32.h`)
- **OPSEC**: Snapshot creation is a documented ETW event source. EDRs see the snapshot+iterate pattern routinely used by lolbins and recon tooling. Use only when the snapshot is plausible cover traffic.

### Handle Leak Detection (defensive / sanity check)
- **What**: Identify leaked handles in your own implant before an analyst does.
- **When to use**: Pre-release implant QA; hunting for handle-leak primitives in target processes (token theft, DLL hijacking via leaked file handles).
- **How**: Sysinternals `handle.exe -p <pid>` or Process Explorer's lower pane (View → Lower Pane View, then File → Handle).
- **Vault link**: T-016 EDR Evasion Suite — `block_handle` is the offensive flip side: deny external `OpenProcess`/`NtOpenProcess` so that *analysts running handle.exe* against your implant get `Access denied`. The training treats handle-leak hunting as defensive; the vault weaponizes the same mechanism as evasion.
- **Tool/code**: `handle.exe -p <pid>`, Process Explorer, `NtQuerySystemInformation(SystemHandleInformation)`
- **OPSEC**: `handle.exe` itself is on most EDR watchlists. Run from a host you control, not the target.

### HRESULT Field Extraction
- **What**: Pull the facility code out of an HRESULT for branching error logic.
- **When to use**: COM-heavy code paths (T-023 client capabilities — `html_overlay.rs` WebView2 returns HRESULTs); Windows Update / WUAUCLT-related persistence chains; COM hijack persistence.
- **How**:
  ```c
  if (FAILED(hr)) {
      DWORD facility = HRESULT_FACILITY(hr);
      DWORD severity = HRESULT_SEVERITY(hr);
      // branch on facility (FACILITY_WIN32=7, FACILITY_ITF=4, etc.)
  }
  ```
- **Vault link**: No direct vault card — the vault is overwhelmingly NT-status-driven (`NTSTATUS` not `HRESULT`). T-017 Five-Layer Persistence uses COM hijack, which sits on top of HRESULT-returning `CoCreateInstance` plumbing. The training's HRESULT taxonomy is the foundation for understanding why `CoCreateInstance` failures in COM hijack chains must be checked with `FAILED()` not `!= S_OK`.
- **Tool/code**: `SUCCEEDED()` / `FAILED()` / `HRESULT_FACILITY()` / `HRESULT_SEVERITY()` (all in `winerror.h`)
- **OPSEC**: None — pure diagnostic idiom.

### FormatMessage Error Lookup Helper
- **What**: Convert `GetLastError()` codes into human-readable strings.
- **When to use**: Debug builds of the implant; operator-facing error logging (encrypted/log-file-only, never stdout on target).
- **How**:
  ```c
  LPSTR msg = NULL;
  FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, GetLastError(), 0, (LPSTR)&msg, 0, NULL);
  if (msg) { /* log msg */ LocalFree(msg); }
  ```
- **Vault link**: No direct card. The training's Lab 1.7 "Can'tHandleIt" (build a custom error lookup function) is exactly the helper that should sit in front of every NT-status-to-HRESULT conversion in the vault's `wrappers.rs`. T-021 Crypto & Obfuscation's build-time string obfuscation proc macro should be applied to any error messages emitted by this helper to keep strings out of static signatures.
- **Tool/code**: `kernel32!FormatMessageA/W`, `FORMAT_MESSAGE_ALLOCATE_BUFFER (0x100)`, `FORMAT_MESSAGE_FROM_SYSTEM (0x1000)`, `FORMAT_MESSAGE_IGNORE_INSERTS (0x200)`, `LocalFree` to release the buffer.
- **OPSEC**: Error strings in your binary are static signatures. If implementing this in an implant, obfuscate the format-string lookup paths and never write the resolved message to stdout or to an unencrypted log file.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `CreateProcessW` | Standard Win32 process creation | Hooked by every EDR; use T-014 NtCreateUserProcess instead |
| `CREATE_SUSPENDED (0x4)` flag | Pre-hollowing / APC-ready suspended process | Heavily fingerprinted in combination with cross-process memory writes |
| `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` | Process enumeration | ETW-visible; use PEB walker (T-004) for self-process only |
| `Process32First` / `Process32Next` | Iterate snapshot | Use `PROCESSENTRY32`, set `dwSize` first |
| `PROCESS_INFORMATION` struct | Read hProcess/hThread/PID/TID | Always `CloseHandle` both handles |
| `OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid)` | Full access to target process | **Anti-pattern** — flagged by `block_handle` (T-016); inheritable handle leaks are exploit primitives |
| `GetCurrentProcess()` / `GetCurrentThread()` | Pseudo-handles `(HANDLE)-1` / `-2` | Kernel grants `*_ALL_ACCESS` internally |
| `GetLastError()` | Per-thread last error | MUST be called immediately after the failing API; any intervening Win32 call overwrites |
| `FormatMessageA(...ALLOCATE_BUFFER \| FROM_SYSTEM \| IGNORE_INSERTS...)` | Stringify error code | `IGNORE_INSERTS` is mandatory for system lookups; `LocalFree` the returned buffer |
| `SUCCEEDED(hr)` / `FAILED(hr)` | HRESULT branch macros | `>= 0` = success, `< 0` = failure |
| `HRESULT_FACILITY(hr)` / `HRESULT_SEVERITY(hr)` | Field extraction | Use for COM/WUA error branching |
| `LSTATUS` (`Reg*` APIs) | Returns error directly | Compare `!= ERROR_SUCCESS (0)` |
| `NtSetInformationObject` | Set `protect from close` flag on handle | Useful for handle-persistence primitives |
| `handle.exe -p <pid>` | Sysinternals CLI handle dump | Watchlisted binary; run from your own host |
| Process Explorer (Sysinternals) | GUI handle/object inspection | Same caveat; good for pre-engagement dev box |
| WinDbg Preview + kernel debug | Inspect object headers, handle tables | Lab 1.9 — kernel-mode debugging required to read `ObTypeIndexTable` |

## Gaps & Extensions

**What the vault covers that this training does not:**

- **Indirect syscalls / SSN resolution** (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate, T-006 Phantom Stubs): the training presents `CreateProcessW` as the API surface; the vault never calls `CreateProcessW` and goes straight to `NtCreateUserProcess` via a recycled `ntdll` gadget.
- **PPID spoofing** (T-015): the training shows `STARTUPINFOEX` exists but never mentions `PROC_THREAD_ATTRIBUTE_LIST` or parent-process attribute injection.
- **Modern injection suite** (T-007 Pool Party, T-008 Threadless, T-009 Process Ghosting, T-010 Herpaderping, T-011 Dirty Vanity, T-012 Early Cascade, T-013 eleven other methods): the training's only injection example is the textbook `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` three-liner from slide 175 — the exact pattern every vault technique exists to replace.
- **Handle blocking** (T-016 `block_handle`): the training treats handle security as a defensive concern (don't leak, don't over-permission). The vault treats the same object-manager ACLs as an offensive surface to *tighten* on your own process.
- **Sleep obfuscation** (T-005 Ekko ROP): not mentioned — the training's process model has no concept of encrypting an implant in memory between beacons.
- **PEB walking / DJB2 API resolution** (T-004): the training relies on Win32 dynamic linking throughout; the vault resolves every NT API by walking the PEB and hashing with DJB2.
- **Argument spoofing** (T-016): the training's note that `lpCommandLine` is `LPWSTR` (mutable, RW memory) is the *enabling observation* for argument-spoofing techniques, but the training never operationalizes it.

**What this training covers that the vault does not:**

- **Object-manager theory**: the 4000+ object types, object header/body split, `ObTypeIndexTable`, security-descriptor-mediated access — this is Windows Internals textbook material that the vault assumes you already know. Useful as a primer before reading T-016 `block_handle` or T-007 thread/process object manipulation.
- **Handle table internals**: multi-level table structure, entry sizes (x86 = 8 bytes, x64 = 12 bytes), `protect from close` flag set via `NtSetInformationObject` — the vault uses these facts implicitly but never documents them. Worth knowing for handle-table-walking primitives used in token theft and `NtQuerySystemInformation(SystemHandleInformation)` recon.
- **HRESULT field layout**: the 32-bit severity/reserved/facility/code breakdown — the vault is NTSTATUS-driven, but client-side COM (WebView2 HTML overlay in T-023, COM hijack in T-017) returns HRESULTs and the vault never explains how to interpret them.
- **FormatMessage error stringification**: the vault's `wrappers.rs` and `dark_crystal/crates/core/src/wrappers.rs` translate NTSTATUS values but don't expose a stringification helper. The training's Lab 1.7 "Can'tHandleIt" is exactly the missing piece — a one-arg helper that turns an error code into a localized message string. Recommended as an addition to the vault's operator-debug logging path.
- **Registry walker pattern** (Lab 1.8 RegWalker): the training builds a recursive `Reg*`-API walker; the vault's T-017 persistence suite uses COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — none of which include a generic recursive registry walker. Useful for COM-hijack target discovery (the `HKCU\Software\Classes\CLSID\{...}\InprocServer32` enumeration prerequisite).

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| `CreateProcessW` 9-parameter façade | T-014 NtCreateUserProcess | Vault bypasses the wrapper; same underlying object creation but skips kernel32/ntdll user-mode hooks |
| `CREATE_SUSPENDED` + hollowing prep | T-013 Remaining Injection (Hollowing), T-012 Early Cascade | Training shows the textbook entry point; vault's Early Cascade hijacks pre-`LdrInitializeThunk` APC flow instead |
| `STARTUPINFOEX` extension | T-015 PPID Spoofing | Training notes the structure exists; vault extends it with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` |
| `CreateRemoteThread` basic injection | T-007 Pool Party, T-008 Threadless, T-012 Early Cascade, T-013 suite | Vault's entire injection suite is a replacement strategy for this OPSEC-broken pattern |
| `CreateToolhelp32Snapshot` enumeration | T-004 PEB Walker | Complementary: training's API for foreign-process enum; vault's PEB walk for self-process enum |
| Object manager + handle table model | T-016 EDR Evasion (`block_handle`) | Training explains the substrate (security descriptors, access masks); vault weaponizes it by tightening ACLs on the implant's own objects |
| `OpenProcess(PROCESS_ALL_ACCESS)` warning | T-016 `block_handle`, T-015 PPID Spoofing | Training flags this as a defensive anti-pattern; vault's `block_handle` denies exactly these calls against your implant |
| `PROCESS_DUP_HANDLE` access right | T-016 `block_handle`, T-011 Dirty Vanity | Dirty Vanity uses process reflection (RtlCloneUserProcess) which duplicates handles — training's access-right table is the prerequisite |
| `NtSetInformationObject` `protect from close` | (no direct vault card) | Training-only — operator should know this primitive exists for handle-persistence corner cases |
| `GetLastError` + `FormatMessage` pattern | (no direct vault card; relevant to `wrappers.rs` NTSTATUS translation) | Training covers Win32 error model; vault uses NTSTATUS — the *stringification* idiom is portable |
| HRESULT `SUCCEEDED`/`FAILED` macros | T-017 COM Hijack persistence, T-023 HTML overlay (WebView2) | Training covers the COM error model; vault's COM-touching modules consume HRESULTs without explaining the macros |
| Process handle lifecycle (`CloseHandle`) | T-016 handle blocking (offensive) | Training teaches defensive handle hygiene; vault teaches offensive handle denial — same object, opposite polarity |
| `PROCESSENTRY32` iteration | T-023 `byakugan.rs` (network recon) | Vault's recon module enumerates network/host state; the snapshot iteration is the prerequisite pattern for any PID-by-name lookup |
| Lab 1.8 RegWalker (recursive registry walk) | T-017 `com_hijack.rs` (COM hijack persistence) | RegWalker is the discovery primitive that identifies COM CLSIDs vulnerable to hijack — vault assumes you can find them, doesn't ship a walker |

---

*Operator note: this is foundational material. If you are deploying vault techniques (T-001 through T-023) you should already know everything in this module cold — the vault's threat model assumes you understand object/handle semantics, error return conventions, and the standard Win32 surface it is bypassing. If any concept above is unfamiliar, pause and internalize it before reading T-014, T-016, or T-007 in depth.*