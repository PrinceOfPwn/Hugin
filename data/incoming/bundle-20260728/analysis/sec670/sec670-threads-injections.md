---
id: RTO-sec670-threads-injections
name: SEC670 — Threads & Process Injection Foundations
source: Red Team Ops / SANS SEC670
category: process-injection
analyzed_by: glm-5.2
analysis_date: 2026-07-21
vault_references: [T-007, T-008, T-009, T-010, T-011, T-012, T-013, T-014, T-015, T-016, T-017, T-018, T-021, T-023]
tags: [process-injection, threads, apc, token-manipulation, uac, privilege-escalation, winapi, pe-format, secdbg-privilege, integrity-levels, classic-dll-injection, process-hollowing, thread-hijacking, setwindowshookex, pe-injection]
---

# SEC670 — Threads & Process Injection Foundations — Training Reference

## TL;DR
SEC670 Section 3 ("Windows Tool Development") teaches the foundational injection primitives — `CreateRemoteThread`, `QueueUserAPC`, `GetThreadContext`/`SetThreadContext`, suspended-process hollowing, manual PE mapping with `.reloc` fixups, and `SetWindowsHookEx`. The material also covers Windows privilege/integrity-level theory and the `LookupPrivilegeValue` → `OpenProcessToken` → `AdjustTokenPrivileges` triad. Operationally, every technique in this module is the *pedagogical ancestor* of a more advanced vault technique — these are the "Teaching implementations" that the vault's T-007 through T-013 supersede with sleep-obfuscation-aware, EDR-evasion-hardened variants. Use this module as a primer for understanding the primitives that the vault chains together; do not field these classic implementations against modern EDR.

## Key Concepts

1. **Thread object topology (ETHREAD / KTHREAD / TEB)**
   - `ETHREAD` and `KTHREAD` live in system (kernel) address space; only the `TEB` resides in user-mode process address space.
   - The `TEB`'s first field is `_NT_TIB` (StackBase, StackLimit, ExceptionList — SEH chain). The `TEB` also holds a pointer to the PEB.
   - Inspector: `dt nt!_ethread`, `dt nt!_kthread`, `dt nt!_teb` in WinDbg. Cross-ref: vault's T-004 PEB Walker uses `gs:[0x60]` to reach the PEB through the TEB — same data structure, far more aggressive use.

2. **CreateThread / CreateRemoteThread dispatch path**
   - Both wrap `CreateRemoteThreadEx` → `NtCreateThreadEx` → `PspCreateThread`. Parameters are converted to flags; a Client ID and TEB address are attached via attribute list.
   - Even local `CreateThread` routes through the remote-capable path; the handle value disambiguates local vs. remote.
   - The new thread is initially suspended by `PspCreateThread` and resumed once context initialization completes.

3. **APC mechanism (alertable-wait dispatch)**
   - Each thread has its own APC queue. When a thread enters its quantum, the kernel checks the queue and dispatches queued APCs.
   - APCs only fire when the thread is in an alertable wait state. This is the basis for Early Bird APC (vault T-013) and Early Cascade (vault T-012) — both of which queue an APC *before* the thread ever becomes alertable via `LdrInitializeThunk`, evading user-mode hooks placed later.

4. **Thread context structure (`CONTEXT`)**
   - 64-bit `CONTEXT` captures all GPRs (Rax–R15), Rip, Rsp, Rbp, segment regs, Dr0–Dr7 (debug registers), EFlags, and `LastExceptionTo/FromRip`.
   - Thread hijacking mutates `Rip` after `SuspendThread` + `GetThreadContext`. The vault's WaitingThread variant (T-013) does the same on a thread already in a wait state to avoid the suspend-detected-by-EDR signal.

5. **PE Image layout and `.reloc` fixups**
   - `SizeOfImage` (Optional Header) determines the allocation size for an injected PE.
   - Manual mapping requires computing the delta between `VirtualAllocEx` return address and the PE's preferred `ImageBase`, then walking the `.reloc` table applying `IMAGE_REL_BASED_DIR64` offsets.
   - The vault's `pe.rs` / `pe_loader.rs` (T-013 PE Loader, T-007 Module Stomp) implement this exact relocation walk with reflective loader semantics.

6. **Securable objects, security descriptors, and the `SECURITY_ATTRIBUTES` parameter**
   - All `Create*` family APIs accept a `SECURITY_ATTRIBUTES*`. NULL ⇒ default DACL.
   - Access denied materializes as `0xC0000005` (STATUS_ACCESS_VIOLATION) at the call site. Note: `OpenProcess` failures return 0 (NULL handle) with `GetLastError() == ERROR_ACCESS_DENIED (5)` — the slide's 0xC0000005 reference is loose.

7. **Access tokens (primary vs. impersonation)**
   - A primary token is tied to the user at logon; an impersonation token is materialized when a server thread impersonates a client (e.g., for `RpcImpersonateClient` flows).
   - The `TOKEN_PRIVILEGES.Privileges[]` array holds `LUID_AND_ATTRIBUTES` entries. `LUID` is 64-bit (DWORD LowPart + LONG HighPart), unique per boot. `Attributes` is a 32-bit flag mask.

8. **Integrity levels (IL)**
   - Six levels: Untrusted (0), Low (1, AppContainer/UWP), Medium (2, default UAC), High (3, elevated), System (4, lsass/wininit/winlogon), Protected (5, kernel-set only).
   - Low-IL cannot write most objects (registry keys, files in user profile). High-IL is where UAC consent prompts fire.

9. **ACL-bypass privileges**
   - `SeBackupPrivilege` ⇒ read any file regardless of DACL (FILE_GENERIC_READ).
   - `SeRestorePrivilege` ⇒ write any file regardless of DACL (FILE_GENERIC_WRITE).
   - `SeTakeOwnershipPrivilege` ⇒ take ownership of any securable object, including protective-process objects.
   - `SeDebugPrivilege` ⇒ open handles to processes across users; *cannot* open *Protected* processes (PPL).

10. **Privilege escalation primitives**
    - `SeLoadDriverPrivilege` → load kernel drivers (vault T-018 BYOVD pipeline).
    - `SeTcbPrivilege` → trusted computing base equivalence.
    - `SeCreateTokenPrivilege` → mint arbitrary user tokens.
    - All of these are absent from a standard user token; they only appear after UAC bypass (vault T-021) or kernel compromise.

## Operational Techniques

### Classic DLL Injection
- **What**: Force `LoadLibraryA` to run in a remote process via `CreateRemoteThread`.
- **When to use**: Legacy/training engagements, non-hardened hosts, or as a baseline to compare detection telemetry.
- **How**:
  1. `OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)` against target (e.g., `notepad.exe`).
  2. `VirtualAllocEx(hProc, NULL, sizeof(path), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`.
  3. `WriteProcessMemory(hProc, pBuffer, "C:\\evil.dll", ...)` — full path required.
  4. `CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pBuffer, 0, NULL)`.
- **Vault link**: T-013 Remaining Methods (Classic DLL Injection section). The vault lists this under "T-013" as a baseline method but the framework's `executor` template (`shellcode_execution/ntapi_shellcode/template.rs`) is preferred — it uses `NtCreateThreadEx` via indirect syscalls (T-001/T-002) rather than kernel32 `CreateRemoteThread`, which is heavily hooked by every modern EDR. **Do not field classic CRT against EDR-protected hosts.**
- **Tool/code**: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `LoadLibraryA` (resolved via `GetModuleHandleA("kernel32.dll")` + `GetProcAddress`).
- **OPSEC**: Catastrophic telemetry — `CreateRemoteThread` fires ETW TI (`Microsoft-Windows-Kernel-Process` event 3) and is caught by every EDR. Also leaves the DLL on disk at a known path. Mitigations: switch to T-007 Pool Party (thread-pool-based, no remote thread) or T-008 Threadless (export-hijack, no thread creation at all).

### APC Injection
- **What**: Queue `LoadLibraryA` as an APC to one or more threads in a target process.
- **When to use**: When you need the APC mechanism as a stepping-stone to Early Bird / Early Cascade.
- **How**:
  1. `OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION, FALSE, pid)`.
  2. `VirtualAllocEx` + `WriteProcessMemory` (DLL path).
  3. `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` — enumerate threads by `th32OwnerProcessID`.
  4. For each thread: `OpenThread(THREAD_SET_CONTEXT, FALSE, tid)` then `QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)pBuffer)`.
  5. Wait for one of the threads to enter an alertable wait (`WaitForSingleObjectEx`, `SleepEx`, etc.) — APC dispatches.
- **Vault link**: T-013 Early Bird APC variant and **T-012 Early Cascade**. The vault's Early Cascade queues an APC to a thread *before* it ever reaches `LdrInitializeThunk`, sidestepping the alertable-wait requirement entirely and executing before any EDR hook in `kernel32`/`ntdll` user-mode stubs has been initialized for the new process. SEC670's variant is strictly inferior for EDR'd hosts but useful for understanding the queueing primitive.
- **Tool/code**: `QueueUserAPC` (processthreadsapi.h), `CreateToolhelp32Snapshot` + `Thread32First`/`Thread32Next`, `THREAD_SET_CONTEXT` access right.
- **OPSEC**: `QueueUserAPC` itself is moderately noisy (ETW `Microsoft-Windows-Kernel-APC`), and threads must be in alertable state — risky if the target process has no thread currently in `SleepEx`/`WaitForSingleObjectEx`. Mitigation: pre-stage the target (pick `explorer.exe` which always has threads in alertable wait) or upgrade to Early Bird on a `CREATE_SUSPENDED` process.

### Thread Hijacking
- **What**: Suspend a target thread, rewrite its `CONTEXT.Rip` to point at your shellcode, then resume.
- **When to use**: When you cannot create a new thread (Block-Windows-Thread-Creation policy, ETW CRT alerting) but can borrow one.
- **How**:
  1. `OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME, FALSE, tid)`.
  2. `SuspendThread(hThread)` — wait for actual suspension (`WaitForSingleObject` with the thread handle is *not* reliable; check via `NtQueryInformationThread(ThreadSuspendCount)`).
  3. `CONTEXT ctx; ctx.ContextFlags = CONTEXT_CONTROL; GetThreadContext(hThread, &ctx);`
  4. `ctx.Rip = (DWORD64)pShellcode; SetThreadContext(hThread, &ctx);`
  5. `ResumeThread(hThread)`.
- **Vault link**: T-013 WaitingThread hijack (the vault's variant picks a thread already in a wait state, avoiding the suspend that EDRs alert on), and T-012 Early Cascade (which performs a "context rewrite" by APC rather than `SetThreadContext`, even stealthier). SEC670's variant is the canonical baseline; the vault's adds EDR-evasion by either skipping the suspend or moving the rewrite earlier in process initialization.
- **Tool/code**: `SuspendThread`, `GetThreadContext`/`SetThreadContext`, `CONTEXT.ContextFlags = CONTEXT_CONTROL`, `ResumeThread`.
- **OPSEC**: `SuspendThread` against an unrelated process thread fires ETW TI and produces a detectable scheduling gap. Some EDRs (Crowdstrike, Elastic) alert on `SetThreadContext` calls against foreign processes specifically. Mitigation: target threads in your *own* spawned suspended process (combine with CREATE_SUSPENDED process hollowing).

### Process Hollowing
- **What**: Spawn a legit process suspended, swap its image for your PE, fix up the PEB ImageBaseAddress and thread Rip, then resume.
- **When to use**: When you need a process to look legitimate on disk (e.g., `svchost.exe` image name in Process Explorer) while running your code.
- **How**:
  1. `CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)`.
  2. Open the replacement image file (`evil.exe`), read its headers + sections.
  3. `VirtualAllocEx(hProc, NULL, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`.
  4. Copy PE headers + each section to the allocated base.
  5. Update PEB ImageBaseAddress via `NtQueryInformationProcess(ProcessBasicInformation)` → `PBI.PebBaseAddress` → `PEB.ImageBaseAddress = (PVOID)newBase`.
  6. Get main thread context, fix `Rip = AddressOfEntryPoint + newBase`, set context, `ResumeThread`.
- **Vault link**: T-013 Hollowing (basic variant, kept for parity) and **T-009 Process Ghosting** + **T-010 Process Herpaderping** + **T-014 NtCreateUserProcess**. The vault's herpaderping/ghosting variants remove the on-disk file entirely (delete-pending or content-race), evading static AV scans of `evil.exe` on disk. The vault's NtCreateUserProcess variant skips `kernel32!CreateProcessA` entirely (bypassing user-mode hooks). SEC670's hollowing is detectable by image-base mismatch between PEB and `VirtualQuery(MEM_IMAGE)` — the vault variants address this by ensuring the image is genuinely MEM_IMAGE-backed.
- **Tool/code**: `CreateProcessA(..., CREATE_SUSPENDED, ...)`, `ReadFile` on replacement PE, `NtQueryInformationProcess(ProcessBasicInformation)`, `IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint`.
- **OPSEC**: Static AV can scan the replacement file on disk. EDRs flag image-base/PEB mismatch (e.g., PE-sieve, Moneta). Mitigation: encrypt the replacement on disk and decrypt into memory only, or use Ghosting/Herpaderping to remove the on-disk artifact entirely.

### PE Injection
- **What**: Map a secondary PE image inside a target process (without hollowing the original) and execute its `AddressOfEntryPoint` via `CreateRemoteThread`.
- **When to use**: When you want the target process to retain its original image (e.g., for legit network behavior) while running your code alongside.
- **How**:
  1. `OpenProcess(... PROCESS_ALL_ACCESS, FALSE, pid)`.
  2. `VirtualAllocEx(hProc, NULL, image.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`.
  3. Copy PE headers, then each section (`CopySection` walk of `IMAGE_SECTION_HEADER[]`).
  4. Walk `.reloc` (`IMAGE_DIRECTORY_ENTRY_BASERELOC`), apply fixups:
     - `delta = newBase - image.OptionalHeader.ImageBase`
     - For each block: for each entry in `PageDirectory`, add `delta` to the 32/64-bit value at `newBase + block.VirtualAddress + entry.offset`.
  5. Resolve imports (`IMAGE_DIRECTORY_ENTRY_IMPORT`) — IAT fixup with `GetProcAddress`.
  6. `CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)(newBase + OptionalHeader.AddressOfEntryPoint), NULL, 0, NULL)`.
- **Vault link**: T-013 PE Loader (reflective loader variant) and T-007 Module Stomp / Func Stomp. SEC670's manual PE mapping is the precursor to the vault's reflective loader; the vault's variant performs the entire mapping in-position with `RtlImageNtHeader` and `Ldrp*` shimmed through, and supports self-restoring exports (T-008 Threadless reuses the host's EAT). The vault additionally implements Module Overloading (T-013) which reuses an existing MEM_IMAGE-backed section rather than `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` — a much stealthier pattern because RWX in foreign processes is heavily flagged.
- **Tool/code**: `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `IMAGE_OPTIONAL_HEADER.SizeOfImage`, `IMAGE_DIRECTORY_ENTRY_BASERELOC`, `IMAGE_REL_BASED_DIR64`, `VirtualAllocEx(..., PAGE_EXECUTE_READWRITE)`.
- **OPSEC**: `PAGE_EXECUTE_READWRITE` allocation in a foreign process is one of the loudest signals possible — every EDR alerts. Mitigation: stage as `PAGE_READWRITE`, write, then `VirtualProtectEx` → `PAGE_EXECUTE_READ` (W^X), and use Module Overloading instead of fresh allocation (T-013 / T-007).

### SetWindowsHookEx Injection
- **What**: Add a hook procedure into the system-wide hook chain for `WH_GETMESSAGE`/`WH_KEYBOARD`/`WH_MOUSE`, which forces `User32` to load your DLL into any GUI process that processes the hooked event.
- **When to use**: When targeting GUI apps (Notepad, Office, browsers) and you want a stealthy DLL-load mechanism that doesn't use `CreateRemoteThread`.
- **How**:
  1. Build an evil DLL with an exported `HOOKPROC` (e.g., `EvilHookFunction`).
  2. `HMODULE hEvilDll = LoadLibraryA("evil.dll");` (in your own process).
  3. `HOOKPROC lpfn = (HOOKPROC)GetProcAddress(hEvilDll, "EvilHookFunction");`
  4. `HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, lpfn, hEvilDll, 0);` (dwThreadId=0 ⇒ all threads in current desktop session).
  5. Generate a message in the target GUI process (or wait for natural input). User32 will `LoadLibrary` your DLL into the target to dispatch the hook.
- **Vault link**: No direct equivalent in the process-injection vault; the technique is mentioned in passing in T-023 Client Capabilities (keylogger section, which uses `WH_KEYBOARD_LL`/`WH_MOUSE_LL` via `input_blocker.rs` — those are low-level hooks that *do not* require DLL injection because they run in the hook-installer's context). The SEC670 variant is `WH_KEYBOARD`/`WH_MOUSE` (high-level, requires DLL injection). The vault's keylogger approach avoids injection entirely.
- **Tool/code**: `SetWindowsHookExA`/`SetWindowsHookExW`, `WH_GETMESSAGE`, `WH_KEYBOARD`, `WH_MOUSE`, `WH_CALLWNDPROC`, `UnhookWindowsHookEx`.
- **OPSEC**: `SetWindowsHookEx` is flagged by EDRs that monitor for hook installation (Elastic, SentinelOne). The DLL must exist on disk. Mitigation: only viable against weak/legacy hosts.

### Token Privilege Manipulation
- **What**: Programmatically enable `Se*` privileges in your own process token (or one you have a handle to).
- **When to use**: After landing on a host as admin (post-UAC-bypass) and needing `SeDebugPrivilege` for process enumeration, `SeLoadDriverPrivilege` for BYOVD, `SeBackupPrivilege`/`SeRestorePrivilege` for SAM/SYSTEM registry hive exfil.
- **How**:
  1. `LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)`.
  2. `OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)`.
  3. `TOKEN_PRIVILEGES tp = { 1, { { luid, SE_PRIVILEGE_ENABLED } } };`
  4. `AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);`
- **Vault link**: T-021 (UAC bypass via `uac_cmstp.rs` — produces a High-IL token to which this triad is then applied), T-018 (BYOVD — `SeLoadDriverPrivilege` is the precondition for `dark_crystal/crowd/src/byovd.rs`), T-023 (`lsass_dump.rs` requires `SeDebugPrivilege` to open `lsass.exe`).
- **Tool/code**: `LookupPrivilegeValueA`, `OpenProcessToken` (`PROCESS_QUERY_INFORMATION` on the process handle), `AdjustTokenPrivileges`, `winnt.h` constants: `SE_DEBUG_NAME`, `SE_BACKUP_NAME`, `SE_RESTORE_NAME`, `SE_TAKE_OWNERSHIP_NAME`, `SE_LOAD_DRIVER_NAME`, `SE_TCB_NAME`, `SE_CREATE_TOKEN_NAME`.
- **OPSEC**: `AdjustTokenPrivileges` itself is quiet but enabling `SeDebugPrivilege` on a non-SYSTEM token is suspicious (most non-admin tokens don't *have* the privilege to enable). EDRs that monitor token privilege sets (Elastic's `process_privilege_changes`) will flag. Mitigation: enable privileges in a process spawned via the UAC-bypassed High-IL token so the privilege set change looks consistent with elevation.

## Tool & Tradecraft Reference

| Tool/Command | Purpose | OPSEC Notes |
|---|---|---|
| `dt nt!_ethread` / `dt nt!_teb` | WinDbg structure inspection | Local-only diagnostic, no OPSEC impact |
| `CreateThread` / `CreateRemoteThread` | Local/remote thread creation | Heavily hooked by EDR; ETW TI event 3 fires. Use indirect syscalls (T-001) instead |
| `CreateRemoteThreadEx` | Underlying CRT impl | Same telemetry as CRT |
| `NtCreateThreadEx` | Native thread creation | Hooked in ntdll; use T-002 SSN cascade to bypass |
| `QueueUserAPC` | APC queue insertion | ETW `Microsoft-Windows-Kernel-APC`; require alertable wait |
| `SuspendThread` / `ResumeThread` | Thread state control | Suspend of foreign thread is flagged (scheduling anomaly) |
| `GetThreadContext` / `SetThreadContext` | Context read/modify | `SetThreadContext` on foreign PID is a CrowdStrike/Elastic alert trigger |
| `OpenProcess` | Process handle acquisition | `PROCESS_ALL_ACCESS` is loud — request minimum needed mask |
| `OpenThread(THREAD_SET_CONTEXT)` | APC queue access | Less noisy than CRT but still ETW'd |
| `VirtualAllocEx` | Remote allocation | RWX flag is a major red flag; use RW→RX staging |
| `WriteProcessMemory` | Remote write | ETW `Microsoft-Windows-Kernel-Memory`; cross-process WPM is heavily flagged |
| `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` | Thread enumeration | Triggers ETW; snapshot is introspectable by EDR |
| `LoadLibraryA` / `GetProcAddress` | API resolution | Public API resolution is fine; PEB-walk (T-004) is stealthier |
| `CreateProcessA(..., CREATE_SUSPENDED, ...)` | Suspended spawn | Required precursor to hollowing; `CREATE_SUSPENDED` flag is mildly suspicious |
| `NtQueryInformationProcess(ProcessBasicInformation)` | PEB location query | Read-only, but cross-process query is lightly flagged |
| `SetWindowsHookExA` | Hook chain install | High-level (`WH_KEYBOARD`) requires DLL injection; low-level (`WH_KEYBOARD_LL`) does not |
| `LookupPrivilegeValueA` | LUID lookup | Quiet |
| `OpenProcessToken(TOKEN_ADJUST_PRIVILEGES)` | Token handle | Quiet; uses PROCESS_QUERY_INFORMATION on caller |
| `AdjustTokenPrivileges` | Privilege enable/disable | Token privilege-set change is logged by Elastic's `process_privilege_changes` |
| `whoami /priv` | Privilege enumeration (manual recon) | Diagnostic only |
| `whoami /groups` | Group/SID enumeration | Diagnostic only |

## Gaps & Extensions

**What the vault covers that this training doesn't:**
- **Indirect syscalls (T-001 RecycledGate, T-002 Hell's/Halo's/Tartarus Gate, T-003 VEH Gate, T-006 Phantom Stubs)**: SEC670 teaches `CreateRemoteThread`/`OpenProcess`/`VirtualAllocEx` as direct kernel32 calls. Every modern EDR hooks these in user-mode; the vault's indirect syscall stack (`NtAllocateVirtualMemory`/`NtWriteVirtualMemory`/`NtCreateThreadEx` via ntdll gadgets) is essential for bypassing them.
- **Advanced injection variants**: SEC670 covers the *original* 2010s injection methods. The vault's T-007 Pool Party (thread-pool work-item abuse), T-008 Threadless (export-hijack, no thread creation), T-009 Process Ghosting (delete-pending execution), T-010 Process Herpaderping (file-content race), T-011 Dirty Vanity (`RtlCreateProcessReflection`), T-012 Early Cascade (pre-`LdrInitializeThunk` APC), and T-014 NtCreateUserProcess are all absent from SEC670.
- **Sleep obfuscation (T-005 Ekko ROP)**: SEC670 has no equivalent — implants are assumed to sit in memory continuously. The vault's Ekko ROP chain encrypts the implant image during `WaitForSingleObjectEx` so memory scanners see only ciphertext.
- **EDR evasion (T-016 Suite)**: AMSI/ETW patching, stack spoofing (basic + multi-frame), PEB unlink, NTDLL unhook, Block-DLL policy, ACG, handle blocking, KiUserException StepOver, arg spoofing, proxy DLLs, PE stomping — none covered in SEC670.
- **Persistence (T-017 Five-Layer, T-018 Edo Tensei, T-019 Dead Drop)**: SEC670 has a separate persistence module but covers none of the vault's COM hijack / NTFS EA / TLS callback / PhantomPersist stack.
- **Anti-analysis (T-020)**: SEC670 touches anti-VM but not the vault's 10-check suite, API hammering (FPU/SIMD), IAT camouflage, or self-deletion via ADS rename.
- **BYOVD (T-018)**: SEC670 mentions `SeLoadDriverPrivilege` but does not chain it into a vulnerable-driver load for kernel read/write primitives.
- **Crypto/encoding (T-021)**: No coverage of IPv4/IPv6/MAC/UUID shellcode encoding, AES-GCM+zstd payload pipeline, or Ethereum-TX-based autonomous C2.

**What this training covers that the vault doesn't (or covers less explicitly):**
- **Thread internals theory**: SEC670's discussion of `ETHREAD`/`KTHREAD`/`TEB` structure, the `PspCreateThread` suspend/resume flow, and the attribute-list construction behind `CreateRemoteThreadEx` is more pedagogically complete than the vault's operator-focused T-013. Useful for understanding *why* Early Bird / Early Cascade work — they intercept during the window SEC670 describes.
- **`SetWindowsHookEx` injection**: The vault's T-023 Client Capabilities covers `WH_KEYBOARD_LL`/`WH_MOUSE_LL` (low-level, in-installer-context hooks) for the keylogger and input blocker, but does not document high-level hooks (`WH_KEYBOARD`, `WH_MOUSE`, `WH_GETMESSAGE`) as a *DLL injection mechanism*. This is a niche technique still occasionally useful against legacy GUI apps that don't have an EDR sensor.
- **Integrity Level taxonomy**: SEC670's six-level IL enumeration (Untrusted/Protected included) is more complete than the vault's implicit reference to High/Medium/System. The Protected-IL (level 5, kernel-set) note is operationally relevant — PPL processes are immune to `SeDebugPrivilege` and require either a BYOVD kernel exploit or a PPL-bypass technique.
- **ACL-bypass privileges (`SeBackup`/`SeRestore`)**: The vault's T-023 lsass dump uses `SeDebugPrivilege`, but does not document `SeBackup`/`SeRestore` as a *file ACL bypass* — useful for exfiltrating SAM/SYSTEM/SECURITY registry hives (via `reg save`) without touching `SeDebugPrivilege` at all.
- **Privilege-token attribute bits**: SEC670's enumeration of `SE_PRIVILEGE_ENABLED` / `ENABLED_BY_DEFAULT` / `REMOVED` / `USED_FOR_ACCESS` is more granular than the vault's typical `SE_PRIVILEGE_ENABLED`-only usage. `SE_PRIVILEGE_REMOVED` is operationally interesting — can strip a privilege from a duplicated token before passing it to a child process to reduce the child's footprint.

## Cross-Reference Matrix

| Training Concept | Vault Technique | Relationship |
|---|---|---|
| Thread object topology (TEB → PEB) | T-004 PEB Walker | Vault uses the same TEB→PEB pointer chain via `gs:[0x60]` for stealthy module resolution instead of `kernel32!GetModuleHandle` |
| `CreateRemoteThread` for injection | T-001 RecycledGate, T-002 Hell's Gate, T-013 Remaining Methods | Vault replaces CRT with `NtCreateThreadEx` via indirect syscalls to bypass user-mode hooks |
| APC injection (alertable wait) | T-012 Early Cascade, T-013 Early Bird | Vault's Early Cascade queues APC *before* `LdrInitializeThunk` (no alertable-wait requirement); SEC670 variant requires victim threads in alertable state |
| Thread hijacking via `SetThreadContext` | T-013 WaitingThread hijack | Vault variant targets threads already in wait state (avoids `SuspendThread` telemetry); SEC670 variant suspends first |
| Process Hollowing | T-009 Process Ghosting, T-010 Process Herpaderping, T-014 NtCreateUserProcess | Vault variants remove on-disk artifact (Ghosting/Herpaderping) and bypass kernel32 (`NtCreateUserProcess`); SEC670 variant leaves replacement on disk and uses `CreateProcessA` |
| PE Injection (manual mapping) | T-013 PE Loader, T-007 Module Stomp, T-007 Module Overloading | Vault's Module Overloading reuses existing MEM_IMAGE section (no RWX alloc); SEC670 variant allocates fresh RWX |
| `SetWindowsHookEx` (high-level) | T-023 Client Capabilities (keylogger) | Vault uses low-level hooks (`WH_KEYBOARD_LL`) only — no DLL injection needed. SEC670's high-level variant (`WH_KEYBOARD`) is absent from the vault |
| `LoadLibraryA` resolution | T-004 PEB Walker, T-006 Phantom Stubs | Vault resolves without `GetProcAddress`; SEC670 uses standard resolver |
| `SeDebugPrivilege` enablement | T-023 lsass_dump.rs, T-018 BYOVD | Vault's lsass dumper uses same triad (`LookupPrivilegeValue`+`OpenProcessToken`+`AdjustTokenPrivileges`); T-018 BYOVD requires `SeLoadDriverPrivilege` enabled |
| `SeLoadDriverPrivilege` | T-018 BYOVD | Vault's `byovd.rs` pipeline chains this privilege into vulnerable-driver loading for kernel r/w |
| `SeBackupPrivilege` / `SeRestorePrivilege` (ACL bypass) | (none) | Vault does not document these — SEC670 adds ACL-bypass exfil capability |
| `SeTakeOwnershipPrivilege` | (none) | Vault does not document — SEC670 adds ownership-take on protective-process objects |
| Integrity Levels (6-level taxonomy) | (implicit in T-016, T-021) | Vault references High/Medium/System only; SEC670 adds Untrusted/AppContainer/Protected |
| UAC-bypass implication (privileges appear post-bypass) | T-021 UAC Bypass (`uac_cmstp.rs`, `escalation/uac.rs`) | Vault implements the bypass; SEC670 documents the resulting token-state prerequisite |
| Manual `.reloc` fixup walk | T-007 PE parsing (`pe.rs`), T-013 PE Loader | Vault implements identical `IMAGE_REL_BASED_DIR64` walk inside reflective loader; SEC670 documents the algorithm explicitly |
| `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` | T-020 Anti-Analysis, T-023 recon | Vault uses native `NtQuerySystemInformation(SystemProcessInformation)` instead — avoids the toolhelp snapshot telemetry |

## Operator Notes

- **Educational baseline only**: every injection technique in SEC670 Section 3 is detected by modern EDRs out-of-the-box. Treat this material as the *conceptual foundation* for understanding the vault's advanced techniques — not as a field-ready toolkit.
- **The privilege triad is field-relevant**: `LookupPrivilegeValue` + `OpenProcessToken` + `AdjustTokenPrivileges` is still the correct way to enable `SeDebugPrivilege` / `SeLoadDriverPrivilege` post-elevation. The vault's `dark_crystal/crowd/src/byovd.rs` (T-018) and `client_rust/src/experimental/harvest/lsass_dump.rs` (T-023) both use this exact triad.
- **ACL-bypass privileges are underused**: `SeBackupPrivilege` for SAM/SYSTEM/SECURITY hive exfil (`reg save HKLM\SAM sam.hiv`) bypasses file ACLs entirely and is quieter than touching `lsass.exe`. Operationally valuable when lsass-dumping is too risky.
- **`SetWindowsHookEx` high-level hooks** still work against legacy GUI apps in environments without EDR sensors on the GUI host — a niche capability worth retaining.
- **Integrity Level 5 (Protected)** is the reason PPL-protected processes (e.g., `MsMpEng.exe`, `SearchIndexer.exe` with PPL) are immune to `SeDebugPrivilege`. BYOVD (T-018) is the canonical vault response.