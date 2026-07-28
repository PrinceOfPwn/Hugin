---
id: T-015, T-016
name: PPID Spoofing + EDR Evasion Suite
category: process-injection, edr-evasion
tier: S, mixed
mitre: T1134.004, T1562.001, T1562.002, T1055.001, T1620, T1574.001, T1106
analyzed_by: glm-5.2
analysis_date: 2026-07-21
confidence: high
requires: [T-001, T-004]
enables: [T-007, T-012, T-014, T-017, T-018]
min_windows: Win10 1607+ (PPID); Win7+ (most evasion sub-techniques)
needs_admin: conditional
tags: [ppid, process-creation, parent-spoofing, nt-api, amsi, etw, stack-spoofing, peb-unlink, ntdll-unhook, block-dll, acg, block-handle, advanced-stack, ki-stepover, arg-spoof, proxy-dll, pe-stomping]
---

# PPID Spoofing + EDR Evasion Suite — Operator Playbook

## TL;DR

**T-015** spawns a child process with a spoofed parent PID (typically `explorer.exe`) by calling `NtCreateUserProcess` directly with a `PS_ATTRIBUTE_PARENT_PROCESS` attribute, bypassing `CreateProcessW`'s wrappers and the `PROCTHREAD_ATTRIBUTE_PARENT_PROCESS` Win32 path entirely. Combined with a Block-DLL policy at creation time, this is the cleanest way to land a sacrificial process that looks user-launched and refuses EDR DLL injection. **T-016** is a 13-piece suite (the card title says 12; the body lists 13) covering AMSI/ETW neutralization, multi-frame stack spoofing, PEB unlinking, NTDLL unhooking, KiUserExceptionDispatcher StepOver, arg spoofing, proxy-DLL loading, PE stomping, Block-DLL/ACG policy, and external-handle blocking — the "pre-flight + post-injection hygiene" layer that makes the rest of the vault (T-007 through T-014) survive against a mature SOC. The two are designed to be wired together: T-016's Block-DLL policy is *applied by* T-015 at process creation time.

## How It Works

### T-015 — PPID Spoofing via NtCreateUserProcess

1. **PID resolution.** `find_pid_by_name()` walks the toolhelp snapshot: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` → `Process32FirstW` / `Process32NextW` over `PROCESSENTRY32W`. Returns the PID of `explorer.exe` (or any configured parent). Note: toolhelp is the noisy path — for low-footprint ops, swap to a PEB-walked `NtQuerySystemInformation(SystemProcessInformation)` (see T-004).
2. **Spoofed parent handle.** `NtOpenProcess` is invoked through RecycledGate (T-001) with `DesiredAccess = PROCESS_CREATE_PROCESS (0x0080)`. The handle is `PROCESS_HANDLE` returned in a `CLIENT_ID`-aware path. The `OBJECT_ATTRIBUTES` is built with `Attributes = OBJ_CASE_INSENSITIVE | OBJ_INHERIT` only if you intend to inherit — typically not inherited so the handle survives but the child doesn't auto-get it.
3. **PS_CREATE_INFO setup.** The `PS_CREATE_INFO` struct (88 bytes on x64) is zeroed and `Size = sizeof(PS_CREATE_INFO)`, `State = PsCreateInitialState`. The `ResultStatus` field will be filled in by the kernel on return — useful for diagnosing `STATUS_INVALID_IMAGE_HASH` or signature-policy rejections.
4. **PS_ATTRIBUTE_LIST construction.** The struct is allocated as `PS_ATTRIBUTE_LIST` with `TotalLength = sizeof(PS_ATTRIBUTE_LIST) + (N-1)*sizeof(PS_ATTRIBUTE)`. The first (and usually only) attribute: `Attribute = PsAttributeParentProcess (0x00020000)`, `Size = sizeof(HANDLE)`, `ValuePtr = <parent handle from step 2>`. If you also want a sibling thread-handle attribute (`PsAttributeClientId`), insert it at index 1.
5. **Process parameters.** `RtlCreateProcessParametersEx` builds `RTL_USER_PROCESS_PARAMETERS` with the image path (`CommandLine`, `ImagePathName`, `CurrentDirectory.DosPath`). Critical: do not pass a `NULL` parameters block — `NtCreateUserProcess` will succeed but the process won't initialize its `PEB->ProcessParameters`.
6. **Block-DLL pre-flight (optional, recommended).** Before resume, the spawned (still-suspended) child has its mitigation policy set: `NtSetInformationProcess(ProcessSignaturePolicy, class 52, &policy, sizeof(PROCESS_MITIGATION_POLICY_INFORMATION))` with `MicrosoftSignedOnly = 1`. This is the same call path as `crowd/src/policy.rs` — see T-016 sub-technique below.
7. **Create suspended.** `NtCreateUserProcess` returns a `CLIENT_ID` (PID/TID), Section/Thread/Process handles. `ProcessFlags` includes `PROCESS_CREATE_FLAGS_SUSPENDED (0x00000004)`. The primary thread is held in `THREAD_STATE_WAITING` until `NtResumeThread`.
8. **Inject & resume.** At this point T-012 Early Cascade can queue the APC *before* `LdrInitializeThunk` runs (the suspended state means the APC sits in the kernel APC queue, fires on the first user-mode transition). For less-stealth chains, T-007 Pool Party or T-013 thread-hijack work too. Then `NtResumeThread` triggers initialization → APC fires → payload runs.

The result: `PROCESS_INFORMATION` reported by Win32 APIs shows `ParentProcessId = explorer.exe`. Event Tracing for Windows (kernel `Process/Start` event) records the spoofed PPID. Sysmon EID 1 also reports the spoofed value — *unless* Sysmon's `ProcessCreate` callback runs on the kernel-side `PsSetCreateProcessNotifyRoutineEx`, which can see the real creator via the `ParentProcess` GUID when running v15+ with `CheckCommandLine` and `ProcessSignaturePolicy` enabled. This is the primary detection surface.

### T-016 — EDR Evasion Suite (13 sub-techniques)

Each entry below is the operator-relevant mechanism. Quoted struct/function names come from the cards; without annotated source I've inferred field names from documented NT internals — verify against the actual `.rs` before relying on offsets.

**1. AMSI Bypass via Hardware Breakpoints (S)** — `crowd/src/amsi_hbp.rs`. Dr0 set on `AmsiScanBuffer`. A `AddVectoredExceptionHandler`-registered VEH catches `EXCEPTION_SINGLE_STEP`, writes `AMSI_RESULT_CLEAN` into the result buffer, sets `RAX = S_OK (0)`, sets `RIP = return address` (skip the call), and `NtContinue`. DR0 occupancy is checked via `GetThreadContext` *before* installation — if AV/EDR already uses DR0 (common with kernel callbacks), fall to sub-technique 2. `AmsiScanBuffer` is resolved without `LoadLibraryW`: PEB-walk `amsi.dll`, parse its export table, walk forward from the export address to find the prologue. This avoids the `LoadLibraryW("amsi.dll")` ETW/`ImageLoad` event that triggers AMSI itself.

**2. AMSI PAGE_GUARD Fallback (B)** — `crowd/src/amsi_page_guard.rs`. `VirtualProtect` flips the page containing `AmsiScanBuffer`'s first byte to `PAGE_READONLY | PAGE_GUARD`. First access raises `STATUS_GUARD_PAGE_VIOLATION` (0x80000001). The VEH handler redirects RIP to a stub `xor eax, eax; ret` placed in RWX memory (or — preferably — into a `RtlAddVectoredExceptionHandler`-allocated trampoline). One-shot: the guard is consumed on first access, so this is a tripwire not a persistent patch.

**3. ETW Muffling (A)** — `crowd/src/etw.rs`. Walks `ntdll!EtwRegistrationList` (an `ntdll!_ETW_REG_ENTRY` circular LIST_ENTRY in `.data`) — `LdrGetProcedureAddress` for the symbol `EtwRegistrationList` (or scan `ntdll.data` for the LIST_ENTRY). For each entry, locate the containing `_ETW_GUID_ENTRY` via `CONTAINING_RECORD`, walk `EnableInfo[N].IsEnabled`, and zero each flag via `volatile write`. No `.text` patching → no `ntdll!EtwEventWrite` hook detection by integrity scanners. Fallback patches `EtwEventWrite` prologue to `48 31 C0 C3` (`xor rax,rax; ret`) — this *does* leave a detectable signature.

**4. Call Stack Spoofing (S)** — `crowd/src/stack_spoof.rs`. Parses `.pdata` (`RUNTIME_FUNCTION`) of the *current module* to compute the caller's frame size via `UNWIND_INFO` opcodes: `UWOP_ALLOC_SMALL`, `UWOP_ALLOC_LARGE`, `UWOP_PUSH_NONVOL`, `UWOP_SET_FPREG`, recursing through `UNW_FLAG_CHAININFO` (cap 32 levels). Then scans `kernelbase.dll` exports for a function with matching frame size (randomized offset within) and overwrites the return address with that function's mid-epilogue address. The `SpoofGuard` is `#[must_use]` — `Drop` restores the original return address. Single-frame spoof (caller's RIP only).

**5. Advanced Stack Spoofing (S)** — `crates/core/src/experimental/evasion/advanced_stack.rs`. Uses `dinvoke_rs` (no static imports — payload-free IAT). `BitReader` parses all `UNWIND_CODE` opcodes. A `global_asm!` trampoline redirects calls transparently. State persists in TLS (`TlsAlloc`/`TlsSetValue`/`TlsGetValue`). The `NewStackInfo` struct (fields: `rtladdr, rtlsize, baseaddr, basesize, current_size, total_size`) describes a synthetic stack. **Multi-frame**: constructs an entire chain `RtlUserThreadStart → BaseThreadInitThunk → <payload>` with realistic `__chkstk`/`_security_cookie`/`GetProcAddress`-looking frames. Difference from basic: this passes `RtlVirtualUnwind`-based stack walkers (which EDRs like Elastic, CrowdStrike, SentinelOne use).

**6. PEB Module Unlinking (A)** — `crowd/src/peb_unlink.rs`. `__readgsqword(0x60)` → PEB → `Ldr` (`PEB_LDR_DATA`) → unlink the module entry from all three lists: `InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`. Loader lock acquired via `LdrLockLoaderLock` (passed through RecycledGate) before mutation, released after. Unlinked entry has its `Flink`/`Blink` zeroed to `&mut self` (self-referential) for anti-forensics so a torn-list walker doesn't crash.

**7. KiUserExceptionDispatcher StepOver (A)** — `crowd/src/ki_step_over.rs`. Instead of unhooking a hooked syscall stub (which trips `ntdll!NtSetInformationThread`-style memory-access telemetry), set a DR0 hardware breakpoint on the *hooked instruction itself*. When `KiUserExceptionDispatcher` is invoked (because the hook does something traceable, e.g., int3 / `INT 2D`), the VEH intercepts, sets `RAX = SSN`, `RIP = &syscall_instruction`, and calls `NtContinue`. Supports up to 8 simultaneous targets via an `AtomicU64` array (one per DR0–DR3 + a 4-deep slot queue, depending on impl — check the source).

**8. Process Argument Spoofing (B)** — `crowd/src/arg_spoof.rs`. Spawn process with benign `CommandLine` (visible to `Process`/`CommandLine`-capturing ETW). While suspended, locate `PEB->ProcessParameters` and overwrite `ProcessParameters->CommandLine.Buffer` (and `.Length`) with the real args. Resume. Creation logs show the benign args; the actual runtime args come from the patched PEB. Detection: Process Monitor's `Process Tampering` event (EID 1 with `IntegrityLevel` mismatch or `CommandLine` re-query showing different value).

**9. Proxy DLL Load (B)** — `crowd/src/proxy_dll.rs`. `TpAllocWork` allocates a `TP_WORK` with the callback `LoadLibraryA(<dll>)`. `TpPostWork` queues it to the default thread pool. The `LoadLibraryA` call now appears in stack as `ntdll!TppWorkerThread → kernel32!LoadLibraryA` — looks like a system-initiated load, not an implant-initiated one. Defeats ETW rules that flag `LoadLibraryA` from non-Microsoft start addresses.

**10. PE Header Stomping (B)** — `crowd/src/stomp.rs`. After loading a module (or stomping one — see T-007 module-stomp), `ptr::write_bytes(header_ptr, 0, nt_headers.SizeOfHeaders)`. This zeros the DOS header, NT header, section table, and export directory. `pe-sieve` and `BeaconEye` fail their `RtlImageNtHeader` walk and skip the module. **Note**: `.text` execution still works because the section is already mapped — header stomping is purely an anti-scrape. Also defeats `GetModuleFileNameW`/`GetModuleHandleW` lookups for the stomped module.

**11. NTDLL Unhooking (A)** — `crowd/src/ntdll_unhook_inject.rs`. `NtCreateFile(\??\C:\Windows\System32\ntdll.dll)` → read `.text` section (located via DOS header → NT headers → section table → `VirtualAddress + SizeOfRawData`). `NtProtectVirtualMemory` to `PAGE_EXECUTE_READWRITE`, `memcpy` clean `.text` over the in-memory hooked copy, restore to `PAGE_EXECUTE_READ`. Idempotent — re-running is safe (the disk file is always clean). **Operator gotcha**: EDRs that map their own clean ntdll copy and compare (`ntdll!ZwXxx` vs `kernelbase!Xxx`) will still see this — but they typically rely on the in-memory version for their own hooks, so this re-enables your own syscalls while their hooks are bypassed via T-001 anyway.

**12. Block-DLL Policy (A)** — `crowd/src/policy.rs`. `NtSetInformationProcess(ProcessMitigationPolicy, class 52, ...)` with `POLICY_TYPE = ProcessSignaturePolicy`, `MicrosoftSignedOnly = 1`. After this, `LoadLibrary` on a non-Microsoft-signed DLL returns `STATUS_INVALID_IMAGE_HASH` (0xC0000428). EDR can't inject its DLL into this process. Companion flag `ProhibitDynamicCode` (Arbitrary Code Guard) prevents `VirtualProtect`/`VirtualAlloc(PAGE_EXECUTE_READWRITE)` post-init — useful for beacon processes that don't need to JIT. **All via RecycledGate**, so the `NtSetInformationProcess` itself doesn't go through a hooked `ntdll!NtSetInformationProcess`.

**13. Block External Handles (B)** — `crowd/src/block_handle.rs`. Build SDDL: `D:P(D;;WD;;;WD)(A;;0x1FFFFF;;;SY)(A;;0x1FFFFF;;;OW)` — Deny ALL for Everyone, Allow All for SYSTEM + owner. Apply via `NtSetSecurityObject(Handle, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | ...)` — *not* `SetKernelObjectSecurity`. This blocks Process Hacker, pe-sieve, and ring-3 EDR handle acquisition (`NtOpenProcess(PROCESS_VM_READ)` returns `STATUS_ACCESS_DENIED`).

## Operational Profile

### When to Use

**T-015 PPID Spoofing:**
- Initial sacrificial process creation where the process must appear user-launched (defeats `parent != expected parent` EDR rules — e.g., spawn `cmd.exe` as child of `explorer.exe`, not of `dark_crystal.exe`)
- Pivoting into a long-running host (e.g., `sihost.exe`/`ctfmon.exe`/`RuntimeBroker.exe`) where Sysmon PPID lineage matters
- Combined with T-014 NtCreateUserProcess for raw NT-only chains that avoid `kernel32!CreateProcessW` entirely
- Engagement where the SOC uses Sysmon EID 1 lineage or Sigma rules on `parent_image != explorer.exe`

**T-016 EDR Evasion Suite:**
- Pre-injection: Block-DLL policy + NTDLL unhook + AMSI/ETW muffle before any payload runs
- During payload execution: Stack spoof on every NT-API call back to C2 (basic version is enough for one-shot beacon; advanced version for long-running implants where EDR walks stacks hourly)
- Persistence scenarios (T-017/T-018): PEB unlink + PE stomping to hide the persistent module from `pe-sieve`
- Anti-forensics on the way out: arg spoofing + KiUserException StepOver for cleanup that touches hooked functions

### When NOT to Use

**T-015:**
- Target runs Sysmon v15+ with `ProcessSignaturePolicy` and `CheckParentProcess` — these can correlate the real creator PID with the spoofed PPID via `PsSetCreateProcessNotifyRoutineEx`
- You're already inside a sacrificial process — PPID spoofing a process from inside a spoofed-parent process produces suspicious lineage chains that SOC rules flag
- Engagement window is < 60 seconds and you're not persisting — PPID spoof adds ~150 lines and ~5 syscalls of overhead for marginal benefit on a one-shot exec

**T-016 sub-techniques — skip when:**
- **AMSI HBP**: target is .NET-heavy and AMSI has DR0 already (CrowdStrike Falcon does this) — fall to PAGE_GUARD or arg-spoof the call out of `AmsiScanBuffer` entirely
- **Advanced stack spoof**: short engagement, EDR doesn't walk stacks at runtime (only on suspicious syscall) — basic spoof is enough
- **PEB unlink**: target uses `EnumProcessModules` in the SOC's inventory tool and you want to appear as a known module — unlinking makes you invisible to `EnumProcessModules` but also flags you to tools that compute delta against the loader's `InLoadOrder` count
- **PE header stomping**: payload module has exports you need to call — stomping breaks `GetProcAddress` for that module
- **Block-DLL policy**: you need to load your own non-MS-signed DLL later (e.g., proxy DLL, OpenH264 in client_rust) — MicrosoftSignedOnly blocks you too
- **Block external handles**: SOC uses `NtGetNextProcess` for inventory rather than `NtOpenProcess` — DACL doesn't help, and you'll just look like the only handle-blocked process on the box

### Kill Chain Position

```
T-004 (PEB walk) → T-002 (SSN resolve) → T-001 (RecycledGate)
                                                  ↓
                          T-016 EDR evasion suite (pre-flight):
                            - NTDLL unhook (T-016.11)
                            - ETW muffle (T-016.3)
                            - AMSI HBP (T-016.1)
                            - Block-DLL policy (T-016.12) [applied to spawned child]
                            - Advanced stack spoof (T-016.5) [active during all subsequent NT calls]
                                                  ↓
                          T-015 PPID spoof → NtCreateUserProcess (suspended)
                                                  ↓
                          T-012 Early Cascade APC (pre-LdrInitializeThunk)
                                                  ↓
                          NtResumeThread → payload init
                                                  ↓
                          T-005 Ekko ROP sleep (encrypted stack during sleep)
                                                  ↓
                          T-017 persistence (COM hijack + NTFS EA + schtask + TLS + PhantomPersist)
                                                  ↓
                          T-016.6 PEB unlink + T-016.10 PE stomp (post-persistence hygiene)
                                                  ↓
                          T-016.13 Block external handles (final ring-3 hardening)
```

**What comes after:** T-016 sub-techniques 1, 3, 11, 12 should be active *before* T-015's `NtCreateUserProcess` — the Block-DLL policy needs to be applied to the *child*, which means it's set inside T-015 itself via `NtSetInformationProcess` on the suspended handle.

### Trade-offs

| Dimension | T-015 Rating | T-015 Notes | T-016 Rating | T-016 Notes |
|---|---|---|---|---|
| Stealth | 8 | Spoofs Sysmon EID 1 PPID, ETW kernel process start | 9 (varies) | Stack spoof + PEB unlink + Block-DLL together is the high-water mark |
| Reliability | 8 | `NtCreateUserProcess` is stable on Win10 1607+; fails if parent handle lacks `PROCESS_CREATE_PROCESS` | 7 | HBP DR0 collides with EDR; PAGE_GUARD is one-shot; advanced stack spoof has TLS race |
| Complexity | 7 | Manual PS_ATTRIBUTE/PS_CREATE_INFO struct definitions from ReactOS | 9 | 13 sub-techniques with interdependencies (e.g., SpoofGuard must Drop in correct order) |
| Version range | Win10 1607+ | `NtCreateUserProcess` stable; PS_ATTRIBUTE_PARENT_PROCESS works back to Vista | Win7+ (most), Win8+ (TP API for proxy load), Win10+ (mitigation policy) | Block-DLL requires `PROCESS_MITIGATION_POLICY` (Win8+); advanced stack spoof needs `.pdata` (x64 only) |
| Privilege needed | medium-IL | Open process on same-user `explorer.exe`; if cross-user parent wanted, need `SE_DEBUG_PRIVILEGE` | medium-IL (most) | Block-handle SDDL works at any IL; NTDLL unhook needs `PROCESS_VM_WRITE` (self only) |

## Rust Implementation Deep Dive

### T-015 — `crowd/src/ppid.rs`

- **`unsafe` boundaries**: All `NtCreateUserProcess`, `NtOpenProcess`, `NtSetInformationProcess` calls go through `recycled!` macro (see T-001). The unsafe block is around the FFI into RecycledGate's assembly stub. The struct definitions for `PS_ATTRIBUTE`, `PS_ATTRIBUTE_LIST`, `PS_CREATE_INFO`, `PS_CREATE_INFO.CreateStatus` union are *manually* defined — there's no `windows-sys` upstream. Verify field offsets against `nt!_PS_CREATE_INFO` if you're targeting newer builds (Microsoft occasionally grows these structs).
- **FFI patterns**: The `windows_targets::link!` macro (per the wrappers pattern in `crates/core/src/wrappers.rs`) is *not* used here — these are ReactOS-source structs, so they're plain `#[repr(C)] struct` definitions. Handle ownership: the spoofed parent handle from `NtOpenProcess` must be `NtClose`'d after `NtCreateUserProcess` succeeds — verify the code does this (a leaked handle is the typical bug).
- **Initialization**: `OnceLock` for the SSN+gadget map for `NtCreateUserProcess`, `NtOpenProcess`, `NtSetInformationProcess`. Cold-path first call resolves and caches; subsequent calls go through cached direct syscalls.
- **Error paths**: `find_pid_by_name` returning `None` (no `explorer.exe`) — the caller should fall back to `NtCreateUserProcess` without the parent attribute, *not* bail. Confirm the code's behavior here.
- **Memory layout**: `PS_ATTRIBUTE_LIST` is heap-allocated via `Vec<u8>` with `TotalLength` field set explicitly — alignment is `8` on x64. The `ValuePtr` union member is used (not `Value` u64) to take a `HANDLE`.

### T-016 — Multiple files

- **`crowd/src/amsi_hbp.rs` (~404 lines)**: VEH handler is registered with `RtlAddVectoredExceptionHandler(1, handler)` (priority 1 = front of queue). DR0 occupancy check uses `NtGetContextThread(GetCurrentThread())` and tests `ContextRecord.Dr0 != 0`. The handler decodes the exception address via `EXCEPTION_RECORD->ExceptionAddress` and matches against the cached `AmsiScanBuffer` address. **`unsafe`** boundary: setting DR0 via `NtSetContextThread`/`NtContinue` requires writing `CONTEXT.ContextFlags |= CONTEXT_DEBUG_REGISTERS`. The result-buffer write to `AMSI_RESULT_CLEAN` (value `0x80070057`? verify — it's actually `AMSI_RESULT_CLEAN = 0` per `amsi.h`) requires knowing the calling convention: `AmsiScanBuffer` takes 6 args; the result is the last `PAMSI_RESULT` pointer. Walking the stack to find it is fragile — confirm the impl uses the `rsp+offset` from the unwind info, not a fixed offset.
- **`crowd/src/stack_spoof.rs` (~325 lines)**: `SpoofGuard` is `#[must_use]` — Drop restores the saved return address. The `RUNTIME_FUNCTION` lookup uses `RtlLookupFunctionEntry` (faster than walking `.pdata` manually). The `UNWIND_INFO` parse handles only 4 opcodes — if you encounter `UWOP_SAVE_NONVOL`, `UWOP_SAVE_NONVOL_FAR`, `UWOP_SET_FPREG_LONG`, the frame-size computation will be wrong. Confirm against `crates/core/src/experimental/evasion/advanced_stack.rs` which uses `BitReader` for full opcode coverage.
- **`crates/core/src/experimental/evasion/advanced_stack.rs`**: `NewStackInfo` struct has 6 fields — `rtladdr` (where the fake stack starts), `rtlsize`, `baseaddr` (committed base), `basesize`, `current_size` (used bytes), `total_size` (committed). TLS slot stores a pointer to this so the trampoline can find it without a global. `global_asm!` defines a trampoline that:
  1. Saves all caller-saved regs (RAX/RCX/RDX/R8/R9/R10/R11)
  2. Swaps RSP to `NewStackInfo.rtladdr + current_size`
  3. Pushes the fake frame chain
  4. Calls the target
  5. Restores RSP
  6. Returns
  The `dinvoke_rs` dependency means a separate cargo feature gate — check `Cargo.toml` for the right `--features` flag.
- **`crowd/src/peb_unlink.rs` (~193 lines)**: `__readgsqword(0x60)` for PEB. `LdrLockLoaderLock` is called via RecycledGate with `Cookie` out-param — the cookie is passed to `LdrUnlockLoaderLock`. Critical: do *not* hold the loader lock across any other NT call that takes it (deadlock with `LdrLoadDll`).
- **`crowd/src/ki_step_over.rs`**: `AtomicU64` array of 8 slots stores the target instruction addresses. The VEH handler does a linear scan — O(8) per exception, which is fine. DR0–DR3 hold up to 4 hardware breakpoints; the remaining 4 slots are presumably queued targets pending a free DR. Verify the source for the slot-promotion logic.
- **`crowd/src/arg_spoof.rs`**: Locates `PEB->ProcessParameters` via `__readgsqword(0x60) -> offset 0x20 -> ProcessParameters`. The `CommandLine.Buffer` is a `PWSTR` in the host process's heap — the new args string is allocated via `RtlCreateUnicodeString` (which calls `RtlAllocateHeap` on the process heap) and the `Buffer` pointer is overwritten. Old `Buffer` is *leaked* (no free) — small heap leak per call; document this in the OPSEC notes.
- **`crowd/src/policy.rs`**: `PROCESS_MITIGATION_POLICY_INFORMATION` is a union; the `ProcessSignaturePolicy` variant is selected via the `Policy` enum field. The struct is 32 bytes — the `MicrosoftSignedOnly` bit is in the `Flags.MicrosoftSignedOnly` sub-field. Confirmed Win8+ (introduced 2012).
- **`crowd/src/block_handle.rs`**: SDDL string parser is `ConvertStringSecurityDescriptorToSecurityDescriptorW` — but the code uses `NtSetSecurityObject`, so the SDDL→SD conversion is done via Win32, then the `SECURITY_DESCRIPTOR` is passed to NT. **Note**: this means `advapi32!ConvertStringSecurityDescriptorToSecurityDescriptorW` *is* imported — check whether this is a target signature.

## Edge Cases & Failure Modes

1. **T-015: Parent process has exited between PID resolution and NtOpenProcess.** Symptom: `NtOpenProcess` returns `STATUS_INVALID_PARAMETER` or `STATUS_NOT_FOUND`. Workaround: re-resolve PID inside a retry loop; prefer long-lived parents (`explorer.exe`, `sihost.exe`) over transient ones (`RuntimeBroker.exe`).
2. **T-015: PS_ATTRIBUTE_LIST alignment error on Win11 23H2.** Symptom: `NtCreateUserProcess` returns `STATUS_INVALID_PARAMETER` (`0xC000000D`). Cause: struct padding assumption broken. Workaround: confirm `core::mem::size_of::<PS_ATTRIBUTE_LIST>()` against `sizeof` in a debug build on the target OS.
3. **T-015: Sysmon v15+ with `ProcessSignaturePolicy` exposes real parent.** Symptom: SOC alerts on "parent process mismatch between PPID and creator". Workaround: launch from a process whose creator PID *is* the spoofed parent (e.g., spawn `dark_crystal.exe` as child of explorer first, then have it spawn the payload with explorer PPID — the real creator chain looks legit).
4. **T-016.1: DR0 already occupied by EDR.** Symptom: `NtSetContextThread` succeeds but the breakpoint never fires; or the breakpoint fires but on the wrong instruction. Workaround: fall to PAGE_GUARD variant (T-016.2) or use KiUserException StepOver (T-016.7) for the same target.
5. **T-016.3: EtwRegistrationList symbol unexported on ntdll.** Symptom: `LdrGetProcedureAddress` fails; ETW muffle silently no-ops. Workaround: scan `ntdll.data` for the LIST_ENTRY pattern (the `.data` section has a recognizable structure around it). Detect failure: instrument the muffle function to return `Result<usize, ()` with the count of disabled providers.
6. **T-016.4: Stack spoof crashes when called from inside a function with `UWOP_SAVE_NONVOL`.** Symptom: `STATUS_ACCESS_VIOLATION` on return — the saved non-volatile register's stack slot was overwritten by the spoof. Workaround: use advanced stack spoof (T-016.5) which handles all opcodes.
7. **T-016.5: TLS slot collision with another thread.** Symptom: stack spoof corrupts another thread's state in multi-threaded implants. Workaround: `TlsAlloc` is process-wide — the slot index is shared but the value is per-thread, so this *shouldn't* be a problem. If it is, check that the trampoline reads TLS via `gs:[0x58]` (TEB->TLS slots) correctly on the calling thread.
8. **T-016.6: PEB unlink crashes the loader lock acquisition.** Symptom: `LdrLockLoaderLock` hangs (deadlock) if called from inside `DllMain` or another loader-locked context. Workaround: only call from main thread outside any loader operation.
9. **T-016.7: KiUserException StepOver DR0 saturation.** Symptom: 9th target can't be set; older target silently dropped. Workaround: free a DR slot by clearing DR0–DR3 of completed targets via `NtSetContextThread`.
10. **T-016.11: NTDLL on disk has been hotpatched by the EDR (e.g., SentinelOne).** Symptom: clean `.text` copy doesn't actually remove hooks — the on-disk file was rewritten. Workaround: read ntdll from `\\?\C:\Windows\WinSxS\...ntdll.dll` (side-by-side cache) or from `KnownDlls\ntdll.dll` section.
11. **T-016.12: Block-DLL policy breaks OpenH264 load in client_rust.** Symptom: `LoadLibrary("openh264.dll")` returns `STATUS_INVALID_IMAGE_HASH`. Workaround: disable Block-DLL for client_rust's host process, or use module overloading (T-007/T-013) to load OpenH264 into a sacrificial process.
12. **T-016.13: SDDL blocks the implant's own C2 thread pool.** Symptom: `NtOpenProcess` from a sibling thread fails. Workaround: the SDDL grants `OW` (owner) full access — verify the implant thread runs as the process owner.

## Variant Ideas

- **T-015 + T-014 fusion**: The `NtCreateUserProcess` path in T-015 *is* T-014's mechanism. Consolidate into a single `spawn_sacrificial(spoofed_ppid: Option<HANDLE>)` function. Operator benefit: one code path, one syscall footprint, one detection surface.
- **T-015 with sibling PID spoofing**: Add `PsAttributeClientId` to the `PS_ATTRIBUTE_LIST` to also fake the TID's reported parent. Useful when the SOC correlates `TID` → owner thread.
- **T-016.5 stack spoof with CFG-aware frame construction**: Build fake frames that pass Control Flow Guard's `__guard_check_icall_fptr` validation. Currently the advanced version constructs legitimate-looking frames but doesn't ensure CFG accepts them.
- **T-016.1 AMSI HBP with DR1/DR2 fallback**: If DR0 is occupied, install on DR1. Few EDRs use more than one debug register per thread.
- **T-016.3 ETW muffle via provider GUID patching**: Instead of zeroing `EnableInfo.IsEnabled`, walk the `_ETW_GUID_ENTRY` list and unlink offending providers entirely. More aggressive but defeats re-enable by EDR.
- **T-016.6 PEB unlink with `InExceptionContextList` unlink**: Some EDRs (Elastic) walk `LdrpInvertedFunctionTable` and the `InExceptionContextList` to find unloaded modules. Unlink these too.
- **T-016.11 NTDLL unhook from `\\KnownDlls\\ntdll.dll` section**: `NtOpenSection` on `\\KnownDlls\\ntdll.dll`, `MapViewOfSection`, copy `.text` from there. Avoids disk read of `ntdll.dll` (defeats file-monitoring EDRs that flag reads of system DLLs).
- **T-015 PPID spoof with primary token duplication**: Combine with `NtSetInformationProcess(ProcessAccessToken)` to also duplicate the parent's primary token — defeats token-based process ancestry heuristics.
- **T-016.13 Block-handle with `NtSetInformationProcess(ProcessAccessRights, class ProcessMachineType)`**: Newer Win10/11 mitigation classes allow restricting handle types. Combine with the SDDL approach for defense-in-depth.
- **T-016 hybrid KiUserException StepOver + stack spoof**: When the StepOver VEH fires, the stack at that moment shows the hooked stub. Spoof the VEH-handler stack itself before returning — currently only the post-NtContinue stack is spoofed.

## OPSEC Notes

### Artifacts Left Behind

- **T-015**: `NtOpenProcess` on `explorer.exe` (handle in target's handle table — visible via `SystemHandleInformation` query). Clean up: `NtClose` immediately after `NtCreateUserProcess`. Process creation event records the spoofed PPID — no rollback possible.
- **T-016.1 (AMSI HBP)**: DR0 set on the calling thread's context. Visible via `NtGetContextThread` from external handles — pair with T-016.13 (block external handles) to prevent this. VEH handler registered via `RtlAddVectoredExceptionHandler` — appears in `NT_TIB->ExceptionList` (legacy) or `KERNEL_DESCRIPTOR_TABLE_ENTRY` — visible via `RtlpVehList` walk.
- **T-016.3 (ETW muffle)**: No byte patching → no static signature. The zeroed `EnableInfo.IsEnabled` flags are in `ntdll.data` — an EDR with a baseline hash of `ntdll.data` would detect. Apply *after* the EDR has taken its baseline.
- **T-016.4/5 (Stack spoof)**: Returns to a synthetic stack — `RtlVirtualUnwind` from a EDR stack walker may fail or return synthetic frames. Some EDRs (Elastic Endgame) flag inconsistent frame chains.
- **T-016.6 (PEB unlink)**: Loader lock acquisition is a notable event — `LdrLockLoaderLock` shows in ETW `Loader` provider events if enabled.
- **T-016.11 (NTDLL unhook)**: `NtCreateFile(\??\C:\Windows\System32\ntdll.dll)` is a high-signal file read event in Sysmon EID 11 if `ntdll.dll` is in the targeted files list.
- **T-016.12 (Block-DLL)**: Process is one of a small set on a typical endpoint with `MicrosoftSignedOnly` enabled. EDR with `PROCESS_MITIGATION_POLICY` enumeration will see this as anomalous.
- **T-016.13 (Block external handles)**: The SDDL is queryable via `NtQuerySecurityObject` — the `Deny ALL for Everyone` ACE is a known IoC.

### Telemetry It Generates

- **Kernel ETW `Process/Start`** records spoofed PPID (T-015) — clean
- **Kernel ETW `Image/Load`** for the spawned child (T-015) — clean (legit image)
- **Kernel ETW `File/Create`** for `ntdll.dll` read (T-016.11) — flag if monitored
- **NT `AuditProcessAccess`** for `NtOpenProcess` on `explorer.exe` (T-015) — flag if object-access auditing is on
- **Process Mitigation Events** (Sysmon EID 1 mitiga field, if `ProcessMitigationPolicy` enabled) for Block-DLL (T-016.12) — high-signal

### Cleanup Procedures

- Before exit: `RtlRemoveVectoredExceptionHandler` on the AMSI HBP, KiStepOver, and PAGE_GUARD handlers (in reverse order of registration)
- Restore DR0–DR3 via `NtSetContextThread` with zeroed `DebugControl` and `Dr0–Dr7`
- Re-acquire loader lock and re-link the PEB module (if you need a clean exit; for most engagements, just bail)
- Restore `EnableInfo.IsEnabled` flags (optional — the EDR will re-enable them on next event)
- Restore the `ProcessParameters->CommandLine` original buffer pointer (T-016.8) and free the leaked buffer
- Undo Block-DLL policy (optional; if you want the process to look normal on exit)
- Remove the SDDL DACL on the process handle (T-016.13)

## Reusable Patterns

### Pattern: RecycledGate-Dispatched NT Process Manipulation

- **Use when**: Any time you manipulate a process via NT APIs (open, create, set info, suspend, resume, terminate) and need to avoid `ntdll!Nt*` inline hooks.
- **How**: Wrap each `Nt*` call in `recycled!(NtXxx, arg1, arg2, ...)`. The macro resolves SSN via T-001/T-002 at first call (OnceLock-cached) and dispatches through a gadget inside `ntdll!.text` (never leaving MEM_IMAGE-backed execution).
- **Code ref**: `crowd/src/ppid.rs` (NtOpenProcess, NtCreateUserProcess, NtSetInformationProcess), `crowd/src/policy.rs`, `crowd/src/block_handle.rs`.

### Pattern: `#[must_use]` RAII Spoof Guard

- **Use when**: Any temporary state mutation that must be reverted on scope exit (stack spoof, PEB unlink, mitigation policy toggle, VEH handler install).
- **How**: Define `pub struct SpoofGuard { saved_state: ... }` with `#[must_use]` on the constructor. `Drop` restores. Compile error if the caller forgets to bind.
- **Code ref**: `crowd/src/stack_spoof.rs` `SpoofGuard`. Apply this pattern to `MitigationPolicyGuard` (T-016.12), `LoaderLockGuard` (T-016.6), `VehHandlerGuard` (T-016.1, T-016.7).

### Pattern: ReactOS-Source NT Struct Definitions

- **Use when**: `windows-sys`/`windows-rs` lacks a struct (PS_ATTRIBUTE_LIST, PS_CREATE_INFO, ETW_GUID_ENTRY, RUNTIME_FUNCTION extensions).
- **How**: `#[repr(C)] struct PsAttributeList { total_length: usize, attributes: [PsAttribute; 1] }` with manual layout. Verify offsets with `core::mem::offset_of!` in a test against `nt!_PS_ATTRIBUTE_LIST` in WinDbg.
- **Code ref**: `crowd/src/ppid.rs`, `crowd/src/etw.rs`, `crowd/src/stack_spoof.rs`.

### Pattern: TLS-Persisted Per-Thread Evasion State

- **Use when**: Evasion state (stack info, spoof context, current spoof depth) needs to survive across function calls in the same thread but be isolated between threads.
- **How**: `TlsAlloc` once (OnceLock the slot index), `TlsSetValue` on entry to the trampoline, `TlsGetValue` inside. Drop clears the slot.
- **Code ref**: `crates/core/src/experimental/evasion/advanced_stack.rs` `NewStackInfo`.

### Pattern: Atomic Array Slot Pool for Hardware Breakpoints

- **Use when**: Multiple hardware-breakpoint targets (KiUserException StepOver, AMSI HBP, anti-debug traps) need to coexist within DR0–DR3 limits.
- **How**: `static SLOTS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];`. `claim()` scans for a 0 entry and CAS a target address in. `release(target)` zeros the matching slot.
- **Code ref**: `crowd/src/ki_step_over.rs`.