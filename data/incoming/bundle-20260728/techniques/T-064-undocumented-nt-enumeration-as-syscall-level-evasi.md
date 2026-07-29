---
id: T-064
name: Undocumented NT Enumeration as Syscall-Level Evasion Primitive
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1057
mitre_secondary: [T1106]
tags: [ntquerysysteminformation, native-api, process-enumeration, hook-bypass, undocumented-api, direct-syscall, recon]
origin: atlas-synthesis
member_notes: [lgtm:undocumented-nt-enum-evasion-primitive]
---

# Undocumented NT Enumeration as Syscall-Level Evasion Primitive — NtQuerySystemInformation Reconnaissance

## Summary

Undocumented NT enumeration replaces documented Win32 discovery APIs with direct calls to native system services — principally NtQuerySystemInformation — so that reconnaissance traffic never crosses the user-mode API surface where EDR hooks and API-monitoring ETW providers concentrate. SEC670 explicitly frames NtQuerySystemInformation as the undocumented alternative to EnumProcesses, WTSEnumerateProcessesEx, and CreateToolhelp32Snapshot for process enumeration, returning the same process inventory without touching psapi, kernel32, or WTS API entry points. The trade is implementation complexity: the caller must manage buffer sizing against STATUS_INFO_LENGTH_MISMATCH and parse the linked SYSTEM_PROCESS_INFORMATION structures directly. On modern hosts where EDR also hooks ntdll, the primitive composes with direct or indirect syscall dispatch to remain effective. The detection surface shifts from Win32 API telemetry to ntdll hook coverage and syscall-origin analysis.

## Mechanism

1. Resolve NtQuerySystemInformation without a static import — walk the PEB and ntdll export table by hash rather than calling GetProcAddress, keeping the IAT clean of enumeration-related entries.
2. Allocate a growable buffer with NtAllocateVirtualMemory. NtQuerySystemInformation has no size-query contract for most classes; the caller guesses, checks the status, and retries.
3. Call NtQuerySystemInformation with SystemInformationClass set to SystemProcessInformation (class 5). On STATUS_INFO_LENGTH_MISMATCH (0xC0000004), double the buffer and retry until STATUS_SUCCESS.
4. Walk the returned chain: each SYSTEM_PROCESS_INFORMATION begins with NextEntryOffset (ULONG at offset 0), which links to the next entry; a value of zero terminates the list. Per entry, read UniqueProcessId, InheritedFromUniqueProcessId, SessionId, HandleCount, NumberOfThreads, CreateTime, and the ImageName UNICODE_STRING, whose Buffer pointer references the process-name string stored inline after the fixed fields.
5. For thread-level detail, parse the Threads array of SYSTEM_THREAD_INFORMATION structures that follows each entry's fixed fields — NumberOfThreads gives the count — exposing per-thread create time, start address, state, and wait reason without opening any thread handle.
6. Extend to adjacent classes as the mission requires: SystemModuleInformation (class 11) for the kernel driver list — the EDR driver inventory — SystemHandleInformation (class 16) for the system-wide handle table, and SystemCodeIntegrityInformation for CI policy state.
7. Where ntdll itself is hooked, dispatch the call as a direct or indirect syscall with the SSN resolved independently, bypassing the ntdll stub entirely.

## OS Internals Context

NtQuerySystemInformation is the kernel's general-purpose system-state query interface: (SystemInformationClass, SystemInformation buffer, SystemInformationLength, ReturnLength). The kernel copies class-specific data into the caller's buffer with no capability check for the basic classes, and — operationally decisive — the call returns global state without opening a single process or thread handle. Every documented enumeration API eventually funnels here: EnumProcesses in psapi is a wrapper over this syscall, and the Toolhelp32 snapshot path captures the same underlying process list. The Win32 layer adds nothing but convenience and a hooking surface.

The SYSTEM_PROCESS_INFORMATION layout is a forward-linked array rather than a true array: entries are variable-length because the thread array trails the fixed fields, so navigation is by NextEntryOffset arithmetic only. Fixed fields include CreateTime, UserTime, and KernelTime as LARGE_INTEGERs, the ImageName UNICODE_STRING, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId, HandleCount, and SessionId. Because no handles are opened, the enumeration generates no ObRegisterCallbacks telemetry — the kernel object-manager callbacks that fire on OpenProcess are how many sensors detect process reconnaissance, and this path produces none of it.

The evasion delta is real but bounded. Hooking at the psapi or kernel32 layer misses the direct ntdll call entirely, which is why the material positions the primitive as an evasion technique. However, the standard modern EDR posture hooks ntdll exports as well, so NtQuerySystemInformation called through the ntdll stub is still visible to that class of sensor. The primitive's full strength appears only when combined with the vault's syscall-dispatch capabilities — SSN resolution plus an indirect-syscall gadget — at which point the enumeration never traverses any user-mode stub at all. The remaining observability is kernel-side: syscall-origin heuristics that flag system calls issued from non-ntdll memory.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The codebase already demonstrates the adjacent pattern: per T-020, the Kaguya module (dark_crystal/crowd/src/kaguya.rs) performs security-product detection via NtQuerySystemInformation, resolved and dispatched without Win32 API calls. A dedicated implementation of this card's primitive would generalize that into a standalone enumeration module: resolve the native function through the existing PEB-walker and DJB2-hash resolution, grow the query buffer on STATUS_INFO_LENGTH_MISMATCH, and expose parsed process, module, and handle inventories to the recon, injection-target-selection, and security-product-detection consumers.

## Why It Matters

Discovery is the first thing an implant does and one of the first places defenders instrument. Replacing the documented enumeration APIs with direct NT queries removes the recon phase from the most heavily hooked API layer, and doing it without opening process handles removes object-manager callback telemetry as well. As a composable primitive, it upgrades every consumer — LOtL inventory, injection target selection, EDR product detection — without changing their logic.

## Detection Considerations

- **Telemetry sources**: Inline ntdll hooks on NtQuerySystemInformation (standard modern EDR coverage) see the call unless dispatched as a direct syscall. Kernel ETW threat-intelligence feeds and syscall-origin analysis flag syscalls issued from memory outside ntdll. Documented-API ETW providers and psapi-layer hooks see nothing.
- **Bypass options**: Direct or indirect syscall dispatch with independently resolved SSNs defeats ntdll hooks; NTDLL unhooking restores a clean stub for the indirect path. Rate-limiting repeated queries avoids behavioral correlation.
- **Residual artifacts**: None on disk and no handles opened. The query buffer exists only in process memory for the duration of the parse.

## Related Techniques

- **T-004 PEB Walker** — provides the import-free resolution of NtQuerySystemInformation that keeps the IAT clean.
- **T-016 EDR Evasion Suite** — NTDLL unhooking and indirect-syscall composition are what keep this primitive effective against sensors that hook ntdll itself.
- **T-023 Client Capabilities Suite** — client reconnaissance features are the consumers of enumeration data produced through this path.

## References

- Atlas material: atlas-enumeration-part1.md
- MITRE ATT&CK: T1057 (https://attack.mitre.org/techniques/T1057/)
- LGTM notes: lgtm:undocumented-nt-enum-evasion-primitive

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.