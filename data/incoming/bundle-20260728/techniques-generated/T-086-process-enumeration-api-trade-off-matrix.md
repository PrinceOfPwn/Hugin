---
id: T-086
name: Process Enumeration API Trade-off Matrix
category: discovery
tier: A
crate: none
mitre: T1057
tags: [process-enum, enumprocesses, toolhelp32-snapshot, wts-enumerate, ntquerysysteminfo, api-tradeoff, syscall-dispatch, recon]
origin: atlas-synthesis
member_notes: ['lgtm:process-enumeration-api-tradeoffs', 'lgtm:convergence-process-enum-api-tradeoffs', 'lgtm:coverage-gap-process-enumeration-variants', 'lgtm:ntquerysysteminformation-recon-via-syscall']
---

# Process Enumeration API Trade-off Matrix — Selecting the Right Process Discovery Primitive

## Summary

Windows exposes four distinct APIs for process enumeration, each with different metadata depth, session visibility, telemetry profiles, and hook susceptibility. The three documented Win32 APIs — K32EnumProcesses, CreateToolhelp32Snapshot, and WTSEnumerateProcessesEx — provide decreasing simplicity for increasing detail and remote capability. NtQuerySystemInformation with SystemProcessInformation (class 5) is the undocumented alternative that returns a linked list of SYSTEM_PROCESS_INFORMATION structures including thread data, CPU times, and image base addresses, bypassing userland hooks in ntdll when called via direct or indirect syscall. The HUGIN vault documents syscall dispatch mechanisms (T-001 through T-004) but does not currently map which recon-class Nt* calls pair with which dispatch mechanism within the same implant. This card bridges that gap by documenting the enumeration API matrix and the operational trade-offs that govern API selection.

## Mechanism

1. **K32EnumProcesses / EnumProcessModules** (psapi.dll): Takes a DWORD array pointer and array size, returns the number of PIDs written. Provides a flat PID list with no parent-child relationship, no process paths, and no session information. The simplest API to call but the least informative. Requires a second pass with EnumProcessModules and GetModuleFileNameEx to obtain executable names. Access is mediated through psapi.dll which forwards to NtQuerySystemInformation internally.

2. **CreateToolhelp32Snapshot** (kernel32.dll): Call with TH32CS_SNAPPROCESS (0x00000002) to create a snapshot of all processes. Returns a snapshot handle that must be closed with CloseHandle. Iterate with Process32FirstW / Process32NextW, which fill PROCESSENTRY32W structures containing th32ProcessID (DWORD), th32ParentProcessID (DWORD), szExeFile (WCHAR[MAX_PATH]), cntThreads (DWORD), and th32ModuleID. The snapshot is point-in-time and may be stale by the time it is consumed. The kernel allocates a handle for the snapshot, which is observable through handle table monitoring.

3. **WTSEnumerateProcessesEx** (wtsapi32.dll): Takes a WTS server handle (WTS_CURRENT_SERVER_HANDLE for local), a level parameter (1 for WTS_PROCESS_INFO, 0 for WTS_PROCESS_INFO_EX), and returns an array. WTS_PROCESS_INFO contains pProcessId, pSessionId, pProcessName, pUserSid. WTS_PROCESS_INFO_EX adds numberOfThreads, pageFaultCount, handleCount, peakWorkingSet, workingSetSize, peakPagedPool, pagedPoolUsage, peakNonPagedPool, nonPagedPoolUsage, pagefileUsage, peakPagefileUsage, privatePageCount. Supports remote server enumeration via WTSOpenServerW. Requires the caller to be a member of the local Administrators group for cross-session visibility. Must free the returned buffer with WTSFreeMemory.

4. **NtQuerySystemInformation** (ntdll.dll, syscall): Call with SystemProcessInformation (class 5). The returned buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures connected via NextEntryOffset (ULONG at offset 0x00). A value of 0 in NextEntryOffset indicates the last entry. Each structure contains: NumberOfThreads (offset 0x04),CreateTime (offset 0x10), UserTime (offset 0x20), KernelTime (offset 0x28), ImageName (UNICODE_STRING at offset 0x38), BasePriority (offset 0x48), UniqueProcessId (HANDLE/ULONG_PTR at offset 0x50), InheritedFromUniqueProcessId (offset 0x58), HandleCount (offset 0x60), SessionId (offset 0x68), PeakVirtualSize/VirtualSize (offset 0x70/0x78), PeakWorkingSetSize/WorkingSetSize (offset 0x90/0x98), and an array of SYSTEM_THREAD_INFORMATION entries starting at offset 0x80 (before UniqueProcessId on some layouts; structure offsets vary by Windows version and should be validated). When called via direct or indirect syscall (T-001 RecycledGate, T-002 Hell's Gate), this API bypasses userland hooks in ntdll's .text section.

## OS Internals Context

All four APIs ultimately query the same kernel data — the active process list rooted at a global list head in ntoskrnl, traversed via EPROCESS.ActiveProcessLinks (a LIST_ENTRY at a version-dependent offset in the EPROCESS structure). The differences lie in how the data is filtered, formatted, and delivered to user mode.

K32EnumProcesses internally calls NtQuerySystemInformation(SystemProcessInformation) and extracts only the PID field from each returned structure. The overhead of the full structure copy is incurred even though only PIDs are returned. CreateToolhelp32Snapshot creates a kernel snapshot object (not a copy — it takes a reference count on the process list state) and iterates it via the Toolhelp driver. The snapshot handle appears in the calling process's handle table and can be detected by EDR via NtQueryInformationProcess or handle table enumeration.

WTSEnumerateProcessesEx routes through the TermSrv (Terminal Services) service via RPC, which in turn calls NtQuerySystemInformation. The RPC layer adds network visibility (the call can target remote servers) but also adds RPC telemetry that the other APIs do not produce. The service requires the caller to have SE_DEBUG_PRIVILEGE or be a local admin for cross-session results.

NtQuerySystemInformation is the raw syscall path. When dispatched via indirect syscall (T-001 RecycledGate), the call originates from a gadget in ntdll's .text section, making the return address appear legitimate. The syscall number for NtQuerySystemInformation is resolved through the same SSN resolution cascade (T-002) used for write-class syscalls like NtAllocateVirtualMemory and NtProtectVirtualMemory. This means a single implant can use the same dispatch infrastructure for both injection operations and recon operations.

The SYSTEM_PROCESS_INFORMATION structure is not documented in the Windows Driver Kit (WDK) headers. Structure offsets vary between Windows versions. Operators using this API must maintain version-specific offset tables or dynamically validate offsets at runtime by parsing the structure against known sentinel values (e.g., UniqueProcessId for the current process equals the value returned by GetCurrentProcessId).

## Key Implementation Details

**No current implementation in the HUGIN source.** The provided source files do not implement any of the four process enumeration APIs. The broader HUGIN codebase references process enumeration in `src/client_rust/src/sysinfo_collect.rs` (system info collection) and `src/client_rust/src/byakugan.rs` (network recon), but these files were not available for verification.

An implementation would select the enumeration API based on operational requirements: for injection target selection where parent-child relationships matter, CreateToolhelp32Snapshot provides the th32ParentProcessID field needed to find spawned child processes. For cross-session injection (T-047), WTSEnumerateProcessesEx provides session IDs. For stealth-constrained operations where the implant already has indirect syscall infrastructure, NtQuerySystemInformation via RecycledGate avoids all Win32 API calls and produces no handle table entries.

## Why It Matters

The vault documents syscall dispatch (T-001 through T-004) and injection techniques (T-007 through T-015) as separate capabilities, but does not connect them to the recon surface that precedes injection. An operator selecting an injection target needs process metadata — PID, parent PID, session ID, image path — and the API chosen to obtain that metadata has its own detection profile. Using CreateToolhelp32Snapshot inside an implant that performs injection via indirect syscall creates an asymmetry: the injection is hook-free but the recon is hookable. Documenting which enumeration APIs pair with which dispatch mechanisms closes this tradecraft gap and lets operators select the lowest-telemetry enumeration path that meets their detail requirement.

## Detection Considerations

- **Telemetry sources**: CreateToolhelp32Snapshot generates a kernel snapshot handle visible via handle table enumeration and the Kernel-Process ETW provider (Microsoft-Windows-Kernel-Process, Event ID 4 for handle creation). K32EnumProcesses generates no direct ETW but calls NtQuerySystemInformation which is hookable in ntdll. WTSEnumerateProcessesEx generates RPC traffic to the TermSrv service, detectable via RPC ETW providers. NtQuerySystemInformation called via direct syscall bypasses ntdll hooks entirely; called via indirect syscall (RecycledGate), the return address appears to originate from ntdll .text.
- **Bypass options**: NtQuerySystemInformation via indirect syscall eliminates userland hooks and produces no handle table entries. The same SSN resolution cascade used for injection syscalls resolves the NtQuerySystemInformation SSN. The caller can filter results to extract only needed fields, reducing the data footprint.
- **Residual artifacts**: CreateToolhelp32Snapshot leaves a snapshot handle in the handle table until CloseHandle is called. WTSEnumerateProcessesEx leaves RPC binding handles. NtQuerySystemInformation leaves no handles — only an allocation for the output buffer that must be freed via NtFreeVirtualMemory.

## Related Techniques

- **T-001 RecycledGate** — Indirect syscall dispatch mechanism that can route NtQuerySystemInformation calls through ntdll gadgets, bypassing userland hooks
- **T-002 Hell's Gate** — SSN resolution cascade resolves the NtQuerySystemInformation syscall number alongside write-class syscalls
- **T-023 Client Capabilities** — Recon module uses process enumeration for injection target selection and situational awareness
- **T-007 Process Injection** — Process enumeration informs injection target selection based on process metadata including parent PID and session ID

## References

- Atlas material: atlas-recon-part1.md, atlas-recon-part4.md, atlas-recon-part5.md, atlas-recon-part7.md
- MITRE ATT&CK: T1057 — https://attack.mitre.org/techniques/T1057
- LGTM notes: lgtm:process-enumeration-api-tradeoffs, lgtm:convergence-process-enum-api-tradeoffs, lgtm:coverage-gap-process-enumeration-variants, lgtm:ntquerysysteminformation-recon-via-syscall
- Public references: SEC670 Units 15, 39-40 (process enumeration API comparison), Units 12-14 (NtQuerySystemInformation recon via syscall)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.