---
id: T-082
name: NtQuerySystemInformation Process Enumeration
category: discovery
tier: A
crate: none
source_file: none
mitre: T1057
mitre_secondary: []
tags: [ntquerysysteminformation, process-enumeration, native-api, evasion, system-process-information, linked-list, two-pass-allocation, syscall-level]
origin: atlas-synthesis
member_notes: ['lgtm:native-process-enumeration-coverage', 'lgtm:undocumented-native-api-process-enum']
---

# NtQuerySystemInformation Process Enumeration — Native System Process List via Undocumented Information Class

## Summary

NtQuerySystemInformation with SystemProcessInformation (information class 5) enumerates all processes and threads on the system through a single native syscall, returning a linked-list buffer of SYSTEM_PROCESS_INFORMATION structures that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next enumeration path EDR products commonly monitor. The technique replaces three Win32 API calls — snapshot creation plus first and next iteration — with a single NtQuerySystemInformation invocation followed by linked-list traversal within the returned buffer. The two-pass allocation pattern, calling with a NULL buffer to obtain required size then allocating and retrying, is the standard idiom for variable-length system information queries. The buffer contains process name, PID, thread count, handle count, parent PID, and creation timestamp for every process in the system. The primary detection surface is NtQuerySystemInformation itself if hooked by EDR, but the technique avoids the layered Win32 toolhelp API and its associated telemetry.

## Mechanism

1. The implant calls NtQuerySystemInformation with the `SystemProcessInformation` information class (value 5), a NULL output buffer pointer, and a buffer length of zero. The call returns STATUS_INFO_LENGTH_MISMATCH (0xC0000004) and sets the `ReturnLength` output parameter to the total byte count required to hold the full process list at the moment of the call.

2. The implant allocates a buffer of `ReturnLength` bytes using NtAllocateVirtualMemory or HeapAlloc. The buffer must be contiguous because the returned data is a linked list where each entry's `NextEntryOffset` field is a relative byte offset from the current entry to the next entry within the same buffer. Implants typically allocate `ReturnLength + 4096` to account for the race condition where new processes appear between the size-query call and the data-fill call.

3. The implant retries NtQuerySystemInformation with `SystemProcessInformation`, the allocated buffer, and the buffer length. On success, the call returns STATUS_SUCCESS (0x00000000) and the buffer is populated with a sequence of SYSTEM_PROCESS_INFORMATION structures.

4. The implant walks the linked list starting at the buffer base address:
   - Read `NextEntryOffset` (ULONG at offset 0x00) of the current entry.
   - If `NextEntryOffset` is 0, the current entry is the last entry — stop traversal.
   - Otherwise, advance the read pointer by `NextEntryOffset` bytes (not by `sizeof(SYSTEM_PROCESS_INFORMATION)`) to reach the next entry. This variable-length encoding accommodates entries with longer image names, because the UNICODE_STRING buffer for ImageName is appended to each fixed-size structure and the total entry size varies.

5. Per entry, the implant extracts the following fields on x64:
   - **UniqueProcessId** (HANDLE at offset 0x80) — the process ID.
   - **ImageName** (UNICODE_STRING at offset 0x88) — the process image name (e.g., `lsass.exe`). The UNICODE_STRING's Buffer pointer references memory within the same system information buffer, so the string data is valid for the lifetime of the buffer.
   - **NumberOfThreads** (ULONG at offset 0x278) — count of threads in this process.
   - **HandleCount** (ULONG at offset 0x288) — number of open handles in the process handle table.
   - **CreateTime** (LARGE_INTEGER at offset 0x98) — process creation timestamp in FILETIME format.
   - **InheritedFromUniqueProcessId** (HANDLE at offset 0x140) — parent process PID.

6. The enumeration results feed injection target selection: processes with known DLL loading patterns (notepad.exe, svchost.exe, explorer.exe) become injection candidates; processes with specific integrity levels or session IDs inform cross-session injection planning (T-047); the parent PID map reveals process ancestry for PPID spoofing (T-015).

7. For per-process detail beyond what SystemProcessInformation provides, the implant pairs this enumeration with NtQueryInformationProcess(ProcessBasicInformation, information class 0) on individual process handles obtained via OpenProcess. ProcessBasicInformation returns a PROCESS_BASIC_INFORMATION structure containing the PEB address (PebBaseAddress field), which enables direct PEB reading for module list enumeration, command line extraction via ProcessParameters, and process path retrieval — all through native NT APIs without invoking any Win32 process enumeration function.

## OS Internals Context

NtQuerySystemInformation is exported by ntdll.dll and performs a syscall into the kernel via the syscall number assigned to NtQuerySystemInformation on the current Windows build. The kernel-side implementation resides in ntoskrnl.exe, function `ExpQuerySystemInformation`, which dispatches to the appropriate information class handler based on the `SystemInformationClass` parameter. For SystemProcessInformation (class 5), the handler iterates the active process list — linked via the `ActiveProcessLinks` LIST_ENTRY field in each EPROCESS structure — and serializes each process's information into the output buffer.

The SYSTEM_PROCESS_INFORMATION structure is variable-length because the ImageName field is a UNICODE_STRING containing a pointer to a variable-length buffer. The kernel writes the name buffer immediately after the fixed portion of each structure entry, and the `NextEntryOffset` field accounts for this variable size. This design means the implant cannot use `sizeof(SYSTEM_PROCESS_INFORMATION)` to advance between entries — it must use the `NextEntryOffset` relative offset, because consecutive entries are not necessarily `sizeof(SYSTEM_PROCESS_INFORMATION)` apart.

The contrast with CreateToolhelp32Snapshot is architectural: CreateToolhelp32Snapshot creates a snapshot handle via an internal NtCreateSnapshot call, then Process32First and Process32Next iterate using that handle. The snapshot mechanism copies process information at snapshot creation time into a kernel-allocated buffer, while NtQuerySystemInformation(SystemProcessInformation) queries the live process list at call time. The Win32 toolhelp path involves multiple syscalls (create snapshot, then first, then next per iteration — one syscall per process in the list), while the NtQuerySystemInformation path involves one or two syscalls total (query for size, then query for data). The reduced syscall count reduces the hook surface area and the number of EDR interception points. Additionally, the snapshot handle itself is observable: EDR can enumerate process handles and detect a snapshot handle with the specific type and access mask that toolhelp creates.

WTSEnumerateProcesses provides a third enumeration path that queries the Terminal Server service (TermSrv) via RPC. It returns process information including session IDs and user SIDs — fields not present in SYSTEM_PROCESS_INFORMATION — but requires the WTS service to be running and generates RPC traffic to the TermSrv endpoint, which is observable via RPC ETW providers.

The two-pass allocation pattern is necessary because the process list is dynamic: between the first call (which returns the required size) and the second call (which fills the buffer), new processes may appear or existing processes may exit. The kernel handles this by truncating the output at the buffer boundary and returning STATUS_INFO_LENGTHMismatch if the buffer is still too small for the current process list. Implants account for this race condition by over-allocating or by retrying in a loop until STATUS_SUCCESS is returned.

The SYSTEM_PROCESS_INFORMATION structure also contains per-thread information: the `Threads` array (starting at offset 0x2D0 on x64) contains SYSTEM_THREAD_INFORMATION entries, each with StartAddress, ClientId (thread TID + PID), Priority, and State. This provides thread-level enumeration in the same buffer without separate calls to NtQueryInformationThread — useful for thread hijack target selection (T-073) because the StartAddress field identifies threads whose start address points into a loaded module's code section, indicating a stable thread for context hijack.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `def.rs` file in the VEH module defines PEB, LDR_DATA_TABLE_ENTRY, ImageDosHeader, ImageNtHeaders, and related structures but does not define SYSTEM_PROCESS_INFORMATION or invoke NtQuerySystemInformation for process enumeration. The `protocol.rs` file defines `MSG_PROCESS_LIST` (0x0A) as a message type for sending process list data from client to server, indicating the client protocol supports process list reporting, but the enumeration logic that would populate this message is not present in the provided source files. An implementation would: (1) resolve NtQuerySystemInformation's SSN via the HUGIN syscall resolution cascade (T-002 Hell's Gate / Tartarus Gate or T-001 RecycledGate for indirect dispatch), (2) define a `#[repr(C)]` struct matching the SYSTEM_PROCESS_INFORMATION layout with fields at the offsets documented above, (3) implement the two-pass allocation pattern using the resolved syscall, (4) walk the linked list via `NextEntryOffset` using raw pointer arithmetic, and (5) serialize the extracted process entries as JSON into a MSG_PROCESS_LIST message for transmission to the C2 server via the `build_message` function in `protocol.rs`.

## Why It Matters

Process enumeration is the prerequisite step for nearly every process injection technique in the vault (T-007 through T-013). The choice of enumeration API determines which detection channels observe the enumeration: CreateToolhelp32Snapshot generates a snapshot handle that EDRs can detect via handle enumeration; WTSEnumerateProcesses generates RPC traffic to the Terminal Server; NtQuerySystemInformation generates a single native syscall that may be hooked but does not produce the layered telemetry of the Win32 path. SEC670 explicitly frames NtQuerySystemInformation as the evasion-friendlier alternative to the documented Win32 enumeration APIs, placing it alongside NtQueryInformationProcess and other native NT enumeration functions as tools for reducing the implant's API footprint. Documenting this as a distinct technique ensures operators can select the enumeration path that matches their evasion posture rather than defaulting to CreateToolhelp32Snapshot, which is the most commonly detected enumeration interface.

## Detection Considerations

- **Telemetry sources**: If EDR hooks NtQuerySystemInformation in ntdll.dll (common practice for process-monitoring EDRs), the call is intercepted and the parameters are inspected. The Microsoft-Windows-Kernel-Process ETW provider ({22fb2cd6-0e7b-422b-a12c-984e92ed35d6}) can capture process enumeration events if enabled. Sysmon does not specifically capture NtQuerySystemInformation calls. The Microsoft-Windows-Kernel-General ETW provider may log system information queries at high verbosity levels.
- **Bypass options**: Using indirect syscalls (T-001 RecycledGate) to invoke NtQuerySystemInformation bypasses ntdll.dll hooks by executing the syscall instruction from a MEM_IMAGE-backed gadget rather than from the ntdll.dll stub. Using the VEH syscall gate (T-003) dispatches the call through a hardware breakpoint-mediated exception handler, avoiding the ntdll.dll stub entirely. Reading the process list via EPROCESS walking through a loaded kernel driver (BYOVD, T-018) avoids the syscall entirely by reading kernel memory directly.
- **Residual artifacts**: No files or registry entries are created. The allocated buffer for the system information data is a user-mode memory allocation with no kernel handle table entry. The only observable artifact is the syscall instruction execution, captured only if the EDR instruments the syscall instruction itself via kernel callbacks or if it hooks the ntdll.dll stub. The two-pass pattern — a failed call followed by a successful call with a large buffer — is a recognizable behavioral pattern if the EDR correlates sequential NtQuerySystemInformation calls.

## Related Techniques

- **T-007 Pool Party and Process Injection** — process enumeration is the prerequisite for injection target selection; this card documents the enumeration primitive that feeds the injection family
- **T-020 Anti-Analysis Suite** — anti-analysis checks may require process list access for detecting analysis tooling; NtQuerySystemInformation provides the evasion-friendlier enumeration path
- **T-023 Client Capabilities** — the client's recon module performs process enumeration; this card documents the native API path as an alternative to Win32 toolhelp
- **T-064 Undocumented NT Enumeration as Syscall-Level Evasion Primitive** — documents the broader pattern of using undocumented NT enumeration classes; this card is the process-list-specific instance of that general principle

## References

- Atlas material: atlas-binary-analysis-part2.md, atlas-edr-evasion-part1.md
- MITRE ATT&CK: T1057 — https://attack.mitre.org/techniques/T1057/
- LGTM notes: lgtm:native-process-enumeration-coverage, lgtm:undocumented-native-api-process-enum

## Source Reference

No current implementation. The `protocol.rs` file defines `MSG_PROCESS_LIST` (0x0A) indicating the protocol supports process list messages, but the enumeration logic using NtQuerySystemInformation is not present in the provided source files. See atlas material and Windows Internals 7ed for the SYSTEM_PROCESS_INFORMATION structure layout.