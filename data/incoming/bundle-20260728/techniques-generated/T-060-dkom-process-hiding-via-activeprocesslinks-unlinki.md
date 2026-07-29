---
id: T-060
name: DKOM Process Hiding via ActiveProcessLinks Unlinking
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1564
tags: [dkom, kernel-mode, process-hiding, activeprocesslinks, eprocess, direct-kernel-object-manipulation, pspcidtable, coverage-gap]
origin: atlas-synthesis
member_notes: [lgtm:dkom-process-hiding]
---

# DKOM Process Hiding via ActiveProcessLinks Unlinking — Kernel-Mode Process Concealment

## Summary

Direct Kernel Object Manipulation (DKOM) process hiding removes a target process from the `_EPROCESS.ActiveProcessLinks` doubly-linked list, rendering it invisible to every documented user-mode process enumeration API. Unlike user-mode PEB unlinking (T-016), which only removes a module from the loaded module list, DKOM operates on the kernel's own process list and eliminates the process from `NtQuerySystemInformation`, `EnumProcesses`, `CreateToolhelp32Snapshot`, and `WmiGetProcess` results simultaneously. The technique requires kernel-mode write access to the `_EPROCESS` structure, obtained either through a loaded vulnerable driver (BYOVD) or a kernel-mode implant component. The primary detection vector is comparing `PspCidTable` handle entries against the `ActiveProcessLinks` list to identify orphaned process objects that have been unlinked.

## Mechanism

1. Obtain kernel-mode code execution. Common paths include loading a vulnerable signed driver via the service control manager (BYOVD), exploiting a kernel vulnerability, or having an existing kernel-mode implant component already resident.

2. Locate the target process's `_EPROCESS` structure. Methods include walking `PsActiveProcessHead` (the head of the kernel's active process list) by following `LIST_ENTRY` links until the target `ImageFileName` or `UniqueProcessId` matches, or using `NtQuerySystemInformation` with `SystemHandleInformation` to find the `_EPROCESS` address from a handle obtained in user mode.

3. Read the `ActiveProcessLinks` field from the target `_EPROCESS`. This is a `LIST_ENTRY` structure containing `Blink` (backward link, pointer to the previous entry's `LIST_ENTRY`) and `Flink` (forward link, pointer to the next entry's `LIST_ENTRY`). The field offset within `_EPROCESS` varies by Windows build and must be resolved dynamically or hardcoded for the target OS version.

4. Unlink the target process from the list. Set `target->ActiveProcessLinks.Blink->Flink = target->ActiveProcessLinks.Flink` and `target->ActiveProcessLinks.Flink->Blink = target->ActiveProcessLinks.Blink`. This splices the target out of the doubly-linked list, connecting its predecessor directly to its successor.

5. Self-reference the unlinked entry to prevent kernel blue screens. Set `target->ActiveProcessLinks.Flink = &target->ActiveProcessLinks` and `target->ActiveProcessLinks.Blink = &target->ActiveProcessLinks`. If this step is omitted, any kernel code that iterates the list and reaches the unlinked entry may follow stale pointers, causing an unhandled page fault and system crash.

6. Optionally update the `ProcessLinks` in the target's parent `_EPROCESS` if the parent tracks child processes via a separate list, though this is not strictly necessary for hiding from standard enumeration APIs.

7. The target process now continues executing normally — its threads are still scheduled by the kernel dispatcher, its handle table remains valid, and its virtual memory is intact — but no user-mode API that walks `ActiveProcessLinks` can discover it.

## OS Internals Context

The `_EPROCESS` structure is the kernel's primary process object. It contains the `ActiveProcessLinks` field as a `LIST_ENTRY` that threads the process into the global active process list headed by `PsActiveProcessHead`. Every user-mode enumeration API ultimately walks this list:

- `NtQuerySystemInformation` with `SystemProcessInformation` calls `ExpGetProcessInformation`, which iterates `ActiveProcessLinks`.
- `EnumProcesses` (psapi) and `CreateToolhelp32Snapshot` both ultimately call `NtQuerySystemInformation` internally.
- The Task Manager process list is populated from the same source.

The `PspCidTable` is the system-wide CID (Client ID) handle table, which maps process and thread IDs to their `_EPROCESS` and `_ETHREAD` objects. This table is separate from `ActiveProcessLinks` and is not modified by the standard DKOM unlinking procedure. An entry in `PspCidTable` for the hidden process persists, which is the primary detection vector: a scanner that enumerates `PspCidTable` and cross-references against `ActiveProcessLinks` will find processes present in the handle table but absent from the process list.

The `PsSetCreateProcessNotifyRoutine` callback mechanism fires `PsSetCreateProcessNotifyRoutineEx` callbacks during process creation and termination. These callbacks execute before DKOM unlinking can occur (unless the unlinking happens during the creation callback itself, which is not practical). A properly registered EDR kernel driver that records process creation events via this callback will have already captured the process before it is hidden. This makes DKOM a post-creation hiding technique — it cannot prevent the creation notification from firing.

The `LIST_ENTRY` self-referencing trick (step 5) exploits the fact that kernel code that walks the list checks for the list head sentinel rather than for self-referencing entries. By pointing both `Flink` and `Blink` at the entry's own `LIST_ENTRY`, the entry becomes a one-element circular list that appears as a terminated list to any traversal that reaches it.

The offset of `ActiveProcessLinks` within `_EPROCESS` varies across Windows versions. On Windows 10 1809 (x64), it is at offset 0x448; on Windows 10 21H2 (x64), it may be at 0x448 or nearby depending on the build. An implementation must either hardcode offsets per OS version or resolve them dynamically by pattern-scanning the kernel image.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The HUGIN source contains `dark_crystal/crowd/src/block_handle.rs`, which implements user-mode handle blocking via `NtSetSecurityObject` to deny `PROCESS_ALL_ACCESS` to external processes. This is a fundamentally different technique — it restricts access to the process via security descriptors rather than hiding it from enumeration via kernel list manipulation. DKOM requires kernel-mode execution, which the current HUGIN crate does not provide directly; the BYOVD module (`dark_crystal/crowd/src/byovd.rs`) could serve as a prerequisite component to obtain the kernel-mode write capability needed for DKOM.

An implementation would require: a kernel-mode component (driver or shellcode executing in ring 0), the target `_EPROCESS` offset resolution for `ActiveProcessLinks`, a safe `LIST_ENTRY` unlinking routine with self-referencing, and a method to locate the target process's `_EPROCESS` address from kernel context. The BYOVD loader already present in HUGIN could provide the initial kernel-mode execution vehicle.

## Why It Matters

DKOM process hiding represents the kernel-mode counterpart to user-mode PEB unlinking documented in T-016. Where PEB unlinking only removes a DLL from the loaded module list (visible to module-walkers but not process-enumerators), DKOM removes the entire process from the kernel's active process list, making it invisible to all documented enumeration APIs simultaneously. The technique fills the gap for scenarios where an implanted process must be completely hidden from system administration tools and EDR process enumeration, not just from module-list inspection. The high privilege requirement (kernel-mode write) limits its applicability to operations where a vulnerable driver or kernel implant is already available.

## Detection Considerations

- **Telemetry sources**: EDR products with kernel drivers can enumerate `PspCidTable` and cross-reference against `ActiveProcessLinks`. Orphaned entries — processes in the handle table but not in the active process list — indicate DKOM hiding. `PsSetCreateProcessNotifyRoutineEx` callbacks fire at process creation time, before unlinking occurs, so a properly registered callback has already recorded the process.

- **Bypass options**: Some implementations also remove the `PspCidTable` entry (more complex, higher risk of instability) to eliminate the cross-reference detection vector. This requires manipulating the `EX_HANDLE_TABLE` structure and is significantly more dangerous.

- **Residual artifacts**: The hidden process still consumes memory, CPU time, and handles. Performance anomaly detection (unexpected CPU usage with no visible consuming process) can reveal hidden processes. Thread-level enumeration via `NtQuerySystemInformation` with `SystemThreadInformation` may still reveal threads belonging to the hidden process, since threads are linked through `_ETHREAD.ThreadListHead` which is not modified by standard DKOM.

Training material does not discuss detection beyond the `PspCidTable` comparison technique and the `PsSetCreateProcessNotifyRoutine` callback limitation.

## Related Techniques

- **T-016 EDR Evasion Suite** — PEB unlink is the user-mode counterpart; DKOM is the kernel-mode escalation of the same hiding concept
- **T-013 Remaining Injection Methods** — DKOM can hide processes that have been injected into or hollowed, complementing injection techniques with concealment

## References

- Atlas material: atlas-post-exploit-part2.md (units 5, 33, 34, 35)
- MITRE ATT&CK: T1564 — https://attack.mitre.org/techniques/T1564/
- LGTM notes: lgtm:dkom-process-hiding
- Public references: SEC670 course material (_EPROCESS structure and DKOM attacks)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. The BYOVD module in `dark_crystal/crowd/src/byovd.rs` provides the kernel-mode execution prerequisite.