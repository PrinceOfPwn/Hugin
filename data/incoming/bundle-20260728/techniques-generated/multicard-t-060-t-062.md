<!-- BEGIN CARD T-060 -->
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
<!-- END CARD T-060 -->

<!-- BEGIN CARD T-061 -->
---
id: T-061
name: Registry Watchdog for Situational Awareness and AV Detection
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1518.001
tags: [registry, regnotifychangekey, situational-awareness, av-detection, watchdog, reg-notify-thread-agnostic, passive-monitoring, evasion-decision]
origin: atlas-synthesis
member_notes: [lgtm:registry-watchdog-situational-awareness]
---

# Registry Watchdog for Situational Awareness and AV Detection — Passive Registry Change Monitoring

## Summary

The registry watchdog technique uses `RegNotifyChangeKey` (and its native counterpart `NtNotifyChangeKey`) to receive asynchronous notifications when registry keys or values change, without resorting to polling. By monitoring `HKLM\SOFTWARE\Microsoft` and related subkeys, an implant detects AV/EDR product installation or configuration changes in real time. The `REG_NOTIFY_THREAD_AGNOSTIC` flag (available on Windows 8.1 and later) decouples notification delivery from the calling thread's lifetime, enabling a persistent watchdog that survives thread creation and termination within the implant's process. This technique provides operators with situational awareness that informs decisions about technique escalation, sleep timing, and evasion posture adjustments.

## Mechanism

1. Open the target registry key using `RegCreateKeyEx` or `RegOpenKeyEx` with `KEY_NOTIFY` access mask. The key path is typically `HKLM\SOFTWARE\Microsoft` or a more specific subkey such as `HKLM\SOFTWARE\Microsoft\Windows Defender` or `HKLM\SOFTWARE\Microsoft\Security Client`.

2. Call `RegNotifyChangeKey` with the following parameters:
   - `hKey`: handle from step 1
   - `hEvent`: optional event handle for asynchronous notification (pass `NULL` for blocking mode)
   - `dwNotifyFilter`: combination of `REG_NOTIFY_CHANGE_NAME` (0x1), `REG_NOTIFY_CHANGE_LAST_SET` (0x4), and `REG_NOTIFY_CHANGE_ATTRIBUTES` (0x2) to capture subkey creation, value modification, and attribute changes
   - `fAsynchronous`: `TRUE` if using an event handle, `FALSE` for blocking call
   - `dwFilter`: flags, including `REG_NOTIFY_THREAD_AGNOSTIC` (0x10000000)

3. If using blocking mode (`fAsynchronous = FALSE`), the call blocks until a change occurs in the monitored subtree. The calling thread is suspended by the kernel until the configuration manager signals a change.

4. If using asynchronous mode (`fAsynchronous = TRUE`), associate the event handle with the notification. Use `WaitForSingleObject` or `WaitForMultipleObjects` to wait on the event, allowing the implant to monitor multiple registry paths concurrently.

5. When the notification fires, enumerate the values and subkeys under the monitored path to determine what changed. Parse product names, version strings, and installation markers from registry values such as `ProductName`, `InstallState`, and `ServiceState`.

6. Cross-reference detected product identifiers against an internal AV/EDR fingerprint database to classify the installed product (e.g., Windows Defender, CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint).

7. Feed the classification into the implant's decision logic — escalate evasion measures, adjust sleep intervals, switch C2 channels, or trigger self-deletion sequences based on the threat assessment.

8. Re-register the notification (the call is one-shot — each `RegNotifyChangeKey` registration fires once per change event). Loop back to step 2 to continue monitoring.

## OS Internals Context

`RegNotifyChangeKey` is a user-mode wrapper in `advapi32.dll` that calls the native `NtNotifyChangeKey` system service. The kernel's configuration manager (CM) handles the notification registration by creating a `CM_NOTIFY_BLOCK` structure and inserting it into the key node's `NotifyList`. When a registry operation modifies the key or its subtree, the CM traverses the `NotifyList` and signals all registered notification blocks.

The notification filter flags map to specific CM operations:

- `REG_NOTIFY_CHANGE_NAME` (0x00000001): fires when a subkey is created or deleted. Internally, this maps to `CM_NOTIFY_KEY_NODE_CREATE` and `CM_NOTIFY_KEY_NODE_DELETE` events.
- `REG_NOTIFY_CHANGE_ATTRIBUTES` (0x00000002): fires when the key's attributes change (e.g., security descriptor modification).
- `REG_NOTIFY_CHANGE_LAST_SET` (0x00000004): fires when any value under the key is written, deleted, or modified. This is the primary filter for detecting AV product installation, as setup routines write product configuration values during installation.
- `REG_NOTIFY_CHANGE_SECURITY` (0x00000008): fires when the key's security descriptor changes.

The `REG_NOTIFY_THREAD_AGNOSTIC` flag (0x10000000), introduced in Windows 8.1, detaches the notification from the calling thread. Without this flag, the notification is associated with the calling thread's `TEB` and is automatically canceled when that thread terminates. With the flag, the notification persists at the process level and can be signaled to any thread that waits on the associated event. This enables an implant to register a watchdog from a short-lived thread and have a separate long-lived thread consume the notifications.

The CM notification mechanism is push-based — the kernel proactively signals registered waiters when changes occur, as opposed to the implant repeatedly querying registry values. This eliminates the I/O and CPU overhead of polling and avoids the behavioral fingerprint of periodic `RegQueryValueEx` calls against security product registry paths.

The notification is scoped to the key and its subtree. A registration on `HKLM\SOFTWARE\Microsoft` captures changes to all subkeys, including `HKLM\SOFTWARE\Microsoft\Windows Defender`, `HKLM\SOFTWARE\Microsoft\Powershell`, and third-party security product keys registered under this path.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

An implementation would reside in the `client_rust` crate as a background monitoring task. The structure would open the target registry key via the `winreg` crate or direct `NtNotifyChangeKey` calls through `wrappers.rs` FFI bindings, register the notification with `REG_NOTIFY_THREAD_AGNOSTIC | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME`, and spawn a worker thread (or use Tokio's blocking task pool) that blocks on the notification. Upon wake, the worker would enumerate changed values, classify detected products against a hardcoded fingerprint table, and emit an event to the implant's main state machine via a channel. The watchdog would re-register after each event to maintain continuous coverage.

The `REG_NOTIFY_THREAD_AGNOSTIC` flag is critical for Rust's async runtime model, where the thread that initiates the notification may differ from the thread that consumes the result. Without this flag, the notification would be silently canceled when the initiating Tokio worker thread moves to another task.

## Why It Matters

The registry watchdog fills a gap in the HUGIN vault's situational awareness capabilities. The existing anti-analysis suite (T-020) performs point-in-time AV detection via registry scanning and process enumeration, but has no mechanism for continuous, real-time detection of AV/EDR product installation during an active engagement. The watchdog approach generates no polling artifacts, consumes minimal CPU, and can detect products installed at any point during the implant's lifetime — including after initial reconnaissance has completed. This informs dynamic evasion decisions: an implant that detects CrowdStrike Falcon installation mid-engagement can switch to sleep-heavy patterns, adjust injection technique selection, or trigger self-deletion.

## Detection Considerations

- **Telemetry sources**: `RegNotifyChangeKey` calls are captured by Sysmon EID 12 (RegistryEvent:ObjectDelete/ValueSet) when the `RegistryMonitor` filter is configured. ETW providers `Microsoft-Windows-Kernel-Registry` (GUID: `{70EB4F8C-6113-414D-B49C-5345A3E2FFEE}`) log notification registrations. EDR products that hook `advapi32!RegNotifyChangeKey` or monitor `NtNotifyChangeKey` system calls can detect the notification registration.

- **Bypass options**: Calling `NtNotifyChangeKey` directly via resolved syscall stubs bypasses user-mode hooks on `advapi32.dll`. Using `RecycledGate` (T-001) or `VEH Gate` (T-003) for the syscall dispatch further reduces hook surface. The notification target can be narrowed to a less-suspicious registry path (e.g., a benign-looking application key) to avoid heuristic flags on monitoring `HKLM\SOFTWARE\Microsoft`.

- **Residual artifacts**: An open registry key handle with `KEY_NOTIFY` access persists for the lifetime of the watchdog. The handle appears in the implant's handle table and is visible via `NtQueryInformationProcess` with `ProcessHandleInformation`. Process Hacker's handle view will show a handle to the monitored registry path.

Training material does not discuss detection beyond the general observability of `RegNotifyChangeKey` calls via standard monitoring tools.

## Related Techniques

- **T-017 Persistence Suite** — Registry watchdog can trigger persistence layer activation or deactivation based on detected AV products
- **T-020 Anti-Analysis Suite** — AV detection is currently point-in-time via registry scanning; T-061 extends this to continuous monitoring

## References

- Atlas material: atlas-edr-evasion-part1.md (units 26, 27)
- MITRE ATT&CK: T1518.001 — https://attack.mitre.org/techniques/T1518/001/
- LGTM notes: lgtm:registry-watchdog-situational-awareness
- Public references: SEC670 course material (RegNotifyChangeKey and REG_NOTIFY_CHANGE_* filter set)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-061 -->

<!-- BEGIN CARD T-061 -->

<!-- BEGIN CARD T-062 -->
---
id: T-062
name: Security Descriptor Manipulation for Object Access Control
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1222
tags: [sddl, security-descriptor, dacl, null-sid, ace, access-control, ntsetsecurityobject, setnamedsecurityinfo, bypass]
origin: atlas-synthesis
member_notes: [lgtm:sddl-security-descriptor-manipulation]
---

# Security Descriptor Manipulation for Object Access Control — SDDL DACL Loosening for Access Bypass

## Summary

Security descriptor manipulation constructs custom DACLs via SDDL (Security Descriptor Definition Language) strings or manual buffer construction and applies them to securable objects to loosen access restrictions. The canonical example from SEC670 grants `GENERIC_ALL` to the NULL SID (S-1-0-0), which permits anonymous, unauthenticated access to objects that would otherwise require elevated privileges. The technique applies to any securable Windows object — services, named pipes, kernel objects, files, registry keys — and uses `SetNamedSecurityInfo` (for named objects) or `NtSetSecurityObject` (for handle-based objects) as the application mechanism. This is the inverse of the handle blocking primitive in T-016: where T-016 tightens DACLs to restrict access to the implant's own objects, T-062 loosens DACLs on third-party objects to permit low-privilege interaction.

## Mechanism

1. Identify the target object — a service, named pipe, file, registry key, or kernel object — whose DACL restricts access to a privilege level the operator does not currently hold.

2. Construct an SDDL string that grants the desired access to the target SID. The SEC670 example uses the string `D:(A;;GA;;;S-1-0-0)`:
   - `D:` prefix indicates the DACL follows
   - `A` = `ACCESS_ALLOWED_ACE_TYPE` (grant, not deny)
   - `GA` = `GENERIC_ALL` (full access)
   - `S-1-0-0` = NULL SID (anonymous/everyone)

3. Parse the SDDL string into a `SECURITY_DESCRIPTOR` structure using `ConvertStringSecurityDescriptorToSecurityDescriptor`, specifying `SDDL_REVISION_1`. The resulting descriptor is in self-relative format (packed, suitable for passing to `SetNamedSecurityInfo` or `NtSetSecurityObject`).

4. Apply the new security descriptor:
   - For named objects (services, files, registry keys): call `SetNamedSecurityInfo` with the object name, object type, and `DACL_SECURITY_INFORMATION` flag.
   - For handle-based objects (processes, threads, events, mutexes): call `NtSetSecurityObject` with the object handle, `DACL_SECURITY_INFORMATION` (0x4), and the self-relative security descriptor pointer.

5. Access the target object from a low-privilege context. The loosened DACL now permits the caller (operating as NULL SID or an unprivileged account) to perform operations that would previously have returned `ACCESS_DENIED`.

6. Optionally restore the original security descriptor after completing the privileged operation to minimize the window of exposure and reduce forensic artifacts.

## OS Internals Context

The Windows security descriptor consists of a `SECURITY_DESCRIPTOR` structure (revision 1, 20 bytes in self-relative form on x64) containing:
- `Revision` (1 byte): always 1
- `Sbz1` (1 byte): reserved
- `Control` (2 bytes): flags including `SE_DACL_PRESENT` (0x0004) and `SE_SELF_RELATIVE` (0x8000)
- `Owner` (4 bytes): offset to owner SID within the descriptor
- `Group` (4 bytes): offset to group SID
- `Sacl` (4 bytes): offset to SACL
- `Dacl` (4 bytes): offset to DACL

The DACL itself is an `ACL` structure (8-byte header on x64):
- `AclRevision` (1 byte): `ACL_REVISION` (2) for standard ACLs
- `Sbz1` (1 byte): reserved
- `AclSize` (2 bytes): total ACL size including all ACEs
- `AceCount` (2 bytes): number of ACE entries
- `Sbz2` (2 bytes): reserved

Each ACE entry consists of:
- `ACE_HEADER` (4 bytes): `AceType` (1 byte, 0x00 = `ACCESS_ALLOWED_ACE_TYPE`, 0x01 = `ACCESS_DENIED_ACE_TYPE`), `AceFlags` (1 byte), `AceSize` (2 bytes)
- `Mask` (4 bytes): `ACCESS_MASK` (e.g., `PROCESS_ALL_ACCESS` = 0x1FFFFF, `GENERIC_ALL` = 0x10000000)
- `Sid` (variable): the SID structure

The NULL SID (S-1-0-0) is a well-known SID with `IdentifierAuthority` = 1 (`SECURITY_WORLD_SID_AUTHORITY`) and `SubAuthority[0]` = 0. It represents "Nobody" in token context but is used in SDDL to mean "anonymous access" when placed in an `ACCESS_ALLOWED_ACE`. The Everyone SID (S-1-1-0) is distinct — it represents all users, including authenticated ones.

The `SeSecurityPrivilege` is required to modify SACLs but not DACLs. DACL modification requires either `WRITE_DAC` access to the object (which itself requires the object's DACL to grant the caller the right to change the DACL) or `SeTakeOwnershipPrivilege` (to become the owner first, then modify the DACL). The `NtSetSecurityObject` syscall performs an access check against the object's existing security descriptor before applying the new one — the caller must have `WRITE_DAC` access or be the owner.

The HUGIN source's `block_handle.rs` demonstrates the manual binary construction of this exact structure layout. It builds a 256-byte buffer containing: a `SECURITY_DESCRIPTOR` header (20 bytes), an `ACL` header (8 bytes), a `DENY` ACE for Everyone (20 bytes), and an `ALLOW` ACE for SYSTEM (20 bytes). The `Control` field is set to `0x8004` (`SE_DACL_PRESENT | SE_SELF_RELATIVE`). This confirms the binary layout and API invocation pattern, even though the ACE contents are inverted (restrictive rather than permissive).

## Key Implementation Details

**No current implementation in the HUGIN source that matches this technique's primary mechanism.**

The file `dark_crystal/crowd/src/block_handle.rs` implements security descriptor manipulation via `NtSetSecurityObject` but applies the **inverse** operation: it tightens the DACL to deny `PROCESS_ALL_ACCESS` to Everyone (S-1-1-0) and allow it only to SYSTEM (S-1-5-18). This is the handle blocking primitive documented in T-016, not the DACL loosening primitive of T-062.

The `block_handle.rs` implementation does demonstrate the same API primitive and binary layout that a T-062 implementation would use:

- Manual `SECURITY_DESCRIPTOR` construction in a raw byte buffer (no SDDL string parsing)
- Direct `NtSetSecurityObject` invocation via `crate::recycled::invoke` (bypassing `advapi32!SetKernelObjectSecurity`)
- `DACL_SECURITY_INFORMATION` (0x4) as the `SecurityInformation` parameter
- Self-relative descriptor format with `SE_SELF_RELATIVE` (0x8000) in the `Control` field

A T-062 implementation would follow the same buffer construction pattern but invert the ACE entries: replace the `ACCESS_DENIED_ACE` for Everyone with an `ACCESS_ALLOWED_ACE` for the NULL SID (S-1-0-0) with `GENERIC_ALL` or the appropriate `ACCESS_MASK` for the target object type. The `NtSetSecurityObject` invocation would remain identical. For named objects (services, named pipes), `SetNamedSecurityInfo` with the object name string would be the application path, or `NtSetSecurityObject` if a handle is already available.

## Why It Matters

Security descriptor manipulation fills the inverse capability gap left by the handle blocking primitive in T-016. Where T-016 restricts access to the implant's own objects (preventing EDR and analysis tools from inspecting the implant process), T-062 loosens access on third-party objects to permit low-privilege interaction with resources that would otherwise require elevation. This applies to scenarios such as: modifying a service's DACL to permit `SERVICE_START` from a standard user context, loosening a named pipe's security descriptor to permit cross-process communication without elevation, or granting anonymous access to a protected file or registry key. The technique is a reusable primitive across persistence (T-017, where service DACL loosening enables persistence installation without elevation), evasion, and privilege escalation chains.

## Detection Considerations

- **Telemetry sources**: `SetNamedSecurityInfo` and `NtSetSecurityObject` calls are logged by ETW provider `Microsoft-Windows-Kernel-General` (GUID: `{A68CA8B7-004F-D7B6-A698-0776580A5E9C}`) via event ID 4656/4663 (object access with handle manipulation). Sysmon EID 4656 (A handle to an object was requested) and EID 4657 (A registry value was modified) may capture DACL changes if object access auditing is enabled. For services, `sc.exe sdshow <service>` reveals the current SDDL and can be used by defenders to detect unexpected DACL changes.

- **Bypass options**: The HUGIN source's `block_handle.rs` demonstrates calling `NtSetSecurityObject` directly via the recycled syscall dispatcher (`crate::recycled::invoke`), bypassing user-mode hooks on `advapi32!SetKernelObjectSecurity` and `kernel32!SetSecurityObject`. The same approach applies to T-062 — using direct syscalls for the `NtSetSecurityObject` call avoids EDR hooks on the Win32 API layer.

- **Residual artifacts**: The modified DACL persists on the target object until explicitly reverted. Service DACL changes are visible via `sc.exe sdshow` or `QueryServiceObjectSecurity`. File system DACL changes are visible via `icacls` or `Get-Acl`. The original DACL is not preserved unless the implant explicitly saves and restores it. An object with a DACL granting access to S-1-0-0 (NULL SID) is an anomaly on most production systems and is flagged by security configuration baseline scanners.

Training material does not discuss detection for this technique beyond the general observability of security descriptor modification APIs.

## Related Techniques

- **T-016 EDR Evasion Suite** — Handle blocking (`block_handle.rs`) is the inverse primitive; T-016 tightens DACLs to restrict access while T-062 loosens them to permit access

## References

- Atlas material: atlas-methodology-part7.md (unit 7)
- MITRE ATT&CK: T1222 — https://attack.mitre.org/techniques/T1222/
- LGTM notes: lgtm:sddl-security-descriptor-manipulation
- Public references: SEC670 course material (SDDL Example #1, GENERIC_ALL to NULL SID)

## Source Reference

No current implementation of the T-062 primary mechanism (DACL loosening). The file `dark_crystal/crowd/src/block_handle.rs` demonstrates the inverse primitive (DACL tightening via `NtSetSecurityObject`) and the same binary security descriptor construction pattern. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-062 -->