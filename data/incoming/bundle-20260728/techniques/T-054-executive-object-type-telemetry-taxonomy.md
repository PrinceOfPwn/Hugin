---
id: T-054
name: Executive Object Type Telemetry Taxonomy
category: discovery
tier: C
crate: none
source_file: none
mitre: T1082
mitre_secondary: [T1055]
tags: [windows-internals, object-types, auditing, access-masks, telemetry, detection-surface, kernel-objects, security-descriptors, sacl, handle-auditing]
origin: atlas-synthesis
member_notes: ['lgtm:executive-object-types-as-telemetry-surface']
---

# Executive Object Type Telemetry Taxonomy — Per-Type Audit Surface Mapping

## Summary

The Windows Object Manager defines typed kernel objects — Process, Thread, Section, Token, Mutex, Key, Desktop, and others — each with a type-specific access mask and an optional security descriptor containing a System Access Control List (SACL). When SACL auditing is enabled for a given object type, the security reference monitor generates Event IDs 4656 (handle requested), 4663 (access attempted), 4658 (handle closed), and 4660 (object deleted) for operations on that object class. Each object type emits different access mask values in these events, meaning the audit surface varies by object class. Understanding which object types produce which audit events under which access masks enables operators to make informed decisions about which kernel objects to touch and which to avoid during an operation.

## Mechanism

1. The Windows Object Manager creates typed executive objects via `ObCreateObject` and related internal functions. Each object belongs to a type defined by an `OBJECT_TYPE` structure that specifies the type's access mask, naming rules, and object-specific methods.

2. Each object type defines a type-specific access mask. Process objects define `PROCESS_TERMINATE` (0x0001), `PROCESS_CREATE_THREAD` (0x0002), `PROCESS_VM_OPERATION` (0x0008), `PROCESS_VM_READ` (0x0010), `PROCESS_VM_WRITE` (0x0020), `PROCESS_DUP_HANDLE` (0x00000040), `PROCESS_SET_INFORMATION` (0x00000200), `PROCESS_QUERY_INFORMATION` (0x00010000), `PROCESS_QUERY_LIMITED_INFORMATION` (0x00001000), and `PROCESS_ALL_ACCESS` (0x1FFFFF).

3. Thread objects define a parallel access mask: `THREAD_TERMINATE` (0x0001), `THREAD_SUSPEND_RESUME` (0x0002), `THREAD_GET_CONTEXT` (0x00000008), `THREAD_SET_CONTEXT` (0x00000010), `THREAD_SET_INFORMATION` (0x00000020), `THREAD_QUERY_INFORMATION` (0x00000040), `THREAD_SET_THREAD_TOKEN` (0x00000080), `THREAD_IMPERSONATE` (0x00000100), `THREAD_DIRECT_IMPERSONATION` (0x00000200), `THREAD_QUERY_LIMITED_INFORMATION` (0x00000800), and `THREAD_ALL_ACCESS` (0x1FFFFF).

4. Section objects (file mappings) define `SECTION_QUERY` (0x0001), `SECTION_MAP_WRITE` (0x0002), `SECTION_MAP_READ` (0x0004), `SECTION_MAP_EXECUTE` (0x0008), `SECTION_MAP_EXECUTE_EXPLICIT` (0x0010), and `SECTION_ALL_ACCESS` (0x1F001F).

5. Token objects define `TOKEN_ASSIGN_PRIMARY` (0x0001), `TOKEN_DUPLICATE` (0x0002), `TOKEN_IMPERSONATE` (0x0004), `TOKEN_QUERY` (0x0008), `TOKEN_QUERY_SOURCE` (0x0010), `TOKEN_ADJUST_PRIVILEGES` (0x00000020), `TOKEN_ADJUST_GROUPS` (0x00000040), `TOKEN_ADJUST_DEFAULT` (0x00000080), `TOKEN_ADJUST_SESSIONID` (0x00000100), and `TOKEN_ALL_ACCESS` (0x000F01FF).

6. Key objects (registry) define `KEY_QUERY_VALUE` (0x0001), `KEY_SET_VALUE` (0x0002), `KEY_CREATE_SUB_KEY` (0x0004), `KEY_ENUMERATE_SUB_KEYS` (0x0008), `KEY_NOTIFY` (0x0010), `KEY_CREATE_LINK` (0x0020), and `KEY_ALL_ACCESS` (0x000F003F).

7. Each object instance may carry a `SecurityDescriptor` stored in the object header. The security descriptor contains a DACL (governing access control) and optionally a SACL (governing audit generation).

8. The SACL contains `SYSTEM_AUDIT_ACE` entries. Each ACE specifies an `AccessMask` (which permission bits trigger auditing), a `Sid` (which principal's access to audit), and `AceFlags` (success auditing, failure auditing, or both).

9. When user-mode code calls `NtOpenProcess`, `NtOpenThread`, `NtOpenSection`, `NtOpenProcessTokenEx`, or equivalent functions, the security reference monitor evaluates the SACL against the requested access mask via `SeAccessCheck` or `SeObjectAuditAlarm`.

10. If the requested access matches a SACL audit ACE and the corresponding audit subcategory is enabled, Event 4656 ("A handle to an object was requested") is written to the Windows Security Event Log. The event includes the object type, object name, requested access mask (as a hex value and as resolved permission names), and the caller's subject context.

11. When the returned handle is subsequently used for operations — `NtReadVirtualMemory` (exercising `PROCESS_VM_READ`), `NtWriteVirtualMemory` (exercising `PROCESS_VM_WRITE`), `NtSetInformationThread` (exercising `THREAD_SET_INFORMATION`), and similar — Event 4663 ("An attempt was made to access an object") is logged with the specific access mask bits exercised.

12. When the handle is closed via `NtClose`, Event 4658 ("The handle to an object was closed") is logged, including the object type and the handle's access mask.

13. When the object's reference count reaches zero and the object is freed, Event 4660 ("An object was deleted") may be logged for certain object types.

14. For these events to appear, the corresponding audit subcategory must be enabled via `auditpol.exe` or Group Policy. Process, Thread, Section, Token, and Mutex objects fall under the "Kernel Object" audit subcategory. Key objects fall under the "Registry" subcategory. File objects fall under "File System." Desktop and WindowStation objects fall under "Other Object Access Events."

## OS Internals Context

The `OBJECT_TYPE` structure (referenced internally as `nt!ObTypeIndexTable` entries) contains a `TypeInfo` field holding an `OBJECT_TYPE_INITIALIZER` structure. This initializer includes an `OpenProcedure` callback — the function the object manager invokes when a handle to the object is opened. Within this call path, the security reference monitor's `SeAccessCheck` function evaluates both the DACL (to grant or deny access) and the SACL (to determine whether to generate audit events).

The `SecurityDescriptor` in the object header is stored in self-relative format — a flat byte buffer where the `SECURITY_DESCRIPTOR` structure's `Owner`, `Group`, `Sacl`, and `Dacl` fields are offsets rather than pointers. The `SE_SELF_RELATIVE` flag (0x8000) in the `Control` field indicates this layout. The SACL is a variable-length `ACL` structure containing `SYSTEM_AUDIT_ACE` entries. Each `SYSTEM_AUDIT_ACE` has an `AceType` of `SYSTEM_AUDIT_ACE_TYPE` (0x02), an `AccessMask` specifying which permission bits to audit, and a `Sid` identifying the principal.

The security reference monitor distinguishes between handle-creation events (4656) and handle-use events (4663). Opening a process with `PROCESS_ALL_ACCESS` generates a single 4656 event with the full access mask, but subsequent operations on the handle generate separate 4663 events for each access mask category exercised. An operator who opens a handle with `PROCESS_ALL_ACCESS` but only reads memory generates one 4656 with `0x1FFFFF` and one 4663 with `PROCESS_VM_READ` (0x0010).

The `block_handle.rs` implementation in the `dark_crystal/crowd` crate demonstrates direct manipulation of a Process object's `SecurityDescriptor` via `NtSetSecurityObject` with `DACL_SECURITY_INFORMATION` (0x4). It constructs a self-relative `SECURITY_DESCRIPTOR` in a raw byte buffer, populating a DACL with `ACCESS_DENIED_ACE_TYPE` for Everyone (S-1-1-0) and `ACCESS_ALLOWED_ACE_TYPE` for SYSTEM (S-1-5-18). The same `NtSetSecurityObject` mechanism can operate with `SACL_SECURITY_INFORMATION` (0x8) to modify the SACL on any executive object, which would alter audit event generation for that specific object instance. `NtSetSecurityObject` requires `SeSecurityPrivilege` (also known as `SeSecurity`) for SACL modifications, which restricts SACL manipulation to contexts where that privilege is present and enabled.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the telemetry taxonomy for reference. The `block_handle.rs` file in `dark_crystal/crowd` implements `NtSetSecurityObject` to modify a Process object's DACL, demonstrating the `SecurityDescriptor` manipulation mechanism that the SACL audit configuration also uses. An implementation of SACL modification would follow the same buffer-construction pattern but set `SACL_SECURITY_INFORMATION` (0x8) as the `SecurityInformation` parameter and populate a SACL with `SYSTEM_AUDIT_ACE` entries in the `Sacl` offset of the security descriptor rather than a DACL in the `Dacl` offset.

## Why It Matters

This card provides a single reference mapping executive object types to the audit events they emit and the access masks those events carry. Operators who know that opening a process with `PROCESS_VM_READ` generates Event 4663 under the "Kernel Object" audit subcategory can make informed decisions about whether to risk handle creation or pursue alternative approaches such as duplicating existing handles. The taxonomy also clarifies which object types are auditable by default (File and Key objects have SACLs configured more frequently than Process objects, where SACL auditing requires explicit configuration) and which require specific audit policy enablement.

## Detection Considerations

- **Telemetry sources**: Windows Security Event Log (Event IDs 4656, 4663, 4658, 4660), gated by per-subcategory audit policy. Sysmon Event ID 10 (ProcessAccess) provides parallel telemetry for process handle creation. ETW provider `Microsoft-Windows-Kernel-Audit-API-Calls` surfaces kernel audit events to real-time consumers.
- **Bypass options**: Operators avoid handle creation by duplicating existing handles via `NtDuplicateObject` from processes that already hold handles to the target, or by operating on objects through mechanisms that do not require `NtOpen*` calls (such as thread pool work items inside the target process). SACL modification via `NtSetSecurityObject` with `SACL_SECURITY_INFORMATION` removes audit ACEs from specific object instances, though this requires `SeSecurityPrivilege`.
- **Residual artifacts**: SACL modifications generate their own audit events (4657: "A registry object was modified" for registry SACLs, and 4670: "Permissions on an object were changed" for general object SACL modifications). Handle duplication via `NtDuplicateObject` still generates a 4656 on the target process if the source handle's access rights trigger the SACL.

## Related Techniques

- **T-007 Pool Party / Process Injection** — injection techniques interact with Process, Thread, and Section objects, all of which emit audit events under the "Kernel Object" subcategory.
- **T-016 EDR Evasion Suite** — `block_handle.rs` implements `NtSetSecurityObject` DACL modification on Process objects, demonstrating the security descriptor manipulation mechanism relevant to SACL audit suppression.
- **T-015 PPID Spoofing** — parent process manipulation involves opening and operating on Process object handles, triggering 4656/4663 events under "Kernel Object" auditing.

## References

- Atlas material: atlas-methodology-part1.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082/
- LGTM notes: lgtm:executive-object-types-as-telemetry-surface

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.