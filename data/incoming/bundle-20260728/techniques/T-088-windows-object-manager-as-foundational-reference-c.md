---
id: T-088
name: Windows Object Manager as Foundational Reference Card
category: discovery
tier: C
crate: none
mitre: T1082
tags: [object-manager, object-header, handle-table, acl, executive-objects, kernel-objects, foundational-concept]
origin: atlas-synthesis
member_notes: ['lgtm:windows-object-manager-foundational-concept', 'lgtm:windows-object-manager-foundation', 'lgtm:windows-object-manager-foundations-card']
---

# Windows Object Manager as Foundational Reference Card — Executive Object Model, Handle Tables, and ACL Gating

## Summary

The Windows Object Manager is the executive subsystem that standardizes object creation, naming, handle management, and security across all kernel object types — Process, Thread, File, Token, Event, Mutant, Section, Key, and 4000+ registered types. Every cross-process and cross-thread operation in the HUGIN vault — injection via handle ops (T-007), PPID spoofing and handle manipulation (T-014/T-015), handle blocking (T-016), PE loading via Section objects (T-013), and PEB walking (T-004) — depends on the Object Manager's handle table and ACL-gated access model. This card documents the executive object schema, the per-process handle table, the ObpCreateHandle flow, and why PEB walking avoids the handle table entirely.

## Mechanism

1. **Object type registration**: The kernel registers object types during boot via ObCreateObjectType. Each type (PsProcessType, IoFileObjectType, ExEventObjectType, etc.) has a OBJECT_TYPE_INITIALIZER structure specifying default pool type, valid access mask, and callbacks: OpenProcedure, CloseProcedure, DeleteProcedure, ParseProcedure, SecurityProcedure, QueryNameProcedure. Windows 10 maintains 70+ executive object types; the full type list is queryable via NtQueryObject(ObjectAllInformation).

2. **Object structure**: Every executive object consists of an OBJECT_HEADER preceding the object body. The header contains TypeIndex (UCHAR, index into ObpTypeObjectTypeTable), and optional sub-headers located via offsets in OBJECT_HEADER: NameInfoOffset (pointer to OBJECT_HEADER_NAME_INFO containing the object's name and directory), SecurityDescriptorOffset (pointer to OBJECT_HEADER_SECURITY_DESCRIPTOR), QuotaInfoOffset (pointer to OBJECT_HEADER_QUOTA_INFO). The object body follows immediately after the header and its optional sub-headers.

3. **Handle creation flow**: When a user-mode thread calls a Create* or Open* API (CreateProcess, OpenProcess, CreateFile, etc.), the call routes to the corresponding Nt* syscall, which calls ObCreateObject to allocate the object body and header from pool memory, then ObpCreateHandle to insert the object into the per-process handle table and return a handle value to user mode.

4. **ACL check during handle creation**: ObpCreateHandle calls SeAccessCheck against the object's security descriptor (referenced via SecurityDescriptorOffset in OBJECT_HEADER). The check evaluates the caller's token (primary or impersonation) against the object's DACL. If the DACL does not grant the requested access right to the caller's SID, ObpCreateHandle returns STATUS_ACCESS_DENIED and no handle is created. This is the kernel-level enforcement that handle blocking (T-016) manipulates.

5. **Per-process handle table**: Each EPROCESS contains a HandleTable field (PHANDLE_TABLE) pointing to the process's handle table structure. The handle table uses a three-level scheme: the top level contains pointers to mid-level tables, each mid-level table contains pointers to low-level tables, and each low-level table contains HANDLE_TABLE_ENTRY structures (8 bytes each on x64) containing the object pointer (with bits reserved for granted access and attributes) and a granted access mask. The global handle table (PspCidTable) stores Process and Thread objects by PID/TID for system-wide lookup.

6. **Handle value encoding**: The handle value returned to user mode is an index into the process handle table, multiplied by 4 (for tag bits). The kernel uses the handle value to index into the handle table, retrieve the HANDLE_TABLE_ENTRY, extract the object pointer, and validate the granted access mask against the operation being performed.

7. **NtQueryObject(ObjectAllInformation)**: Returns a buffer containing the count of object types, followed by an array of OBJECT_TYPE_INFORMATION structures (one per type) containing TypeName (UNICODE_STRING), TotalNumberOfObjects, TotalNumberOfHandles, TotalPagedPoolUsage, TotalNonPagedPoolUsage, and type-specific information. This provides the complete Object Manager view from user mode without kernel debugging.

## OS Internals Context

The distinction between executive objects, kernel objects, USER objects, and GDI objects is structural. Executive objects are managed by the Object Manager and use the OBJECT_HEADER schema — Process, Thread, File, Token, Event, Mutant, Section, Key, Desktop, and others. Kernel objects are internal structures not exposed through the Object Manager (e.g., DEVICE_NODE, DRIVER_OBJECT). USER objects (windows, menus, cursors) and GDI objects (bitmaps, brushes, DCs) are managed by win32k.sys through a separate handle table (the shared USER/GDI handle table in the session's SessionId space) and do not have OBJECT_HEADER structures.

The handle table's three-level design supports up to 16 million handles per process (2^24 entries in the low level). Each HANDLE_TABLE_ENTRY contains the object pointer in its upper bits, with the low bits encoding GrantedAccess (25 bits) and handle attributes (inherit, audit on close, protect from close). The GrantedAccess bits are set at handle creation time from the requested access mask after the ACL check, and are checked on every subsequent operation through the handle.

The ObpCreateHandle flow for process creation (NtCreateUserProcess, used by T-014) involves: allocating EPROCESS and KPROCESS structures via ObCreateObject, setting up the address space via MmCreatePeb, creating the Section object for the image, inserting the Process object into PspCidTable (the global handle table indexed by PID), and inserting a handle into the parent process's handle table. The parent's handle to the new process carries the access rights granted by the ACL check — typically PROCESS_ALL_ACCESS if the parent has SE_DEBUG_PRIVILEGE.

Section objects (used by T-013 PE Loader and T-007 mapping injection) are executive objects backed by the Memory Manager's section/subsection structures. NtCreateSection creates a Section object with a control area pointing to either a file object (for image and data files) or to committed page table entries (for pagefile-backed sections). The Section object's ACL determines which processes can map it via NtMapViewOfSection.

PEB walking (T-004) avoids the Object Manager entirely. The PEB is located via the TEB (gs:[0x30] on x64 points to the TEB, TEB.ProcessEnvironmentBlock at offset 0x60 points to the PEB). The PEB is already mapped in the current process's address space — it is not an object with an OBJECT_HEADER, and accessing it requires no handle and triggers no ACL check. The Ldr.InLoadOrderModuleList within the PEB contains pointers to LDR_DATA_TABLE_ENTRY structures, each with a DllBase field pointing to the module's mapped image. Reading these pointers is pure memory dereference with no kernel transition.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents a foundational Windows internals concept that underpins multiple HUGIN techniques. The Object Manager structures and handle table mechanics are not directly implemented in Rust source code — they are kernel structures that HUGIN techniques interact with through NT syscalls.

An implementation leveraging Object Manager knowledge would use NtQueryObject(ObjectAllInformation) to enumerate object types and NtQueryDirectoryObject to enumerate named objects in the Object Manager namespace (rooted at "\"). The per-process handle table can be enumerated via NtQuerySystemInformation(SystemExtendedHandleInformation) to discover handles held by other processes, which is relevant for handle hijacking operations.

The `dark_crystal/crowd/src/herpaderping.rs` implementation interacts with the Object Manager when calling NtCreateSection (creating a Section object), NtOpenFile (creating a File object handle), NtCreateProcessEx (creating a Process object), and NtCreateThreadEx (creating a Thread object). Each of these calls passes through ObpCreateHandle and the ACL check. The PROCESS_ALL_ACCESS constant (0x001FFFFF) used in herpaderping.rs reflects the full access mask granted on process objects.

## Why It Matters

The vault documents handle blocking (T-016), PPID spoofing (T-015), injection via handle ops (T-007), PE loading via Section objects (T-013), and PEB walking (T-004) as independent techniques, but all of them operate within the Object Manager's framework. Operators who understand why handle-based detection fires, why PEB walking avoids the handle table, and why Section objects mediate mapping injection can trace technique success or failure to the kernel's ACL check rather than guessing at API behavior. A reference card for the Object Manager lets readers reach the technique cards with the prerequisite mental model already in place.

## Detection Considerations

- **Telemetry sources**: Handle creation generates Object Manager ETW events (Microsoft-Windows-Kernel-Object, Event ID 1 for handle creation). Process and Thread object creation generates Kernel-Process ETW events. NtQueryObject and NtQueryDirectoryObject calls are hookable in ntdll. Handle table enumeration via NtQuerySystemInformation(SystemHandleInformation) is a reconnaissance indicator monitored by EDR.
- **Bypass options**: PEB walking avoids all handle creation and ACL checks by reading in-process memory directly. Direct syscalls (T-001, T-002) bypass userland hooks on Nt* APIs that create objects. Object creation with minimal access masks reduces the footprint of granted access bits.
- **Residual artifacts**: Every executive object created through ObpCreateHandle leaves an entry in the creating process's handle table until the handle is closed. Section objects persist until all views are unmapped and the handle is closed. Process and Thread objects persist in PspCidTable until termination.

## Related Techniques

- **T-004 PEB Walker** — PEB walking avoids the Object Manager handle table entirely by reading in-process memory structures through TEB → PEB → Ldr traversal
- **T-007 Process Injection** — Injection techniques create and manipulate Section, Process, and Thread objects through the Object Manager handle creation and ACL check flow
- **T-016 EDR Evasion Suite** — Handle blocking manipulates Object Manager security descriptors and ACLs to deny external process handle access
- **T-015 PPID Spoofing** — Parent PID spoofing manipulates process object creation through the Object Manager handle flow via NtCreateUserProcess

## References

- Atlas material: atlas-methodology-part1.md, atlas-methodology-part2.md, atlas-methodology-part5.md
- MITRE ATT&CK: T1082 — https://attack.mitre.org/techniques/T1082
- LGTM notes: lgtm:windows-object-manager-foundational-concept, lgtm:windows-object-manager-foundation, lgtm:windows-object-manager-foundations-card
- Public references: SEC670 Units 33, 35-39 (Object Manager, executive objects, handle tables, ACL gating)

## Source Reference

No current implementation. See atlas material and MITRE reference for Object Manager concepts. The `dark_crystal/crowd/src/herpaderping.rs` implementation interacts with Object Manager structures through NtCreateSection, NtCreateProcessEx, and NtCreateThreadEx syscalls.