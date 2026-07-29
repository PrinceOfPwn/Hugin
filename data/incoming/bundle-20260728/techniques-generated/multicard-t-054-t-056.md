<!-- BEGIN CARD T-054 -->
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
<!-- END CARD T-054 -->

<!-- BEGIN CARD T-055 -->
---
id: T-055
name: Native Application Win32 Subsystem Bypass
category: discovery
tier: B
crate: none
source_file: none
mitre: T1106
mitre_secondary: [T1055]
tags: [native-application, nt-process-startup, peb, subsystem-bypass, minimal-footprint, nt-api, image-loader, pe-subsystem]
origin: atlas-synthesis
member_notes: ['lgtm:native-application-development']
---

# Native Application Win32 Subsystem Bypass — Direct PEB Entry Point

## Summary

Native applications are PE executables compiled with `IMAGE_SUBSYSTEM_NATIVE` (value 1) in the optional header, causing the Windows image loader to bypass Win32 subsystem initialization entirely and invoke the entry point with the PEB passed directly as a parameter. The entry point signature `NTSTATUS NtProcessStartup(PPEB peb)` replaces the standard Win32 CRT startup chain — no `kernel32!BaseThreadInitThunk`, no CRT initialization, no Win32 thread environment block setup. Only `ntdll.dll` is loaded into the process address space at startup. This eliminates the userland hook surface that EDR products install in Win32 API functions and reduces the volume of ETW events from Win32 providers, producing a minimal-footprint execution environment for implant code that requires only NT API access.

## Mechanism

1. A PE executable is compiled and linked with the optional header's `Subsystem` field set to `IMAGE_SUBSYSTEM_NATIVE` (1). This field resides at offset 68 (0x44) from the start of the `IMAGE_OPTIONAL_HEADER` structure.

2. The linker sets the `AddressOfEntryPoint` field in the `IMAGE_FILE_HEADER` to the native entry point function. No CRT startup object (`crt0.obj` or equivalent) is linked.

3. No Win32 libraries (`kernel32.dll`, `user32.dll`, `gdi32.dll`, `advapi32.dll`) are linked or imported. The IAT contains only `ntdll.dll` exports.

4. When the image loader (`ntdll!LdrpInitializeProcess`) processes the executable, it reads the `Subsystem` field from the PE optional header. Recognizing `IMAGE_SUBSYSTEM_NATIVE`, it takes a different initialization path from Win32 GUI/CUI executables.

5. The loader does not initialize the Win32 thread environment. `kernel32.dll` is not loaded unless explicitly requested. The `BaseThreadInitThunk` trampoline that normally wraps the user entry point is not invoked.

6. The loader passes the PEB pointer directly to the entry point function. On x64, the PEB pointer is passed in `RCX` per the x64 calling convention. The entry point signature is `NTSTATUS NtProcessStartup(PPEB peb)`.

7. The native application accesses `peb->Ldr->InLoadOrderModuleList` to enumerate loaded modules. At process start, `ntdll.dll` is the only module in the list. The `LDR_DATA_TABLE_ENTRY` for `ntdll.dll` provides the `DllBase` field, which the application uses to resolve `Nt*` function addresses by walking the export directory.

8. All system service calls go through `ntdll.dll` `Nt*` stubs (which contain the `syscall` instruction on x64) or through direct `syscall` instructions if the application implements its own SSN resolution.

9. To access Win32 APIs if needed, the native application calls `NtLoadDriver` or manually maps `kernel32.dll` via `NtCreateSection` and `NtMapViewOfSection`, then walks the export table to resolve function pointers. This is a manual operation with no loader support for dependency resolution.

10. `NtCreateUserProcess` can spawn additional native applications by specifying the process parameters. The `RTL_USER_PROCESS_PARAMETERS` structure passed to `NtCreateUserProcess` does not require Win32 subsystem initialization for native target images.

11. The entry point returns an `NTSTATUS` value. The loader interprets the return value: `STATUS_SUCCESS` (0x00000000) causes normal process termination. A nonzero status causes process termination with the specified exit code. There is no `ExitProcess` call — the loader calls `NtTerminateProcess` directly.

## OS Internals Context

The `IMAGE_OPTIONAL_HEADER.Subsystem` field determines how the image loader initializes the process. For `IMAGE_SUBSYSTEM_WINDOWS_GUI` (2) and `IMAGE_SUBSYSTEM_WINDOWS_CUI` (3), the loader initializes the Win32 subsystem: it loads `kernel32.dll` and `user32.dll` (for GUI), calls `kernel32!BaseDllInitialize`, sets up the Win32 thread environment block (`TEB.ProcessEnvironmentBlock` is populated, but the Win32-specific `TEB` fields such as `ReservedForOleActivation` and the thread-local storage slots are also initialized), and wraps the entry point call through `kernel32!BaseThreadInitThunk`.

For `IMAGE_SUBSYSTEM_NATIVE` (1), the loader skips the Win32 initialization path. The `PEB` is constructed and populated by the loader before the entry point is called — `PEB->ImageBaseAddress` points to the native executable's base, `PEB->Ldr` is initialized with the `ntdll.dll` module entry, and `PEB->ProcessParameters` contains the `RTL_USER_PROCESS_PARAMETERS` structure. However, the Win32-specific fields of the PEB (such as `PEB->KernelCallbackTable`, which holds the Win32 kernel callback dispatch table) are not populated.

The canonical native application on Windows is `smss.exe` (Session Manager Subsystem). It is the first user-mode process launched by the kernel and runs as a native application to initialize the session manager before any Win32 subsystem process starts. `autochk.exe` (the disk-checking utility that runs during boot) is another native application. These examples demonstrate that native applications can perform I/O, create processes, and interact with the kernel entirely through `ntdll.dll` exports.

The `PEB->Ldr` pointer leads to the `PEB_LDR_DATA` structure, which contains three doubly-linked lists: `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and `InInitializationOrderModuleList`. For a native application at startup, all three lists contain exactly one entry: the `LDR_DATA_TABLE_ENTRY` for `ntdll.dll`. The `DllBase` field in this entry provides the base address needed for export table walking to resolve `Nt*` function pointers.

The `TEB` (Thread Environment Block) is accessible via the `GS` segment register on x64 (`gs:[0x30]` for the TEB self-pointer, `gs:[0x60]` for the PEB pointer). Native applications can use the PEB parameter passed to the entry point directly, but they can also access the PEB via `gs:[0x60]` at any time — the TEB is set up by the kernel before the entry point is called regardless of subsystem.

ETW providers that depend on Win32 subsystem initialization (such as `Microsoft-Windows-Kernel-Process` for process/thread events, and the various `.NET` and Win32-specific providers) emit events during the Win32 initialization path. Native applications skip this path, so the initial ETW event volume is lower. The kernel-level ETW providers (such as `NT Kernel Logger`) still emit events for native application process creation and system calls, since these operate at the kernel level regardless of subsystem.

## Key Implementation Details

**No current implementation in the HUGIN source.** An implementation would set `IMAGE_OPTIONAL_HEADER.Subsystem` to `IMAGE_SUBSYSTEM_NATIVE` (1) in the PE header during the build process, link only against `ntdll.dll` exports, and define the entry point as `extern "C" fn nt_process_startup(peb: *mut PEB) -> NTSTATUS`. API resolution would walk `peb->Ldr->InLoadOrderModuleList` to locate the `ntdll.dll` `LDR_DATA_TABLE_ENTRY`, then parse the export directory (`IMAGE_EXPORT_DIRECTORY`) at `ntdll_base + export_dir_rva` to resolve `Nt*` function addresses by name or by hash. System calls would go through the resolved `Nt*` stubs or through a direct syscall mechanism (T-001 RecycledGate or T-002 Hell's Gate) using SSN values extracted from the `Nt*` stubs. The `#![no_std]` attribute and `#![no_main]` attribute in Rust would prevent the standard library's Win32 initialization code from being linked. A minimal `link.exe` or `lld-link` invocation with `/SUBSYSTEM:NATIVE` and `/ENTRY:nt_process_startup` would produce the correct PE header.

## Why It Matters

Native applications eliminate the entire Win32 subsystem initialization chain, removing the userland hook surface that EDR products install in `kernel32.dll` and `user32.dll` API functions. A native application never calls `kernel32!CreateProcessW`, never loads `user32.dll`, and never initializes the Win32 thread environment. This reduces the loaded module list to a single entry (`ntdll.dll`), eliminates TLS callbacks from Win32 DLLs, and minimizes the ETW events generated during process startup. The tradeoff is that native applications cannot use any Win32 API without manually loading the DLL and resolving its exports, which adds implementation complexity for operations that require Win32 functionality such as GUI interaction or COM initialization.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 1 (Process Create) includes the process's image path and can be correlated with the PE subsystem field. The absence of `kernel32.dll` in the loaded module list is visible in Sysmon Event ID 7 (Image Loaded). ETW `Microsoft-Windows-Kernel-Process` provider still emits process creation events for native applications at the kernel level. Memory scanning tools can detect native PE images by reading the optional header and checking the `Subsystem` field.
- **Bypass options**: The technique itself is a bypass of Win32 telemetry. An operator can further reduce visibility by avoiding `ntdll.dll` `Nt*` stubs in favor of direct `syscall` instructions (T-001, T-002, T-003), which removes `ntdll.dll` from the call stack. Loading `kernel32.dll` later via `NtCreateSection`/`NtMapViewOfSection` avoids the loader's dependency resolution and associated ETW events.
- **Residual artifacts**: The PE file on disk has `IMAGE_SUBSYSTEM_NATIVE` in the optional header. The process's loaded module list contains only `ntdll.dll` at startup. The PEB's `ImageBaseAddress` points to the native executable. The `KernelCallbackTable` field in the PEB is null (uninitialized for native subsystem).

## Related Techniques

- **T-014 NtCreateUserProcess** — direct NT process creation; `NtCreateUserProcess` can spawn native applications by providing a native subsystem image path, which the loader initializes without Win32 setup.
- **T-004 PEB Walker** — native applications receive the PEB directly as an entry point parameter, eliminating the need for `gs:[0x60]` PEB access for module resolution at startup.

## References

- Atlas material: atlas-post-exploit-part13.md
- MITRE ATT&CK: T1106 — https://attack.mitre.org/techniques/T1106/
- LGTM notes: lgtm:native-application-development

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-055 -->

<!-- BEGIN CARD T-056 -->
---
id: T-056
name: PE-sieve Injection Detection Mechanics
category: discovery
tier: B
crate: none
source_file: none
mitre: T1055
mitre_secondary: [T1518.001]
tags: [pe-sieve, memory-scanner, detection, process-injection, hollowed-modules, unbacked-memory, moneta, defensive-tools, memory-forensics, evasion-planning]
origin: atlas-synthesis
member_notes: ['lgtm:pe-sieve-detection-coverage', 'lgtm:pe-sieve-detection-tool-card']
---

# PE-sieve Injection Detection Mechanics — Memory Scanner Evasion Reference

## Summary

PE-sieve is a community-driven memory scanner that detects process injection artifacts by comparing in-memory PE images against their on-disk counterparts and by scanning for unbacked executable memory regions. The tool operates by opening target process handles, walking the PEB module list, reading in-memory PE headers via `NtReadVirtualMemory`, and comparing them against the on-disk PE file to identify hollowed or stomped modules. It also enumerates all `MEM_COMMIT` pages with execute protection and checks whether each page is backed by a mapped image file, flagging `MEM_PRIVATE` executable regions as manually mapped PE images. PE-sieve and similar tools — Moneta, Hunt-Sleeping-Beacons, and hollows_hunter — represent the defender-side detection surface that operators must understand to evade when deploying injection techniques from T-007 and T-013.

## Mechanism

1. PE-sieve enumerates all running processes via `NtQuerySystemInformation(SystemProcessInformation)`, obtaining a list of PIDs and process names.

2. For each target process, PE-sieve calls `NtQueryInformationProcess(ProcessBasicInformation)` to retrieve the `PEB` address. This requires `PROCESS_QUERY_INFORMATION` (0x00010000) access on the target process handle.

3. PE-sieve reads the PEB structure via `NtReadVirtualMemory`, then follows `PEB->Ldr->InLoadOrderModuleList` to walk the loaded module list. For each `LDR_DATA_TABLE_ENTRY`, it reads the `DllBase`, `FullDllName`, and `BaseDllName` fields.

4. For each module, PE-sieve reads the in-memory PE headers starting at `DllBase`: the `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS` (including the `OptionalHeader` and the section table), and the export directory if present.

5. PE-sieve resolves the module's on-disk file path from `FullDllName` and reads the on-disk PE file. It parses the on-disk headers and section data.

6. PE-sieve compares the in-memory PE headers against the on-disk headers. If the `IMAGE_DOS_HEADER`, `IMAGE_FILE_HEADER`, `IMAGE_OPTIONAL_HEADER`, or section headers differ between the in-memory image and the on-disk file, the module is flagged as "hollowed" — indicating that the process's module has been replaced with different content.

7. PE-sieve then scans the entire virtual address space of the target process. For each virtual address range, it calls `NtQueryVirtualMemory(MemoryBasicInformation)` to retrieve the `State`, `Protect`, and `Type` fields of the `MEMORY_BASIC_INFORMATION` structure.

8. Ranges with `State == MEM_COMMIT` (0x1000) and `Protect` including `PAGE_EXECUTE` (0x10), `PAGE_EXECUTE_READ` (0x20), or `PAGE_EXECUTE_READWRITE` (0x40) are flagged as executable regions.

9. For each executable region, PE-sieve checks the `Type` field. `MEM_IMAGE` (0x1000000) indicates the region is backed by a mapped image file. `MEM_PRIVATE` (0x20000) indicates the region is allocated from the process's private pages and has no file backing.

10. `MEM_PRIVATE` executable regions are flagged as "unbacked executable memory" — a primary indicator of manually mapped shellcode or PE images. PE-sieve attempts to parse PE headers at the start of these regions to identify whether the unbacked memory contains a mapped DLL.

11. For stomped modules — where a legitimate module's `.text` section has been overwritten with different code — PE-sieve compares the in-memory `.text` section content against the on-disk `.text` section content. If the `.text` section differs but the headers match, the module is flagged as "stomped."

12. PE-sieve reports results per process, categorizing each anomaly as: hollowed module, unbacked executable region, stomped module, or impersonated module (where the PEB module name does not match the file at the resolved path).

13. Moneta operates with a similar but narrower algorithm: it focuses specifically on `MEM_PRIVATE` executable pages and RWX regions, using `NtQueryVirtualMemory(MemoryMappedFilenameInformation)` to determine whether a page is file-backed. Moneta does not perform in-memory vs on-disk PE comparison, making it faster but less comprehensive than PE-sieve for hollowed-module detection.

14. Hunt-Sleeping-Beacons takes a different approach: it enumerates threads via `NtQuerySystemInformation(SystemProcessInformation)` with `ThreadInformation` class, identifies threads in `Waiting` state (which includes threads waiting on timers — the sleep mechanism used by beacons), and checks whether each thread's `StartAddress` points into `MEM_PRIVATE` memory. A sleeping thread with a start address in unbacked memory is flagged as a potential beacon.

15. hollows_hunter is a companion tool to PE-sieve that focuses specifically on the hollowed-module detection algorithm, scanning for modules where the in-memory image differs from the on-disk file. It provides deeper analysis of the specific bytes that differ between in-memory and on-disk images.

## OS Internals Context

The `MEMORY_BASIC_INFORMATION` structure returned by `NtQueryVirtualMemory` contains the `Type` field, which distinguishes between `MEM_IMAGE` (0x1000000, backed by a mapped image section), `MEM_MAPPED` (0x40000, backed by a mapped data section), and `MEM_PRIVATE` (0x20000, allocated from the process page file with no file backing). The VAD (Virtual Address Descriptor) tree in the kernel maintains the backing-store information for each virtual address range — `MEM_IMAGE` regions have a `Subsection` pointer in their VAD entry that references the `CONTROL_AREA` and `SEGMENT` objects describing the mapped file. `MEM_PRIVATE` regions have no `Subsection` pointer.

When `NtMapViewOfSection` maps a section created from a file object, the resulting VAD entry carries the `MEM_IMAGE` or `MEM_MAPPED` type depending on the section's `AllocationAttribute` flags. `SEC_IMAGE` (0x1000000) in the section attributes produces `MEM_IMAGE` pages; `SEC_COMMIT` without `SEC_IMAGE` produces `MEM_MAPPED` or `MEM_PRIVATE` pages. This distinction is what PE-sieve and Moneta exploit: manually mapped PE images created via `NtCreateSection` with `SEC_COMMIT` and then copied into the section view without proper `SEC_IMAGE` attributes produce `MEM_PRIVATE` pages that scanners flag as anomalies.

Module stomping — where the `.text` section of a legitimate `MEM_IMAGE` module is overwritten with shellcode — produces a different detection surface. The pages remain `MEM_IMAGE` because the VAD tree is not modified, but the content of the `.text` section no longer matches the on-disk file. PE-sieve detects this by reading the in-memory `.text` section and comparing it against the on-disk `.text` section at the same RVA. The comparison uses a hash or byte-by-byte comparison of the `.text` section content.

The `LDR_DATA_TABLE_ENTRY` structure contains `HashLinks` for the `BaseDllName` hash table used by `LdrGetDllHandleByName`. When a module is unlinked from the PEB (T-016 PEB unlink), the `InLoadOrderModuleList`, `InMemoryOrderModuleList`, and `InInitializationOrderModuleList` links are removed, but the `DllBase` memory is not freed. PE-sieve can detect orphaned `MEM_IMAGE` regions — where the VAD indicates a mapped image file but the module does not appear in the PEB module list — as an indicator of PEB unlinking.

## Key Implementation Details

**No current implementation in the HUGIN source.** The `dark_crystal/crowd` crate's `block_handle.rs` implements `NtSetSecurityObject` to apply a custom DACL that denies `PROCESS_ALL_ACCESS` (0x1FFFFF) to Everyone (S-1-1-0) and allows it only for SYSTEM (S-1-5-18). This prevents PE-sieve and similar scanners from obtaining the process handle needed to read memory, because `NtOpenProcess` returns `STATUS_ACCESS_DENIED` when the DACL denies the requested access. The security descriptor is constructed in a 256-byte raw buffer as a self-relative `SECURITY_DESCRIPTOR` with `SE_DACL_PRESENT` (0x0004) and `SE_SELF_RELATIVE` (0x8000) control flags, containing a DACL with two ACEs: `ACCESS_DENIED_ACE_TYPE` (0x01) for Everyone and `ACCESS_ALLOWED_ACE_TYPE` (0x00) for SYSTEM. This is a mitigation against PE-sieve scanning but does not implement PE-sieve's detection mechanics.

## Why It Matters

PE-sieve represents the most widely deployed community-driven memory scanner for detecting process injection artifacts. Operators who deploy techniques from T-007 (Pool Party, Threadless, Process Ghosting) and T-013 (process hollowing, module stomping, manual mapping) will encounter PE-sieve during engagements, particularly in environments where commercial EDR is supplemented by threat hunting tooling. Understanding the specific detection algorithms — header comparison for hollowing, `MEM_PRIVATE` scanning for manual mapping, `.text` section comparison for stomping, and thread start address analysis for sleeping beacons — allows operators to choose injection variants that minimize the specific indicators each tool searches for.

## Detection Considerations

- **Telemetry sources**: PE-sieve does not use ETW, kernel callbacks, or real-time monitoring. It operates as a batch scanner that opens process handles and reads memory via `NtReadVirtualMemory`. Its presence is detectable through `NtOpenProcess` calls that request `PROCESS_QUERY_INFORMATION` or `PROCESS_VM_READ` access on many processes in rapid succession, which generates Sysmon Event ID 10 (ProcessAccess) events and may trigger EDR behavioral rules for mass process access. PE-sieve's own process has a distinctive import table containing `NtReadVirtualMemory`, `NtQueryInformationProcess`, `NtQueryVirtualMemory`, and `NtQuerySystemInformation` from `ntdll.dll`.
- **Bypass options**: `block_handle.rs` (T-016) denies `PROCESS_ALL_ACCESS` to external processes via DACL modification, preventing PE-sieve from opening the target process handle. Thread pool injection (T-007 Pool Party) executes code via existing thread pool worker threads, avoiding creation of new `MEM_PRIVATE` executable regions. Module stomping with header preservation — overwriting only the `.text` section while keeping PE headers intact — avoids the hollowed-module heuristic but remains detectable via `.text` section comparison. Reflective DLL injection into `MEM_IMAGE` regions of existing modules avoids the `MEM_PRIVATE` flag. Threadless injection (T-008) avoids creating new threads, evading Hunt-Sleeping-Beacons.
- **Residual artifacts**: PE-sieve generates console output and optional JSON/XML reports listing flagged processes and anomaly types. The scanner process itself is visible in the process list with its import table. Scanning activity generates `NtReadVirtualMemory` calls visible to EDR telemetry. The `block_handle.rs` DACL modification generates Event 4670 ("Permissions on an object were changed") if SACL auditing is enabled on the target process.

## Related Techniques

- **T-007 Pool Party / Process Injection** — PE-sieve detects unbacked executable memory from manual mapping and module stomping; thread pool injection avoids creating new `MEM_PRIVATE` regions.
- **T-008 Threadless Injection** — threadless injection avoids new thread creation, evading Hunt-Sleeping-Beacons' thread start address analysis, though the hijacked export's replaced code may still be detected by `.text` section comparison.
- **T-013 Remaining Injection Methods** — process hollowing, module stomping, and manual mapping are PE-sieve's primary detection targets; each variant has a distinct detection algorithm that operators must account for.

## References

- Atlas material: atlas-recon-part6.md, atlas-edr-evasion-part6.md
- MITRE ATT&CK: T1055 — https://attack.mitre.org/techniques/T1055/
- LGTM notes: lgtm:pe-sieve-detection-coverage, lgtm:pe-sieve-detection-tool-card
- Public references: PE-sieve (hasherezade), Moneta, Hunt-Sleeping-Beacons, hollows_hunter

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-056 -->