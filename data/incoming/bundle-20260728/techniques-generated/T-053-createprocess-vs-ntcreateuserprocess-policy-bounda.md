---
id: T-053
name: CreateProcess vs NtCreateUserProcess Policy Boundary
category: discovery
tier: B
crate: dark_crystal
source_file: src/dark_crystal/crowd/src/nt_create_process.rs
mitre: T1106
mitre_secondary: [T1134.004]
tags: [createprocess, ntcreateuserprocess, ppid-spoofing, policy-boundary, win32-vs-nt, startupinfoex, ps-attribute-list, block-dll]
origin: atlas-synthesis
member_notes: [lgtm:createprocess-vs-ntcreateuserprocess-policy-boundary]
---

# CreateProcess vs NtCreateUserProcess Policy Boundary — Choosing the Process-Creation Layer

## Summary

Every user-mode process creation flows through one of two layers: CreateProcessW, whose kernelbase internal applies attribute-driven policy automatically, or NtCreateUserProcess, which accepts a caller-built PS_ATTRIBUTE_LIST and skips the Win32 wrapper entirely. The boundary matters because the Win32 layer is the standard EDR hook point — kernelbase!CreateProcessInternalW is the most-instrumented process-creation API across major vendors — and it is the layer where mitigation inheritance, Block-DLL policy, and parent-process assignment are handled implicitly, whereas the NT layer requires the operator to encode each policy explicitly and bypasses every user-mode hook chain in the wrapper. Operators choose the NT path when they need PPID spoofing, Block-DLL, and suspended creation delivered in a single syscall with no Win32 API footprint; the Win32 path remains relevant when default policy inheritance and subsystem integration are desired. The detection delta is confined to user mode: kernel process-creation notify routines and Kernel-Process ETW fire identically on both paths.

## Mechanism

Win32 wrapper path:

1. The caller allocates STARTUPINFOEX and builds a PROC_THREAD_ATTRIBUTE_LIST: InitializeProcThreadAttributeList sizes the opaque buffer, UpdateProcThreadAttribute fills it.
2. PROC_THREAD_ATTRIBUTE_PARENT_PROCESS carries a handle to the spoofed parent (opened with PROCESS_CREATE_PROCESS); PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY carries Block-DLL and ACG bits. This is the Win32 route to PPID spoofing.
3. CreateProcessW with EXTENDED_STARTUPINFO_PRESENT enters kernelbase!CreateProcessInternalW — the canonical user-mode hook point — which normalizes paths, processes the attribute list, applies policy, and ultimately calls NtCreateUserProcess itself.

NT-direct path, as implemented in crowd:

4. Convert the image path to an NT-path UNICODE_STRING; build_nt_image_path prepends `\??\` when the caller supplies a Win32 path.
5. Build RTL_USER_PROCESS_PARAMETERS via RtlCreateProcessParametersEx with RTL_USER_PROC_PARAMS_NORMALIZED, supplying the image path as both ImagePathName and CommandLine.
6. Zero an 88-byte PS_CREATE_INFO and leave its state field at PsCreateInitialState (0).
7. Assemble a PS_ATTRIBUTE_LIST — header length plus up to four entries: PS_ATTRIBUTE_IMAGE_NAME (0x20005) pointing at the NT path buffer; PS_ATTRIBUTE_CLIENT_ID (0x10003) to receive the new PID and TID; optionally PS_ATTRIBUTE_PARENT_PROCESS (0x0006_0000) carrying the spoofed-parent handle, with PID 0 auto-resolving to explorer.exe; optionally PS_ATTRIBUTE_MITIGATION_OPTIONS (0x20010) carrying BLOCK_NON_MS_BINARIES_ALWAYS_ON (0x0000_1000_0000_0000).
8. Invoke NtCreateUserProcess via RecycledGate with PROCESS_CREATE_FLAGS_SUSPENDED (0x1); on success destroy the parameters with RtlDestroyProcessParameters and close the parent handle.
9. For injection, continue entirely over direct syscalls: NtAllocateVirtualMemory (MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), NtWriteVirtualMemory, NtProtectVirtualMemory (PAGE_EXECUTE_READ), NtQueueApcThread with the shellcode as the APC routine, NtResumeThread — the APC fires before the PE entry point, completing an Early Bird delivery.

## OS Internals Context

CreateProcessW has not created a process itself since Vista: CreateProcessInternalW is a thick wrapper that converts DOS paths, builds the RTL_USER_PROCESS_PARAMETERS, translates the Win32 attribute list into a PS_ATTRIBUTE_LIST, and invokes NtCreateUserProcess. The training material frames the policy delta as follows: the Win32 layer applies mitigation inheritance, Block-DLL policy, and parent-process validation, while the NT layer skips these implicit behaviors. Concretely, the wrapper computes defaults on the caller's behalf — inheriting the creator's mitigation policy unless overridden, processing the parent-handle attribute, selecting console and desktop state — whereas the NT caller receives exactly the policies encoded in its attribute list: nothing inherited, nothing applied that was not requested. Attribute encodings differ between the layers but share a shape: a 16-bit attribute number combined with flag bits (INPUT 0x20000, ADDITIVE 0x40000 on the NT side), which is why the crowd module defines PS_ATTRIBUTE_IMAGE_NAME as 0x20005 and PS_ATTRIBUTE_MITIGATION_OPTIONS as 0x20010, sourcing the constants from ReactOS and Windows Internals because the ntapi crate does not expose them.

Both paths converge in the kernel at PspCreateProcess: routines registered with PsSetCreateProcessNotifyRoutineEx, kernel-side policy evaluation, and ETW Microsoft-Windows-Kernel-Process all fire regardless of which user-mode layer initiated creation. The crowd module header records the practical consequences of the boundary: CreateProcessW is the number-one hooked API among major EDRs, going direct skips the entire user-mode hook chain in kernelbase, fewer Win32-subsystem ETW events are generated, and one syscall replaces the InitializeProcThreadAttributeList / UpdateProcThreadAttribute / CreateProcessW sequence — PPID spoof, Block-DLL, and suspended state collapse into a single call. The evasion gain is therefore real but bounded: user-mode sensors lose the event, kernel sensors never do.

## Key Implementation Details

`src/dark_crystal/crowd/src/nt_create_process.rs` implements the NT-direct side of the boundary. `build_nt_image_path` normalizes the image path and produces the UNICODE_STRING. `open_parent_handle` obtains the spoof-parent handle through `crate::recycled::nt_open_process` with PROCESS_CREATE_PROCESS (0x0080), the minimum right NtCreateUserProcess requires of a parent handle. `create_suspended` constructs the 88-byte PS_CREATE_INFO, assembles the four-slot attribute list, resolves `Some(0)` PPIDs to explorer.exe via `crate::ppid::find_pid_by_name`, and issues the syscall through `crate::recycled::nt_create_user_process`, then tears down parameters and the parent handle on both success and failure paths. `create_and_inject` forces the Block-DLL mitigation on, allocates remote memory, writes the payload, flips protection to PAGE_EXECUTE_READ (treating a failed flip as non-fatal), queues the APC, and resumes the thread; every failure branch frees the region, terminates the process, and closes handles in order. Convenience wrappers `create_default_suspended` and `inject_into_svchost` hardcode svchost.exe with explorer.exe PPID spoofing. All NT calls route through RecycledGate, so the chain contains zero Win32 API entries.

## Why It Matters

T-014 documents NtCreateUserProcess as a creation primitive and T-015 documents PPID spoofing, but neither records the policy delta that drives the choice between layers. That delta is the operational decision: the Win32 wrapper provides automatic policy inheritance and maximal hook exposure, while the NT layer provides explicit policy control, single-syscall PPID-plus-Block-DLL-plus-suspend, and no Win32 footprint — with kernel telemetry constant across both. Understanding the boundary prevents redundant work, such as spoofing a parent through a hooked API, and prevents false assumptions, such as expecting the NT path to evade kernel process-creation callbacks.

## Detection Considerations

- **Telemetry sources**: ETW Microsoft-Windows-Kernel-Process and PsSetCreateProcessNotifyRoutineEx fire on both paths; Sysmon Event ID 1 logs process creation with ParentImage and ParentProcessId taken from the reported parent. For PPID spoofing performed on either layer, the kernel-reported CreatorProcessId (the true creator) diverges from the spoofed ParentProcessId — a documented anomaly that defenders correlate.
- **Bypass options**: the NT path removes user-mode hook visibility because kernelbase!CreateProcessInternalW is never reached, and it reduces Win32-subsystem ETW emission. Crowd's implementation additionally applies BLOCK_NON_MS_BINARIES_ALWAYS_ON at creation so EDR DLLs cannot load into the new process, and delivers the payload by APC before the entry point executes.
- **Residual artifacts**: none on disk — the technique is in-memory. Detectable state lives in the new process's creation parameters (reported parent, mitigation flags) and in the Early Bird sequence shape: suspended creation followed by remote write and an APC queued before the first instruction runs.

## Related Techniques

- **T-014 NtCreateUserProcess** — implements the NT-side primitive whose boundary against the Win32 wrapper this card defines.
- **T-015 PPID Spoofing** — both layers can spoof the parent (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS versus PS_ATTRIBUTE_PARENT_PROCESS); this card records where each mechanism is enforced.
- **T-013 Remaining Injection Methods** — Early Bird APC is the natural payload-delivery follow-on to suspended NT creation, as exercised by create_and_inject.
- **T-016 EDR Evasion Suite** — Block-DLL policy and user-mode hook bypass are the evasion controls whose layer-of-application this card clarifies.

## References

- Atlas material: atlas-binary-analysis-part6.md (units 16, 17, 19)
- MITRE ATT&CK: T1106 — Native API (https://attack.mitre.org/techniques/T1106/); T1134.004 — Access Token Manipulation: Parent PID Spoofing
- LGTM notes: lgtm:createprocess-vs-ntcreateuserprocess-policy-boundary
- Public references: ReactOS, Windows Internals (attribute constant sources cited in the crowd module header)

## Source Reference

src/dark_crystal/crowd/src/nt_create_process.rs — `build_nt_image_path` and `open_parent_handle` (helpers), `create_suspended` (PS_CREATE_INFO and PS_ATTRIBUTE_LIST construction, RecycledGate dispatch of NtCreateUserProcess), `create_and_inject` (allocate → write → protect → APC → resume chain), convenience wrappers `create_default_suspended` and `inject_into_svchost`.