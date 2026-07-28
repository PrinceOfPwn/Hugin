<!-- BEGIN CARD T-051 -->
---
id: T-051
name: VERSIONINFO Resource Impersonation for Binary Spoofing
category: anti-analysis
tier: B
crate: none
source_file: none
mitre: T1036
tags: [versioninfo, metadata-spoofing, resource-section, masquerading, rsrc, static-analysis-evasion, pe-resources, vendor-impersonation]
origin: atlas-synthesis
member_notes: [lgtm:binary-versioninfo-impersonation]
---

# VERSIONINFO Resource Impersonation for Binary Spoofing — Forge Vendor Metadata in the PE Resource Section

## Summary

VERSIONINFO resource impersonation embeds forged vendor metadata — CompanyName, FileDescription, OriginalFilename, ProductVersion — into the PE `.rsrc` section so that static analysis tooling attributes the binary to a legitimate application such as Google Chrome or a Windows component. The technique exploits the fact that VS_VERSION_INFO is purely informational: the Windows loader never reads it, while Explorer, Task Manager, Sysmon, sigcheck, and triage tooling surface it as authoritative provenance. Operators use it to defeat human triage and metadata-based heuristics that compare binary provenance against known-good vendor signatures before any behavioral analysis begins. The MalDev Academy metadata.src unit demonstrates the pattern by impersonating Google Chrome with CompanyName=Google LLC, FileDescription=Google Chrome, OriginalFilename=chrome.exe, and ProductVersion=112.0.5615.86. The primary detection surface is the mismatch between the claimed vendor and everything else about the binary — missing Authenticode signature, inconsistent file path, inconsistent filename.

## Mechanism

1. Author a `.rc` resource script containing a VS_VERSION_INFO root block with two payloads: a fixed numeric header and a string table.
2. Populate the StringFileInfo entries with the impersonation target's values: CompanyName, FileDescription, FileVersion, InternalName, LegalCopyright, OriginalFilename, ProductName, ProductVersion — for the Chrome example, Google LLC / Google Chrome / chrome.exe / 112.0.5615.86.
3. Populate the fixed file info to match the strings numerically: FILEVERSION and PRODUCTVERSION as the same 112.0.5615.86 quad, file OS VOS_NT_WINDOWS32, file type VFT_APP, flags zero. Keeping the numeric and string forms consistent prevents trivial string-versus-number cross-checks.
4. Compile the `.rc` into a `.res` (rc.exe, llvm-rc, or windres) and link it; the linker emits a `.rsrc` section containing the version resource under resource type RT_VERSION (16).
5. On disk, any consumer calling GetFileVersionInfoSize / GetFileVersionInfo / VerQueryValue, or walking the resource directory tree directly, receives the forged strings and presents them as attribution.
6. Execution is unaffected — the loader, memory manager, and loader snaps ignore RT_VERSION entirely — so the impersonation is pure data. Because it lives in the resource section rather than in code, it survives compilation choices, packing, and in-memory loading unchanged; the same bytes are read whether the binary is inspected on disk or dumped from memory.

## OS Internals Context

The `.rsrc` section is organized as a three-level IMAGE_RESOURCE_DIRECTORY tree: Type level (RT_VERSION = 16 for version resources), Name/ID level, Language level, terminating in an IMAGE_RESOURCE_DATA_ENTRY whose OffsetToData and Size locate the VS_VERSION_INFO blob. That blob opens with VS_FIXEDFILEINFO — signature 0xFEEF04BD, dwFileVersionMS/dwFileVersionLS carrying the numeric version consumed by installer and version-comparison APIs — followed by StringFileInfo containing one or more StringTable blocks keyed by an 8-hex-digit language-plus-codepage identifier ("040904b0" for en-US Unicode), each holding the human-readable strings, and finally VarFileInfo with a Translation value listing the same language/codepage pairs. Two consumer paths diverge: VerQueryValue resolves the localized strings through the language table, while version-comparison logic reads only the fixed numeric quad; forging both keeps the two representations coherent.

Consumers of this data are numerous and none of them validate it: Explorer's file Properties → Details tab, Task Manager's process list, PowerShell's Get-AuthenticodeSignature-adjacent version cmdlets, WMI CIM_DataFile version queries, sigcheck, and Sysmon Event ID 1, which extracts Description, Product, Company, and OriginalFileName from the image at process-create time and forwards them to the SIEM. The forged metadata therefore propagates automatically into defender telemetry pipelines under the attacker's chosen vendor identity.

Authenticode interacts with the resource section in a way that bounds the technique: the image digest computed by ImageGetDigestStream hashes the `.rsrc` contents, so editing VERSIONINFO on a signed binary invalidates its signature. Impersonation is consequently applied to unsigned implants, and the resulting gap — a binary claiming CompanyName "Google LLC" with no signature — is itself the standard analyst catch. Machine-learning classifiers also consume metadata as static features (presence of a company string, OriginalFilename-to-filename agreement, version-string entropy), which is the heuristic class the technique targets: an implant carrying plausible, internally consistent vendor metadata scores closer to the benign distribution than one with empty or garbage version fields.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. An implementation would add a build-time step to the dark_crystal pipeline: a `.rc` script with the VS_VERSION_INFO block compiled via the `embed-resource` crate in `build.rs`, parameterized by a builder profile that selects the impersonation target (chrome.exe, Microsoft component strings, or a verbatim copy extracted from a genuine binary on disk). A post-build variant would open the compiled binary with BeginUpdateResourceW, write the RT_VERSION payload with UpdateResourceW, and commit with EndUpdateResourceW, allowing per-build metadata rotation without recompiling the implant.

## Why It Matters

The vault's T-020 anti-analysis suite manipulates import tables (IAT camouflage) and on-disk presence (self-deletion) but does not surface provenance metadata, which is the first artifact an analyst reads during triage and a field that flows unmodified into Sysmon Event ID 1. VERSIONINFO impersonation is a compile-time control with zero runtime cost and zero additional API surface that shapes both human judgment and static heuristics before behavioral analysis ever runs. It composes directly with filename and path masquerading: the Chrome strings are maximally effective when the binary actually presents as chrome.exe in a plausible directory, making the resource the load-bearing half of a coherent disguise.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 1 logs Company, Description, Product, and OriginalFileName extracted from the image at process creation; EDR consoles surface the same fields as attribution; static scanners (peframe, YARA with the pe module, sigcheck) read the `.rsrc` section directly.
- **Bypass options**: copy metadata verbatim from a genuine binary of the impersonated product so both string and numeric version forms match a real release; align OriginalFilename with the actual on-disk filename and directory; select impersonation targets whose legitimate distribution is unsigned or whose signature absence is unremarkable in the environment; keep resource-section size and language-table structure plausible (a single 040904b0 table matches most en-US binaries).
- **Residual artifacts**: the forged resource is a permanent static artifact embedded in the deliverable. Mismatch heuristics are the primary catch — CompanyName "Google LLC" with no Authenticode signature, OriginalFilename disagreeing with the actual path, version strings inconsistent with PE compile timestamps, or vendor strings on binaries with high-entropy sections. Public YARA rules match known-vendor version strings appearing on unsigned executables.

## Related Techniques

- **T-020 Anti-Analysis Suite** — T-020 covers IAT camouflage, anti-VM, API hammering, and self-deletion; VERSIONINFO impersonation is the static-provenance complement that the suite does not document, operating on the analyst-facing metadata layer rather than imports or disk artifacts.

## References

- Atlas material: atlas-binary-analysis-part8.md (unit 39, metadata.src)
- MITRE ATT&CK: T1036 — Masquerading (https://attack.mitre.org/techniques/T1036/)
- LGTM notes: lgtm:binary-versioninfo-impersonation
- Public references: MalDev Academy (metadata.src unit)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.
<!-- END CARD T-051 -->

<!-- BEGIN CARD T-052 -->
---
id: T-052
name: Advanced Capability Escalation Decision Framework
category: discovery
tier: B
crate: none
source_file: none
mitre: T1518.001
tags: [operational, trigger-framework, technique-selection, tradecraft, escalation, edr-detection, capability-tiers, methodology]
origin: atlas-synthesis
member_notes: [lgtm:advanced-capability-selection-framework]
---

# Advanced Capability Escalation Decision Framework — Trigger-Based Selection of Implant Capabilities

## Summary

The Advanced Capability Escalation Decision Framework is a SEC670 methodology for deciding when an implant must move from basic to advanced capabilities, driven by four explicit triggers and four escalation options. It is an operator-side decision process rather than endpoint code: it maps observed defender posture to the minimum sufficient technique tier so that advanced tradecraft is only exposed when the environment demands it. Operators use it to avoid two failure modes — under-matching, where a hooked-API technique is deployed against an EDR that instruments exactly that API, and over-matching, where direct syscalls or manual loaders are burned on a target that LoadLibrary would have serviced, exposing premium capability to telemetry and reverse engineering. The framework itself emits no endpoint telemetry; its inputs (defender discovery actions) and outputs (the deployed techniques) carry the entire detection surface.

## Mechanism

1. Deploy a baseline capability tier chosen for a default-assumed environment — standard Win32 APIs, conventional module loading, established C2.
2. Enumerate defender posture: installed security products, running services and kernel drivers, EDR DLLs present in processes, monitoring and hunting tooling.
3. Evaluate the four triggers against the observations: (1) **defender match** — a specific EDR is identified whose instrumentation covers the technique currently in use; (2) **tech-savvy admin** — indicators of competent active defense such as hunting scripts, Sysmon deployment, or rapid incident response; (3) **stealth requirement** — a mission constraint that demands minimal telemetry regardless of what defense is observed; (4) **basic technique failure** — an API call is blocked, an alert fires, or a payload terminates in a way that indicates interception.
4. Map the fired triggers to escalation options: **manual image loading** to replace LoadLibrary-based module introduction; **API hook reimplementation** to supply own implementations instead of calling hooked APIs; **C2 callbacks** to shift execution into the communication channel; **shellcode execution** to abandon PE artifacts in favor of position-independent payloads. The consolidated cluster description records the same option set in broader terms as manual image loading, hook reimplementation, direct syscalls, and custom tooling.
5. Validate the selected technique against a lab replica of the observed defender stack before it touches the target again.
6. Deploy, monitor for the failure trigger, and re-enter the loop at step 3 if interception recurs — escalation is iterative, not one-shot.

## OS Internals Context

Each escalation option changes which OS boundary the implant crosses, and therefore which instrumentation layer observes it. LoadLibrary crosses the user-mode loader: LdrLoadDll inside ntdll walks the module dependency graph, snaps the PEB loader lists (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList), fires ImageLoad ETW events, and passes through any EDR hooks on the loader path. A manual image loader performs its own section mapping, relocation, and import resolution, skipping loader bookkeeping and its ETW surface — at the cost of absent LDR entries that become their own anomaly under memory analysis. Calling Win32 APIs crosses kernelbase and ntdll stubs, which is precisely where EDR inline hooks and ETW user-mode providers sit; reimplementing the functionality locally, or descending to the syscall instruction directly, removes the hooked entry points from the call path and leaves kernel callbacks and ETW Threat-Intelligence as the remaining observers. C2 callbacks shift work off the endpoint entirely, reducing local API volume at the price of network-layer telemetry — the trade documented in the networking cards. Shellcode execution removes PE structure from memory and defeats image-based scanning, but encounters RWX-page heuristics, thread start-address analysis, and the absence of a backing module. The framework is the disciplined act of choosing which boundary to cross after learning which boundaries are watched, rather than defaulting to the most exotic primitive available.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. The nearest existing analog is the static phase pipeline in `src/dark_crystal/crates/core/src/runner.rs`, where technique selection is fixed at build time through `selection_config` constants — anti-VM on or off, injection type, syscall mode, hammering — and where `dispatch_injection` cascades through module overloading, ghosting, threadless, reflection, and fiber injection in a predetermined order. A framework implementation would make that pipeline conditional on runtime posture: a posture-assessment phase enumerating EDR processes, drivers, and injected DLLs whose results gate which later phases activate, plus failure-feedback handling that re-selects the injection path when a phase returns an interception-indicating error, converting the current fixed fallback ordering into trigger-driven selection.

## Why It Matters

The vault documents more than eighty techniques as isolated cards, but nothing previously recorded the selection logic that SEC670 teaches for navigating among them. The framework fills the operational gap between "technique exists" and "technique is appropriate," protecting high-tier capabilities — RecycledGate, VEH Gate, Early Cascade — from premature exposure against targets that basic tradecraft would have handled. It also gives engagement teams a shared vocabulary for escalation decisions when defender posture shifts mid-operation, and it defines when to stop escalating: the stealth-requirement trigger caps exposure rather than rewarding maximal sophistication.

## Detection Considerations

- **Telemetry sources**: the framework is operator-side and emits nothing itself. Its posture-enumeration inputs — process, service, driver, and loaded-module inventory — can touch ETW Threat-Intelligence when privileged handles are opened, and its outputs inherit the full detection surface of whichever technique card is selected.
- **Bypass options**: derive defender posture from passive sources where possible, such as file-system artifacts of EDR installations and service registry keys, rather than broad live enumeration; validate escalations against a lab replica so the target never observes the probing that would confirm defender presence.
- **Residual artifacts**: none from the framework itself; each escalated technique leaves the artifacts documented on its own card.
- The training material documents the triggers and escalation options but does not discuss detection of the framework itself.

## Related Techniques

- **T-007 Pool Party and Process Injection Methods** — the injection catalog is the primary escalation target when the basic-technique-failure trigger fires on module introduction or shellcode execution.
- **T-016 EDR Evasion Suite** — the capability pool selected when the defender-match trigger identifies specific instrumentation such as AMSI, ETW, or user-mode hooks.
- **T-022 Network Suite** — the C2-callback escalation option shifts execution into the networking and transport layer documented here.

## References

- Atlas material: atlas-exploit-dev-part15.md (unit 38)
- MITRE ATT&CK: T1518.001 — Software Discovery: Security Software Discovery (https://attack.mitre.org/techniques/T1518/001/)
- LGTM notes: lgtm:advanced-capability-selection-framework
- Public references: SEC670 (trigger framework unit)

## Source Reference

No current implementation. The static selection pipeline in src/dark_crystal/crates/core/src/runner.rs and dark_crystal/crowd/src/payload_cfg.rs is the nearest analog; see atlas material for the methodology.
<!-- END CARD T-052 -->

<!-- BEGIN CARD T-053 -->
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
<!-- END CARD T-053 -->