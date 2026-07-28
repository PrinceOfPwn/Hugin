<!-- BEGIN CARD T-075 -->
---
id: T-075
name: Memory Forensics Tooling Awareness
category: anti-analysis
tier: A
crate: none
source_file: none
mitre: T1518.001
tags: [memory-forensics, volatility, pe-sieve, moneta, detection-awareness, vad-scanning, hash-mismatch, rwx-detection, evasion-constraint, defensive-tools]
origin: atlas-synthesis
member_notes: [lgtm:memory-forensics-tooling-coverage-gap, lgtm:memory-forensics-defense-landscape]
---

# Memory Forensics Tooling Awareness — Understanding the Defensive Memory Scanner Landscape

## Summary

SEC670 identifies three memory forensics tools that constrain every in-memory evasion technique: Volatility, PE-sieve, and Moneta. Volatility performs kernel-level analysis by locating the Directory Table Base (CR3) and walking EPROCESS, PEB module lists, VAD tree, and handle tables. PE-sieve operates in user mode by hashing the .text section of each loaded module and comparing against on-disk counterparts to detect hooks, hollowing, and stomping. Moneta scans for PAGE_EXECUTE_READWRITE memory pages with no corresponding VAD file mapping, catching unbacked executable allocations including PIC shellcode and manually mapped payloads. The operational consequence — "being in memory is not a get out of jail free card" — means T-007 injection methods and T-016 evasion techniques must account for detection by these scanners, not just by EDR kernel callbacks and user-mode hooks.

## Mechanism

1. Volatility acquires a memory image (via live acquisition tools such as winpmem, or via crash dumps) and identifies the DTB (CR3 value) for each process by scanning for the DirectoryTableBase field stored in the EPROCESS structure. It then walks the ActiveProcessLinks doubly-linked list to enumerate all processes.
2. For each process, Volatility reads the PEB (via the PEB pointer in EPROCESS at a known offset) and walks the InLoadOrderModuleList, InMemoryOrderModuleList, and InInitializationOrderModuleList to enumerate loaded DLLs. Discrepancies between these three lists reveal PEB unlinking — a module present in the VAD but absent from the PEB module lists indicates active evasion (T-016 PEB unlink).
3. Volatility walks the VAD tree rooted at the VadRoot field in EPROCESS to reconstruct the process virtual memory layout. Each VAD node (MMVAD_SHORT or MMVAD_LONG) describes a virtual address range, its protection flags (MM_PROTECT_MASK), and whether it is backed by a file (the Subsection pointer links to a ControlArea, which links to a FileObject). Unbacked executable regions are flagged for investigation.
4. Volatility dumps process handles via the HandleTable in EPROCESS, revealing open handles to other processes, tokens, sections, or threads that indicate injection or token manipulation activity.
5. PE-sieve runs in user mode (or attaches to a target process) and enumerates loaded modules via the PEB's InLoadOrderModuleList. For each module, it reads the .text section from memory and computes a hash of the in-memory bytes.
6. PE-sieve reads the corresponding on-disk file (using the module's FullDllName from the LDR_DATA_TABLE_ENTRY), locates its .text section using the PE section headers, and computes a hash of the on-disk bytes. If the in-memory hash differs from the on-disk hash, the module is flagged as modified — indicating inline hooks, module stomping, or process hollowing.
7. PE-sieve also scans for modules present in the VAD (file-backed MEM_IMAGE regions) but absent from the PEB module lists. These "unlinked" modules indicate PEB unlinking or manually mapped DLLs that were loaded outside the normal loader path.
8. Moneta operates in user mode and scans the virtual address space of a target process by calling NtQueryVirtualMemory (MemoryWorkingSetEx or MemoryBasicInformation class) for each page range. It identifies pages with PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY protection that have no file backing — the AllocationProtect and Type fields indicate MEM_PRIVATE with no associated Section object.
9. Moneta flags these unbacked executable regions as suspicious. They typically contain PIC shellcode allocated via VirtualAlloc/NtAllocateVirtualMemory, manually mapped payloads loaded through NtCreateSection + NtMapViewOfSection of a transient section (created with SEC_COMMIT and no file handle), or module-stomped code that was allocated privately rather than mapped from a legitimate file.

## OS Internals Context

The EPROCESS structure (kernel mode, size approximately 0x800 bytes on Windows 10 x64) contains VadRoot (an MM_AVL_TABLE root pointing to the VAD tree), ActiveProcessLinks (a LIST_ENTRY connecting all EPROCESS structures), ThreadListHead, and HandleTable (pointer to the EX_HANDLE_TABLE structure). Volatility's ability to walk these structures comes from having a kernel memory image — it operates at a level below EDR's user-mode hooks and does not trigger any ntdll/kernel32 API monitoring.

The VAD entries are of type MMVAD (with MMVAD_SHORT for simple allocations and MMVAD_LONG for file-backed or extended entries). Each MMVAD has a Subsection pointer that links to the CONTROL_AREA structure, which in turn links to the FILE_OBJECT — this is the chain that Volatility and Moneta follow to determine whether a memory region is backed by a file. A VirtualAlloc allocation creates a VAD entry with no Subsection (Type = MEM_PRIVATE), while NtMapViewOfSection of a file-backed section creates a VAD entry with a Subsection chain pointing to the file.

The PEB (user mode, accessible via gs:[0x60] on x64) contains the Ldr field pointing to the PEB_LDR_DATA structure. The three module lists in PEB_LDR_DATA (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList) are traversed via LDR_DATA_TABLE_ENTRY structures. When an operator unlinks a module from the PEB (T-016 PEB unlink), the module's LDR_DATA_TABLE_ENTRY is removed from all three lists, but the section mapping remains in the VAD with its file backing intact. Volatility detects this by cross-referencing VAD file-backed regions against PEB module lists.

PE-sieve's hash comparison leverages the fact that the Windows loader maps a DLL's sections into memory according to the section headers in the PE file. For a legitimate system DLL with a preferred base address (no relocations applied to .text), the in-memory .text bytes should be byte-identical to the on-disk .text bytes. Any deviation — inline hooks (jmp or call instructions patched at function prologues), module stomping (entire .text overwritten with shellcode), or process hollowing (entire image replaced) — produces a hash mismatch that PE-sieve flags.

Moneta's detection of unbacked RWX pages targets the Windows memory protection model. NtAllocateVirtualMemory creates VAD entries with Type = MEM_PRIVATE and no Subsection pointer. A region allocated as PAGE_EXECUTE_READWRITE with MEM_PRIVATE type is a strong indicator of shellcode. In contrast, NtMapViewOfSection of a file-backed section creates VAD entries with Type = MEM_IMAGE, backed by a FileObject via the Subsection → ControlArea chain. Moneta does not flag these regions, which is why mapping shellcode through a legitimate DLL section defeats Moneta's detection.

## Key Implementation Details

**No current implementation in the HUGIN source.** The dark_crystal crate's evasion modules (src/evasion/, src/ntdll_unhook_inject.rs, src/peb_unlink.rs, src/experimental/evasion/advanced_stack.rs) implement evasion techniques that must account for these scanners, but do not implement detection of or counter-detection against Volatility, PE-sieve, or Moneta. An implementation would consist of a pre-deployment self-scan module that enumerates the process's own VAD tree and PEB module lists, identifies unbacked RWX regions and hash-mismatched modules, and either remediates them (by converting allocations to file-backed mappings via NtMapViewOfSection of a legitimate DLL, or by restoring original .text bytes via fresh-copy unhook) or reports them as detection risks before executing payloads.

## Why It Matters

Every evasion technique in the vault operates against a dual threat model: EDR hooks and kernel callbacks (which monitor API calls and process creation), and memory forensics scanners (which perform direct memory inspection outside the EDR hook infrastructure). A technique that bypasses EDR hooks but leaves unbacked RWX pages or hash-mismatched modules is detectable by memory scanners that operate through a different detection axis. SEC670 explicitly frames this as a constraint on all in-memory operations — "being in memory is not a get out of jail free card" — making this awareness card a cross-cutting prerequisite for every injection and evasion technique in the vault.

## Detection Considerations

- **Telemetry sources**: Volatility acquires memory images via tools like winpmem (which loads a temporary kernel driver) or LiveKD; PE-sieve and Moneta run as standalone user-mode executables that query virtual memory via NtQueryVirtualMemory. These tools do not rely on ETW, kernel callbacks, or Sysmon — they perform direct memory inspection after-the-fact.
- **Bypass options**: To defeat PE-sieve, use a fresh-copy unhook (T-016) that replaces ntdll.dll .text with bytes read from the on-disk file (C:\Windows\System32\ntdll.dll), making the in-memory hash match the on-disk hash. To defeat Moneta, allocate shellcode in a region backed by a file mapping — use NtCreateSection on a legitimate DLL from System32, NtMapViewOfSection to map it into the process, then overwrite the mapped content with shellcode. The VAD entry will show MEM_IMAGE with a file backing via the Subsection → ControlArea chain, and Moneta will not flag the region. To defeat Volatility's PEB cross-referencing, ensure that mapped DLLs remain in the PEB module lists (do not unlink them), since PEB unlinking creates the discrepancy that Volatility detects.
- **Residual artifacts**: Volatility's acquisition tools (winpmem driver) create a temporary device object visible in the object namespace. PE-sieve and Moneta are standalone executables that appear in the process list and can be detected by process name scanning. An implant can detect these tools by checking for their process names (pe-sieve.exe, Moneta.exe, vol.py) or by scanning for their characteristic NtQueryVirtualMemory call patterns.

## Related Techniques

- **T-007 Process Injection Suite** — Injection techniques must account for VAD-backed allocation to evade Moneta and hash-matched modules to evade PE-sieve
- **T-013 Remaining Injection Methods** — Module stomping and function stomping produce .text hash mismatches detectable by PE-sieve
- **T-016 EDR Evasion Suite** — PEB unlinking is detected by Volatility's VAD-to-PEB cross-referencing; NTDLL fresh-copy unhook defeats PE-sieve hash comparison

## References

- Atlas material: atlas-edr-evasion-part1.md (units 23, 24, 25, 32), atlas-edr-evasion-part4.md (units 1, 9)
- MITRE ATT&CK: T1518.001 — https://attack.mitre.org/techniques/T1518/001/
- LGTM notes: lgtm:memory-forensics-tooling-coverage-gap, lgtm:memory-forensics-defense-landscape
- Public references: Volatility 3 (volatilityfoundation), PE-sieve (hasherezade), Moneta (Fox-IT)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling (Volatility 3, PE-sieve by hasherezade, Moneta by Fox-IT).
<!-- END CARD T-075 -->

<!-- BEGIN CARD T-076 -->
---
id: T-076
name: AV/EDR Cloud Sample Submission OPSEC
category: anti-analysis
tier: B
crate: none
source_file: none
mitre: T1027
tags: [cloud-submission, opsec, egress-discipline, sample-submission, defender-maps, crowdstrike-falcon, sentinelone, signature-generation, vendor-endpoints, behavioral-alert]
origin: atlas-synthesis
member_notes: [lgtm:av-cloud-sample-submission-opsec, lgtm:cloud-sample-submission-egress-discipline]
---

# AV/EDR Cloud Sample Submission OPSEC — Egress Discipline for Sample Submission Prevention

## Summary

SEC670 documents the operational risk that modern AV/EDR products — notably Microsoft Defender SmartScreen, CrowdStrike Falcon, and SentinelOne — automatically upload binaries that trigger behavioral alerts but match no known signature to vendor cloud analysis environments. The cloud sandbox detonates the submitted sample, extracts indicators of compromise, and generates new detection signatures that are distributed to all deployed agents. This process can expose the full capability set and implementation details of a custom implant to the vendor. The operational response is egress discipline: restricting the implant's network access to only the C2 channel, blocking known vendor submission endpoints at the host firewall, and using signed or known-good payload containers where possible to reduce the likelihood of behavioral alerts that trigger submission.

## Mechanism

1. The AV/EDR client monitors process behavior via kernel callbacks (ObRegisterCallbacks for handle operations, PsSetCreateProcessNotifyRoutine for process creation, PsSetCreateThreadNotifyRoutine for thread creation), ETW providers (Microsoft-Windows-Threat-Intelligence for memory operations), and user-mode hooks on ntdll/kernel32 functions. When a process exhibits behavior that matches a heuristic rule — for example, VirtualAllocEx followed by WriteProcessMemory followed by CreateRemoteThread — the client generates a behavioral alert.
2. If the binary that performed the suspicious behavior matches no existing signature in the local signature database, the client packages the executable file (or a memory dump of the loaded image) for cloud submission. The submission includes the binary, the behavioral context (which heuristic rule fired, what API call sequence was observed), and metadata about the process execution context.
3. The submission occurs over HTTPS to a vendor-specific endpoint. Microsoft Defender uses MAPS (Microsoft Active Protection Service) endpoints under *.cloud.app or SmartScreen reputation endpoints. CrowdStrike Falcon sensors submit to falcon-*.crowdstrike.com cloud endpoints. SentinelOne agents submit to management console endpoints under *.sentinelone.net or vendor-specific cloud domains.
4. The vendor's cloud sandbox executes the submitted sample in an instrumented environment with API monitoring, file system change tracking, registry modification logging, and network traffic capture. The sandbox extracts file system, registry, and network IOCs from the execution and generates a detection signature or YARA rule based on the observed behavior and static artifacts.
5. The new signature is distributed to all deployed agents via the vendor's cloud management platform. Retroactive scanning applies the new signature to all endpoints, detecting the implant across the entire fleet — not just the single host where the behavioral alert originally fired.
6. The operational countermeasure is egress isolation: the implant must be prevented from reaching any endpoint other than the C2 server. The operator configures the Windows Filtering Platform (WFP) or the host firewall (netsh advfirewall) to block outbound connections to known vendor submission domains and IP ranges before executing any evasion research or payload testing.
7. Vendor submission endpoints are enumerated via DNS resolution and network traffic analysis during pre-deployment testing. The operator resolves the vendor's cloud domains, identifies the resulting IP ranges, and adds host firewall rules blocking outbound TCP 443 to those ranges.
8. For payload containers, using binaries signed by a trusted certificate authority reduces the likelihood of behavioral alerts, as some AV/EDR products apply reduced scrutiny to signed binaries. However, signing does not guarantee immunity from cloud submission — behavioral anomalies still trigger submission regardless of signature status.

## OS Internals Context

The cloud submission pipeline operates through several Windows subsystems. The AV/EDR client typically runs as a service registered with the Service Control Manager (SCM) under the LocalSystem account or as a protected process (PS_PROTECTED type), with a kernel-mode network filter driver that inspects outbound traffic. When a behavioral alert triggers, the client uses WinHTTP or WinINet to upload the sample binary to the vendor's cloud endpoint over TLS 1.2+.

Microsoft Defender's cloud submission is governed by the MAPS (Microsoft Active Protection Service) configuration. The registry key HKLM\Software\Microsoft\Windows Defender\Spynet contains the SpynetReporting value (0 = disabled, 1 = basic metadata, 2 = advanced with file samples) and the SubmitSamplesConsent value (0 = always prompt, 1 = send safe samples automatically, 3 = send all samples automatically, 7 = never send). In enterprise environments, these settings are controlled via Group Policy under Administrative Templates → Windows Components → Microsoft Defender Antivirus → MAPS.

CrowdStrike Falcon's sensor operates through a kernel-mode driver (typically CSFalconService.sys or similar) with a user-mode service component (CSFalconService.exe) that communicates with the CrowdStrike cloud. The sensor's cloud submission behavior is controlled by sensor policy in the Falcon management console and cannot be disabled from the host without detection — the sensor itself monitors for tampering attempts against its configuration.

Windows Filtering Platform (WFP) provides the kernel infrastructure for network filtering. An operator can add WFP filter rules using the FwpmFilterAdd0 API with the FWPM_LAYER_ALE_AUTH_CONNECT_V4 layer identifier (for outbound IPv4 TCP connections) to block connections to specific remote IP ranges. The netsh advfirewall firewall add rule interface provides a user-mode wrapper around WFP for adding outbound blocking rules targeting specific remote addresses or IP subnets.

The relationship between behavioral alerts and cloud submission is critical: an implant that bypasses EDR hooks (T-016) may still trigger behavioral alerts through kernel callbacks that monitor memory operations (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) or through ETW Threat Intelligence providers that operate at the kernel level. These kernel-level detection mechanisms are not bypassed by user-mode unhooking, creating a scenario where the implant successfully evades EDR hooks but its behavior still triggers a behavioral alert that leads to cloud submission.

## Key Implementation Details

**No current implementation in the HUGIN source.** The dark_crystal crate does not implement cloud-submission endpoint blocking or egress filtering. The client_rust crate's discovery module (src/discovery.rs) handles C2 endpoint discovery via rentry.co and Sepolia contract lookup but does not implement egress filtering or vendor endpoint blocking. An implementation would consist of: (1) a DNS-based enumeration module that resolves known vendor submission endpoints (Microsoft Defender MAPS endpoints, CrowdStrike cloud endpoints, SentinelOne management endpoints) to IP ranges; (2) a WFP filter injection module or netsh advfirewall rule generator that blocks outbound connections to these IP ranges; (3) a pre-deployment verification check that confirms the C2 channel is the only permitted egress path before executing payloads or evasion research.

## Why It Matters

Cloud sample submission is the highest-impact detection risk for custom implants. A single submission can compromise an entire tool family by exposing implementation details — API call sequences, crypto routines, C2 protocol structure — that vendors use to generate signatures distributed to all endpoints. SEC670 frames this as the principal downside of iterating custom bypasses against real EDR: each iteration risks uploading the sample if the bypass itself triggers a behavioral alert. This discipline sits between T-016 (evasion) and T-020 (anti-analysis) because it governs the operational environment in which evasion techniques are developed and deployed.

## Detection Considerations

- **Telemetry sources**: The AV/EDR client's cloud submission generates outbound TLS connections to vendor domains. Network monitoring (IDS/IPS, proxy logs, DNS query logs) can detect these connections. From the implant's perspective, the submission is passive — the operator does not control or observe the upload, making it a silent detection risk.
- **Bypass options**: Egress isolation is the primary countermeasure. Block vendor submission endpoints at the host firewall before executing any payload. For Microsoft Defender, disable MAPS via registry (HKLM\Software\Policies\Microsoft\Windows Defender\Spynet, set SpynetReporting=0 and SubmitSamplesConsent=7) in environments where Group Policy permits. For CrowdStrike and SentinelOne, the sensor's cloud submission behavior is controlled by vendor-side policy and cannot be disabled from the host without triggering tamper alerts.
- **Residual artifacts**: Host firewall rules blocking vendor endpoints are visible in netsh advfirewall firewall show rule output. Registry changes to MAPS settings are logged in the Microsoft-Windows-Windows Defender/Operational ETW channel. Network connections to vendor endpoints during pre-deployment testing may be logged by network monitoring infrastructure.

## Related Techniques

- **T-016 EDR Evasion Suite** — After bypassing EDR hooks, the implant must prevent cloud submission of its binary; the bypass itself may trigger behavioral alerts via kernel callbacks
- **T-020 Anti-Analysis Suite** — Pre-flight hygiene includes verifying egress isolation before executing evasion research or payload testing
- **T-021 Crypto & Obfuscation** — Build-time feature gating decisions affect the implant's behavioral fingerprint; minimal-feature builds reduce behavioral alert surface and thus reduce cloud submission risk

## References

- Atlas material: atlas-edr-evasion-part1.md (units 11, 35, 36, 37), atlas-edr-evasion-part6.md (unit 7)
- MITRE ATT&CK: T1027 — https://attack.mitre.org/techniques/T1027/
- LGTM notes: lgtm:av-cloud-sample-submission-opsec, lgtm:cloud-sample-submission-egress-discipline

## Source Reference

No current implementation. See atlas material for SEC670 coverage of cloud submission OPSEC discipline.
<!-- END CARD T-076 -->

<!-- BEGIN CARD T-077 -->
---
id: T-077
name: Native Application NT_main Execution Surface
category: anti-analysis
tier: B
crate: none
source_file: none
mitre: T1106
tags: [native-application, nt-main, early-boot, smss, ntdll-only, bootexecute, subsystem-native, ntapi-entry, minimal-surface, image-subsystem]
origin: atlas-synthesis
member_notes: [lgtm:native-application-execution-surface, lgtm:native-application-entry-point]
---

# Native Application NT_main Execution Surface — Pre-Subsystem Execution via Native Entry Point

## Summary

SEC670 documents the native Windows application execution mode, distinguished by the entry signature NTSTATUS NTAPI NT_main(int argc, char* argv[]) and the PE optional header Subsystem field set to IMAGE_SUBSYSTEM_NATIVE (value 1). Native applications execute before the Win32 subsystem (csrss.exe and win32k.sys) is fully initialized and are invoked by the Session Manager (smss.exe) during early boot or via RtlCreateUserProcess with the image path. They have no Win32 API surface — all I/O must use ntdll exports exclusively (NtCreateFile, NtCreateKey, NtSetValueKey, NtWriteFile, NtReadFile). This execution mode is operationally valuable for early-boot persistence via BootExecute registry entries, for SurvivableProtectedProcess launchers, and for minimal recon droppers that avoid the Win32 API surface monitored by most EDR products.

## Mechanism

1. The PE optional header's Subsystem field (located at offset 0x44 in the IMAGE_OPTIONAL_HEADER64 structure on x64) is set to IMAGE_SUBSYSTEM_NATIVE (value 1) rather than IMAGE_SUBSYSTEM_WINDOWS_GUI (2) or IMAGE_SUBSYSTEM_WINDOWS_CUI (3). This signals to the image loader that the executable does not require the Win32 subsystem.
2. The entry point function uses the signature NTSTATUS NTAPI NT_main(int argc, char* argv[]), returning an NTSTATUS code rather than a Win32 DWORD exit code. The NTAPI calling convention maps to __stdcall on x86 and the standard x64 calling convention on x64, matching the ntdll export convention.
3. The image's import table contains entries only from ntdll.dll — no kernel32.dll, kernelbase.dll, user32.dll, or advapi32.dll imports. The image loader (LdrpInitializeProcess in ntdll.dll) resolves only ntdll exports for native applications, because no other subsystem DLLs are loaded at the time of execution.
4. For early-boot execution, the image path is registered in HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute as a REG_MULTI_SZ value. The default value is "autocheck autochk *". The operator appends their native application name to this multi-string.
5. During boot, smss.exe (the Session Manager Subsystem) reads the BootExecute value after performing its initial setup (creating the KnownDlls object directory, initializing the registry transaction log) and invokes each listed executable via the internal process creation path before csrss.exe is started for the session.
6. The native application performs its operations using ntdll exports: NtCreateKey/NtSetValueKey for registry access, NtCreateFile/NtWriteFile for file I/O, NtAllocateVirtualMemory for memory allocation, NtCreateSection/NtMapViewOfSection for section operations, NtQueryInformationProcess for process information.
7. The application exits by returning an NTSTATUS from NT_main. A return value of STATUS_SUCCESS (0x00000000) indicates successful completion. smss.exe interprets the return status and proceeds to the next BootExecute entry or continues the boot sequence.

## OS Internals Context

The Windows boot sequence proceeds through a fixed chain of user-mode processes. The kernel (ntoskrnl.exe) loads smss.exe as the first user-mode process during the Session Manager initialization phase. smss.exe runs in native mode — it uses only ntdll exports and executes before any Win32 subsystem components are available. smss.exe reads the BootExecute registry value from HKLM\System\CurrentControlSet\Control\Session Manager and executes each program listed there using an internal process creation routine that calls NtCreateUserProcess (or its equivalent internal call path).

The PE loader (ntdll.dll's LdrpInitializeProcess function) checks the Subsystem field in the image's IMAGE_OPTIONAL_HEADER. For IMAGE_SUBSYSTEM_NATIVE (1), the loader does not attempt to initialize the Win32 subsystem — it does not load csrss.exe, does not initialize user32.dll or gdi32.dll, and does not create a window station or desktop object for the process. The process has no access to Win32 GUI functions, no console subsystem, and no standard environment block beyond what smss.exe or the process creator provides via RTL_USER_PROCESS_PARAMETERS.

The entry point calling convention for native applications differs from the standard C runtime entry point (mainCRTStartup or WinMainCRTStartup). The standard C runtime performs initialization — CRT heap creation, atexit registration, TLS callback invocation, I/O stream initialization — before calling main or WinMain. Native applications bypass this entirely. NT_main is called directly by the loader after minimal LdrpInitializeProcess setup, with argc and argv parsed from the command line string stored in the RTL_USER_PROCESS_PARAMETERS structure referenced by the PEB's ProcessParameters field.

The RTL_USER_PROCESS_PARAMETERS structure (defined in ntdll.h, approximately 0x420 bytes on x64) contains the CommandLine field (a UNICODE_STRING at a known offset), which native applications parse using RtlCommandLineToArgvW or an equivalent ntdll parsing routine. This structure is populated by the loader based on the parameters passed to NtCreateUserProcess via the PROCESS_CREATE_INFO structure or, in the case of BootExecute, by smss.exe's internal process creation logic.

The def.rs file in the HUGIN VEH module defines the PEB, RTL_USER_PROCESS_PARAMETERS, and related structures (PebLoaderData, LoaderDataTableEntry). These definitions mirror the ntdll internal structures and are used for VEH syscall gate functionality, not for native application execution. The structures demonstrate the layout of process parameters and PEB fields that a native application would access directly.

## Key Implementation Details

**No current implementation in the HUGIN source.** The dark_crystal crate's main.rs uses standard Win32 entry conventions (linking against kernel32/kernelbase via windows_targets::link!) and the crowd crate's entry points use standard Rust main. The def.rs file in the VEH module (src/experimental/evasion/veh/def.rs) defines PEB, RTL_USER_PROCESS_PARAMETERS, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, and LDR_DATA_TABLE_ENTRY structures, but these serve the VEH syscall gate implementation, not native application execution.

An implementation would require: (1) setting IMAGE_SUBSYSTEM_NATIVE in the PE optional header via a custom linker configuration (#pragma comment(linker, "/SUBSYSTEM:NATIVE") in MSVC or a custom linker script for the Rust toolchain); (2) defining the entry point as NTSTATUS NT_main with the correct signature, bypassing the C runtime startup; (3) replacing all kernel32/kernelbase API calls with ntdll equivalents (the dark_crystal crate already implements many ntdll calls via wrappers.rs); (4) for BootExecute persistence, writing the image path to HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute using NtSetValueKey.

## Why It Matters

Native application execution provides an execution surface that most EDR products do not monitor with the same depth as Win32 applications. EDR products typically hook ntdll functions in user mode and register kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) for process and handle operations. Native applications that run during early boot via BootExecute may execute before the EDR's filter driver or user-mode service is fully initialized, creating a monitoring gap. The absence of a Win32 subsystem import surface also reduces the behavioral fingerprint — no kernel32 imports, no user32 imports, no standard C runtime initialization patterns in the import table. SEC670 identifies this as operationally valuable for early-boot persistence and minimal-footprint droppers that avoid the Win32 API surface.

## Detection Considerations

- **Telemetry sources**: Sysmon Event ID 1 (Process Create) captures native application launches, including the image path and parent process (smss.exe for BootExecute launches). Process creation kernel callbacks (PsSetCreateProcessNotifyRoutineEx) fire for native applications regardless of subsystem. EDR products that monitor ntdll API calls via inline hooks will observe NtCreateFile, NtCreateKey, and other calls made by the native application.
- **Bypass options**: The primary advantage of native applications is reduced EDR coverage during early boot, not complete invisibility. EDR products that load their filter driver as a Boot Start driver (SERVICE_BOOT_START) may still monitor native application activity from the earliest boot phase. Some EDR products do not install their user-mode hooks until the Win32 subsystem initializes, creating a window of reduced monitoring for native applications that execute via BootExecute before csrss.exe starts.
- **Residual artifacts**: BootExecute persistence leaves a registry entry in HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute, enumerable via reg query or NtEnumerateKey. The native application binary on disk has IMAGE_SUBSYSTEM_NATIVE (1) in its PE optional header, detectable via static analysis of the Subsystem field. The absence of kernel32.dll in the import table is itself an indicator of a non-standard application, as nearly all legitimate Win32 executables import from kernel32.

## Related Techniques

- **T-017 Five-Layer Persistence** — BootExecute is an early-boot persistence mechanism distinct from the five layers in T-017 (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) but operates in the same persistence category
- **T-020 Anti-Analysis Suite** — Native application execution avoids the Win32 API surface that anti-analysis checks and EDR hooks target, reducing the behavioral fingerprint

## References

- Atlas material: atlas-binary-analysis-part5.md (unit 32), atlas-binary-analysis-part8.md (unit 30)
- MITRE ATT&CK: T1106 — https://attack.mitre.org/techniques/T1106/
- LGTM notes: lgtm:native-application-execution-surface, lgtm:native-application-entry-point

## Source Reference

No current implementation. See atlas material for SEC670 coverage of native application entry conventions. The def.rs file in the VEH module (src/experimental/evasion/veh/def.rs) defines PEB and RTL_USER_PROCESS_PARAMETERS structures that mirror the internal layouts a native application would access.
<!-- END CARD T-077 -->

<!-- BEGIN CARD T-078 -->
---
id: T-078
name: CNG over Legacy CryptoAPI Migration
category: crypto
tier: A
crate: none
source_file: none
mitre: T1027
tags: [cng, bcrypt, cryptoapi, aes-gcm, api-migration, authenticated-encryption, cryptoapi-deprecated, bcrypt-provider, symmetric-encryption, windows-crypto]
origin: atlas-synthesis
member_notes: [lgtm:cng-vs-cryptoapi-modernization-signal, lgtm:cryptoapi-to-cng-migration-guidance, lgtm:cng-api-crypto-coverage]
---

# CNG over Legacy CryptoAPI Migration — Windows-Native Authenticated Encryption via BCrypt*

## Summary

SEC670 explicitly frames the deprecated CryptoAPI (Crypt*) family versus the recommended CNG (Cryptography Next Generation, BCrypt*) family as a tradecraft decision for Windows-native cryptographic operations. CryptoAPI uses CryptAcquireContextA with PROV_RSA_AES, CryptDeriveKey, and CryptEncrypt — an API surface that lacks support for authenticated encryption modes (AEAD) such as GCM and CCM. CNG uses BCryptOpenAlgorithmProvider, BCryptSetProperty, BCryptGenerateSymmetricKey, and BCryptEncrypt, providing AES-GCM and AES-CCM support via the BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure. The HUGIN dark_crystal crate uses Rust's aes-gcm crate rather than either Windows API family, which avoids the bcrypt.dll import dependency but introduces a third implementation path. This card documents the CNG API sequence for AES-GCM encryption and the operational tradeoffs between CNG, CryptoAPI, and language-native crypto crates.

## Mechanism

1. (Legacy CryptoAPI path) CryptAcquireContextA is called with the PROV_RSA_AES provider type (value 24) to obtain a cryptographic provider handle (HCRYPTPROV). This provider type maps to the Microsoft Enhanced RSA and AES Cryptographic Provider and supports RSA and AES algorithms, but the CSP (Cryptographic Service Provider) interface does not expose authenticated encryption modes.
2. CryptDeriveKey derives a symmetric key from the provider handle using a hash of the input key material. The key algorithm is specified via the ALG_ID parameter (e.g., CALG_AES_256 for 256-bit AES).
3. CryptEncrypt performs encryption using the derived key. For AES-CBC, the caller sets the cipher mode via CryptSetKeyParam with KP_MODE set to CRYPT_MODE_CBC. No GCM or CCM mode is available through the CryptoAPI CSP interface, making it unsuitable for modern authenticated encryption requirements.
4. (CNG path) BCryptOpenAlgorithmProvider is called with the algorithm identifier BCRYPT_AES_ALGORITHM (L"AES") and an optional provider name (NULL for the default Microsoft Primitive Provider). This returns a BCRYPT_ALG_HANDLE representing the AES algorithm provider.
5. BCryptSetProperty sets the chaining mode on the algorithm provider handle before key generation. The property name is BCRYPT_CHAINING_MODE (L"ChainingMode") and the value is BCRYPT_CHAIN_MODE_GCM (L"ChainingModeGCM"). For CBC mode, the value would be BCRYPT_CHAIN_MODE_CBC.
6. BCryptGenerateSymmetricKey creates a BCRYPT_KEY_HANDLE from the algorithm provider handle and the raw key material buffer (32 bytes for AES-256). The key material is passed directly as a byte array — CNG does not require key derivation through a separate CSP step, unlike CryptoAPI.
7. BCryptEncrypt performs authenticated encryption using the key handle. The caller provides a BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure as the pPaddingInfo parameter. This structure contains:
   - pbNonce: pointer to the nonce/IV buffer (12 bytes for GCM per NIST SP 800-38D)
   - cbNonce: size of the nonce (12)
   - pbAuthData: pointer to optional additional authenticated data (AAD)
   - cbAuthData: size of the AAD
   - pbTag: pointer to the output authentication tag buffer (16 bytes for GCM)
   - cbTag: size of the tag (16)
   - dwVersion and cbSize: structure version and size fields (initialized via the BCRYPT_INIT_AUTH_MODE_INFO macro)
8. BCryptEncrypt returns the ciphertext in the output buffer and writes the authentication tag to pbTag. The tag is stored alongside the ciphertext for transmission. On the receiving end, BCryptDecrypt uses the same BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure with the received tag — if the tag does not match the computed GMAC over the ciphertext and AAD, BCryptDecrypt returns STATUS_AUTH_TAG_MISMATCH (0xC000A002).
9. BCryptDestroyKey releases the key handle, and BCryptCloseAlgorithmProvider releases the algorithm provider handle. The bcrypt.dll module remains loaded in the process's module list for the lifetime of the process once any BCrypt* function is called.

## OS Internals Context

CNG was introduced in Windows Vista as the replacement for the legacy CryptoAPI (also known as Wincrypt or CryptoAPI 1.0). CryptoAPI uses a CSP (Cryptographic Service Provider) architecture where cryptographic operations are delegated to pluggable provider DLLs loaded via the CryptLoadCSP function. The PROV_RSA_AES provider type (24) maps to the Microsoft Enhanced RSA and AES Cryptographic Provider (rsaenh.dll). The CSP interface was designed in the Windows NT 4.0 era and predates the standardization of authenticated encryption modes (GCM was specified in NIST SP 800-38D in 2007). CryptoAPI's lack of AEAD support is a structural limitation of the CSP architecture, not a missing feature.

CNG uses a different architecture: algorithm providers are loaded by the CNG configuration subsystem (configured under HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Providers) and exposed through the BCrypt* function surface implemented in bcrypt.dll (user mode) and ksecdd.sys (kernel mode). The Microsoft Primitive Provider (Microsoft Primitive Provider, loaded by default when no provider name is specified) implements AES, SHA-2, RSA, and ECDSA primitives directly in the CNG framework without requiring an external provider DLL.

The BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure (defined in bcrypt.h) is approximately 100 bytes on x64. It contains version fields (dwVersion must be set to BCRYPT_INIT_AUTH_MODE_INFO_VERSION, cbSize to sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)), the nonce (pbNonce/cbNonce), additional authenticated data (pbAuthData/cbAuthData), the tag (pbTag/cbTag), and MAC context fields (pbMacContext/cbMacContext) used for multi-part authenticated encryption via BCryptEncrypt with the BCRYPT_BLOCK_PADDING flag and multiple calls.

For AES-GCM, the nonce should be 12 bytes (96 bits) per NIST SP 800-38D, and the tag is 16 bytes (128 bits). AES-GCM processes the plaintext in counter mode (AES-CTR) and computes a Galois MAC (GMAC) over the ciphertext and AAD using GHASH polynomial evaluation over GF(2^128). The CNG provider performs both the AES-CTR and GHASH operations internally when BCryptEncrypt is called with the BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure.

The deprecation of CryptoAPI is implicit in Microsoft's documentation: the Crypt* functions are marked as "superseded" by CNG equivalents, and new cryptographic algorithms are only available through CNG providers. The Windows CNG framework is the only way to use AES-GCM or AES-CCM through Windows-native APIs. The legacy CryptoAPI remains present for backward compatibility but should not be used for new development.

## Key Implementation Details

**No current implementation in the HUGIN source.** The dark_crystal crate's crypto module (dark_crystal/crates/core/src/crypto.rs, mapped to T-021) implements AES-256-GCM encryption using the Rust aes-gcm crate (the Aes256Gcm type from the aes-gcm crate), not CNG. The crypto module uses a 12-byte nonce and 16-byte tag matching the GCM standard. The client_rust crate's protocol.rs defines binary protocol message types but does not implement cryptographic operations — it defines message type constants (MSG_FRAME, MSG_HELLO, etc.) and build_message/parse_message functions for the wire format.

The dark_crystal crate's wrappers.rs module uses windows_targets::link! for ntdll API bindings, and the crowd crate's resolve.rs implements PEB walking and DJB2 hash resolution for dynamic API loading. An implementation using CNG would replace the aes-gcm crate dependency with FFI bindings to bcrypt.dll, resolved either via the static import table or dynamically via the PEB walker (T-004) and manual GetProcAddress (T-050) to avoid a static bcrypt.dll import. The sequence would be: BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) → BCryptSetProperty(BCRYPT_CHAINING_MODE_GCM) → BCryptGenerateSymmetricKey(key_material) → BCryptEncrypt with BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO. This approach produces no Rust crypto code in the binary but adds a bcrypt.dll dependency.

## Why It Matters

The choice of cryptographic API family affects the implant's import table, binary size, and detection surface. CNG adds a bcrypt.dll import that may appear anomalous in an implant binary that does not otherwise require Windows crypto services — a static import of bcrypt.dll in a dropper or loader is a signal that cryptographic operations are performed, which narrows the analyst's search. The Rust aes-gcm crate produces self-contained crypto code with no external DLL dependency, compiled directly into the binary, but increases binary size by approximately 50-100 KB due to the embedded AES and GHASH implementations. SEC670's explicit recommendation of CNG over CryptoAPI reflects the industry shift toward authenticated encryption — CryptoAPI's lack of GCM and CCM support makes it unsuitable for modern C2 protocols that require AEAD for message integrity and confidentiality. Operators working in C/C++ must use CNG; operators in Rust can choose either CNG via FFI or the native aes-gcm crate.

## Detection Considerations

- **Telemetry sources**: BCryptOpenAlgorithmProvider and BCryptEncrypt are exported by bcrypt.dll and may be hooked by EDR products that monitor cryptographic API calls. Import table analysis (via dumpbin /imports or similar) reveals bcrypt.dll as a static dependency, which is a static indicator of cryptographic operations. The Rust aes-gcm crate does not appear in the import table — its code is compiled into the binary as pure Rust with no Windows API calls.
- **Bypass options**: Dynamic resolution of bcrypt.dll functions via the PEB walker (T-004) and manual GetProcAddress (T-050) avoids the static bcrypt.dll import in the import table. The Rust aes-gcm crate avoids the bcrypt.dll dependency entirely. API calls to bcrypt.dll through dynamically resolved function pointers may still be monitored by EDR products that hook at the function level, but the aes-gcm crate's in-process computation produces no observable API calls to bcrypt.dll.
- **Residual artifacts**: CNG usage via static imports produces bcrypt.dll in the import table. CNG usage via dynamic resolution creates a loaded module entry for bcrypt.dll visible in the PEB's InLoadOrderModuleList (detectable by PE-sieve and Volatility). The Rust aes-gcm crate produces no file system, module list, or import table artifacts but adds compiled AES and GHASH code to the binary's .text section, increasing the code size footprint.

## Related Techniques

- **T-021 Crypto & Obfuscation** — The existing crypto card documents AES-256-GCM with zstd compression using the Rust aes-gcm crate; this card documents the Windows-native CNG API alternative and the deprecated CryptoAPI path that the Rust approach replaces

## References

- Atlas material: atlas-exploit-dev-part13.md (units 18, 19, 40), atlas-exploit-dev-part14.md (units 1, 2, 3), atlas-exploit-dev-part19.md (units 28, 39)
- MITRE ATT&CK: T1027 — https://attack.mitre.org/techniques/T1027/
- LGTM notes: lgtm:cng-vs-cryptoapi-modernization-signal, lgtm:cryptoapi-to-cng-migration-guidance, lgtm:cng-api-crypto-coverage

## Source Reference

No current implementation. The dark_crystal crate uses the Rust aes-gcm crate (dark_crystal/crates/core/src/crypto.rs) as an alternative to both CNG and CryptoAPI. See atlas material for SEC670 coverage of the CNG vs CryptoAPI tradecraft decision.
<!-- END CARD T-078 -->