# LGTM Notes to Cluster (106 notes)

=== NOTE 1 ===
id: lgtm:heavens-gate-wow64-syscall-bridge
title: Heaven's Gate (WOW64 32→64 Bit Syscall Bridge)
would_relate_to: ['T-001', 'T-002', 'T-004']
origin: atlas-binary-analysis-part1
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part1
**Would relate to:** T-001, T-002, T-004
**Source units:** unit 7

Unit 7 references the Heaven's Gate technique for 32-bit processes transitioning to 64-bit code space via ntdll.dll offset. The vault's syscall dispatch cards (T-001 RecycledGate, T-002 Hells/Halo/Tartarus, T-003 VEH Gate, T-006 Phantom Stubs) all assume 64-bit ex

=== NOTE 2 ===
id: lgtm:kuser-shared-data-info-source
title: KUSER_SHARED_DATA as Detection-Free System Info Source
would_relate_to: ['T-004', 'T-020']
origin: atlas-binary-analysis-part2
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part2
**Would relate to:** T-004, T-020
**Source units:** unit 21, unit 22, unit 23

SEC670 dedicates explicit material to KUSER_SHARED_DATA at VA 0x7FFE0000 — a fixed-VA kernel-mapped page readable without any API call. The vault's T-004 (PEB Walker) documents module resolution via the PEB, but the KUSER_SHARED_DATA page is a distinct

=== NOTE 3 ===
id: lgtm:cross-session-injection-primitive
title: Cross-Session Process Injection via WTS Target Selection
would_relate_to: ['T-013', 'T-007']
origin: atlas-binary-analysis-part2
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part2
**Would relate to:** T-013, T-007
**Source units:** unit 30, unit 31

SEC670 frames WTSEnumProcessSessions as the path to identifying cross-session process injection opportunities. The vault's T-013 (Remaining Injection Methods) catalogues injection primitives but does not specifically address cross-session targeting — the operat

=== NOTE 4 ===
id: lgtm:service-based-persistence-as-distinct-technique
title: Windows Service-Based Persistence as a Distinct Persistence Layer
would_relate_to: ['T-017']
origin: atlas-binary-analysis-part4
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part4
**Would relate to:** T-017
**Source units:** unit 32, unit 33, unit 34, unit 35, unit 36, unit 37

SEC670 dedicates an entire services module (CreateService, QueryServiceStatusEx, QueryServiceConfig, ChangeServiceConfig, ServiceMain pattern) to service-based persistence. The vault's T-017 persistence suite currently lists COM hij

=== NOTE 5 ===
id: lgtm:token-theft-privilege-escalation
title: Access Token Theft (TokenThief Pattern)
would_relate_to: ['T-021', 'T-023']
origin: atlas-binary-analysis-part4
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part4
**Would relate to:** T-021, T-023
**Source units:** unit 30, unit 31

SEC670's escalation module includes the TokenThief lab pairing OpenProcessToken with token duplication for privilege escalation. The vault's T-021/T-023 UAC bypass coverage addresses auto-elevation but does not document the broader token-theft primitive (open a

=== NOTE 6 ===
id: lgtm:gui-application-hook-injection-distinction
title: GUI Application Hook Injection as a Distinct Injection Variant
would_relate_to: ['T-013', 'T-007']
origin: atlas-binary-analysis-part4
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part4
**Would relate to:** T-013, T-007
**Source units:** unit 26, unit 27, unit 28

SEC670 explicitly identifies SetWindowsHookEx as the API for injecting DLLs into GUI applications specifically, distinct from CreateRemoteThread-based injection. The vault's T-013 remaining methods lists callback, fiber, Early Bird, PE loader, etc. but

=== NOTE 7 ===
id: lgtm:port-monitor-print-spooler-persistence
title: Port Monitor (AddMonitor / Print Spooler) Persistence
would_relate_to: ['T-017']
origin: atlas-binary-analysis-part5
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part5
**Would relate to:** T-017
**Source units:** unit 18

SEC670 unit 18 documents the AddMonitor API and _MONITORINFO_2 structure for installing a local port monitor. A malicious port monitor DLL loaded by the spooler service executes in SYSTEM context and is enumerated at every spooler restart. The vault's T-017 persistence suite c

=== NOTE 8 ===
id: lgtm:service-failure-actions-persistence
title: Service Failure Actions as Persistence
would_relate_to: ['T-017']
origin: atlas-binary-analysis-part5
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part5
**Would relate to:** T-017
**Source units:** unit 8

SEC670 unit 8 documents the SERVICE_FAILURE_ACTIONS structure used with ChangeServiceConfig2. Operators can install a malicious recovery command that the SCM executes when a service fails — including services that fail deliberately or are forced to fail. This is a persistence v

=== NOTE 9 ===
id: lgtm:createprocess-vs-ntcreateuserprocess-policy-boundary
title: CreateProcess vs NtCreateUserProcess Policy Boundary
would_relate_to: ['T-014', 'T-015', 'T-013', 'T-016']
origin: atlas-binary-analysis-part6
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part6
**Would relate to:** T-014, T-015, T-013, T-016
**Source units:** unit 16, unit 17, unit 19

The unit walks through CreateProcess as the Win32 wrapper, including STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as the Win32 path to PPID spoofing. The vault has T-014 NtCreateUserProcess and T-015 PPID Spoofing as separate card

=== NOTE 10 ===
id: lgtm:registry-enumeration-fingerprint
title: RegOpenKeyExW + RegQueryInfoKey + RegEnumValue Fingerprint
would_relate_to: ['T-017', 'T-023', 'T-020']
origin: atlas-binary-analysis-part6
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part6
**Would relate to:** T-017, T-023, T-020
**Source units:** unit 21, unit 35, unit 36, unit 37

The unit documents the canonical three-call registry enumeration pattern with LSTATUS return checking and ERROR_NO_MORE_ITEMS loop termination. This pattern is the operational basis for COM-hijack target discovery (T-017), autostart enu

=== NOTE 11 ===
id: lgtm:binary-versioninfo-impersonation
title: VERSIONINFO Resource Impersonation
would_relate_to: ['T-020']
origin: atlas-binary-analysis-part8
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part8
**Would relate to:** T-020
**Source units:** unit 39

The MalDev Academy metadata.src unit shows a VERSIONINFO resource block impersonating Google Chrome (CompanyName=Google LLC, FileDescription=Google Chrome, OriginalFilename=chrome.exe, ProductVersion=112.0.5615.86). This is a distinct anti-analysis technique — embedding spoofe

=== NOTE 12 ===
id: lgtm:proposed-thread-context-hijack-primitive
title: CONTEXT-Based Thread Hijack as Standalone Primitive
would_relate_to: ['T-005', 'T-013', 'T-012']
origin: atlas-binary-analysis-part9
description: **Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part9
**Would relate to:** T-005, T-013, T-012
**Source units:** unit 20, unit 21, unit 22

SEC670 establishes thread hijacking as the act of modifying a thread's CONTEXT structure (specifically the Rip field) rather than thread state or priority. T-013 bundles thread hijack under 'Remaining Methods' alongside hollowing, mapping, and m

=== NOTE 13 ===
id: lgtm:registry-watchdog-situational-awareness
title: Registry Watchdog for Situational Awareness
would_relate_to: ['T-017', 'T-020']
origin: atlas-edr-evasion-part1
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part1
**Would relate to:** T-017, T-020
**Source units:** unit 26, unit 27

SEC670 dedicates material to RegNotifyChangeKey and the REG_NOTIFY_CHANGE_* filter set as a watchdog primitive — detecting AV product installation in real time without polling, with REG_NOTIFY_THREAD_AGNOSTIC enabling thread-persistent notifications. The vault has 

=== NOTE 14 ===
id: lgtm:system32-blending-evasion
title: System32 Folder Blending as Evasion Technique
would_relate_to: ['T-017', 'T-020']
origin: atlas-edr-evasion-part1
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part1
**Would relate to:** T-017, T-020
**Source units:** unit 33, unit 34

SEC670 documents a concrete strategy for file-based blending: place payloads in System32 (4,200+ files to hide among), choose a middle-listing position, match filename conventions of surrounding entries, and align timestamps. The vault's persistence card (T-017) co

=== NOTE 15 ===
id: lgtm:appcert-dll-persistence
title: AppCert DLLs as a Persistence Layer
would_relate_to: ['T-017']
origin: atlas-edr-evasion-part2
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part2
**Would relate to:** T-017
**Source units:** unit 2

SEC670 documents the AppCertDlls registry mechanism that injects a DLL into any process calling CreateProcess-family APIs or WinExec. This is a distinct persistence vector from COM hijack, schtask, NTFS EA, TLS callback, and PhantomPersist in T-017 — it triggers on host activity ra

=== NOTE 16 ===
id: lgtm:ifeo-silent-process-exit-persistence
title: IFEO GlobalFlag and Silent Process Exit as Persistence Primitives
would_relate_to: ['T-017']
origin: atlas-edr-evasion-part2
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part2
**Would relate to:** T-017
**Source units:** unit 7, unit 8, unit 9, unit 10, unit 11, unit 12, unit 13, unit 14

SEC670 devotes multiple units to IFEO GlobalFlag and Silent Process Exit as abuse targets. The vault's T-017 persistence suite does not document IFEO as a layer. These primitives are gated on Admin/SYSTEM and produce per-

=== NOTE 17 ===
id: lgtm:sddl-service-hiding-tradecraft
title: SDDL-Based Service Hiding
would_relate_to: ['T-017']
origin: atlas-edr-evasion-part2
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part2
**Would relate to:** T-017
**Source units:** unit 3, unit 4, unit 5

SEC670 documents a real-world SDDL string crafted by Joshua Wright that denies standard query rights to Interactive Users, Service Users, and Built-in Administrators while preserving SYSTEM access, effectively hiding a service from sc query and similar enumeration. 

=== NOTE 18 ===
id: lgtm:sywshipers3-random-syscall-dispatch
title: Random Syscall Dispatch via Sywshipers3 (EGH-based)
would_relate_to: ['T-001', 'T-002', 'T-003', 'T-006']
origin: atlas-edr-evasion-part3
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part3
**Would relate to:** T-001, T-002, T-003, T-006
**Source units:** unit 13

SEC670 surfaces Sywshipers3 as a syscall-detection bypass tool that uses EGGs (egg-hunter style stubs) and direct syscall jumps to random syscall numbers, in both Wow64 and x64. This is operationally distinct from HUGIN's T-001 (RecycledGate indirect via ntdll

=== NOTE 19 ===
id: lgtm:proposed-trampoline-infrastructure
title: Hook Trampoline as Standalone Primitive
would_relate_to: ['T-016', 'T-013']
origin: atlas-edr-evasion-part5
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part5
**Would relate to:** T-016, T-013
**Source units:** unit 22, unit 23

SEC670 units 22 and 23 cover trampolines as the infrastructure that makes inline hooks non-reentrant: a stub that executes the displaced original bytes and jumps back to the original function past the hook. The vault's T-016 EDR Evasion Suite covers unhooking but d

=== NOTE 20 ===
id: lgtm:appinit-dlls-persistence-card
title: AppInit_DLLs as a Standalone Persistence Technique Card
would_relate_to: ['T-017', 'T-016']
origin: atlas-edr-evasion-part6
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part6
**Would relate to:** T-017, T-016
**Source units:** unit 14

SEC670 unit 14 names AppInit as the correct technique for processes linked against User32.dll, distinct from AppCert and RunOnce. The vault's T-017 five-layer persistence suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) does not include AppInit_DLLs, despi

=== NOTE 21 ===
id: lgtm:pe-sieve-detection-tool-card
title: Defensive Memory Scanner Coverage (PE-sieve Class)
would_relate_to: ['T-007', 'T-013', 'T-016']
origin: atlas-edr-evasion-part6
description: **Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part6
**Would relate to:** T-007, T-013, T-016
**Source units:** unit 12, unit 23

SEC670 units 12 and 23 reference PE-sieve as the canonical defender-side tool for detecting manually mapped, hollowed, and stomped modules — the exact effects produced by T-013 and T-007. The vault's detection insights are written from first-principle indica

=== NOTE 22 ===
id: lgtm:undocumented-nt-enum-evasion-primitive
title: Undocumented NT Enumeration as Evasion Primitive
would_relate_to: ['T-016', 'T-023', 'T-004']
origin: atlas-enumeration-part1
description: **Kind:** proposed-technique
**Origin:** atlas-enumeration-part1
**Would relate to:** T-016, T-023, T-004
**Source units:** unit 13

SEC670 explicitly frames NtQuerySystemInformation as an undocumented alternative to EnumProcesses, WTSEnumerateProcessesEx, and CreateToolhelp32Snapshot for process enumeration. This positions direct NT enumeration as an evasion primitive that bypasses Win32-layer ho

=== NOTE 23 ===
id: lgtm:winsock-reverse-shell-primitive
title: Winsock + STARTUPINFOA Handle-Redirected Reverse Shell
would_relate_to: ['T-022', 'T-023']
origin: atlas-exploit-dev-part1
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part1
**Would relate to:** T-022, T-023
**Source units:** unit 14, unit 15

Units 14 and 15 together describe the canonical Winsock reverse shell: WSAStartup(MAKEWORD(2,2)) initializes Winsock, a socket is created, STARTUPINFOA is populated with hStdInput/hStdOutput/hStdError set to the socket HANDLE, dwFlags=STARTF_USESTDHANDLES, and Crea

=== NOTE 24 ===
id: lgtm:sddl-acl-manipulation-proposed
title: SDDL and ACL Manipulation for Persistence Hardening
would_relate_to: ['T-017', 'T-021']
origin: atlas-exploit-dev-part10
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part10
**Would relate to:** T-017, T-021
**Source units:** unit 19, unit 20

SEC670 covers SDDL string format with ACE field decomposition (AceType, AccessMask, SID) and the GetNamedSecurityInfoA API for retrieving security descriptors across NTFS objects, services, registry keys, shares, and file-mapping objects. The vault does not curren

=== NOTE 25 ===
id: lgtm:srdi-as-distinct-technique
title: Shellcode Reflective DLL Injection (sRDI) as Standalone Technique
would_relate_to: ['T-013', 'T-007']
origin: atlas-exploit-dev-part11
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part11
**Would relate to:** T-013, T-007
**Source units:** unit 3, unit 4, unit 5

SEC670 units 3-5 treat sRDI as a distinct capability from RDI: the loader itself is position-independent shellcode that does not require the target DLL to be compiled with RDI support, and exposes custom helpers like GetProcAddressR. The vault folds reflecti

=== NOTE 26 ===
id: lgtm:heavens-gate-wow64-syscalls
title: Heaven's Gate / Wow64 Cross-Architecture Syscalls
would_relate_to: ['T-001', 'T-002', 'T-006']
origin: atlas-exploit-dev-part12
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part12
**Would relate to:** T-001, T-002, T-006
**Source units:** unit 6, unit 7

SEC670 units 6-7 cover Heaven's Gate — the 32-bit-to-64-bit transition mechanism Wow64 processes use to issue syscalls. This is a distinct operational capability: a 32-bit implant can issue 64-bit syscalls to bypass 32-bit ntdll hooks entirely. The vault's T-

=== NOTE 27 ===
id: lgtm:inline-hook-implementation-side
title: Inline Hook Implementation (Red-Team-Side Hooking)
would_relate_to: ['T-016']
origin: atlas-exploit-dev-part12
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part12
**Would relate to:** T-016
**Source units:** unit 1, unit 8, unit 9, unit 10, unit 11

Units 1, 8-11 cover inline hooking from the implementer's perspective — how to patch bytes, construct trampolines to avoid infinite loops, and structure x64 hooks with mov rax/jmp rax. The vault's T-016 documents EDR-side hooks as something to byp

=== NOTE 28 ===
id: lgtm:certificate-pinning-for-c2-transports
title: Certificate Pinning for C2 TLS Transports
would_relate_to: ['T-022']
origin: atlas-exploit-dev-part13
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part13
**Would relate to:** T-022
**Source units:** unit 21

SEC670 unit 21 documents a full certificate pinning workflow (InternetQueryOption with INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, CertGetNameString, CertGetCertificateContextProperty with CERT_HASH_PROP_ID, hex conversion for comparison). The vault's T-022 network suite covers HT

=== NOTE 29 ===
id: lgtm:dll-export-for-injection-surface
title: DLL Export Mechanics as Injection Prerequisite
would_relate_to: ['T-013']
origin: atlas-exploit-dev-part14
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part14
**Would relate to:** T-013
**Source units:** unit 24, unit 25, unit 26, unit 27, unit 28, unit 29, unit 30, unit 31

SEC670 presents DLL construction with exported functions as a direct enabler of process injection, noting that DLLs are great for injecting into processes. The vault's T-013 covers callback and fiber-based injection b

=== NOTE 30 ===
id: lgtm:advanced-capability-selection-framework
title: Trigger-Based Selection Framework for Advanced Implant Techniques
would_relate_to: ['T-007', 'T-016', 'T-022']
origin: atlas-exploit-dev-part15
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part15
**Would relate to:** T-007, T-016, T-022
**Source units:** unit 38

SEC670 provides a structured framework for when to escalate from basic to advanced capabilities: four explicit triggers (defender match, tech-savvy admin, stealth requirement, basic technique failure) and four escalation options (manual image loading, API hook reimp

=== NOTE 31 ===
id: lgtm:wldp-dynamic-code-trust-query
title: WldpQueryDynamicCodeTrust as Pre-Flight Check
would_relate_to: ['T-016', 'T-013']
origin: atlas-exploit-dev-part16
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part16
**Would relate to:** T-016, T-013
**Source units:** unit 13

Unit 13 surfaces WldpQueryDynamicCodeTrust — the API Device Guard exposes for querying whether in-memory dynamic code is trusted by policy before execution. This is a distinct operational capability: a pre-flight check that lets an implant determine whether ACG/WDAC will b

=== NOTE 32 ===
id: lgtm:manual-loader-api-reimplementation
title: Manual Reimplementation of LoadLibrary/GetProcAddress
would_relate_to: ['T-004', 'T-013', 'T-016']
origin: atlas-exploit-dev-part17
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part17
**Would relate to:** T-004, T-013, T-016
**Source units:** unit 25, unit 28

The material explicitly flags that future modules cover manually implementing LoadLibrary and GetProcAddress to further hide imports beyond what explicit linking alone achieves. This is the conceptual bridge between T-004 (PEB Walker for module resolution) 

=== NOTE 33 ===
id: lgtm:custom-recon-tooling-lotl-reimplementation
title: Custom Recon Tooling via LotL Reimplementation (ipconfig/arp/netstat)
would_relate_to: ['T-023', 'T-020']
origin: atlas-exploit-dev-part18
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part18
**Would relate to:** T-023, T-020
**Source units:** unit 28, unit 29, unit 30

SEC670 Units 28-30 task students with reimplementing ipconfig, arp, and netstat using Win32 APIs rather than shelling out to the system binaries. This is a distinct tradecraft — building LotL-equivalent recon tools that produce the same data as the system

=== NOTE 34 ===
id: lgtm:pe-injection-additional-image-card
title: PE Injection (Additional Image, Non-Hollowing)
would_relate_to: ['T-013']
origin: atlas-exploit-dev-part19
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part19
**Would relate to:** T-013
**Source units:** unit 14

SEC670 documents PE Injection as a distinct technique from process hollowing: an additional PE image is loaded into the target process without removing the original. The vault's T-013 lists 'Hollowing' but does not explicitly distinguish this additive variant. PE Injection has di

=== NOTE 35 ===
id: lgtm:security-descriptor-acl-hardening
title: Security Descriptor ACL Hardening for Persistence
would_relate_to: ['T-017']
origin: atlas-exploit-dev-part19
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part19
**Would relate to:** T-017
**Source units:** unit 20, unit 21, unit 22

SEC670 covers GetNamedSecurityInfoA/SetNamedSecurityInfoA and EXPLICIT_ACCESS_A as tools to modify DACLs on service objects, denying stop and delete permissions to defenders. This is a persistence resilience technique distinct from the execution-based persistenc

=== NOTE 36 ===
id: lgtm:proposed-manual-pe-loader-technique-card
title: Standalone Manual PE Loader Technique Card
would_relate_to: ['T-013', 'T-007']
origin: atlas-exploit-dev-part20
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part20
**Would relate to:** T-013, T-007
**Source units:** unit 5, unit 6, unit 7, unit 11, unit 21

SEC670 spends substantial material on the manual x64 PE loader implementation — MZ/Machine validation, header traversal, data directory processing, IAT/EAT construction, base relocations, and entry-point dispatch. The vault currently folds 

=== NOTE 37 ===
id: lgtm:proposed-port-monitor-persistence
title: Port Monitor Print Spooler Persistence
would_relate_to: ['T-017']
origin: atlas-exploit-dev-part22
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part22
**Would relate to:** T-017
**Source units:** unit 19, unit 20

SEC670 dedicates a module to Port Monitor source code as a SYSTEM-context persistence tradecraft. T-017's persistence suite documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include the print spooler Port Monitor vector. This would mer

=== NOTE 38 ===
id: lgtm:proposed-binary-patching-technique
title: Binary Patching of Compiled PE Files
would_relate_to: ['T-006', 'T-021']
origin: atlas-exploit-dev-part22
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part22
**Would relate to:** T-006, T-021
**Source units:** unit 17

SEC670 introduces binary patching as a distinct module with stated objectives and benefits. The vault does not have a technique card covering on-disk PE binary modification (code-cave shellcode insertion, import-table patching, resource-section modification). T-021 covers 

=== NOTE 39 ===
id: lgtm:proposed-port-monitor-persistence-card
title: Port Monitor DLL as a Standalone Persistence Technique
would_relate_to: ['T-017']
origin: atlas-exploit-dev-part24
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part24
**Would relate to:** T-017
**Source units:** unit 25

SEC670 dedicates a source code review module (Unit 25) to implementing a Port Monitor DLL for Print Spooler persistence. The vault's T-017 Five-Layer Persistence card covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — but does not surface Port Monitor as a di

=== NOTE 40 ===
id: lgtm:proposed-appinit-dlls-persistence-card
title: AppInit_DLLs Registry Persistence
would_relate_to: ['T-017']
origin: atlas-exploit-dev-part24
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part24
**Would relate to:** T-017
**Source units:** unit 22

SEC670 Lab 4.5 'InitToWinInit' (Unit 22) instructs students to create the AppInit_DLLs key and load a malicious DLL into every user32-linked process. This is a distinct persistence primitive from the five layers currently in T-017: it is registry-resident, user32-conditional, and

=== NOTE 41 ===
id: lgtm:service-based-persistence-with-dacl-hiding
title: Service-Based Persistence with SDDL DACL Hiding
would_relate_to: ['T-017']
origin: atlas-exploit-dev-part3
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part3
**Would relate to:** T-017
**Source units:** unit 11, unit 12

The SEC670 material dedicates two units (11 and 12 — 'Programmatically Hide a Service' and Lab 4.4 'NotInService') to installing a custom service via the SCM APIs and then hiding it via SetNamedSecurityInfo DACL modification. The vault's T-017 Five-Layer Persistence card 

=== NOTE 42 ===
id: lgtm:heavens-gate-wow64-bypass-as-standalone-technique
title: Heaven's Gate WoW64 Transition as a Standalone Technique
would_relate_to: ['T-002', 'T-016']
origin: atlas-exploit-dev-part3
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part3
**Would relate to:** T-002, T-016
**Source units:** unit 26

Unit 26 explains the Heaven's Gate 32-to-64-bit syscall transition in detail — the segment 0x33 jump through ntdll.Wow64Transition to wow64cpu.dll, then to the 64-bit ntdll syscall stub. The vault's T-002 covers SSN resolution but does not document the bitness-transition ev

=== NOTE 43 ===
id: lgtm:port-monitor-addmonitor-persistence
title: AddMonitor Port Monitor Persistence as a Standalone T-NNN
would_relate_to: ['T-017']
origin: atlas-exploit-dev-part4
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part4
**Would relate to:** T-017
**Source units:** unit 31

SEC670 documents AddMonitor with MONITOR_INFO_2 as a persistence mechanism that loads an attacker DLL into spoolsv.exe (SYSTEM context) on every print spooler start. The vault's T-017 Five-Layer Persistence covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but 

=== NOTE 44 ===
id: lgtm:proposed-technique-manual-pe-loading
title: Manual PE Image Loading (Reflective Loader Primitives)
would_relate_to: ['T-007', 'T-013']
origin: atlas-exploit-dev-part5
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part5
**Would relate to:** T-007, T-013
**Source units:** unit 31

Unit 31 lists 'manually load an image into memory' as a distinct last-resort capability. The vault's T-007 process-injection card covers reflective PE loading as one entry in a list of 14 methods but does not elevate the standalone capability — manually loading a DLL/EXE in

=== NOTE 45 ===
id: lgtm:wldp-dynamic-code-trust-edr-mechanism
title: WldpQueryDynamicCodeTrust as Documented EDR Mechanism
would_relate_to: ['T-006', 'T-016', 'T-013']
origin: atlas-exploit-dev-part6
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part6
**Would relate to:** T-006, T-016, T-013
**Source units:** unit 19, unit 20

Units 19 and 20 surface WldpQueryDynamicCodeTrust — the user-mode query into Device Guard's dynamic-code-trust policy that determines whether in-memory code is allowed to execute under WDAC. The vault's T-016 EDR evasion suite lists ACG and CIG policy among 

=== NOTE 46 ===
id: lgtm:cross-session-injection-as-distinct-primitive
title: Cross-Session Process Injection as Standalone Primitive
would_relate_to: ['T-013', 'T-023']
origin: atlas-exploit-dev-part7
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part7
**Would relate to:** T-013, T-023
**Source units:** unit 36

SEC670 explicitly calls out cross-session process injection via WTSEnumerateProcessesEx as a distinct operational capability enabled by session-aware enumeration. The vault's T-013 documents injection methods but does not currently frame cross-session targeting as a primiti

=== NOTE 47 ===
id: lgtm:manual-getprocaddress-as-standalone-primitive
title: Manual GetProcAddress Implementation as Standalone Primitive
would_relate_to: ['T-001', 'T-004', 'T-006']
origin: atlas-exploit-dev-part8
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part8
**Would relate to:** T-001, T-004, T-006
**Source units:** unit 38, unit 39, unit 40

The material dedicates substantial space to walking kernel32.dll's IMAGE_EXPORT_DIRECTORY via AddressOfNames → AddressOfNameOrdinals → AddressOfFunctions, including hex-dump analysis of the real kernel32 export table. The vault currently covers PEB-

=== NOTE 48 ===
id: lgtm:pipe-ipc-for-staged-implant-communication
title: Anonymous and Named Pipes as Implant IPC Transports
would_relate_to: ['T-022', 'T-007']
origin: atlas-exploit-dev-part9
description: **Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part9
**Would relate to:** T-022, T-007
**Source units:** unit 36, unit 37, unit 38, unit 39, unit 40

Units 36–40 cover CreatePipe, anonymous pipe semantics (local-only, one-way, parent/child), and named pipe semantics (duplex, network-capable). The vault's T-022 documents SOCKS5, HVNC, VNC/RFB, malleable C2, peer relay, HTTP poll, NT soc

=== NOTE 49 ===
id: lgtm:port-monitor-persistence
title: AddMonitor Port Monitor Persistence
would_relate_to: ['T-017']
origin: atlas-labs-part1
description: **Kind:** proposed-technique
**Origin:** atlas-labs-part1
**Would relate to:** T-017
**Source units:** unit 35

Unit 35 explicitly identifies AddMonitor (vs. CreateNewMonitor or AddNewMonitor) as the correct API to install a port monitor. Port monitor persistence survives reboot inside spoolsv.exe and is a recognized tradecraft distinct from T-017's persistence layers, which target userland and bo

=== NOTE 50 ===
id: lgtm:silentprocessexit-trigger-persistence
title: SilentProcessExit Registry Trigger Persistence
would_relate_to: ['T-017']
origin: atlas-labs-part1
description: **Kind:** proposed-technique
**Origin:** atlas-labs-part1
**Would relate to:** T-017
**Source units:** unit 36

Unit 36 references SilentProcessExit as a registry key that can watch for process termination. The same key is abuseable as a persistence mechanism by configuring ReportingMode and MonitorProcess values to relaunch an implant when a sacrificial process exits. The vault does not currently

=== NOTE 51 ===
id: lgtm:token-impersonation-theft-card
title: Token Theft and Impersonation as a Standalone Technique Card
would_relate_to: ['T-023', 'T-017']
origin: atlas-labs-part2
description: **Kind:** proposed-technique
**Origin:** atlas-labs-part2
**Would relate to:** T-023, T-017
**Source units:** unit 1

SEC670 Lab 3.5 'TokenThief' dedicates an entire lab to token theft and impersonation, indicating it is a distinct, teachable offensive capability. The vault currently distributes token-related logic implicitly across T-023 client capabilities (lsass_dump, wmi_exec) but has no card 

=== NOTE 52 ===
id: lgtm:customshell-shellcode-loader-card
title: Custom Shell Loader as Distinct from Generic Injection
would_relate_to: ['T-007', 'T-022']
origin: atlas-labs-part2
description: **Kind:** proposed-technique
**Origin:** atlas-labs-part2
**Would relate to:** T-007, T-022
**Source units:** unit 4, unit 5, unit 7, unit 8

SEC670 Lab 4.7 'CustomShell' pairs with Lab 5.1 'The Loader' and Lab 5.5 'ShadowCraft' to indicate that custom shell construction is treated as its own offensive capability — distinct from the injection method catalog in T-007. The vault's T-007 card enumera

=== NOTE 53 ===
id: lgtm:executive-object-types-as-telemetry-surface
title: Executive Object Types as a Telemetry Taxonomy
would_relate_to: ['T-007', 'T-016', 'T-015']
origin: atlas-methodology-part1
description: **Kind:** proposed-technique
**Origin:** atlas-methodology-part1
**Would relate to:** T-007, T-016, T-015
**Source units:** unit 38

Unit 38 tabulates executive object types (Process, Thread, Section, Token, Mutex, Key, Desktop) and notes that object-access auditing is gated per object type. The vault currently treats detection concepts inline per technique card. A cross-cutting concept card mappi

=== NOTE 54 ===
id: lgtm:patch-recon-for-exploit-selection
title: Patch and Hotfix Reconnaissance for Exploit Viability
would_relate_to: ['T-023']
origin: atlas-methodology-part2
description: **Kind:** proposed-technique
**Origin:** atlas-methodology-part2
**Would relate to:** T-023
**Source units:** unit 28, unit 30, unit 33

The material covers using WUA APIs and service-pack/hotfix enumeration to determine which vulnerabilities remain unpatched, directly informing exploit and LPE technique selection. The vault's T-023 (Client Capabilities) includes recon and sysinfo collection but d

=== NOTE 55 ===
id: lgtm:svchost-hosting-model-target-selection
title: svchost Shared vs Isolated Service Hosting as Injection Target Selection Criterion
would_relate_to: ['T-007', 'T-013']
origin: atlas-methodology-part3
description: **Kind:** proposed-technique
**Origin:** atlas-methodology-part3
**Would relate to:** T-007, T-013
**Source units:** unit 19

SEC670 distinguishes shared services (multiple services in one svchost, share address space, shared crash fate) from isolated services (dedicated svchost). This distinction is operationally relevant when selecting a process injection host: targeting a shared svchost group r

=== NOTE 56 ===
id: lgtm:ifeo-debugger-persistence
title: Image File Execution Options (IFEO) Debugger Persistence
would_relate_to: ['T-017']
origin: atlas-methodology-part4
description: **Kind:** proposed-technique
**Origin:** atlas-methodology-part4
**Would relate to:** T-017
**Source units:** unit 9, unit 13, unit 14, unit 15, unit 16

SEC670 Section 4 dedicates two labs (4.2 Sauron, 4.3 IFEOPersisto) to IFEO-based persistence. The vault's T-017 Five-Layer Persistence card documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include IFEO. IFEO i

=== NOTE 57 ===
id: lgtm:wmi-event-subscription-persistence
title: WMI Permanent Event Subscription Persistence
would_relate_to: ['T-017', 'T-023']
origin: atlas-methodology-part4
description: **Kind:** proposed-technique
**Origin:** atlas-methodology-part4
**Would relate to:** T-017, T-023
**Source units:** unit 27, unit 28, unit 29, unit 30, unit 31

SEC670 Section 4 lists WMI Event Subscriptions as a distinct persistence mechanism, and units 27-30 provide the CIM/WMI schema background (Core/Common/Extended classes, CIM_ and Win32_ prefixes) that the technique operates on. The vault's

=== NOTE 58 ===
id: lgtm:sddl-security-descriptor-manipulation
title: Security Descriptor Manipulation via SDDL
would_relate_to: ['T-016']
origin: atlas-methodology-part7
description: **Kind:** proposed-technique
**Origin:** atlas-methodology-part7
**Would relate to:** T-016
**Source units:** unit 7

SEC670's SDDL Example #1 walks through constructing a security descriptor that grants GENERIC_ALL to the NULL SID (S-1-0-0), demonstrating the primitive of loosening object DACLs to permit anonymous access. The vault's T-016 covers handle blocking (restricting access to the implant

=== NOTE 59 ===
id: lgtm:proposed-technique-binary-patching-persistence
title: Binary Patching as a Persistence Mechanism
would_relate_to: ['T-017']
origin: atlas-methodology-part8
description: **Kind:** proposed-technique
**Origin:** atlas-methodology-part8
**Would relate to:** T-017
**Source units:** unit 16, unit 17, unit 18, unit 19, unit 20, unit 22

SEC670 Section 4 (units 16-22) lists Binary Patching as a distinct persistence topic alongside Registry Keys, Services, IFEO, and WMI Event Subscriptions. The vault does not have a technique card covering in-place modification of binary

=== NOTE 60 ===
id: lgtm:wmi-event-subscription-persistence-card
title: WMI Event Subscription Persistence as Standalone Card
would_relate_to: ['T-017']
origin: atlas-methodology-part9
description: **Kind:** proposed-technique
**Origin:** atlas-methodology-part9
**Would relate to:** T-017
**Source units:** unit 19, unit 20, unit 21

SEC670 Section 4 dedicates a persistence module to WMI Event Subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding). T-017 currently covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not list WMI Event Subscription as a

=== NOTE 61 ===
id: lgtm:proposed-appinit-dlls-persistence
title: AppInit_DLLs as Standalone Persistence Technique
would_relate_to: ['T-017', 'T-013']
origin: atlas-misc-part1
description: **Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017, T-013
**Source units:** unit 5, unit 6, unit 8, unit 9

SEC670 documents AppInit_DLLs across multiple units (5, 6, 8, 9) as a registry-driven DLL injection persistence mechanism with specific requirements: User32.dll linking of targets, LoadAppInit_DLLs gate, admin privileges, and infinite-loop avoidance. The vau

=== NOTE 62 ===
id: lgtm:proposed-ifeo-persistence
title: Image File Execution Options Persistence
would_relate_to: ['T-017']
origin: atlas-misc-part1
description: **Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 2, unit 28

SEC670 dedicates Lab 4.2 (Sauron IFEO) and Lab 4.3 (IFEOPersisto) to IFEO persistence with two variants documented: 'process start' (debugger redirect on launch) and 'silent.exe'. The vault's T-017 does not document IFEO. IFEO persistence is distinct enough — uses Debugger/Global

=== NOTE 63 ===
id: lgtm:proposed-silent-process-exit-persistence
title: Silent Process Exit via GlobalFlag Persistence
would_relate_to: ['T-017']
origin: atlas-misc-part1
description: **Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 11, unit 12, unit 22, unit 23, unit 27

SEC670 covers Silent Process Exit configured via Gflags.exe / GlobalFlag registry key as a process-exit-triggered persistence mechanism distinct from boot-time or launch-time persistence. Units 11, 12, 22, 23, 27 document the configuration via GflagsX 

=== NOTE 64 ===
id: lgtm:proposed-service-modification-persistence
title: Service ImagePath/binPath/FailureCommand Persistence
would_relate_to: ['T-017']
origin: atlas-misc-part1
description: **Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 1, unit 10

SEC670 Book 4 documents modifying existing services via ImagePath, binPath, and FailureCommand registry keys as a persistence mechanism. The vault's T-017 persistence suite does not include service-based persistence. Service persistence has unique operational properties (SCM-driv

=== NOTE 65 ===
id: lgtm:proposed-wmi-event-subscription-persistence
title: WMI Event Subscription Persistence
would_relate_to: ['T-017']
origin: atlas-misc-part1
description: **Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 1, unit 2, unit 7, unit 26

SEC670 Book 4 roadmap lists WMI Event Subscriptions as a persistence module. WMI event subscriptions execute attacker actions on system events (process creation, logon, timed) within WmiPrvSE.exe context, surviving reboots without typical filesystem or registry pe

=== NOTE 66 ===
id: lgtm:wmi-permanent-subscription-card
title: WMI Permanent Event Subscription as a Standalone Technique
would_relate_to: ['T-017', 'T-018']
origin: atlas-post-exploit-part1
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part1
**Would relate to:** T-017, T-018
**Source units:** unit 7, unit 36, unit 37

SEC670 Book 4 dedicates a full module and Lab 4.6 OhMyWMI to permanent WMI subscriptions as a persistence vector combining __EventFilter, __EventConsumer, and __FilterToConsumerBinding in the CIM repository. The vault's T-017 covers schtask, COM hijack, NT

=== NOTE 67 ===
id: lgtm:service-failure-actions-card
title: SERVICE_FAILURE_ACTIONS Persistence
would_relate_to: ['T-017']
origin: atlas-post-exploit-part1
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part1
**Would relate to:** T-017
**Source units:** unit 12, unit 31

SEC670 presents SERVICE_FAILURE_ACTIONS via ChangeServiceConfig2 as a persistence vector that triggers a configured command (e.g., 'ping C2') when a service fails, evading ImagePath-based detection while still executing on a recurring schedule. The vault's T-017 persiste

=== NOTE 68 ===
id: lgtm:named-pipe-c2-transport
title: Named Pipe C2 Transport as Proposed Networking Layer
would_relate_to: ['T-022']
origin: atlas-post-exploit-part10
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part10
**Would relate to:** T-022
**Source units:** unit 15, unit 16, unit 17, unit 18, unit 19

SEC670 covers named pipes with duplex communication, network accessibility via the Server service, and \ComputerName\pipe\PipeName addressing. T-022's networking suite lists SOCKS5, HVNC, VNC/RFB, malleable C2, peer relay, HTTP poll, and NT so

=== NOTE 69 ===
id: lgtm:service-failure-actions-as-persistence
title: SERVICE_FAILURE_ACTIONS Abuse for Crash-Triggered Persistence
would_relate_to: ['T-017']
origin: atlas-post-exploit-part11
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part11
**Would relate to:** T-017
**Source units:** unit 37, unit 38, unit 39

SEC670 documents the SERVICE_FAILURE_ACTIONS structure (set via ChangeServiceConfig2) as a mechanism to execute a binary when a service 'fails' per SCM's contract (no SERVICE_STOPPED reported or non-zero Win32ExitCode). This is a distinct persistence trigger fr

=== NOTE 70 ===
id: lgtm:on-disk-patching-system-dlls
title: On-Disk Patching of System DLLs for Persistent AV Bypass
would_relate_to: ['T-016']
origin: atlas-post-exploit-part11
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part11
**Would relate to:** T-016
**Source units:** unit 19

SEC670 raises on-disk patching of system binaries (potentially including Ntdll.dll and signature-scanning binaries) as a persistence mechanism that survives reboot unlike in-memory unhooking. T-016 documents NTDLL .text restoration (in-memory unhooking) but does not document the

=== NOTE 71 ===
id: lgtm:service-persistence-card
title: Custom Windows Service Persistence (SCM-based)
would_relate_to: ['T-017']
origin: atlas-post-exploit-part12
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part12
**Would relate to:** T-017
**Source units:** unit 1, unit 2, unit 4, unit 10, unit 12, unit 16

SEC670 dedicates a full module (units 1–22) to OpenSCManager / CreateService persistence and SDDL-based service hiding — a persistence vector absent from the vault's T-017 card (which covers COM hijack, NTFS EA, schtask, TLS callback, Ph

=== NOTE 72 ===
id: lgtm:port-monitor-persistence-card
title: Print Spooler Port Monitor Persistence
would_relate_to: ['T-017']
origin: atlas-post-exploit-part12
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part12
**Would relate to:** T-017
**Source units:** unit 24, unit 25, unit 26, unit 28, unit 29

SEC670 units 24–29 cover the Print Spooler port monitor persistence vector in depth — registering a malicious DLL as a port monitor under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors to gain spoolsv.exe-hosted execution at service star

=== NOTE 73 ===
id: lgtm:ifeo-silentprocessexit-persistence-card
title: IFEO / SilentProcessExit Registry Persistence
would_relate_to: ['T-017']
origin: atlas-post-exploit-part12
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part12
**Would relate to:** T-017
**Source units:** unit 31, unit 32, unit 35, unit 38, unit 39

SEC670 units 31–40 detail both IFEO Debugger-value persistence and SilentProcessExit MonitorProcess persistence, including the GlobalFlag=512 → ReportingMode=1 → MonitorProcess=<path> registry sequence. The vault's T-017 card does not include 

=== NOTE 74 ===
id: lgtm:native-application-development
title: Native Application Entry Point and Subsystem Bypass
would_relate_to: ['T-014', 'T-004']
origin: atlas-post-exploit-part13
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part13
**Would relate to:** T-014, T-004
**Source units:** unit 16, unit 17

SEC670 identifies NTSTATUS NtProcessStartup(PPEB peb) as the function signature for native applications — executables that bypass the Win32 subsystem entirely and receive the PEB directly. The vault's T-014 (NtCreateUserProcess) covers direct NT process creation 

=== NOTE 75 ===
id: lgtm:proposed-token-theft-technique
title: Token Theft as Standalone Privilege Escalation Technique
would_relate_to: ['T-021', 'T-023']
origin: atlas-post-exploit-part14
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part14
**Would relate to:** T-021, T-023
**Source units:** unit 19, unit 20, unit 21, unit 22, unit 25, unit 26, unit 27

SEC670's TokenThief lab (Lab 3.5) and the OpenProcessToken review material cover token theft, duplication, and impersonation as a distinct offensive capability. T-023 includes credential harvest and T-021 includes UAC 

=== NOTE 76 ===
id: lgtm:proposed-ifeo-persistence-suite
title: IFEO Persistence (Debugger + SilentProcessExit)
would_relate_to: ['T-017']
origin: atlas-post-exploit-part15
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part15
**Would relate to:** T-017
**Source units:** unit 8, unit 9, unit 10, unit 11, unit 12, unit 13, unit 14, unit 15

SEC670 Lab 4.3 (IFEOPersisto) covers IFEO persistence in two distinct variants: the Debugger key (triggered by target process start) and the SilentProcessExit key (triggered by target process exit). The vault's T-017 d

=== NOTE 77 ===
id: lgtm:proposed-wmi-persistence-suite
title: WMI Permanent Event Subscription Persistence
would_relate_to: ['T-017']
origin: atlas-post-exploit-part15
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part15
**Would relate to:** T-017
**Source units:** unit 16, unit 17, unit 18, unit 19, unit 20, unit 21, unit 22, unit 23

SEC670 covers WMI persistence via the EventFilter / EventConsumer / FilterToConsumerBinding trio, distinguishing extrinsic events (require polling) from intrinsic events (fire immediately). The vault's T-017 does not

=== NOTE 78 ===
id: lgtm:wmi-permanent-subscription-persistence-card
title: WMI Permanent Subscription as a Standalone Persistence Technique
would_relate_to: ['T-017']
origin: atlas-post-exploit-part16
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part16
**Would relate to:** T-017
**Source units:** unit 27, unit 28, unit 29, unit 30, unit 31, unit 32, unit 33

SEC670 Book 4 devotes a module to WMI permanent subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding) for persistence and elevation, including a dedicated lab (OhMyWMI) and explicit discussion of extrinsic vs 

=== NOTE 79 ===
id: lgtm:token-theft-and-impersonation-primitive
title: Token Theft (TokenThief) as a Standalone Privilege Technique
would_relate_to: ['T-015', 'T-023']
origin: atlas-post-exploit-part16
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part16
**Would relate to:** T-015, T-023
**Source units:** unit 18, unit 20, unit 21, unit 26

SEC670 Book 3 Lab 3.5 TokenThief teaches token theft as a distinct primitive and the OpenProcessToken API as its entry point. T-015 (PPID Spoofing) touches parent-process attribute manipulation but the vault has no dedicated technique card for t

=== NOTE 80 ===
id: lgtm:hidden-service-technique
title: Hidden Service Persistence Technique
would_relate_to: ['T-017', 'T-020']
origin: atlas-post-exploit-part17
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part17
**Would relate to:** T-017, T-020
**Source units:** unit 1

SEC670 references hiding a service as a SANS-taught persistence tradecraft item in the same Book 4 module as port monitor and IFEO. Hiding a service from SCM enumeration complements T-017's persistence layers and T-020's anti-analysis posture. The vault currently has no ca

=== NOTE 81 ===
id: lgtm:dkom-process-hiding
title: Kernel DKOM Process Hiding via ActiveProcessLinks Unlinking
would_relate_to: ['T-016', 'T-013']
origin: atlas-post-exploit-part2
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part2
**Would relate to:** T-016, T-013
**Source units:** unit 5, unit 33, unit 34, unit 35

SEC670 dedicates multiple units to the _EPROCESS structure and DKOM attacks that unlink a process from the ActiveProcessLinks doubly-linked list to hide it from every documented enumeration API. The vault currently documents PEB unlink (T-016) as 

=== NOTE 82 ===
id: lgtm:proposed-token-theft-technique-card
title: Token Theft as a Distinct Technique
would_relate_to: ['T-015', 'T-023']
origin: atlas-post-exploit-part4
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part4
**Would relate to:** T-015, T-023
**Source units:** unit 13, unit 14, unit 15, unit 16, unit 17, unit 18, unit 19, unit 20, unit 21, unit 22

SEC670 dedicates Lab 3.5 (TokenThief) and multiple slides to OpenProcessToken-based primary-token theft from High-IL/SYSTEM processes followed by CreateProcessWithTokenW or ImpersonateLoggedOn

=== NOTE 83 ===
id: lgtm:proposed-service-failure-action-resilience
title: Service Failure Action as Resilience Primitive
would_relate_to: ['T-017']
origin: atlas-post-exploit-part4
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part4
**Would relate to:** T-017
**Source units:** unit 32, unit 33

The material surfaces that SERVICE_WIN32_OWN_PROCESS services can be configured with failure actions (restart on failure) as a fail-safe. This pairs naturally with T-017's resilience monitor (PhantomPersist) but is distinct: failure actions are SCM-native and survive reb

=== NOTE 84 ===
id: lgtm:named-pipe-ipc
title: Named Pipe Duplex IPC Tradecraft
would_relate_to: ['T-022']
origin: atlas-post-exploit-part5
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part5
**Would relate to:** T-022
**Source units:** unit 1, unit 2, unit 3

SEC670 covers Windows named pipes as a duplex, network-capable IPC mechanism between unrelated processes, with CreateNamedPipe, ConnectNamedPipe, CreateFile, and CallNamedPipe as the API surface. The vault's T-022 Network Suite documents NT Sockets via the AFD driv

=== NOTE 85 ===
id: lgtm:proposed-windows-services-persistence-card
title: Windows Services Persistence Suite (Sibling to T-017)
would_relate_to: ['T-017']
origin: atlas-post-exploit-part6
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part6
**Would relate to:** T-017
**Source units:** unit 9, unit 10, unit 11, unit 12, unit 14, unit 15, unit 17, unit 19, unit 21, unit 23, unit 24, unit 27, unit 30, unit 33

SEC670 dedicates an entire module to service-based persistence: creating new services via SCM APIs, modifying ImagePath/binPath/FailureCommand on existing services,

=== NOTE 86 ===
id: lgtm:ifeo-persistence-card
title: Image File Execution Options Persistence as a Distinct Technique Card
would_relate_to: ['T-017']
origin: atlas-post-exploit-part7
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part7
**Would relate to:** T-017
**Source units:** unit 9, unit 10, unit 11, unit 12, unit 13, unit 14, unit 15, unit 16, unit 17, unit 18, unit 19, unit 20, unit 21, unit 22, unit 23, unit 24, unit 25, unit 26, unit 27, unit 28, unit 29, unit 30, unit 31, unit 32, unit 33, unit 34, unit 35

SEC670 covers IFEO persistence across two varia

=== NOTE 87 ===
id: lgtm:wmi-permanent-subscription-persistence
title: WMI Permanent Event Subscription Persistence
would_relate_to: ['T-017']
origin: atlas-post-exploit-part8
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part8
**Would relate to:** T-017
**Source units:** unit 1, unit 2, unit 3, unit 5, unit 6, unit 9, unit 11, unit 12, unit 15, unit 16

SEC670 dedicates extensive material to WMI permanent event subscriptions as a persistence mechanism using __EventFilter, CommandLineEventConsumer, and FilterToConsumerBinding. The vault's T-017 covers five

=== NOTE 88 ===
id: lgtm:service-hiding-coverage-gap
title: Service Hiding from SCM Enumeration
would_relate_to: ['T-017']
origin: atlas-post-exploit-part8
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part8
**Would relate to:** T-017
**Source units:** unit 13

SEC670 Lab 4.4 covers developing a custom Windows service for persistence and then hiding it from system view using Win32 APIs. The vault does not document service hiding as a stealth technique. This would complement T-017's persistence coverage by addressing the detection-evasio

=== NOTE 89 ===
id: lgtm:c2-beaconing-operational-pattern
title: C2 Check-in and Beaconing Operational Pattern
would_relate_to: ['T-019', 'T-022']
origin: atlas-post-exploit-part8
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part8
**Would relate to:** T-019, T-022
**Source units:** unit 25, unit 26, unit 28, unit 30, unit 31, unit 32, unit 33, unit 34

SEC670 covers the C2 check-in/beaconing cycle in detail: initial call-home, periodic check-ins with jitter, missed-check-in handling, task execution with UUID-based task IDs via UuidCreateSequential, and result

=== NOTE 90 ===
id: lgtm:cross-session-injection-variant
title: Cross-Session Process Injection
would_relate_to: ['T-007', 'T-013', 'T-015']
origin: atlas-post-exploit-part9
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part9
**Would relate to:** T-007, T-013, T-015
**Source units:** unit 35

SEC670's WTSEnumerateProcessesEx coverage explicitly names cross-session process injection as a distinct variant — injecting into a process running in a different user's logon session. The vault's T-007 methods do not distinguish in-session from cross-session inject

=== NOTE 91 ===
id: lgtm:dpapi-master-key-extraction
title: DPAPI Master Key Extraction as Credential Sub-Technique
would_relate_to: ['T-023']
origin: atlas-post-exploit-part9
description: **Kind:** proposed-technique
**Origin:** atlas-post-exploit-part9
**Would relate to:** T-023
**Source units:** unit 20, unit 21

CRTO and SEC670 both surface DPAPI as the cryptographic substrate protecting Chrome and Credential Manager secrets. T-023 covers credential harvest broadly but does not document the DPAPI master key access step (locating %APPDATA%\Microsoft\Protect\<SID>, decrypting the 

=== NOTE 92 ===
id: lgtm:proposed-token-stealing-lpe-card
title: Token Stealing (TokenThief) Admin-to-SYSTEM LPE
would_relate_to: ['T-013', 'T-015']
origin: atlas-privesc-part1
description: **Kind:** proposed-technique
**Origin:** atlas-privesc-part1
**Would relate to:** T-013, T-015
**Source units:** unit 7, unit 10, unit 17, unit 18

SEC670 Lab 3.5 TokenThief walks through the full OpenProcess + OpenProcessToken + DuplicateTokenEx + CreateProcessWithTokenW sequence to spawn a System-IL child from a High-IL admin context. The vault's T-013 (Remaining Methods) covers process hollowin

=== NOTE 93 ===
id: lgtm:proposed-acl-bypass-privilege-card
title: SeBackupPrivilege / SeRestorePrivilege ACL Bypass
would_relate_to: []
origin: atlas-privesc-part1
description: **Kind:** proposed-technique
**Origin:** atlas-privesc-part1
**Would relate to:** (new territory)
**Source units:** unit 5, unit 12, unit 20, unit 37, unit 38

SEC670 explicitly calls out SeBackupPrivilege and SeRestorePrivilege as the two privileges that bypass the standard ACL check entirely — granted complete read or write access regardless of the file's DACL. The vault does not currently cover

=== NOTE 94 ===
id: lgtm:proposed-technique-service-lpe-enumeration
title: Service-Based LPE Enumeration and Exploitation
would_relate_to: ['T-017', 'T-023']
origin: atlas-privesc-part2
description: **Kind:** proposed-technique
**Origin:** atlas-privesc-part2
**Would relate to:** T-017, T-023
**Source units:** unit 9, unit 10, unit 11, unit 12, unit 13, unit 14, unit 15, unit 16, unit 37, unit 38, unit 39

SEC670 devotes multiple units (9–16) to Windows services as a privilege-escalation surface: SCM interaction via OpenSCManager, service enumeration via EnumServicesStatus and QueryServiceSta

=== NOTE 95 ===
id: lgtm:proposed-technique-security-descriptor-reconnaissance
title: Security Descriptor and SDDL Reconnaissance
would_relate_to: ['T-023']
origin: atlas-privesc-part2
description: **Kind:** proposed-technique
**Origin:** atlas-privesc-part2
**Would relate to:** T-023
**Source units:** unit 28, unit 29, unit 30, unit 35, unit 36, unit 37, unit 38, unit 39, unit 40

SEC670 documents a structured tradecraft workflow around security descriptors: sc.exe sdshow for service DACLs, SDDL/ACE string interpretation (ace_type, ace_flags, rights constants, SID abbreviations), GetNamedSe

=== NOTE 96 ===
id: lgtm:token-privilege-abuse-proposed-technique
title: Token Privilege Abuse as Standalone Technique
would_relate_to: ['T-016', 'T-023']
origin: atlas-privesc-part3
description: **Kind:** proposed-technique
**Origin:** atlas-privesc-part3
**Would relate to:** T-016, T-023
**Source units:** unit 5, unit 6, unit 13, unit 14, unit 28, unit 32, unit 34, unit 35, unit 40

SEC670 covers AdjustTokenPrivileges, SeDebugPrivilege, SE_BACKUP_NAME/SE_RESTORE_NAME ACL bypass, and token stealing as a coherent privilege-abuse tradecraft block. The vault references SeDebugPrivilege impli

=== NOTE 97 ===
id: lgtm:service-based-lpe-proposed-technique
title: Service-Based Local Privilege Escalation
would_relate_to: ['T-017', 'T-020']
origin: atlas-privesc-part3
description: **Kind:** proposed-technique
**Origin:** atlas-privesc-part3
**Would relate to:** T-017, T-020
**Source units:** unit 11, unit 15, unit 16, unit 17, unit 18

SEC670 and CRTO both cover service enumeration (OpenSCManager, EnumServicesStatus, QueryServiceStatus), weak binary permissions (Get-Acl on service paths), and unquoted path LPE. This is distinct from the persistence suite — the operational p

=== NOTE 98 ===
id: lgtm:host-survey-script-primitive
title: Host Survey Script as a Unified Recon Capability
would_relate_to: ['T-023', 'T-020', 'T-022', 'T-007']
origin: atlas-recon-part1
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part1
**Would relate to:** T-023, T-020, T-022, T-007
**Source units:** unit 19, unit 20, unit 21

SEC670 dedicates an entire Section 2 to the host survey — a unified operational primitive that aggregates OS version, patch status, process list, installed software, services/tasks, NIC state, and registry state into a single survey output. The vau

=== NOTE 99 ===
id: lgtm:patch-status-inventory-card
title: Patch / Hotfix Inventory as a Standalone Capability
would_relate_to: ['T-020', 'T-023']
origin: atlas-recon-part1
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part1
**Would relate to:** T-020, T-023
**Source units:** unit 27, unit 28, unit 29, unit 32, unit 33, unit 34

SEC670 covers hotfix enumeration via three distinct paths (Get-HotFix cmdlet, wmic qfe list, WUA COM APIs) and frames the result as a precondition for exploit selection and for reasoning about kernel-callback/ETW differences across bui

=== NOTE 100 ===
id: lgtm:proposed-recon-survey-card
title: Dedicated Recon & Survey Technique Card
would_relate_to: ['T-023', 'T-020', 'T-016']
origin: atlas-recon-part2
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part2
**Would relate to:** T-023, T-020, T-016
**Source units:** unit 1, unit 4, unit 8, unit 15, unit 20, unit 27, unit 40

SEC670 dedicates an entire course section to Windows survey APIs: process enumeration (WTSEnumerateProcessesEx, NtQuerySystemInformation, CreateToolhelp32Snapshot), installed-software discovery via Program Files directory 

=== NOTE 101 ===
id: lgtm:kuser-shared-data-sysinfo-primitive
title: KUSER_SHARED_DATA Direct-Read Sysinfo Primitive
would_relate_to: ['T-023', 'T-016']
origin: atlas-recon-part3
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part3
**Would relate to:** T-023, T-016
**Source units:** unit 15, unit 16

SEC670 cites KUSER_SHARED_DATA as a BONUS sysinfo target alongside GetProductInfo, GetWindowsDirectory, GetComputerName, GetNativeSystemInfo. The vault's T-023 lists sysinfo collection but does not document the direct-page-read approach that bypasses syscall-based EDR ho

=== NOTE 102 ===
id: lgtm:proposed-host-survey-card
title: Host Survey and Situational Awareness as a Standalone Technique
would_relate_to: ['T-023', 'T-016', 'T-017', 'T-020']
origin: atlas-recon-part4
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part4
**Would relate to:** T-023, T-016, T-017, T-020
**Source units:** unit 7, unit 9, unit 14, unit 25, unit 26, unit 29, unit 38

SEC670 dedicates an entire Book (Book 2, 'Getting to Know Your Target') to host survey: OS info, hotfixes/SPs, process enum, services, network adapters, registry hives, and user enumeration. The vault folds this in

=== NOTE 103 ===
id: lgtm:proposed-host-survey-recon-card
title: Host Survey Recon as a Standalone Technique Card
would_relate_to: ['T-023', 'T-016', 'T-020']
origin: atlas-recon-part5
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part5
**Would relate to:** T-023, T-016, T-020
**Source units:** unit 1, unit 2, unit 3, unit 8, unit 11, unit 21, unit 35

SEC670 devotes an entire book (Section 2) to host surveying: OS info, service packs, process enumeration across four API families, installed software directory walks, user enumeration, services and tasks, network info, and 

=== NOTE 104 ===
id: lgtm:pe-sieve-detection-coverage
title: PE-sieve Detection Mechanics Against Injection Techniques
would_relate_to: ['T-007', 'T-008', 'T-013']
origin: atlas-recon-part6
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part6
**Would relate to:** T-007, T-008, T-013
**Source units:** unit 36

SEC670 identifies PE-sieve as a community-driven state-of-the-art tool for identifying malicious activity, alongside profit-driven products like Huntress Labs. The vault documents many injection techniques (T-007 through T-013) but does not document how PE-sieve specifical

=== NOTE 105 ===
id: lgtm:windows-registry-internals-deep-dive
title: Windows Registry Internal Structure and Link Semantics
would_relate_to: ['T-017']
origin: atlas-recon-part6
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part6
**Would relate to:** T-017
**Source units:** unit 16, unit 17, unit 18, unit 19

SEC670 dedicates multiple slides to the merged-view and link semantics of HKCR, HKCU, and HKCC, explaining that per-user classes override machine-wide ones and that HKCC is entirely linked to HKLM. This structural knowledge underpins COM hijack persistence (T-

=== NOTE 106 ===
id: lgtm:recon-enumeration-api-surface
title: Recon Enumeration API Surface as a Standalone Technique
would_relate_to: ['T-023', 'T-007', 'T-017']
origin: atlas-recon-part7
description: **Kind:** proposed-technique
**Origin:** atlas-recon-part7
**Would relate to:** T-023, T-007, T-017
**Source units:** unit 1, unit 2, unit 5, unit 12, unit 13, unit 16, unit 17

SEC670 dedicates an entire module to enumerating targets across four domains (network adapters, registry, processes, services) using specific Win32/NT/WTS APIs with operational trade-offs (snapshot lag, hookability, remote
