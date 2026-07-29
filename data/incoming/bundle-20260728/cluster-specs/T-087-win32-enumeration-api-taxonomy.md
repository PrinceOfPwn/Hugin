# Cluster Spec — T-087: Win32 Enumeration API Taxonomy and Primitive Selection

- **T-NNN ID**: `T-087`
- **Canonical name**: Win32 Enumeration API Taxonomy and Primitive Selection
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: high — Four member notes from three atlas batches; fills a critical foundational gap; cross-source convergence between SEC670 and MalDev Academy.
- **would_relate_to**: ['T-023', 'T-017', 'T-007', 'T-004']

## Consolidated Description

SEC670 systematically compares CreateToolhelp32Snapshot (Process32First/Next, rich
metadata via PROCESSENTRY32), EnumProcesses (PID-only array, simplest), and
WTSEnumerateProcessesEx (session-aware, WTSEnumerateProcessesEx level info class) as
process-enumeration primitives with explicit tradeoffs: metadata depth vs. simplicity
vs. EDR visibility. The vault's T-004 (PEB Walker) deliberately avoids all three Win32
patterns, walking the PEB via gs:[0x60] → Ldr → InLoadOrderModuleList instead. A dedicated
card should document the full taxonomy across processes, users, groups, services,
scheduled tasks (ITaskScheduler COM), and network interfaces, with each primitive's
detection surface and the PEB-walker alternative positioned as the evasion path. The
cross-source convergence between SEC670 and MalDev Academy on this taxonomy elevates
its priority as a foundational discovery card.


## Member LGTM Notes (4)

### Note 1: Recon API Taxonomy Coverage Gap
- id: `lgtm:recon-api-taxonomy-coverage`
- origin: atlas-enumeration-part1
- would_relate_to: ['T-023', 'T-017', 'T-007']
- tags: ['recon', 'enumeration', 'coverage-gap', 'api-taxonomy']

**Kind:** coverage-gap
**Origin:** atlas-enumeration-part1
**Would relate to:** T-023, T-017, T-007
**Source units:** unit 1, unit 2, unit 3, unit 5, unit 13, unit 17, unit 19, unit 22, unit 24

SEC670 dedicates substantial material to the taxonomy of Win32 enumeration APIs across processes, users, groups, services, scheduled tasks, and network interfaces — distinguishing each by return type, level parameter, and access mask. The vault's T-023 recon module (byakugan.rs) is documented as covering ARP, TCP, and AD enum, but the broader enumeration surface (SCM, COM task scheduler, NetLocalGroupEnum, GetAdaptersAddresses) is not surfaced in any technique card. This material would inform a more complete recon capability matrix.

### Note 2: Cross-Source Convergence on Process Enumeration API Choice
- id: `lgtm:sec670-maldev-recon-convergence`
- origin: atlas-enumeration-part1
- would_relate_to: ['T-023']
- tags: ['convergence', 'process-enum', 'api-selection']

**Kind:** cross-source-convergence
**Origin:** atlas-enumeration-part1
**Would relate to:** T-023
**Source units:** unit 5, unit 7, unit 8, unit 11, unit 13

SEC670 material systematically compares CreateToolhelp32Snapshot, EnumProcesses, and WTSEnumerateProcesses as enumeration primitives with explicit tradeoffs (metadata depth vs. simplicity vs. remote capability). This converges with the broader MalDev Academy pattern of selecting enumeration APIs based on operational context. The vault's recon module would benefit from a documented decision matrix for enumeration API selection tied to operational intent (injection targeting vs. situational awareness vs. lateral movement).

### Note 3: Vault Lacks Dedicated Enumeration Technique Card
- id: `lgtm:enumeration-primitives-coverage`
- origin: atlas-enumeration-part2
- would_relate_to: ['T-023', 'T-007', 'T-017']
- tags: ['enumeration', 'recon', 'coverage-gap', 'win32', 'com']

**Kind:** coverage-gap
**Origin:** atlas-enumeration-part2
**Would relate to:** T-023, T-007, T-017
**Source units:** unit 1, unit 2, unit 4, unit 6, unit 7, unit 15, unit 19, unit 20

SEC670 devotes an entire book section to enumeration primitives — ITaskScheduler COM, CreateToolhelp32Snapshot, EnumProcesses, WTSEnumerateProcesses, NtQuerySystemInformation, NetUserEnum, EnumServicesStatusEx, and directory enumeration APIs. The vault references recon in T-023 but does not document the Win32/COM enumeration API surface as a structured capability. A dedicated technique card or expanded T-023 section documenting which APIs are documented, undocumented, NT-direct, or COM-routed would help operators choose enumeration paths with the right EDR-evasion profile.

### Note 4: Toolhelp Snapshot vs PEB Walker — Operational Divergence
- id: `lgtm:toolhelp-vs-peb-walker-divergence`
- origin: atlas-exploit-dev-part16
- would_relate_to: ['T-004', 'T-023']
- tags: ['toolhelp', 'peb', 'enumeration', 'evasion', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-exploit-dev-part16
**Would relate to:** T-004, T-023
**Source units:** unit 21

Unit 21 documents CreateToolhelp32Snapshot/Process32First/Process32Next as the standard Win32 process-enumeration pattern. HUGIN's T-004 (PEB Walker) deliberately avoids this pattern, walking the PEB via gs:[0x60] → Ldr → InLoadOrderModuleList for module resolution. The divergence is operational: Toolhelp is observable via the Kernel-Process ETW provider and produces a kernel snapshot handle, while PEB walking is in-process memory traversal that produces no kernel telemetry. The vault does not currently document why the PEB walker is the preferred enumeration path or what detections it sidesteps — only the implementation.

---
Use `id: T-087`, canonical name above, and `member_notes: ['lgtm:recon-api-taxonomy-coverage', 'lgtm:sec670-maldev-recon-convergence', 'lgtm:enumeration-primitives-coverage', 'lgtm:toolhelp-vs-peb-walker-divergence']`.
Cross-reference `would_relate_to`: ['T-023', 'T-017', 'T-007', 'T-004'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.