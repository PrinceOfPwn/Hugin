# Cluster Spec — T-082: NtQuerySystemInformation Process Enumeration

- **T-NNN ID**: `T-082`
- **Canonical name**: NtQuerySystemInformation Process Enumeration
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: high — Two convergence notes; distinct primitive that replaces the Win32 enumeration path monitored by EDRs.
- **would_relate_to**: ['T-007', 'T-020', 'T-023']

## Consolidated Description

Documents NtQuerySystemInformation(SystemProcessInformation, class 5) as the native enumeration path that bypasses the Win32 CreateToolhelp32Snapshot/Process32First/Process32Next path EDRs commonly monitor. The buffer contains a linked list of SYSTEM_PROCESS_INFORMATION structures where NextEntryOffset (ULONG at offset 0x00) walks the list; each entry contains UniqueProcessId (HANDLE at offset 0x80 on x64), ImageName (UNICODE_STRING at offset 0x88), and NumberOfThreads (ULONG at offset 0x278). The two-pass allocation pattern: call with NULL buffer, get STATUS_INFO_LENGTH_MISMATCH + required size, allocate, retry. Pairs with NtQueryInformationProcess(ProcessBasicInformation) for per-process PEB and PE walker discovery.


## Member LGTM Notes (2)

### Note 1: NtQuerySystemInformation as Evasion-Friendlier Enumeration Path
- id: `lgtm:native-process-enumeration-coverage`
- origin: atlas-binary-analysis-part2
- would_relate_to: ['T-007', 'T-020']
- tags: ['ntquerysysteminformation', 'enumeration', 'evasion', 'coverage-gap', 'recon']

**Kind:** coverage-gap
**Origin:** atlas-binary-analysis-part2
**Would relate to:** T-007, T-020
**Source units:** unit 27, unit 28, unit 29, unit 32, unit 33, unit 34, unit 35

The vault documents process injection (T-007 family) and anti-analysis (T-020), but does not explicitly cover the enumeration-API selection problem that precedes injection target selection. SEC670's contrast of CreateToolhelp32Snapshot, EnumProcesses, and NtQuerySystemInformation — with NtQuerySystemInformation framed as the native evasion-friendlier path — is operational knowledge that belongs in the graph as either a recon sub-technique or cross-cutting metadata on injection cards.

### Note 2: Undocumented Native API Process Enumeration
- id: `lgtm:undocumented-native-api-process-enum`
- origin: atlas-edr-evasion-part1
- would_relate_to: ['T-023', 'T-020']
- tags: ['native-api', 'ntquerysysteminformation', 'process-enum', 'evasion', 'undocumented']

**Kind:** coverage-gap
**Origin:** atlas-edr-evasion-part1
**Would relate to:** T-023, T-020
**Source units:** unit 21

SEC670 explicitly surfaces NtQuerySystemInformation with SYSTEM_INFORMATION_CLASS as an 'undocumented method' for process enumeration that bypasses the Win32 toolhelp32 path EDRs commonly monitor. The vault has no concept or technique entry covering native-API-based process enumeration as an evasion-aware alternative to Process32First/Next. This is reusable across recon, injection target selection, and anti-analysis.

---
Use `id: T-082`, canonical name above, and `member_notes: ['lgtm:native-process-enumeration-coverage', 'lgtm:undocumented-native-api-process-enum']`.
Cross-reference `would_relate_to`: ['T-007', 'T-020', 'T-023'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.