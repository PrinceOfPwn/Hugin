# Cluster Spec — T-086: Process Enumeration API Trade-off Matrix

- **T-NNN ID**: `T-086`
- **Canonical name**: Process Enumeration API Trade-off Matrix
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: high — Four member notes with strong cross-source convergence (SEC670 / MalDev / CRTO) on a concrete API matrix bridging syscall and recon cards
- **would_relate_to**: ['T-023', 'T-013', 'T-007', 'T-012', 'T-001', 'T-002', 'T-003', 'T-004']

## Consolidated Description

Documented process enumeration APIs split into three families: K32EnumProcesses / EnumProcessModules (simple flat PID list, no parent-child), CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, PROCESSENTRY32 with th32ParentProcessID, full PID tree), and WTSEnumerateProcessesEx (multi-session support, returns SID and full path via WTS_PROCESS_INFO). Each has explicit trade-offs: simplicity vs detail vs remote/session visibility. NtQuerySystemInformation with SystemProcessInformation (class 5) is the undocumented alternative returning a linked list of SYSTEM_PROCESS_INFORMATION structures via NextEntryOffset, including thread info, CPU times, and image base; bypasses userland hooks in ntdll when called via direct or indirect syscall. The vault documents syscall dispatch (T-001..T-004) but does not catalog which recon APIs pair with which dispatch mechanism; a new card should explicitly bridge the syscall cards with the recon surface.


## Member LGTM Notes (4)

### Note 1: Process Enumeration API Tradeoff Matrix
- id: `lgtm:process-enumeration-api-tradeoffs`
- origin: atlas-recon-part1
- would_relate_to: ['T-023', 'T-007']
- tags: ['process-enum', 'api-tradeoff', 'tradecraft', 'recon', 'coverage-gap']

**Kind:** cross-source-convergence
**Origin:** atlas-recon-part1
**Would relate to:** T-023, T-007
**Source units:** unit 15, unit 40

SEC670 documents three documented process-enumeration APIs (EnumProcesses, CreateToolhelp32Snapshot, WTSEnumerateProcesses) with explicit tradeoffs: simplicity vs detail vs remote/multi-session capability. The vault uses CreateToolhelp32Snapshot-style enumeration implicitly in T-023 recon but does not document why that API is selected over the alternatives. A concept node capturing the tradeoff matrix (already added) plus a card-internal note would surface this as a tradecraft decision rather than an arbitrary implementation choice.

### Note 2: Process Enumeration API Trade-off Convergence
- id: `lgtm:convergence-process-enum-api-tradeoffs`
- origin: atlas-recon-part4
- would_relate_to: ['T-023', 'T-013']
- tags: ['process-enum', 'convergence', 'telemetry', 'api-selection']

**Kind:** cross-source-convergence
**Origin:** atlas-recon-part4
**Would relate to:** T-023, T-013
**Source units:** unit 39, unit 40

SEC670, MalDev Academy, and CRTO all converge on presenting EnumProcesses, CreateToolhelp32Snapshot, and WTSEnumerateProcesses as the three documented process enumeration APIs with the same trade-off matrix (simplicity vs detail vs remote capability). This is strong tradecraft consensus that the vault should reflect: T-023 currently treats process enumeration as a single capability rather than three distinct APIs with different telemetry profiles and operational niches. Documenting the trade-off explicitly would help operators select the lowest-telemetry API that meets their detail requirement.

### Note 3: Process Enumeration API Variant Tradecraft Coverage
- id: `lgtm:coverage-gap-process-enumeration-variants`
- origin: atlas-recon-part5
- would_relate_to: ['T-007', 'T-012', 'T-013', 'T-023']
- tags: ['process-enum', 'tradecraft', 'coverage-gap', 'api-selection']

**Kind:** coverage-gap
**Origin:** atlas-recon-part5
**Would relate to:** T-007, T-012, T-013, T-023
**Source units:** unit 1, unit 30, unit 31, unit 32, unit 33, unit 34

SEC670 documents four distinct process-enumeration APIs (CreateToolhelp32Snapshot, EnumProcesses, WTSEnumerateProcessesEx, NtQuerySystemInformation) with explicit tradeoffs: snapshot staleness, remote capability, stealth, undocumented status. The vault references process enumeration tangentially under injection-target selection but does not document which enumeration path pairs with which injection technique. A cross-cutting reference mapping enumeration API to injection technique would close a tradecraft gap.

### Note 4: NtQuerySystemInformation Recon via Indirect Syscall
- id: `lgtm:ntquerysysteminformation-recon-via-syscall`
- origin: atlas-recon-part7
- would_relate_to: ['T-001', 'T-002', 'T-003', 'T-004', 'T-023']
- tags: ['nt-api', 'recon', 'indirect-syscall', 'cross-source']

**Kind:** cross-source-convergence
**Origin:** atlas-recon-part7
**Would relate to:** T-001, T-002, T-003, T-004, T-023
**Source units:** unit 12, unit 13, unit 14

SEC670 surfaces NtQuerySystemInformation(SystemProcessInformation) as the 'undocumented' option for process enumeration that avoids userland hooks. The vault's syscall-dispatch techniques (T-001 RecycledGate, T-002 Hell's Gate family, T-003 VEH Gate) are framed around NT calls that perform writes, allocations, and protects. The vault does not currently document which recon-class Nt* calls are operationally dispatched via indirect syscall in the same implant that performs injection via indirect syscall. Cross-cutting metadata linking the syscall-dispatch cards to recon NT calls (NtQuerySystemInformation, NtQueryInformationProcess, NtOpenProcess) would clarify this.

---
Use `id: T-086`, canonical name above, and `member_notes: ['lgtm:process-enumeration-api-tradeoffs', 'lgtm:convergence-process-enum-api-tradeoffs', 'lgtm:coverage-gap-process-enumeration-variants', 'lgtm:ntquerysysteminformation-recon-via-syscall']`.
Cross-reference `would_relate_to`: ['T-023', 'T-013', 'T-007', 'T-012', 'T-001', 'T-002', 'T-003', 'T-004'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.