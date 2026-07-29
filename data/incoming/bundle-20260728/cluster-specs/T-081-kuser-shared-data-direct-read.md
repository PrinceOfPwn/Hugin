# Cluster Spec — T-081: KUSER_SHARED_DATA Direct Read Recon

- **T-NNN ID**: `T-081`
- **Canonical name**: KUSER_SHARED_DATA Direct Read Recon
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: high — Cross-source convergence (SEC670 + CRTO) on a concrete, telemetry-free primitive not documented in T-001..T-074
- **would_relate_to**: ['T-023', 'T-020', 'T-016', 'T-004']

## Consolidated Description

KUSER_SHARED_DATA is a read-only page mapped at fixed virtual address 0x7FFE0000 in every user-mode process, containing SystemTime, TickCount, TimeZoneBias, NtMajorVersion, NtMinorVersion, ProductType, and SuiteMask. Direct reads avoid invoking NtQuerySystemInformation, GetSystemTime, or GetVersionEx and therefore bypass userland hooks while generating no ETW or syscall telemetry. SEC670 presents this as the undocumented alternative path for OS fingerprinting and timestamp reads, framing it as critical for evasive recon. The vault currently has neither a technique card nor a concept node documenting the layout and tradecraft around this primitive; a new card should enumerate the structure's high-value fields (offsets for SystemTime at 0x14, TickCount at 0x320, NtMajorVersion at 0x260, NtMinorVersion at 0x264), the fixed virtual address, and the implication that an operator can fingerprint OS, read high-resolution time, and enumerate processors without any syscall.


## Member LGTM Notes (2)

### Note 1: KUSER_SHARED_DATA Direct Reads as Telemetry-Free Recon
- id: `lgtm:kuser-shared-data-recon`
- origin: atlas-recon-part1
- would_relate_to: ['T-023', 'T-004']
- tags: ['kuser-shared-data', 'undocumented-api', 'telemetry-evasion', 'recon']

**Kind:** emerging-tradecraft
**Origin:** atlas-recon-part1
**Would relate to:** T-023, T-004
**Source units:** unit 5, unit 17, unit 24

SEC670 presents direct reads of KUSER_SHARED_DATA at 0x7FFE0000 as the undocumented alternative to documented OS-info APIs, useful precisely because it does not generate API-call telemetry. The vault documents KUSER_SHARED_DATA indirectly (T-004 PEB Walker relies on the same family of fixed user-mode structures) but does not surface direct KUSER_SHARED_DATA reads as a recon technique for OS version / architecture / system time. Worth tracking because the same page exposes SystemTime, Cookie, and other fields that support additional primitives.

### Note 2: KUSER_SHARED_DATA Direct Read Coverage Gap
- id: `lgtm:coverage-kuser-shared-data-access`
- origin: atlas-recon-part4
- would_relate_to: ['T-023', 'T-020', 'T-016']
- tags: ['kuser-shared-data', 'undocumented', 'sysinfo', 'evasion', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-recon-part4
**Would relate to:** T-023, T-020, T-016
**Source units:** unit 26, unit 28

SEC670 presents KUSER_SHARED_DATA as a BONUS undocumented method to obtain system info without invoking documented sysinfo syscalls, framing it as an alternative path for recon. The vault has no technique card or concept node documenting the fixed user-mode shared page, the specific fields it exposes (OS version, tick count, product type, timezone bias), or the evasion implication of reading it directly (no syscall, no API hook contact). This is a concrete evasion-adjacent sysinfo path worth documenting as either a concept node on existing T-023/T-020 cards or a standalone LGTM-tracked item.

---
Use `id: T-081`, canonical name above, and `member_notes: ['lgtm:kuser-shared-data-recon', 'lgtm:coverage-kuser-shared-data-access']`.
Cross-reference `would_relate_to`: ['T-023', 'T-020', 'T-016', 'T-004'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.