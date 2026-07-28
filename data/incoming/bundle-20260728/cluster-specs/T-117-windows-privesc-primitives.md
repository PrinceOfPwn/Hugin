# Cluster Spec — T-117: Windows Privilege Escalation Primitives (Admin to SYSTEM)

- **T-NNN ID**: `T-117`
- **Canonical name**: Windows Privilege Escalation Primitives (Admin to SYSTEM)
- **Proposed category**: `privesc`
- **Proposed tier**: `A`
- **Priority**: high — Three-source convergence (SEC670 / MalDev / CRTO) on canonical privilege set; fills a critical prerequisite gap for multiple privesc chains
- **would_relate_to**: ['T-013', 'T-022', 'T-016', 'T-023', 'T-021']

## Consolidated Description

SEC670, MalDev Academy, and CRTO converge on the same five-privilege set as the canonical admin-to-SYSTEM escalation paths: SeTakeOwnership (take ownership of a SYSTEM process binary or service path via SetSecurityInfo, replace with malicious payload, restart service), SeTcbPrivilege (call NtCreateThreadEx inside a SYSTEM process via ZwOpenProcess + thread creation), SeCreateTokenPrivilege (craft a SYSTEM token directly via NtCreateToken specifying SYSTEM SID in TOKEN_USER), SeLoadDriverPrivilege (load unsigned kernel driver via NtLoadDriver that performs PsSetCreateProcessNotifyRoutineEx manipulation or token theft), SeDebugPrivilege (OpenProcess(PROCESS_ALL_ACCESS) on winlogon.exe, DuplicateTokenEx with SecurityImpersonation level, CreateProcessWithTokenW). The vault documents LSASS credential harvest (T-023) and CMSTP UAC bypass (T-021) but has no card cataloging these privilege primitives — they are the building blocks for chaining admin -> SYSTEM -> kernel.


## Member LGTM Notes (2)

### Note 1: Admin-to-SYSTEM Privilege Escalation Set Convergence
- id: `lgtm:cross-source-convergence-admin-to-system-privilege-set`
- origin: atlas-privesc-part1
- would_relate_to: ['T-013', 'T-022', 'T-016']
- tags: ['privilege', 'admin-to-system', 'convergence', 'se-debug', 'se-load-driver', 'se-take-ownership']

**Kind:** cross-source-convergence
**Origin:** atlas-privesc-part1
**Would relate to:** T-013, T-022, T-016
**Source units:** unit 39, unit 40

SEC670, MalDev Academy, and CRTO all converge on the same five-privilege set (SeTakeOwnership, SeTcb, SeCreateToken, SeLoadDriver, SeDebug) as the canonical admin-to-SYSTEM escalation paths. Each course treats these as the answer to 'I have admin, how do I get SYSTEM?' The vault currently does not surface this privilege-set-as-escalation-paths pattern in any single technique card — the knowledge is scattered across T-022 (SeLoadDriver via BYOVD), T-013 (SeDebug via process hollowing), and unmentioned elsewhere. Worth surfacing as cross-cutting metadata on what each admin-tier privilege enables.

### Note 2: Windows Privilege Escalation Primitives Coverage Gap
- id: `lgtm:coverage-gap-windows-privesc-primitives`
- origin: atlas-privesc-part2
- would_relate_to: ['T-023', 'T-021']
- tags: ['coverage-gap', 'privesc', 'token', 'sedebugprivilege', 'services', 'lsass-prereq']

**Kind:** coverage-gap
**Origin:** atlas-privesc-part2
**Would relate to:** T-023, T-021
**Source units:** unit 1, unit 2, unit 3, unit 6, unit 7, unit 8, unit 14, unit 15

The vault documents LSASS credential harvest (T-023) and CMSTP-based UAC bypass (T-021/T-023) as standalone capabilities, but contains no technique card for the privilege-escalation prerequisites that make those operations operationally viable: programmatic SeDebugPrivilege enablement via LookupPrivilegeValue/OpenProcessToken/AdjustTokenPrivileges, SCM-based service enumeration for unquoted-path LPE, or token-stealing via OpenProcessToken + ImpersonateLoggedOnUser. SEC670 dedicates a full module to these primitives as the foundation for the vault's higher-level credential-access and elevation techniques. The vault currently leaves an operator unable to chain T-023 LSASS access without external knowledge of how to enable SeDebugPrivilege first.

---
Use `id: T-117`, canonical name above, and `member_notes: ['lgtm:cross-source-convergence-admin-to-system-privilege-set', 'lgtm:coverage-gap-windows-privesc-primitives']`.
Cross-reference `would_relate_to`: ['T-013', 'T-022', 'T-016', 'T-023', 'T-021'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.