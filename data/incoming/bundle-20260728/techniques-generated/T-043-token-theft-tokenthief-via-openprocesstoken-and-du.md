---
id: T-043
name: Token Theft (TokenThief) via OpenProcessToken and Duplication
category: privesc
tier: A
crate: none
source_file: none
mitre: T1134.001
mitre_secondary: [T1134.002]
tags: [token-theft, privilege-escalation, openprocesstoken, duplicatetokenex, createprocesswithtokenw, impersonation, sedebugprivilege, integrity-levels, admin-to-system, access-tokens]
origin: atlas-synthesis
member_notes: ['lgtm:token-theft-privilege-escalation', 'lgtm:token-impersonation-theft-card', 'lgtm:proposed-token-theft-technique', 'lgtm:proposed-token-stealing-lpe-card', 'lgtm:token-theft-and-impersonation-primitive', 'lgtm:proposed-token-theft-technique-card']
---

# Token Theft via OpenProcessToken and Duplication — Steal a SYSTEM Token and Spawn Under It

## Summary

Token theft opens the access token of a higher-privilege process, duplicates it, and assigns the copy to a new child process or to the calling thread, yielding execution at the donor token's privilege level. The chain runs OpenProcess with SeDebugPrivilege, OpenProcessToken against the donor, DuplicateTokenEx with MAXIMUM_ALLOWED rights, and CreateProcessWithTokenW (or ImpersonateLoggedOnUser for thread-level impersonation), moving a High-IL administrator to SYSTEM without any UAC consent prompt. SEC670 teaches it as Lab 3.5 "TokenThief," with winlogon.exe-class SYSTEM processes as donors, and the material frames it as the conceptual backend of Meterpreter's getsystem command. The primary detection surface recorded in the notes is Kernel-Process TokenOpen ETW telemetry and process-creation events showing an elevated-integrity child with no corresponding consent-UI activity.

## Mechanism

1. Enable SeDebugPrivilege in the implant's own primary token. Call OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hSelfTok), resolve the privilege LUID with LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid), populate a TOKEN_PRIVILEGES structure (PrivilegeCount = 1, Privileges[0].Luid = luid, Privileges[0].Attributes = SE_PRIVILEGE_ENABLED), then AdjustTokenPrivileges(hSelfTok, FALSE, &tkp, 0, NULL, NULL). The material presents LookupPrivilegeValue → OpenProcessToken → AdjustTokenPrivileges as the programmatic privilege-adjustment path, with AdjustTokenPrivileges as the final step that flips a present-but-disabled privilege to Enabled.
2. Enumerate processes and select a donor running at System integrity level. Enumeration uses CreateToolhelp32Snapshot (SEC670 Lab 2.3); the material names winlogon.exe alongside wininit and lsass as System-IL processes, and one note explicitly describes opening a SYSTEM token on winlogon.exe. The notes flag donor-PID selection as an operator decision without prescribing a target beyond these examples.
3. OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, donorPid) to obtain hDonor. With SeDebugPrivilege enabled, the access check against a SYSTEM process succeeds; without it, a High-IL admin cannot obtain this handle on winlogon.exe-class targets.
4. OpenProcessToken(hDonor, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hDonorTok). The material documents this API's contract directly: "Obtains a handle to a process' access token," three parameters (ProcessHandle, DesiredAccess, TokenHandle), BOOL return. It adds that no privilege in a token can be changed without first holding a handle to it — OpenProcessToken is the entry point. Requested access-mask choice is a tradecraft variable per the notes.
5. DuplicateTokenEx(hDonorTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimary). This produces a new token object — a copy of the donor's token requested with MAXIMUM_ALLOWED rights per the consolidated description — typed TokenPrimary so it can be assigned to a child process. The same call with TokenImpersonation yields the impersonation variant used in step 6b.
6a. Spawn path: CreateProcessWithTokenW(hPrimary, 0, lpApplicationName, ...) creates a child that runs under the stolen token — the notes describe spawning a System-IL child from a High-IL admin context. The caller requires SeImpersonatePrivilege, which High-IL admins hold. Note 3 records CreateProcessAsUser as the alternate spawn API in the same chain; it additionally demands SeAssignPrimaryTokenPrivilege.
6b. Impersonate path: with a TokenImpersonation duplicate, ImpersonateLoggedOnUser(hDup) attaches the donor's security context to the calling thread, which then operates as SYSTEM on subsequent object access until RevertToSelf. Note 2 names the MakeToken / ImpersonateLoggedOnUser / DuplicateTokenEx primitive family explicitly.
7. Close handles: CloseHandle on the duplicated token, the donor token, and the donor process handle once the child is spawned or impersonation ends. The notes list duplicated-handle closure as an explicit tradecraft item; leaked handles to a SYSTEM token persist as forensic artifacts.

## OS Internals Context

Access tokens are issued after successful authentication, and every process created after logon carries a primary token tied to the user. The material enumerates token contents: user SID and logon SID, privileges, a default DACL, and the primary-versus-impersonation type flag. Privileges live in a TOKEN_PRIVILEGES structure as an array of LUID_AND_ATTRIBUTES — a LUID identifying the privilege plus attribute bits SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, and SE_PRIVILEGE_USED_FOR_ACCESS. The enabled/disabled distinction matters operationally: whoami /priv on a High-IL token shows a large privilege set mostly marked Disabled, and those privileges can be enabled on the fly, which is exactly what step 1 does. A standard user's token holds little beyond an enabled SeChangeNotifyPrivilege.

Windows defines six integrity levels for privilege separation — Untrusted (0), Low (1), Medium (2), High (3), System (4), Protected (5) — queryable via GetTokenInformation(TokenIntegrityLevel) and stored in the token as a mandatory-label SID of the form S-1-16-\<rid\>. System IL hosts wininit, winlogon, and lsass; Protected is settable only by kernel-mode callers. Mandatory Integrity Control blocks lower-IL processes from writing to higher-IL objects, but the theft path requests query- and duplicate-style access masks rather than write access, and SeDebugPrivilege neutralizes the per-process access check that would otherwise stop a High-IL admin at step 3. This is why the whole chain gates on a single privilege flip rather than on any ACL modification.

On the kernel side, a token is a securable executive object: the process object (EPROCESS) references its primary token, and each thread may additionally reference an impersonation token. DuplicateTokenEx allocates a new token object that shares the donor's logon session — the same authentication ID — so the copy authenticates as NT AUTHORITY\SYSTEM wherever the donor did, and its lifetime is governed by its own handle count, independent of the donor handle. Token type is fixed at duplication time: a TokenPrimary copy cannot be used for thread impersonation, and a TokenImpersonation copy cannot be assigned to a process. CreateProcessWithTokenW and ImpersonateLoggedOnUser each demand the matching type, which is why step 5's TokenType parameter decides which of steps 6a and 6b is available.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C/C++ (the SEC670 Lab 3.5 "TokenThief" source review).

Two grep-matched files were verified and rejected. `dark_crystal/crates/core/src/escalation/uac.rs` calls OpenProcessToken only against GetCurrentProcess() with TOKEN_QUERY to read TokenElevation for a self-elevation check — no foreign process token is opened. `dark_crystal/crowd/src/persist/phantom_restart.rs` calls OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) to enable SeShutdownPrivilege on its own token — the same LookupPrivilegeValueW → AdjustTokenPrivileges shape as mechanism step 1, but with no cross-process token access and no duplication. Neither implements the primary mechanism this card describes.

An implementation would follow the vault's established FFI pattern: windows_targets::link! bindings for DuplicateTokenEx and CreateProcessWithTokenW added alongside wrappers.rs, a donor-PID resolver over CreateToolhelp32Snapshot mirroring the find_pid_by_name approach in ppid.rs, a SeDebugPrivilege-enable helper shaped like phantom_restart.rs's enable_shutdown_privilege, and RAII guards that close the donor process handle and both token handles on drop so no reference to the stolen token outlives the spawn call.

## Why It Matters

The vault's existing elevation coverage stops at High IL: T-021's slui.exe bypass and T-023's CMSTP bypass convert Medium to High via auto-elevation, and neither reaches SYSTEM. Token theft is the High-to-System step, operates on token objects rather than on injected memory or the parent-attribute manipulation of T-015, and therefore composes with any downstream execution primitive — the material explicitly frames it as the backend logic of Meterpreter's getsystem. The notes also record it as a lateral-movement primitive through thread impersonation, and no UAC consent UI appears anywhere in the chain, which removes the user-interaction dependency that constrains auto-elevation.

## Detection Considerations

- **Telemetry sources**: The notes record Kernel-Process TokenOpen ETW events as the provider-level observation of OpenProcessToken against a foreign process (GUID and event IDs not documented in the material). They also record Security event 4688 process-creation telemetry showing a child at High or System Mandatory Level with no corresponding consent-UI activity as the anomaly this technique produces. The material documents no Sysmon event IDs or additional providers for this technique.
- **Bypass options**: The notes list three operator-controlled variables: which donor PID to target, which access mask to request from OpenProcessToken (minimal masks such as TOKEN_DUPLICATE rather than broad rights), and prompt closure of duplicated token handles after the spawn.
- **Residual artifacts**: During the theft window the implant holds handles to the donor process and to its token; the spawned child appears in process-creation telemetry with SYSTEM integrity parented to the implant; and SeDebugPrivilege remains enabled in the implant's own token after step 1 unless explicitly re-disabled.

## Related Techniques

- **T-015 PPID Spoofing** — T-015 forges the parent-process attribute of a new process; T-043 forges the token the new process receives. Same T1134 family, different creation parameter, and the notes position token duplication as the primitive T-015 does not cover.
- **T-021 Cryptography and Obfuscation** — hosts the slui.exe UAC bypass that reaches High IL; T-043 is the follow-on that converts High-IL admin context into SYSTEM.
- **T-023 Client Capabilities** — privileged capabilities catalogued there (LSASS dump via MiniDumpWriteDump, CMSTP UAC bypass) presume SeDebugPrivilege or SYSTEM context; token theft is the escalation primitive that supplies it, and the notes flag that token logic is currently only implicit in T-023.

## References

- Atlas material: atlas-binary-analysis-part4.md, atlas-labs-part2.md, atlas-post-exploit-part4.md, atlas-post-exploit-part14.md, atlas-post-exploit-part16.md, atlas-privesc-part1.md
- MITRE ATT&CK: T1134.001 Token Impersonation/Theft (https://attack.mitre.org/techniques/T1134/001/); T1134.002 Create Process with Token (https://attack.mitre.org/techniques/T1134/002/)
- LGTM notes: lgtm:token-theft-privilege-escalation, lgtm:token-impersonation-theft-card, lgtm:proposed-token-theft-technique, lgtm:proposed-token-stealing-lpe-card, lgtm:token-theft-and-impersonation-primitive, lgtm:proposed-token-theft-technique-card
- Public references: SANS SEC670 Lab 3.5 "TokenThief" (source-review lab named in the material); Meterpreter getsystem command (named in the material as the technique's backend implementation)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. Grep-matched files `dark_crystal/crates/core/src/escalation/uac.rs` and `dark_crystal/crowd/src/persist/phantom_restart.rs` were verified to use OpenProcessToken only against the current process and do not implement this technique.