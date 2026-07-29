---
id: T-045
name: "Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation"
category: privesc
tier: A
crate: none
source_file: none
mitre: T1134
mitre_secondary: [T1134.001, T1134.002]
tags: [token-privileges, adjusttokenprivileges, sedebugprivilege, sebackup-privilege, serestore-privilege, seimpersonate-privilege, token-theft, lpe]
origin: atlas-synthesis
member_notes: ['lgtm:token-privilege-abuse-proposed-technique']
---

# Token Privilege Abuse — Enabling Dormant Token Privileges for Local Escalation

## Summary

Token privilege abuse enables privileges that are present-but-disabled in the current process token by calling AdjustTokenPrivileges, converting dormant account rights into active capabilities without any exploit or credential theft. Windows assigns privileges such as SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, and SeImpersonatePrivilege to accounts and groups, but delivers them in a disabled state; each process must explicitly enable the privilege in its own token before the kernel will honor it. Once enabled, SeDebugPrivilege turns OpenProcess into an all-access handle request against arbitrary PIDs, SE_BACKUP_NAME grants read access to any file regardless of its ACL, SE_RESTORE_NAME grants the equivalent write access, and SeImpersonatePrivilege authorizes the token-impersonation and token-theft chain. The AdjustTokenPrivileges call itself is a silent in-memory edit to the token object — observability falls almost entirely on the downstream privileged operations it unlocks.

## Mechanism

1. Inventory the current token's privileges before attempting escalation. The material demonstrates this with `whoami /priv` (units 38-39), where a non-admin token shows a short list — SeChangeNotifyPrivilege enabled by default, SeShutdownPrivilege and SeIncreaseWorkingSetPrivilege present but Disabled — while an elevated administrative token carries SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, and SeImpersonatePrivilege in the Disabled state. Programmatically, the same data comes from GetTokenInformation with the TokenPrivileges class.
2. Open the current process token with the rights required for modification: `OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)`.
3. Resolve the target privilege name to its LUID via `LookupPrivilegeValueW(NULL, "SeDebugPrivilege", &luid)`. LUIDs are assigned per boot, so the string constant (SE_DEBUG_NAME) must be translated at runtime rather than hardcoded.
4. Populate a TOKEN_PRIVILEGES structure: PrivilegeCount = 1, with a single LUID_AND_ATTRIBUTES entry pairing the resolved LUID with Attributes = SE_PRIVILEGE_ENABLED. Unit 35 enumerates the attribute flags this field accepts: ENABLED, ENABLED_BY_DEFAULT, REMOVED, USED_FOR_ACCESS.
5. Commit the change with `AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL)`. The full signature in unit 13 takes TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, and ReturnLength, and the material calls this "the last and final step" of the sequence. The SEC670 reference wrapper EnableDebug(Token, Privilege, EnablePrivilege) returns the BOOL from AdjustTokenPrivileges so the caller can branch on success or failure (units 5, 6, 12). A complete check also inspects GetLastError: ERROR_NOT_ALL_ASSIGNED indicates the privilege was never present in the token and cannot be enabled, even though the API returns TRUE.
6. Weaponize according to the privilege enabled:
   - **SeDebugPrivilege**: call OpenProcess with broad access (PROCESS_ALL_ACCESS, or PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) against any non-protected PID, including services and lsass.exe. Units 32 and 34 tie SeDebugPrivilege directly to obtaining process handles that a standard user cannot get.
   - **SeBackupPrivilege (SE_BACKUP_NAME)**: open files with backup semantics; the filesystem grants complete read access regardless of the file's ACL (unit 40).
   - **SeRestorePrivilege (SE_RESTORE_NAME)**: the write counterpart — complete write access regardless of the ACL (units 28, 40).
   - **SeImpersonatePrivilege**: execute the token-stealing chain the material frames as a dedicated escalation lab (unit 14) — open a SYSTEM process, open its token, duplicate it, and either impersonate it on the current thread or launch a new process under it. Opening another process's token presupposes handle access to that process, itself commonly gated by SeDebugPrivilege.
7. Optionally pass a PreviousState buffer in step 5 to capture the original attribute mask, then restore it after the privileged operation to leave the token as found.

## OS Internals Context

**Token structure and privilege masks.** A Windows access token stores its privilege set as an array of LUID_AND_ATTRIBUTES, and the kernel-side TOKEN object maintains three parallel 64-bit privilege masks: Present, Enabled, and EnabledByDefault. AdjustTokenPrivileges (NtAdjustPrivilegesToken in ntoskrnl.exe) flips bits in the Enabled mask — it cannot set a bit that is absent from Present, which is the in-kernel expression of the material's Enabled/Disabled distinction (units 33-34): Disabled means the privilege is authorized and present in the token but not set; Enabled means present and set. SE_PRIVILEGE_REMOVED (0x4) deletes the privilege from the token for the remainder of the logon session — a one-way operation. SE_PRIVILEGE_USED_FOR_ACCESS (0x80000000) is set by the system to record that the privilege was exercised to gain access to an object or service (unit 35).

**Privileges versus ACLs.** The material draws the line precisely (units 34-35): privileges are not tied to an object, they are tied to what can be done — system-related operations such as loading drivers, changing the system time, or debugging processes. The DACL on an object is irrelevant when a privilege check short-circuits it, which is the entire basis of the SeBackup/SeRestore abuse in unit 40.

**Kernel access-check behavior for SeDebugPrivilege.** When a thread whose token has SeDebugPrivilege enabled calls OpenProcess or OpenThread, the kernel's access check grants the requested access mask regardless of the target process's DACL. This is why unit 34 presents the privilege as the gate for obtaining process handles. The documented boundary is Protected Process Light: PPL-protected targets (lsass.exe when RunAsPPL or Credential Guard is configured) refuse the open even from a SeDebugPrivilege-enabled caller, because the PPL signer check runs ahead of the privilege grant.

**Backup semantics in the I/O path.** CreateFile accepts FILE_FLAG_BACKUP_SEMANTICS, which signals backup or restore intent to the I/O manager. With that flag, the filesystem consults the caller's token for SeBackupPrivilege on read operations or SeRestorePrivilege on write operations instead of enforcing the file's DACL — producing the "complete read/write regardless of ACL" behavior unit 40 describes. The privilege must be enabled in the token first; a disabled privilege fails the check exactly as if it were absent.

**Token theft internals.** Tokens are executive objects referenced by handle. The chain unit 14 points at uses OpenProcessToken on a high-privilege process to obtain a handle to its token, DuplicateTokenEx to produce a new token of the desired type (an impersonation token or a primary token), then either ImpersonateLoggedOnUser to adopt the identity on the current thread or CreateProcessWithTokenW to spawn a child under the duplicated primary token — the latter API itself requires SeImpersonatePrivilege. The impersonation level negotiated at duplication time (SecurityAnonymous through SecurityDelegation) constrains whether the token can be used locally or forwarded across the network.

**Integrity level is a separate axis.** Unit 37's six integrity levels (Untrusted 0 through Protected 5) do not change when privileges are enabled; UAC strips administrative privileges from the filtered Medium-IL token entirely, so privilege enablement composes with — and normally follows — an integrity-raising step such as the UAC bypass material in the same module.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for the reference implementation in C++ (SEC670's EnableDebug wrapper, units 5-6).

The AdjustTokenPrivileges primitive itself appears once in the codebase, in a persistence context rather than an escalation one: `dark_crystal/crowd/src/persist/phantom_restart.rs::enable_shutdown_privilege()` performs the exact sequence — OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), LookupPrivilegeValueW on "SeShutdownPrivilege", a zeroed TOKEN_PRIVILEGES with PrivilegeCount = 1 and SE_PRIVILEGE_ENABLED, then AdjustTokenPrivileges — to authorize the ExitWindowsEx(EWX_RESTARTAPPS | EWX_FORCE) call inside PhantomPersist's WM_QUERYENDSESSION handler. It demonstrates the call pattern but enables a shutdown privilege, not any of the escalation privileges this card covers.

A dedicated implementation would expose a generic `enable_privilege(name: &str) -> bool` helper mirroring the SEC670 EnableDebug signature, then layer per-privilege consumers: an OpenProcess(PROCESS_ALL_ACCESS) wrapper for SeDebugPrivilege feeding the injection and credential-harvest paths, a FILE_FLAG_BACKUP_SEMANTICS file-copy path for SeBackup/SeRestore, and a DuplicateTokenEx-based impersonation path for SeImpersonatePrivilege. Routing the NT-level equivalents (NtAdjustPrivilegesToken, NtOpenProcessToken) through the existing indirect-syscall dispatcher would keep the sequence out of the IAT, consistent with the rest of the crowd crate.

## Why It Matters

The vault previously referenced SeDebugPrivilege only implicitly — through T-016's handle operations and T-023's LSASS dump — without documenting the token manipulation that makes those operations possible from an elevated-but-not-SYSTEM context. The AdjustTokenPrivileges + privilege-enablement chain is a standalone precondition layer: reusable across injection, credential access, and persistence scenarios, and independent of any specific evasion or exploitation primitive. As a dedicated card it captures the full SEC670 tradecraft block — privilege inventory, enablement, per-privilege weaponization, and token stealing — in one place rather than as scattered assumptions inside other cards.

## Detection Considerations

Training material does not discuss detection for this technique.

## Related Techniques

- **T-016 EDR Evasion Suite** — T-016 references SeDebugPrivilege implicitly through its handle operations (block external handles, remote NTDLL unhook); this card documents the privilege enablement that authorizes those cross-process handle acquisitions in the first place.
- **T-023 Client Capabilities Suite** — the LSASS dump capability (MiniDumpWriteDump with PROCESS_ALL_ACCESS) requires SeDebugPrivilege enabled in the calling token; the CMSTP UAC bypass produces the elevated token whose disabled privileges this technique then enables.

## References

- Atlas material: atlas-privesc-part3.md (units 5, 6, 12-14, 28, 32-40)
- MITRE ATT&CK: T1134 Access Token Manipulation (https://attack.mitre.org/techniques/T1134/); sub-techniques T1134.001 Token Impersonation/Theft (https://attack.mitre.org/techniques/T1134/001/) and T1134.002 Create Process with Token (https://attack.mitre.org/techniques/T1134/002/)
- LGTM notes: lgtm:token-privilege-abuse-proposed-technique
- Public references: SANS SEC670, "Red Teaming Tools: Developing Custom Tools for Windows," Book 3 — Operational Actions (privilege escalation module); Microsoft documentation for AdjustTokenPrivileges and SE_PRIVILEGE_* constants

## Source Reference

No current implementation as a dedicated module. The AdjustTokenPrivileges primitive appears in `dark_crystal/crowd/src/persist/phantom_restart.rs` (`enable_shutdown_privilege`, SeShutdownPrivilege for PhantomPersist). See atlas material for the SEC670 EnableDebug reference implementation and the MITRE reference for public tooling.