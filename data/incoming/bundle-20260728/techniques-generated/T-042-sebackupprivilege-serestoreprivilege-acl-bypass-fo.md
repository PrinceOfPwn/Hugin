---
id: T-042
name: 'SeBackupPrivilege / SeRestorePrivilege: ACL Bypass for File Access'
category: privesc
tier: S
crate: none
source_file: none
mitre: T1134
mitre_secondary: [T1003.002]
tags: [acl-bypass, sebackup-privilege, serestore-privilege, token-privileges, adjusttokenprivileges, file-system, dacl-bypass, lpe, credential-access]
origin: atlas-synthesis
member_notes: ['lgtm:proposed-acl-bypass-privilege-card']
---

# SeBackupPrivilege / SeRestorePrivilege ACL Bypass — Unrestricted File Read and Write Regardless of DACL

## Summary

SeBackupPrivilege (`SE_BACKUP_NAME`) and SeRestorePrivilege (`SE_RESTORE_NAME`) are the only two Windows privileges that bypass the standard access check entirely: a token holding SeBackupPrivilege is granted complete read access to a file regardless of its ACL, and a token holding SeRestorePrivilege is granted complete write access regardless of its ACL. SEC670 states the exception directly — most privileges allow an operation only after the system performs a check, but these two bypass that check. The privileges live in the process access token as `LUID_AND_ATTRIBUTES` entries, ship Disabled in most tokens that carry them, and are enabled on demand through the OpenProcessToken → LookupPrivilegeValue → AdjustTokenPrivileges chain against the caller's own token. Operators use them in the post-exploitation phase to read otherwise-inaccessible objects — SAM and SYSTEM registry hives, NTDS.dit, DPAPI keys, restricted user files — and to write into ACL-protected locations. Unlike ACL editing or ownership takeover, the bypass modifies nothing on the target object's security descriptor; only the caller's token changes state.

## Mechanism

1. Confirm the privileges are present in the current token. The material contrasts `whoami /priv` output across integrity levels: a standard (Medium-IL) user holds almost nothing — only SeChangeNotify enabled — while a High-IL process shows a large set of privileges present but Disabled, including SeBackupPrivilege and SeRestorePrivilege, which "can be enabled on the fly on an as needed basis" (units 35, 36). If the privilege is absent from the token entirely, no user-mode call can add it.

2. Obtain a handle to the caller's own access token with `OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)`. Unit 21 gives the contract: the function returns a Boolean, and "you cannot change any privileges in a token without having a handle to it."

3. Resolve each privilege name to its locally assigned LUID with `LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luid)` and `LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &luid)`. `SE_BACKUP_NAME` and `SE_RESTORE_NAME` are string constants declared in winnt.h, which the material points to for additional privilege constants (units 5, 20, 37, 38).

4. Populate a `TOKEN_PRIVILEGES` structure with one `LUID_AND_ATTRIBUTES` entry per privilege: `Luid` set to the resolved LUID and `Attributes` set to `SE_PRIVILEGE_ENABLED`. Unit 30 defines the attribute family: ENABLED (privilege is present and set), ENABLED_BY_DEFAULT, REMOVED (for removing privileges), and USED_FOR_ACCESS (used to obtain access to a service or object).

5. Call `AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL)` — the function unit 1 calls "the last and final step" of the enable sequence. `DisableAllPrivileges` is FALSE so only the listed privileges are touched. The signature also accepts `PreviousState` and `ReturnLength` out-parameters, which capture the prior attribute state for later reversion. Per MSDN, `GetLastError()` returns `ERROR_NOT_ALL_ASSIGNED` when the token does not hold every requested privilege, which is the check that distinguishes "absent from token" from a general failure.

6. Open the protected object with the access class the enabled privilege covers. Per unit 37, these privileges trump the standard check for `FILE_GENERIC_READ` and `FILE_GENERIC_WRITE`: with SeBackupPrivilege enabled, a read open succeeds against any file ACL; with SeRestorePrivilege enabled, a write open succeeds against any file ACL. Unit 12 poses the same fact as a review question — the privilege granting complete write access regardless of the ACL is `SE_RESTORE_PRIVILEGE`.

7. Consume the access: copy the SAM and SYSTEM hives from `%SystemRoot%\System32\config`, read NTDS.dit on a domain controller, read DPAPI master key material or another user's files, or write into an ACL-protected destination. No `SetSecurityInfo`, no ownership change, no DACL rewrite occurs on the object.

8. Revert the token by calling `AdjustTokenPrivileges` again with the captured `PreviousState`, or by setting `Attributes` to 0 / `SE_PRIVILEGE_REMOVED`, returning the privileges to their prior Disabled state (units 1, 30).

## OS Internals Context

The access token stores privileges as an array of `LUID_AND_ATTRIBUTES` inside `TOKEN_PRIVILEGES` (units 30, 32). The LUID is a locally unique identifier assigned per system, which is why `LookupPrivilegeValue` must translate the winnt.h string constant into the local LUID before use. The `Attributes` DWORD is a bitmask from the `SE_PRIVILEGE_*` family; the material distinguishes the two states that matter operationally — Enabled means the privilege is present and set in the token, Disabled means present but not set, and a Disabled privilege "could be enabled" (unit 26). `SE_PRIVILEGE_REMOVED` strips a privilege from the token outright.

The central internal fact is the two-privilege exception the material documents verbatim: most privileges allow the caller to perform an operation but only after the system performs its check, whereas SeBackupPrivilege and SeRestorePrivilege bypass that check (units 5, 20). Unit 37 ties the bypass to the specific access masks that would otherwise gate the operation — `FILE_GENERIC_READ` for SeBackupPrivilege and `FILE_GENERIC_WRITE` for SeRestorePrivilege — meaning the DACL evaluation against the requested mask is short-circuited when the corresponding privilege is enabled. The material does not name the open-time mechanism that presents this intent to the kernel; per MSDN, the user-mode-realizable form is opening the file with backup intent (`CreateFile` with `FILE_FLAG_BACKUP_SEMANTICS`), at which point the access check consults the token's privilege array for the backup/restore privilege rather than walking the object's DACL. The privilege-level behavior the material describes and this open path are the same check site.

The enable operation is entirely user-mode and self-directed: the caller adjusts its own primary token, requiring no cross-process handle and no SeDebugPrivilege. `AdjustTokenPrivileges` can only flip attributes on privileges already present in the token — it cannot grant privileges the account does not hold, which is why the standard-user `whoami /priv` output in unit 35 shows almost nothing while the High-IL output in unit 36 shows the privileges present but Disabled. The bypass itself is enforced kernel-side at object open: the kernel sees an ordinary file-open request whose access check returns success because of a token privilege, not because of handle tricks, injection, or descriptor tampering.

Integrity-level placement determines where the privileges are available. The material enumerates six integrity levels — Untrusted (0), Low (1), Medium (2) for typical UAC-on processes, High (3) for UAC-elevated processes, System (4) for services such as wininit, winlogon, and lsass, and Protected (5) set only by kernel-mode callers (units 3, 19). SeBackupPrivilege and SeRestorePrivilege appear in High-IL administrator tokens, in System-level service tokens, and per the cluster description in Backup Operators group members — accounts an implant commonly already runs as after initial elevation.

The material situates these two privileges among siblings used for Admin→SYSTEM movement: SeTakeOwnershipPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, and SeDebugPrivilege (units 39, 40). The distinction that matters is mechanical — SeTakeOwnershipPrivilege works by changing the object's owner so a subsequent DACL edit can succeed, a two-step write to the target's security descriptor, while SeBackupPrivilege and SeRestorePrivilege never touch the object at all.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C (SEC670 Win32 API walkthroughs, units 1, 6, 21).

Three Rust files were provided with this request and verified against the technique: `src/client_rust/src/browser_hook.rs` implements MV3 browser extension sideloading, `src/client_rust/src/commands.rs` implements the client command dispatcher, and `src/dark_crystal/crates/core/src/experimental/iat_camouflage.rs` implements IAT camouflage profiles. None of them call `OpenProcessToken`, `LookupPrivilegeValue`, or `AdjustTokenPrivileges`, and none open files with backup semantics. No file in the vault manifest maps to token-privilege manipulation.

An implementation would follow the crate's existing `wrappers.rs` pattern — FFI bindings via `windows_targets::link!` against advapi32 for `OpenProcessToken`, `LookupPrivilegeValueW`, and `AdjustTokenPrivileges` — plus a `TOKEN_PRIVILEGES` buffer holding two `LUID_AND_ATTRIBUTES` entries with `SE_PRIVILEGE_ENABLED`, an enable/disable pair that captures `PreviousState` for clean reversion, and a read path issuing `CreateFileW` with `FILE_FLAG_BACKUP_SEMANTICS` (MSDN) to stream protected files such as the SAM/SYSTEM hives, NTDS.dit, and DPAPI master keys into the exfil channel, with a symmetric write path for the restore side. The module would sit behind a Cargo feature gate consistent with the crate's minimal-footprint build model.

## Why It Matters

The vault has no card covering file-ACL bypass, and these are the only two privileges that skip the access check outright rather than satisfying it, which makes this a distinct primitive rather than a variant of ACL editing, ownership takeover, or token theft. It fills the post-exploitation file-access gap — reading SAM/SYSTEM hives, NTDS.dit, DPAPI keys, and restricted user files, and writing to ACL-protected locations — without modifying the target object's security descriptor, so no DACL or ownership artifacts are left on the object. Because the privileges ride in High-IL admin, SYSTEM service, and Backup Operators tokens that implants commonly already hold, the activation cost is three Win32 calls against the caller's own token with no injection and no cross-process handles.

## Detection Considerations

Training material does not discuss detection for this technique. The material documents the enabling API sequence (OpenProcessToken → LookupPrivilegeValue → AdjustTokenPrivileges; units 1, 6, 21) and the resulting access behavior, but names no ETW providers, Sysmon event IDs, kernel callbacks, memory-scan heuristics, or residual-artifact guidance.

## Related Techniques

None. The cluster spec assigns an empty `would_relate_to` list and the member note marks this technique as new territory for the vault; no existing T-NNN card provided with this request covers adjacent ground (token manipulation, ACL editing, or credential-store file access) closely enough to cross-reference.

## References

- Atlas material: atlas-privesc-part1.md (units 1, 3, 5, 6, 12, 19, 20, 21, 26, 30, 32, 35–40)
- MITRE ATT&CK: T1134 Access Token Manipulation — https://attack.mitre.org/techniques/T1134/ ; T1003.002 OS Credential Dumping: Security Account Manager — https://attack.mitre.org/techniques/T1003/002/
- LGTM notes: lgtm:proposed-acl-bypass-privilege-card
- Public references: MSDN privilege constants in winnt.h (`SE_BACKUP_NAME`, `SE_RESTORE_NAME`), cited by the material (units 5, 20, 37); MSDN documentation for `AdjustTokenPrivileges` and `OpenProcessToken` (units 1, 21). No external tools or blog posts are named in the material.

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling. The three Rust files provided with this request (`src/client_rust/src/browser_hook.rs`, `src/client_rust/src/commands.rs`, `src/dark_crystal/crates/core/src/experimental/iat_camouflage.rs`) were reviewed and do not implement this technique.