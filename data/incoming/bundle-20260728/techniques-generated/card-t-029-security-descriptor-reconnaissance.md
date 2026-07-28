---
id: T-029
name: Security Descriptor and SDDL Reconnaissance
category: discovery
tier: B
crate: none
source_file: none
mitre: T1007
mitre_secondary: [T1083, T1012]
tags: [sddl, security-descriptor, dacl, ace-parsing, sc-sdshow, getnamedsecurityinfo, service-recon, privesc-recon, se-restore-privilege]
origin: atlas-synthesis
member_notes: ['lgtm:proposed-technique-security-descriptor-reconnaissance']
---

# Security Descriptor and SDDL Reconnaissance — Weak-DACL Discovery for Privilege-Escalation Planning

## Summary

Security descriptor reconnaissance is the read-side workflow of retrieving, parsing, and evaluating DACLs on Windows securable objects — services, registry keys, NTFS files, shares, and file-mapping objects — to identify weak permissions that enable local privilege escalation. The material presents a structured tradecraft loop: `sc.exe sdshow` exposes a service's security descriptor as an SDDL string, manual ACE-string parsing decodes ace_type, ace_flags, rights constants, and SID abbreviations, and `GetNamedSecurityInfoA` generalizes descriptor retrieval across object classes by name. When a target object's DACL blocks access outright, the workflow falls back to the ACL-bypass privileges `SE_BACKUP_NAME` and `SE_RESTORE_NAME`, enabled programmatically through the standard token-adjustment API chain. The workflow is read-only and uses documented query interfaces; the training material does not document a detection surface for it.

## Mechanism

1. **Build the service target list.** Open the SCM database with `OpenSCManager` and enumerate services with `EnumServicesStatus`, optionally calling `QueryServiceStatus` per service. The material frames this enumeration as standard on-target recon whose purpose is surfacing LPE vectors — unquoted paths and weak-permission services.

2. **Retrieve the service security descriptor.** From a shell, run `sc.exe sdshow <service>` (the material uses BITS as the example). Programmatically, call `GetNamedSecurityInfoA`:
   ```
   DWORD GetNamedSecurityInfoA(
       LPCSTR pObjectName,
       SE_OBJECT_TYPE ObjectType,
       SECURITY_INFORMATION SecInfo,
       PSID *ppsidOwner, PSID *ppsidGroup,
       PACL *ppDacl, PACL *ppSacl,
       PSECURITY_DESCRIPTOR *pSecDscrptr );
   ```
   `ObjectType` selects the object class: NTFS objects, services, registry keys, shares, and file-mapping objects are all named in the material as valid targets. `SecInfo` selects which descriptor components to return (owner SID, group SID, DACL, SACL).

3. **Split the SDDL string into sections.** The descriptor serializes as `O:<owner>G:<group>D:<dacl>S:<sacl>`. The DACL section is a parenthesized sequence of ACE strings, each with six semicolon-separated fields: `(ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid)`.

4. **Decode ace_type and ace_flags.** Per the material's ACE string layout: ace_type `A` (access allowed), `D` (access denied), `OA`/`OD` (object allowed/denied), `AU` (audit), `AL` (alarm). ace_flags: `CI` container inherit, `OI` object inherit, `NP` no propagate, `IO` inherit only, `ID` inherited, `SA` audit success.

5. **Decode the rights field against the object's class.** Rights constants are object-class-dependent. The material lists generic rights (`GA` all, `GR` read, `GW` write, `GX` execute), standard rights (`RC` read control, `SD` standard delete, `WD` write DAC, `WO` write owner), directory rights (`RP`, `WP`, `CC`, `DC`, `LC`, `SW`), registry rights (`KA` all, `KR` read, `KW` write, `KX` execute), and file rights (`FA` all, `FR` read). Service objects use the service-specific set documented by Microsoft (`CC` query config, `DC` change config, `LC` query status, `SW` enumerate dependents, `RP` start, `WP` stop, `DT` pause/continue, `LO` interrogate, `CR` user-defined control), which matches the service ACE strings in the material's SDDL exercise.

6. **Decode the account_sid field.** Two-letter abbreviations stand in for well-known SIDs: the material's exercise uses `IU` (interactive user), `SU` (service user), `BA` (built-in administrators), and `SY` (local system). Unrecognized SIDs are resolved to account names for operator readability.

7. **Evaluate the parsed DACL against the current token.** The operator looks for ACEs granting a principal they control — directly or via group membership — any write-class right on a high-privilege object: `WD` (rewrite the DACL), `WO` (take ownership, then rewrite), `DC`/`RP`/`WP` on a service running as SYSTEM (reconfigure `binPath` and restart), `KW` on an autostart registry key, or `FA`/`GW` on a binary or DLL loaded by a privileged process. The material's exercise DACL — `(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)` — is the lockdown baseline: deny change-config/stop/pause/delete to interactive users, service users, and admins, allow read-type rights only, reserve start/stop/write for SYSTEM. Any deviation from this pattern on a privileged service is the finding.

8. **Fall back to backup/restore privileges when the DACL blocks access.** The material poses the review question "what privilege gives complete write access regardless of the ACL?" with options `SE_BACKUP_NAME`, `SE_RESTORE_NAME`, `SE_WRITE_NAME`. Per Windows documentation, `SE_RESTORE_NAME` (SeRestorePrivilege) grants write access to any object regardless of its DACL, while `SE_BACKUP_NAME` (SeBackupPrivilege) grants the equivalent read access. If present-but-disabled in the token, enable them via `LookupPrivilegeValue` → `OpenProcessToken` → `AdjustTokenPrivileges`, the three-API chain the material documents for programmatic privilege adjustment, then retry the access with backup semantics.

## OS Internals Context

A self-relative `SECURITY_DESCRIPTOR` is a 20-byte header — Revision (0x01), Sbz1, Control flags (`SE_DACL_PRESENT` 0x0004, `SE_SELF_RELATIVE` 0x8000) — followed by four 32-bit offsets to the Owner SID, Group SID, SACL, and DACL. An `ACL` begins with an 8-byte header (AclRevision 0x02, AclSize, AceCount) followed by variable-length ACEs: a 4-byte `ACE_HEADER` (AceType, AceFlags, AceSize), a 4-byte `ACCESS_MASK`, then the trustee SID (Revision, SubAuthorityCount, 6-byte big-endian IdentifierAuthority, SubAuthority array). SDDL is a text serialization of exactly this binary layout, which is why the two-letter constants map one-to-one onto ACCESS_MASK bits.

The `ACCESS_MASK` partitions into object-specific rights (bits 0–15), standard rights (bits 16–23: `DELETE` 0x00010000, `READ_CONTROL` 0x00020000, `WRITE_DAC` 0x00040000, `WRITE_OWNER` 0x00080000), and generic rights (bits 28–31) that the object manager maps to class-specific rights at access time. The SDDL rights field is therefore only interpretable in the context of the object class — `CC` means create-child on a directory object but query-config on a service.

On the enforcement side, the kernel evaluates these descriptors in `SeAccessCheck` during object open (`ObpLookupObjectName` for named objects), comparing the requestor's token against the DACL in canonical order — deny ACEs before allow ACEs — with the object owner implicitly holding `READ_CONTROL` and `WRITE_DAC`. Service objects are special-cased: the SCM maintains each service's security descriptor, persisted under `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Security`, and enforces it on `OpenService` / `ChangeServiceConfig` calls. This is why `sc.exe sdshow` output is authoritative for what a remote or local caller may do to a service. Reading a SACL requires `ACCESS_SYSTEM_SECURITY`, which in turn requires SeSecurityPrivilege in the caller's token.

The backup/restore privileges bypass this check at the object manager and filesystem level: SeBackupPrivilege causes the access check to grant read regardless of the DACL (with `FILE_FLAG_BACKUP_SEMANTICS` on file objects), and SeRestorePrivilege grants write — including `WRITE_DAC` and `WRITE_OWNER`, which is what makes it the answer to the material's "complete write access regardless of the ACL" question. Both privileges are normally held by administrators and backup operators but ship disabled, requiring the `AdjustTokenPrivileges` enable step before use.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation. See the atlas material for reference implementations in C (Win32 API) and `sc.exe`/PowerShell command-line usage.

An implementation would be a small read-only module: a resolver for `GetNamedSecurityInfoA` (or `QueryServiceObjectSecurity` as the SCM-specific path, which is what `sc.exe sdshow` wraps), a request of `OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION` per target, and either `ConvertSecurityDescriptorToStringSecurityDescriptorA` to obtain SDDL text or a manual `GetAce` walk with `LookupAccountSidA` for structured output. A token-privilege pre-check via `GetTokenInformation(TokenPrivileges)` gates the `AdjustTokenPrivileges` enable call for `SE_BACKUP_NAME`/`SE_RESTORE_NAME`. The crowd codebase already contains the write-side counterpart: `crowd/src/block_handle.rs` (mapped to T-016) manually constructs a self-relative `SECURITY_DESCRIPTOR` with deny-Everyone/allow-SYSTEM ACEs and applies it via `NtSetSecurityObject`. Its byte-level layout comments (20-byte header, 8-byte ACL header, ACE = header + mask + SID) describe precisely the structure a reconnaissance parser must walk in reverse.

## Why It Matters

The vault documents the write side of security descriptors (T-016's handle-blocking via `NtSetSecurityObject`) and service abuse only as an exploitation outcome, but no card documents how an operator systematically answers "which securable objects can my current token modify?" This card fills that gap between service enumeration — which finds services — and exploitation, which modifies them, by defining the retrieval API surface (`sc.exe sdshow`, `GetNamedSecurityInfoA`), the SDDL grammar needed to interpret results without third-party tooling, and the backup/restore privilege fallback for DACLs that deny access. It converts ACL assessment from ad-hoc tooling (AccessChk, SharpUp) into a portable implant capability.

## Detection Considerations

Training material does not discuss detection for this technique.

## Related Techniques

- **T-023 Client Capabilities Suite** — T-023 covers client-side reconnaissance (Byakugan network scanning, sysinfo collection, credential harvest); T-029 extends that reconnaissance into the authorization-metadata plane, producing the weak-DACL target list that privilege-escalation and harvest modules act on.

## References

- Atlas material: atlas-privesc-part2.md (units 28–30, 35–40; privilege-adjustment API chain in units 1–7; SCM/service enumeration context in units 12–16)
- MITRE ATT&CK: T1007 System Service Discovery (https://attack.mitre.org/techniques/T1007/); secondary: T1083 File and Directory Discovery, T1012 Query Registry
- LGTM notes: lgtm:proposed-technique-security-descriptor-reconnaissance
- Public references: SANS SEC670 *Red Teaming Tools: Developing Custom Tools for Windows* (source document cited throughout atlas-privesc-part2.md)

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling (`sc.exe sdshow`, `GetNamedSecurityInfoA`). The write-side counterpart exists in `dark_crystal/crowd/src/block_handle.rs` under T-016.