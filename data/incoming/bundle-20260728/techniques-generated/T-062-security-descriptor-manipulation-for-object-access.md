---
id: T-062
name: Security Descriptor Manipulation for Object Access Control
category: edr-evasion
tier: B
crate: none
source_file: none
mitre: T1222
tags: [sddl, security-descriptor, dacl, null-sid, ace, setnamedsecurityinfo, access-control, object-loosening]
origin: atlas-synthesis
member_notes: [lgtm:sddl-security-descriptor-manipulation]
---

# Security Descriptor Manipulation for Object Access Control — SDDL-Driven DACL Loosening

## Summary

Security descriptor manipulation rewrites the DACL on Windows securable objects — files, services, named pipes, kernel objects — to grant access that the object's original access-control policy denied. The SEC670 material walks through constructing an SDDL string that grants GENERIC_ALL to the NULL SID (S-1-0-0), demonstrating the primitive of loosening an object's DACL so that anonymous or low-privilege access succeeds against a protected object. The technique is the inverse of handle blocking: rather than restricting access to the implant's own objects, it strips access-control barriers from objects the implant needs to reach. Conversion from SDDL text to a binary security descriptor via ConvertStringSecurityDescriptorToSecurityDescriptor, followed by application through SetNamedSecurityInfo or SetSecurityInfo, is the documented entry point. Detection surfaces are permission-change auditing and post-hoc DACL review.

## Mechanism

1. Identify the target object and its object type: a file path (SE_FILE_OBJECT), a service name (SE_SERVICE), a named pipe or other named kernel object (SE_KERNEL_OBJECT). The type determines which SetNamedSecurityInfo object-type constant applies.
2. Construct the SDDL string encoding the desired DACL. The material's Example #1 builds a DACL containing a single ACCESS_ALLOWED ACE granting GENERIC_ALL to S-1-0-0: in SDDL syntax, `D:(A;;GA;;;S-1-0-0)`, where `D:` introduces the DACL, `A` marks an access-allowed ACE, `GA` is the GENERIC_ALL rights alias, and S-1-0-0 is the NULL SID.
3. Convert the SDDL text into a self-relative PSECURITY_DESCRIPTOR with ConvertStringSecurityDescriptorToSecurityDescriptorW. The returned buffer is LocalAlloc-owned and freed with LocalFree.
4. Apply the descriptor with SetNamedSecurityInfoW, passing the object name, the object type, DACL_SECURITY_INFORMATION in the SecurityInfo mask, and the converted descriptor as the new DACL. For an already-open handle, SetSecurityInfo performs the same operation without reopening the object.
5. For services specifically, this is the programmatic equivalent of `sc.exe sdset <service> <SDDL>`; the SCM stores the descriptor and enforces it on subsequent OpenService access checks.
6. Verify by reopening the object from the low-privilege context that was previously denied, or by reading the descriptor back with GetNamedSecurityInfo and confirming the ACE landed.
7. Alternatively, bypass the SDDL layer entirely: build the SECURITY_DESCRIPTOR, ACL, ACE, and SID structures manually in a byte buffer and apply with NtSetSecurityObject — the pattern already used elsewhere in the vault for the inverse operation.

## OS Internals Context

A self-relative security descriptor is a contiguous buffer: a SECURITY_DESCRIPTOR header (Revision, Control, and four offsets to Owner, Group, Sacl, and Dacl), followed by the referenced structures. The Dacl offset points to an ACL — an 8-byte header (AclRevision, AclSize, AceCount) followed by ACEs. Each ACCESS_ALLOWED_ACE is an ACE_HEADER (AceType 0x00, AceFlags, AceSize), a 4-byte ACCESS_MASK, and a variable-length SID. GENERIC_ALL (0x10000000) is a generic right that the access check expands through the object type's GENERIC_MAPPING table into the type's specific rights — for a service, SERVICE_ALL_ACCESS; for a file, FILE_ALL_ACCESS.

The access check (AccessCheck in user mode, SeAccessCheck in the kernel) walks the DACL in order, comparing each ACE's SID against the SIDs present in the caller's access token and accumulating granted rights on match. S-1-0-0 is the NULL SID: authority SECURITY_NULL_SID_AUTHORITY (0), RID 0, conventionally the "Nobody" identifier. The SEC670 example uses it as the grantee to demonstrate the anonymous-access construction, illustrating that the operator controls the full ACE tuple — type, rights, and trustee — with nothing more than a text string.

The right to rewrite a DACL is itself access-controlled: the caller needs WRITE_DAC against the object, which owners hold implicitly (READ_CONTROL and WRITE_DAC are granted to owners via the owner-lookup path), and modifying the SACL additionally demands SE_SECURITY_NAME. For service objects, the descriptor lives in the SCM's database; for kernel objects such as named pipes, it is attached to the object in the Object Manager namespace and persists until the object is destroyed — a transient weakening that vanishes on reboot for pipes but survives for services and files.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The vault contains the inverse primitive, verified in dark_crystal/crowd/src/block_handle.rs: block_external_handles() hand-builds a self-relative SECURITY_DESCRIPTOR in a byte buffer — Revision 1, Control 0x8004 (SE_SELF_RELATIVE | SE_DACL_PRESENT), a Dacl offset of 20, then an ACL with a DENY Everyone (S-1-1-0) ACE followed by an ALLOW SYSTEM (S-1-5-18) ACE, each carrying PROCESS_ALL_ACCESS — and applies it to a child-process handle through NtSetSecurityObject dispatched via RecycledGate. A loosening implementation would reuse that buffer-construction skeleton verbatim, substituting an ACCESS_ALLOWED ACE whose SID and mask grant the required access, and would target the external object (service, pipe, file) rather than the implant's own process handle.

## Why It Matters

Handle blocking (T-016) hardens the implant; descriptor loosening opens the target. Named pipes hardened against non-admin callers, services whose DACLs block SERVICE_START or SERVICE_CHANGE_CONFIG for the current user, and files ACL'd to SYSTEM-only all become reachable once their DACLs are rewritten. Because the change is an access-control edit rather than a payload, it leaves no code artifacts — the object simply becomes usable, which makes the technique composable with any follow-on capability that needs the object open.

## Detection Considerations

- **Telemetry sources**: Windows Security event 4670 (Permissions changed) fires only when a SACL with audit policy is present on the target object — absent on most objects by default. EDR products that snapshot service DACLs or monitor SCM descriptor writes alert on SE_SERVICE changes; sc.exe sdset equivalence makes service-descriptor edits a known-hunted behavior.
- **Bypass options**: Applying the descriptor via NtSetSecurityObject skips advapi32 and any user-mode hooks on SetNamedSecurityInfo. Targeting transient kernel objects (pipes) leaves no durable artifact after reboot.
- **Residual artifacts**: The modified DACL itself is the artifact. Get-Acl, AccessChk, and sc.exe sdshow reveal it immediately, and a DACL granting broad rights to an unusual trustee on a hardened object is a high-signal forensic find.

## Related Techniques

- **T-016 EDR Evasion Suite** — Block External Handles applies identical SDDL and security-descriptor mechanics in the inverse direction, restricting access to the implant rather than loosening access to target objects.

## References

- Atlas material: atlas-methodology-part7.md
- MITRE ATT&CK: T1222 (https://attack.mitre.org/techniques/T1222/)
- LGTM notes: lgtm:sddl-security-descriptor-manipulation

## Source Reference

No current implementation. Adjacent verified pattern: dark_crystal/crowd/src/block_handle.rs (manual self-relative SECURITY_DESCRIPTOR construction and NtSetSecurityObject application — the inverse, restrictive direction of this primitive).