---
id: T-068
name: SDDL/ACL Hardening for Persistence Resilience
category: persistence
tier: B
crate: none
source_file: none
mitre: T1222.001
mitre_secondary: [T1543.003]
tags: [sddl, acl-hardening, security-descriptor, dacl, deny-ace, persistence-resilience, anti-remediation, setnamedsecurityinfo]
origin: atlas-synthesis
member_notes: [lgtm:sddl-acl-manipulation-proposed, lgtm:security-descriptor-acl-hardening]
---

# SDDL/ACL Hardening for Persistence Resilience — Deny ACEs Against Remediation

## Summary

SDDL/ACL hardening modifies the discretionary access control lists on objects that host persistence — services, registry keys, NTFS files — so that defender accounts cannot stop, delete, or reconfigure them. The operator retrieves the object's current security descriptor with `GetNamedSecurityInfoA`, composes a replacement DACL containing deny ACEs built from `EXPLICIT_ACCESS_A` structures, and writes it back with `SetNamedSecurityInfoA`. The result is a persistence entry whose removal demands ownership takeover and DACL rewriting rather than a simple `sc stop` / `sc delete` or `RegDeleteKey`. The technique hardens existing persistence rather than creating new persistence, and its detection surface is object-access auditing plus the anomalous end state itself — a service that returns access denied to a SYSTEM stop request is inherently suspicious.

## Mechanism

1. A persistence object is installed through any primary method — service creation (T-036), a registry autostart value, or a dropped binary. The hardening pass runs afterward against that object.
2. `GetNamedSecurityInfoA(objectName, objectType, DACL_SECURITY_INFORMATION, ...)` retrieves the object's current DACL. The `objectType` parameter (`SE_OBJECT_TYPE`) selects the object class: `SE_SERVICE` for Service Control Manager objects, `SE_REGISTRY_KEY` for hive keys, `SE_FILE_OBJECT` for NTFS paths; the training material notes the same API pair reaches shares and file-mapping objects.
3. The descriptor is optionally rendered to SDDL with `ConvertSecurityDescriptorToStringSecurityDescriptorA` for inspection. The SDDL ACE field decomposition — ace type, ace flags, rights, object GUID, inherited-object GUID, account SID — provides the manipulation vocabulary.
4. Replacement ACEs are built as `EXPLICIT_ACCESS_A` entries: `grfAccessMode = DENY_ACCESS`; `grfAccessPermissions` set to the remediation-critical rights — `SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE | WRITE_DAC` for a service, `DELETE | WRITE_DAC` with key-specific rights for a registry key; the `Trustee` bound to well-known SIDs (`WinBuiltinAdministratorsSid`, `WinLocalSystemSid`) via `BuildTrusteeWithSidA`.
5. `SetEntriesInAclA` merges the new entries with the retained allow ACEs into a new ACL, applying canonical ordering with deny ACEs ahead of allow ACEs.
6. `SetNamedSecurityInfoA` with `DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION` writes the DACL and severs inheritance, preventing parent-container ACEs from re-granting the denied rights.
7. Verification round-trips the descriptor: `sc.exe sdshow <service>` for services, or a second `ConvertSecurityDescriptorToStringSecurityDescriptorA` call, confirms the deny ACEs are in place.

## OS Internals Context

A Windows `SECURITY_DESCRIPTOR` consists of a header, an owner SID, a group SID, a SACL, and a DACL. The DACL is an ordered list of access control entries; the two entry types relevant here are `ACCESS_ALLOWED_ACE` (type 0x0) and `ACCESS_DENIED_ACE` (type 0x1). During an access check, `SeAccessCheck` in the kernel (mirrored by user-mode `AccessCheck`) walks the DACL and evaluates entries in order: a matching deny ACE that intersects the requested access mask terminates evaluation immediately with `STATUS_ACCESS_DENIED`. This short-circuit is why canonical ordering — deny before allow — is the load-bearing property, and why the high-level `SetEntriesInAclA`/`SetNamedSecurityInfoA` path, which normalizes order, is preferred over hand-assembled ACL writes.

Service objects expose their DACLs through the SCM with a service-specific SDDL rights vocabulary used by `sc sdshow` and `sc sdset`: `CC` (SERVICE_QUERY_CONFIG), `DC` (SERVICE_CHANGE_CONFIG), `LC` (SERVICE_QUERY_STATUS), `SW` (SERVICE_ENUMERATE_DEPENDENTS), `RP` (SERVICE_START), `WP` (SERVICE_STOP), `DT` (SERVICE_PAUSE_CONTINUE), `LO` (SERVICE_INTERROGATE), `CR` (SERVICE_USER_DEFINED_CONTROL), alongside the standard rights `SD` (DELETE), `RC` (READ_CONTROL), `WD` (WRITE_DAC), and `WO` (WRITE_OWNER). A deny ACE blocking stop, delete, reconfigure, and DACL-write for SYSTEM and Administrators takes the representative form `D:(D;;WPSDDCWD;;;SY)(D;;WPSDDCWD;;;BA)` prepended ahead of the allow ACEs. After such a write, `sc stop` and `sc delete` fail with `ERROR_ACCESS_DENIED` even from an elevated SYSTEM shell.

The lock is not absolute, and the reason is documented Windows behavior: an object's owner implicitly retains `READ_CONTROL` and `WRITE_DAC` regardless of DACL contents. Deny ACEs cannot strip the owner's ability to rewrite the DACL. A defender holding `SeTakeOwnershipPrivilege` — granted to administrators by default — can call `SetNamedSecurityInfoA` with `OWNER_SECURITY_INFORMATION` to seize ownership, then replace the DACL outright. Hardening therefore raises remediation cost, forces additional attacker-visible steps, and generates extra telemetry, rather than producing an unremovable object.

The abstraction that makes one technique cover many persistence types is `SE_OBJECT_TYPE`. The same `GetNamedSecurityInfoA`/`SetNamedSecurityInfoA` pair, with a different enumeration constant, reaches service objects in the SCM database (`services.exe`), registry keys in the hives, NTFS files and directories, network shares, and named kernel objects such as file mappings. One code path hardens every persistence layer the vault documents.

`EXPLICIT_ACCESS_A` is the composition structure throughout: `grfAccessPermissions` carries the mask, `grfAccessMode` selects `GRANT_ACCESS`, `DENY_ACCESS`, `SET_ACCESS`, or `REVOKE_ACCESS`, `grfInheritance` controls propagation to child objects (relevant for registry keys and directories), and the embedded `TRUSTEE_A` identifies the SID or name the ACE governs.

## Key Implementation Details

**No current implementation in the HUGIN source.** This card documents the technique for future implementation.

The codebase contains one SDDL-adjacent capability that must not be confused with this technique: `block_handle.rs` (manifest role: "Block external handle access"; the `payload_cfg.rs` comment describes "BlockHandle SDDL — restrict handle access via security descriptor") applies a restrictive security descriptor to the operator's own process to block external handle access — an EDR-evasion mechanism in the T-016 suite, not persistence hardening. A T-068 implementation would be a `persist/acl_harden.rs` module using `windows-sys::Win32::Security` (`GetNamedSecurityInfoA`, `SetEntriesInAclA`, `SetNamedSecurityInfoA`, `EXPLICIT_ACCESS_A`, `BuildTrusteeWithSidA`), invoked as a post-install step after each persistence layer, parameterized by object name and `SE_OBJECT_TYPE`.

## Why It Matters

Every persistence layer in the vault is removable by a one-line defender command; this technique converts disposable entries into resilient ones by moving the cost of removal from a delete operation to an ownership-takeover-plus-DACL-rewrite sequence. It is method-agnostic — the same call sequence hardens a service, a run key, or a dropped DLL — so it composes with any T-017 layer without coupling to that layer's install logic. The SDDL parsing literacy it requires also feeds directly into reconnaissance of defender-side hardening (T-029).

## Detection Considerations

- **Telemetry sources**: Windows does not log DACL changes by default; visibility requires SACL-based auditing. Security Event ID 4670 ("Permissions on an object were changed") fires when a SACL is present on the hardened object, and Event ID 4663 records the denied access attempts that follow. Denied service-control operations surface in SCM error events. Sysmon does not natively capture DACL modification; its Event ID 13 covers the persistence install's registry writes but not the ACL pass.
- **Bypass options**: restricting deny ACEs to specific remediation tooling SIDs rather than SYSTEM and Administrators broadly produces a subtler descriptor; leaving `WP` (stop) allowed while denying `SD`/`DC` (delete/reconfigure) lets the service appear stoppable while resisting removal.
- **Residual artifacts**: the DACL itself is durable — it survives payload deletion and reboot, and a service or key whose SDDL shows deny ACEs against SY/BA (visible via `sc sdshow` or `Get-Acl`) is a standing indicator. The anomalous state is self-incriminating: a service that returns access denied to a SYSTEM stop request draws analyst attention.

The atlas material for this technique does not discuss detection; the sources above reflect standard Windows auditing behavior.

## Related Techniques

- **T-017 Five-Layer Persistence** — the hardening pass applies as a post-install step to any of the five layers, converting them from removable to remediation-resistant.
- **T-036 Service-Based Persistence** — services are the primary hardening target documented in the material, with deny ACEs against `SERVICE_STOP`, `SERVICE_CHANGE_CONFIG`, and `DELETE`.
- **T-029 Security Descriptor and SDDL Reconnaissance** — the inspection counterpart: SDDL parsing and descriptor retrieval used defensively-offensively to audit objects rather than harden them.

## References

- Atlas material: atlas-exploit-dev-part10.md (units 19, 20), atlas-exploit-dev-part19.md (units 20, 21, 22)
- MITRE ATT&CK: [T1222.001 — File and Directory Permissions Modification: Windows File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/001/)
- LGTM notes: lgtm:sddl-acl-manipulation-proposed, lgtm:security-descriptor-acl-hardening

## Source Reference

No current implementation. See atlas material and MITRE reference for public tooling.