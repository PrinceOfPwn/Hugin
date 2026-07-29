---
id: T-113
name: Service Hiding via SDDL DACL Security Descriptor Tampering
category: persistence
tier: A
crate: none
source_file: none
mitre: T1564
mitre_secondary: [T1222]
tags: [persistence, sddl, security-descriptor, dacl, service-hiding, enumeration-evasion, sc-exe, setnamedsecurityinfo]
origin: atlas-synthesis
member_notes: ['lgtm:sddl-security-descriptor-tampering', 'lgtm:programmatically-hidden-service']
---

# Service Hiding via SDDL DACL Security Descriptor Tampering — Enumeration Evasion via Security Descriptor Modification

## Summary

SDDL (Security Descriptor Definition Language) string manipulation on service objects denies enumeration rights to common SIDs, causing the service to be invisible to sc query, services.msc, Get-Service, and other standard enumeration tools. Using sc.exe sdset or SetNamedSecurityInfo with DACL_SECURITY_INFORMATION, an operator denies SERVICE_QUERY_STATUS and SERVICE_ENUMERATE_DEPENDENTS to Everyone or INTERACTIVE while retaining SERVICE_START in a separate ACE for their own access. The service remains startable and persists across reboots, but is invisible to standard enumeration. This is a persistence resilience measure layered on top of service-based persistence (CreateService), not a standalone autostart mechanism. T-016 and T-017 do not document this stealth hardening.

## Mechanism

1. The operator creates a service via CreateService with standard parameters (SERVICE_AUTO_START, SERVICE_WIN32_OWN_PROCESS) establishing the persistence base layer.
2. The operator constructs an SDDL string that denies enumeration rights to broad SIDs while allowing start and control to a narrower SID. The SDDL string format is: D:(A;ace_flags;rights;object_guid;inherit_guid;account_sid), where D: denotes DACL, A denotes allow ACE, and the rights token controls the specific access.
3. The SDDL rights tokens relevant to service objects include: SC_MANAGER_CONNECT (standard), SERVICE_QUERY_CONFIG (0x0001), SERVICE_CHANGE_CONFIG (0x0002), SERVICE_QUERY_STATUS (0x0004), SERVICE_ENUMERATE_DEPENDENTS (0x0008), SERVICE_START (0x0010), SERVICE_STOP (0x0020), SERVICE_PAUSE_CONTINUE (0x0040), SERVICE_INTERROGATE (0x0080), SERVICE_USER_DEFINED_CONTROL (0x0100), and SERVICE_ALL_ACCESS (0xF01FF).
4. The operator denies SERVICE_QUERY_STATUS (0x0004) and SERVICE_ENUMERATE_DEPENDENTS (0x0008) to Everyone (S-1-1-0) or INTERACTIVE (S-1-5-4) by including a deny ACE: D:(D;;0x000C;;;WD) where D denotes deny, 0x000C is the bitmask for QUERY_STATUS|ENUMERATE_DEPENDENTS, and WD is the well-known SID for Everyone.
5. The operator allows SERVICE_START (0x0010) and SERVICE_ALL_ACCESS to SYSTEM (S-1-5-18) and the operator's SID in separate allow ACEs: D:(A;;GA;;;SY)(A;;0x10;;;S-1-5-32-544) where GA is GENERIC_ALL for SYSTEM and 0x10 is SERVICE_START for Administrators.
6. The operator applies the SDDL string via sc.exe sdset <ServiceName> "<SDDL_STRING>" or programmatically via SetNamedSecurityInfo with SE_OBJECT_TYPE=SE_SERVICE, specifying DACL_SECURITY_INFORMATION in the SecurityInformation parameter.
7. After the DACL is applied, sc query returns ACCESS_DENIED for the service, services.msc does not display it, and Get-Service throws an access error. The service remains registered in the SCM database and auto-starts at boot per its Start=2 configuration, but is invisible to standard enumeration.
8. The operator can still control the service by calling StartServiceW or ControlService with a handle opened with SERVICE_START access, which the DACL allows for their SID.

## OS Internals Context

Service objects in Windows are securable objects managed by the SCM. Each service has an associated security descriptor containing an owner SID, a group SID, a SACL (system access control list for auditing), and a DACL (discretionary access control list for access control). The DACL contains ACEs (access control entries) that map SIDs to access rights. When a caller attempts to open a service handle via OpenService, the SCM performs an access check against the service's DACL using the caller's primary token.

The SDDL string format encodes the security descriptor in a text representation. The DACL section begins with D: and contains a parenthesized list of ACEs. Each ACE has six semicolon-delimited fields: ace_type (A=allow, D=deny), ace_flags (inheritance and audit flags), rights (access mask as a hex string or SDDL-specific string constants), object_guid (for object-specific ACEs), inherit_object_guid, and account_sid (as a well-known SID string like WD for Everyone, SY for SYSTEM, or a full SID string).

The rights field for service objects uses the same access mask values as the dwDesiredAccess parameter to OpenService and CreateService. SERVICE_QUERY_STATUS (0x0004) is the right required by EnumServicesStatus and sc query to retrieve service state. SERVICE_ENUMERATE_DEPENDENTS (0x0008) is required to list dependent services. By denying these specific rights to broad SIDs while allowing them to SYSTEM and the operator's SID, the service becomes invisible to any process running under a non-privileged token that does not have an explicit allow ACE.

The SetNamedSecurityInfo API (from advapi32.dll) is the programmatic interface for modifying a service's security descriptor. It accepts the service name, SE_OBJECT_TYPE=SE_SERVICE (0x2), a SecurityInformation bitmask (DACL_SECURITY_INFORMATION=0x4), and optional pointers to the new owner SID, group SID, DACL, and SACL. The function internally sends an RPC to services.exe to update the service's security descriptor in the SCM database. The NtSetSecurityObject native API provides a lower-level alternative that operates on a service handle rather than a name, avoiding the advapi32 hook surface.

## Key Implementation Details

**No current implementation in the HUGIN source for service object DACL manipulation.** The file `dark_crystal/crowd/src/block_handle.rs` implements the same SDDL/DACL buffer construction pattern for process objects via NtSetSecurityObject — building a raw SECURITY_DESCRIPTOR with ACL header, deny ACE for Everyone (S-1-1-0), and allow ACE for SYSTEM (S-1-5-18) in a byte buffer, then applying it with DACL_SECURITY_INFORMATION. This pattern would be adapted for service objects by changing the target from a process handle to a service handle (obtained via OpenServiceW) and modifying the denied access rights from PROCESS_ALL_ACCESS to SERVICE_QUERY_STATUS|SERVICE_ENUMERATE_DEPENDENTS. The block_handle.rs implementation constructs the security descriptor in a manual byte buffer rather than using BuildSecurityDescriptor or SDDL parsing functions, avoiding the advapi32 hook surface.

## Why It Matters

Service DACL hiding provides enumeration evasion for service-based persistence, complementing the autostart mechanism with stealth. A hidden service survives reboots, auto-starts at boot, and is invisible to standard incident response tooling (sc query, services.msc, Get-Service). This addresses a gap in T-016's evasion suite (which covers PEB unlink and stack spoofing but not SDDL-based enumeration hiding) and in T-017's persistence suite (which documents PhantomPersist resilience but not service-level stealth). The technique applies to any securable Windows object, making it a general-purpose evasion primitive.

## Detection Considerations

- **Telemetry sources**: Sysmon EID 4657 (registry value modified) if registry auditing is enabled on the Services key, as the security descriptor is stored in the registry's SECURITY value. Windows Security event log EID 4678 (security descriptor modified) if SACL auditing is configured. The sc.exe sdset command generates a command-line event (Sysmon EID 1) that can be filtered. Anomalous DACL configurations on services can be detected by baseline comparison — querying all service DACLs and flagging those that deny SERVICE_QUERY_STATUS to Everyone.
- **Bypass options**: Using SetNamedSecurityInfo via FFI rather than sc.exe avoids command-line logging. Using NtSetSecurityObject on a service handle avoids the advapi32 hook surface. Denying only SERVICE_QUERY_STATUS rather than all access reduces anomaly scoring while still hiding the service from standard enumeration.
- **Residual artifacts**: The modified security descriptor persists in the SCM database and the registry's SECURITY value under the service key. A service that returns ACCESS_DENIED to sc query while still appearing in the boot start list (Start=2) is a detection indicator. Tools that enumerate services via SCM RPC at a lower level than sc query (e.g., direct EnumServicesStatusEx calls) may still enumerate the service name even if status query is denied.

## Related Techniques

- **T-017 Five-Layer Persistence** — T-113 complements T-017's persistence suite with service-level enumeration evasion
- **T-016 EDR Evasion Suite** — T-113 fills the SDDL-based enumeration hiding gap absent from T-016's evasion suite
- **T-041 Service Hiding from SCM Enumeration** — existing vault card covering service hiding from the same conceptual angle
- **T-062 Security Descriptor Manipulation for Object Access Control** — existing vault card covering SDDL manipulation as a general technique

## References

- Atlas material: atlas-post-exploit-part2.md, atlas-post-exploit-part12.md
- MITRE ATT&CK: T1564 — https://attack.mitre.org/techniques/T1564/
- LGTM notes: lgtm:sddl-security-descriptor-tampering, lgtm:programmatically-hidden-service

## Source Reference

No current implementation for service object DACL manipulation. The file `dark_crystal/crowd/src/block_handle.rs` implements the same SDDL/DACL buffer construction pattern for process objects via NtSetSecurityObject, which would be adapted for service objects by changing the target handle type and denied access rights.