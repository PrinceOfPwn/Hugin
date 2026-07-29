# Cluster Spec — T-113: Service Hiding via SDDL/DACL Security Descriptor Tampering

- **T-NNN ID**: `T-113`
- **Canonical name**: Service Hiding via SDDL/DACL Security Descriptor Tampering
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes, distinct stealth hardening technique with concrete API surface
- **would_relate_to**: ['T-016', 'T-017']

## Consolidated Description

SEC670 documents SDDL (Security Descriptor Definition Language) string syntax for service objects: ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid, where the rights token controls access (e.g., RC=Read Config, DC=Delete/Config, CC=Create Child). Using sc.exe sdset <service> D:(A;;DC;;;AU) or SetNamedSecurityInfo with DACL_SECURITY_INFORMATION, an operator can deny SERVICE_QUERY_STATUS and SERVICE_ENUMERATE_DEPENDENTS to 'Everyone' or 'INTERACTIVE', causing the service to be invisible to sc query, services.msc, and Get-Service enumeration. The service remains startable by an operator who retains SERVICE_START in their own ACE. This is a persistence resilience measure layered on top of service-based persistence (CreateService), not a standalone autostart mechanism. The vault's T-016 and T-017 do not document this stealth hardening.


## Member LGTM Notes (2)

### Note 1: SDDL Service/Object Security Descriptor Tampering
- id: `lgtm:sddl-security-descriptor-tampering`
- origin: atlas-post-exploit-part12
- would_relate_to: ['T-016', 'T-017']
- tags: ['sddl', 'security-descriptor', 'evasion', 'services', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part12
**Would relate to:** T-016, T-017
**Source units:** unit 5, unit 6, unit 10, unit 12, unit 14

SEC670 units 5–14 cover SDDL syntax, ACE string layout (ace_type/ace_flags/rights tokens), and the use of sc.exe sdset or SetNamedSecurityInfo to hide services by denying enumeration rights to common SIDs. The vault's T-016 EDR evasion suite covers PEB unlink and stack spoofing but does not document SDDL-based enumeration hiding — a relevant evasion primitive applicable to services, scheduled tasks, and other securable objects.

### Note 2: Programmatic Service Hiding via DACL Modification
- id: `lgtm:programmatically-hidden-service`
- origin: atlas-post-exploit-part2
- would_relate_to: ['T-017']
- tags: ['service-hiding', 'dacl', 'persistence', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part2
**Would relate to:** T-017
**Source units:** unit 8

SEC670 covers modifying the DACL on a service object to hide it from standard service enumeration while retaining the ability to start and persist. T-017 does not currently document service-hiding as a persistence resilience measure. The technique complements the existing PhantomPersist resilience monitor because a hidden service survives reboots and is invisible to sc query and Get-Service enumeration.

---
Use `id: T-113`, canonical name above, and `member_notes: ['lgtm:sddl-security-descriptor-tampering', 'lgtm:programmatically-hidden-service']`.
Cross-reference `would_relate_to`: ['T-016', 'T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.