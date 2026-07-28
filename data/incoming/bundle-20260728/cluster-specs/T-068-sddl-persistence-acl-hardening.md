# Cluster Spec — T-068: SDDL/ACL Hardening for Persistence Resilience

- **T-NNN ID**: `T-068`
- **Canonical name**: SDDL/ACL Hardening for Persistence Resilience
- **Proposed category**: `persistence`
- **Proposed tier**: `B`
- **Priority**: low — 2 member notes, secondary persistence-hardening technique, overlaps with service hiding.
- **would_relate_to**: ['T-017']

## Consolidated Description

SDDL and ACL hardening for persistence resilience via GetNamedSecurityInfo/SetNamedSecurityInfo/EXPLICIT_ACCESS_A. Operators deny stop and delete permissions to defenders, preventing removal of persistence objects. SDDL string format with ACE field decomposition provides the manipulation primitive.

## Member LGTM Notes (2)

### Note 1: SDDL and ACL Manipulation for Persistence Hardening
- id: `lgtm:sddl-acl-manipulation-proposed`
- origin: atlas-exploit-dev-part10
- would_relate_to: ['T-017', 'T-021']
- tags: ['sddl', 'acl', 'security-descriptor', 'persistence-hardening', 'getnamedsecurityinfo', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part10
**Would relate to:** T-017, T-021
**Source units:** unit 19, unit 20

SEC670 covers SDDL string format with ACE field decomposition (AceType, AccessMask, SID) and the GetNamedSecurityInfoA API for retrieving security descriptors across NTFS objects, services, registry keys, shares, and file-mapping objects. The vault does not currently document ACL inspection and manipulation as a technique for hardening persistence entries against defender cleanup or for escalating access to protected objects. This would merit a technique card covering SDDL parsing, security descriptor retrieval, and ACL modification.

### Note 2: Security Descriptor ACL Hardening for Persistence
- id: `lgtm:security-descriptor-acl-hardening`
- origin: atlas-exploit-dev-part19
- would_relate_to: ['T-017']
- tags: ['security-descriptor', 'dacl', 'acl-hardening', 'persistence-resilience', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part19
**Would relate to:** T-017
**Source units:** unit 20, unit 21, unit 22

SEC670 covers GetNamedSecurityInfoA/SetNamedSecurityInfoA and EXPLICIT_ACCESS_A as tools to modify DACLs on service objects, denying stop and delete permissions to defenders. This is a persistence resilience technique distinct from the execution-based persistence methods in T-017 — it hardens existing persistence entries against remediation rather than creating new ones. The vault does not currently document ACL-level hardening of persistent artifacts as a technique.

---
Use `id: T-068`, canonical name above, and `member_notes: ['lgtm:sddl-acl-manipulation-proposed', 'lgtm:security-descriptor-acl-hardening']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.