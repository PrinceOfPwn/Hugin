# Cluster Spec — T-062: Security Descriptor Manipulation for Object Access Control

- **T-NNN ID**: `T-062`
- **Canonical name**: Security Descriptor Manipulation for Object Access Control
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `B`
- **Priority**: low — Singleton, secondary evasion mechanism; narrow applicability.
- **would_relate_to**: ['T-016']

## Consolidated Description

SDDL-based security descriptor manipulation to loosen object DACLs and bypass access restrictions. Example: granting GENERIC_ALL to S-1-0-0 permits anonymous access to protected objects. Entry point is SDDL string construction and SetNamedSecurityInfo application. Evasion by removing access-control barriers.

## Member LGTM Notes (1)

### Note 1: Security Descriptor Manipulation via SDDL
- id: `lgtm:sddl-security-descriptor-manipulation`
- origin: atlas-methodology-part7
- would_relate_to: ['T-016']
- tags: ['sddl', 'security-descriptor', 'null-sid', 'ace', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-methodology-part7
**Would relate to:** T-016
**Source units:** unit 7

SEC670's SDDL Example #1 walks through constructing a security descriptor that grants GENERIC_ALL to the NULL SID (S-1-0-0), demonstrating the primitive of loosening object DACLs to permit anonymous access. The vault's T-016 covers handle blocking (restricting access to the implant) but does not cover the inverse primitive: loosening security descriptors on services, named pipes, or kernel objects to permit low-privilege access. This is a distinct offensive capability that would merit its own treatment under the EDR Evasion suite.

---
Use `id: T-062`, canonical name above, and `member_notes: ['lgtm:sddl-security-descriptor-manipulation']`.
Cross-reference `would_relate_to`: ['T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.