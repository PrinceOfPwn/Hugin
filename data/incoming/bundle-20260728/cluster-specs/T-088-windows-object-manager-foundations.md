# Cluster Spec — T-088: Windows Object Manager as Foundational Reference Card

- **T-NNN ID**: `T-088`
- **Canonical name**: Windows Object Manager as Foundational Reference Card
- **Proposed category**: `discovery`
- **Proposed tier**: `C`
- **Priority**: high — 3 member notes; concept card that unblocks 6 existing T-NNN cards.
- **would_relate_to**: ['T-004', 'T-007', 'T-013', 'T-014', 'T-015', 'T-016']

## Consolidated Description

SEC670 Book 1 devotes multiple units to the Windows Object Manager — the
executive subsystem standardizing object headers, bodies, handle tables,
and ACL-gated access for 4000+ object types (Process, Thread, File, Token,
Event, Mutant, Section, Key, etc.). The vault's T-016 (handle blocking),
T-014/T-015 (PPID spoof + handle manipulation), T-007 (process injection
via handle ops), T-013 (PE loader using Section objects), and T-004 (PEB
walk relies on object-manager-backed handle) all assume this knowledge. The
card should document: executive objects vs kernel objects (USER-objects vs
GDI-objects are non-executive), the OBJECT_HEADER structure (with Type
index, NameInfoOffset, SecurityDescriptorOffset, QuotaInfoOffset fields
preceding the body), the per-process handle table (PspCidTable via
EPROCESS->HandleTable → PHANDLE_TABLE), and the ObpCreateHandle flow
(ExCreateHandle → OBJECT_HEADER->SecurityDescriptor check →
ObpIncrementHandleCount). Reference: NtQueryObject/ObjectAllInformation
returns the entire OM view.


## Member LGTM Notes (3)

### Note 1: Windows Object Manager as a Foundational Concept Card
- id: `lgtm:windows-object-manager-foundational-concept`
- origin: atlas-methodology-part1
- would_relate_to: ['T-004', 'T-007', 'T-016']
- tags: ['windows-internals', 'object-manager', 'handles', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part1
**Would relate to:** T-004, T-007, T-016
**Source units:** unit 33, unit 35, unit 36, unit 37, unit 38, unit 39

Multiple SEC670 units (35-39) treat the Windows object manager — executive objects, the 4,000+ object type space, the kernel/user object split, and the Create*→Nt*→executive-object→handle flow — as prerequisite knowledge for understanding why handles mediate every cross-process and cross-thread operation. The vault documents techniques that depend on this model (T-007 injection, T-016 handle blocking, T-004 PEB walking) but has no standalone concept card explaining the object manager itself. Adding one would let operators trace why handle-based detection fires, why PEB walking avoids the handle table, and why Section objects are the backbone of mapping injection.

### Note 2: Windows Object Manager as Foundational Knowledge for Handle Tradecraft
- id: `lgtm:windows-object-manager-foundation`
- origin: atlas-methodology-part2
- would_relate_to: ['T-015', 'T-016', 'T-007', 'T-014']
- tags: ['object-manager', 'handle', 'acl', 'coverage-gap', 'windows-internals']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part2
**Would relate to:** T-015, T-016, T-007, T-014
**Source units:** unit 2, unit 3, unit 5, unit 8

SEC670 dedicates multiple units to the Object Manager's role in standardizing object headers, bodies, handle tables, and ACL-gated access. The vault documents handle blocking (T-016), PPID spoofing (T-015), and injection (T-007) without explaining the Object Manager layer that mediates all of these. A cross-cutting concept document on the Object Manager would help operators understand why handle-based techniques succeed or fail at the kernel's ACL check, not just at the API call level.

### Note 3: Windows Object Manager Foundations as a Reference Concept Card
- id: `lgtm:windows-object-manager-foundations-card`
- origin: atlas-methodology-part5
- would_relate_to: ['T-004', 'T-007', 'T-013', 'T-015', 'T-016']
- tags: ['windows-internals', 'object-manager', 'foundation', 'coverage-gap', 'concept-cluster']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part5
**Would relate to:** T-004, T-007, T-013, T-015, T-016
**Source units:** unit 21, unit 24, unit 25, unit 26, unit 27

SEC670 Book 1 devotes multiple units to the Object Manager, object header/body schema, handle table mechanics, and ACL/security-descriptor gating on securable objects. The vault currently distributes this knowledge implicitly across T-007, T-013, T-015, and T-016 — operators must reverse-engineer the conceptual model from scattered technique cards. A standalone reference node (not a T-NNN technique, but a graph-anchored concept cluster) would let readers new to Windows internals reach the technique cards with the prerequisite mental model already in place.

---
Use `id: T-088`, canonical name above, and `member_notes: ['lgtm:windows-object-manager-foundational-concept', 'lgtm:windows-object-manager-foundation', 'lgtm:windows-object-manager-foundations-card']`.
Cross-reference `would_relate_to`: ['T-004', 'T-007', 'T-013', 'T-014', 'T-015', 'T-016'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.