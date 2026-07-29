# Cluster Spec — T-041: Service Hiding from SCM Enumeration

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-041`
- **Canonical name**: Service Hiding from SCM Enumeration
- **Proposed category**: `persistence`
- **Proposed tier**: `B`
- **Priority**: medium — 3 member notes, distinct stealth mechanism complementing service persistence.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017', 'T-020']

## Consolidated Description (from clustering)

Service hiding via SDDL string configuration that denies query rights to Interactive Users, Service Users, and Administrators while preserving SYSTEM access. Custom SDDL strings hide services from sc query and GUI enumeration. Complements service-based persistence by concealing the execution layer.

## Member LGTM Notes (3)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: SDDL-Based Service Hiding
- **id**: `lgtm:sddl-service-hiding-tradecraft`
- **origin**: atlas-edr-evasion-part2
- **source_units**: ['unit 3', 'unit 4', 'unit 5']
- **would_relate_to**: ['T-017']
- **tags**: ['tradecraft', 'sddl', 'service-hiding', 'acl', 'security-descriptor', 'proposed']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part2
**Would relate to:** T-017
**Source units:** unit 3, unit 4, unit 5

SEC670 documents a real-world SDDL string crafted by Joshua Wright that denies standard query rights to Interactive Users, Service Users, and Built-in Administrators while preserving SYSTEM access, effectively hiding a service from sc query and similar enumeration. The vault does not currently cover ACL-based service hiding. Programmatic implementation via SetSecurityDescriptorControl and SetNamedSecurityInfo is also covered. This is distinct from the persistence mechanism itself — it is a stealth layer applied on top.

### Note 2: Hidden Service Persistence Technique
- **id**: `lgtm:hidden-service-technique`
- **origin**: atlas-post-exploit-part17
- **source_units**: ['unit 1']
- **would_relate_to**: ['T-017', 'T-020']
- **tags**: ['persistence', 'hidden-service', 'scm', 'evasion']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part17
**Would relate to:** T-017, T-020
**Source units:** unit 1

SEC670 references hiding a service as a SANS-taught persistence tradecraft item in the same Book 4 module as port monitor and IFEO. Hiding a service from SCM enumeration complements T-017's persistence layers and T-020's anti-analysis posture. The vault currently has no card covering SCM database manipulation to evade service enumeration, which would deserve its own card or a slot in the persistence suite.

### Note 3: Service Hiding from SCM Enumeration
- **id**: `lgtm:service-hiding-coverage-gap`
- **origin**: atlas-post-exploit-part8
- **source_units**: ['unit 13']
- **would_relate_to**: ['T-017']
- **tags**: ['service', 'hiding', 'stealth', 'scm', 'persistence']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part8
**Would relate to:** T-017
**Source units:** unit 13

SEC670 Lab 4.4 covers developing a custom Windows service for persistence and then hiding it from system view using Win32 APIs. The vault does not document service hiding as a stealth technique. This would complement T-017's persistence coverage by addressing the detection-evasion aspect of service-based persistence, including manipulating service visibility in the SCM database.

---

## Your Task

Produce the technique card for **T-041** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-041` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017', 'T-020'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:sddl-service-hiding-tradecraft', 'lgtm:hidden-service-technique', 'lgtm:service-hiding-coverage-gap']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.