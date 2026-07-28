# Cluster Spec — T-029: Security Descriptor and SDDL Reconnaissance for Privilege-Escalation Planning

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-029`
- **Canonical name**: Security Descriptor and SDDL Reconnaissance for Privilege-Escalation Planning
- **Proposed category**: `discovery`
- **Proposed tier**: `B`
- **Priority**: medium — Singleton reconnaissance methodology, clear tradecraft value for privilege-escalation planning.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-023']

## Consolidated Description (from clustering)

Security descriptor reconnaissance workflow: sc.exe sdshow reveals service DACLs; manual SDDL parsing decodes ACE types, rights, and SIDs; GetNamedSecurityInfo retrieves descriptors for services, registry keys, shares, file-mapping objects. Enables identification of weak DACLs and privilege-escalation targets. Complements service-based LPE and ACL-bypass exploitation.

## Member LGTM Notes (1)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Security Descriptor and SDDL Reconnaissance
- **id**: `lgtm:proposed-technique-security-descriptor-reconnaissance`
- **origin**: atlas-privesc-part2
- **source_units**: ['unit 28', 'unit 29', 'unit 30', 'unit 35', 'unit 36', 'unit 37', 'unit 38', 'unit 39', 'unit 40']
- **would_relate_to**: ['T-023']
- **tags**: ['proposed-technique', 'sddl', 'acl', 'reconnaissance', 'security-descriptor', 'se-backup-restore']

**Kind:** proposed-technique
**Origin:** atlas-privesc-part2
**Would relate to:** T-023
**Source units:** unit 28, unit 29, unit 30, unit 35, unit 36, unit 37, unit 38, unit 39, unit 40

SEC670 documents a structured tradecraft workflow around security descriptors: sc.exe sdshow for service DACLs, SDDL/ACE string interpretation (ace_type, ace_flags, rights constants, SID abbreviations), GetNamedSecurityInfoA for cross-object-type descriptor retrieval, and SE_BACKUP_NAME/SE_RESTORE_NAME as ACL-bypass privileges. This is a reconnaissance capability with distinct API surface and parsing requirements that the vault does not document anywhere. Adding a card would help operators identify weak-permission targets (services, registry keys, file paths) systematically rather than via ad-hoc tooling.

---

## Your Task

Produce the technique card for **T-029** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-029` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-023'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:proposed-technique-security-descriptor-reconnaissance']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.