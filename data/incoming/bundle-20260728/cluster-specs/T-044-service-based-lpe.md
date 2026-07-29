# Cluster Spec — T-044: Service-Based Local Privilege Escalation via SCM Enumeration

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-044`
- **Canonical name**: Service-Based Local Privilege Escalation via SCM Enumeration
- **Proposed category**: `privesc`
- **Proposed tier**: `A`
- **Priority**: medium — 2 member notes, distinct from service persistence, covers full enumeration-to-exploitation flow.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017', 'T-020', 'T-023']

## Consolidated Description (from clustering)

Service-based LPE via enumeration and permission weakness exploitation. Operators enumerate with OpenSCManager/EnumServicesStatus, identify services running as SYSTEM or with weak binary permissions, and exploit unquoted service paths or weak DACL/ACL. Distinct from service persistence (T-017); focuses on privilege-escalation leverage of service architecture.

## Member LGTM Notes (2)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Service-Based LPE Enumeration and Exploitation
- **id**: `lgtm:proposed-technique-service-lpe-enumeration`
- **origin**: atlas-privesc-part2
- **source_units**: ['unit 9', 'unit 10', 'unit 11', 'unit 12', 'unit 13', 'unit 14', 'unit 15', 'unit 16', 'unit 37', 'unit 38', 'unit 39']
- **would_relate_to**: ['T-017', 'T-023']
- **tags**: ['proposed-technique', 'services', 'scm', 'lpe', 'unquoted-path', 'sddl']

**Kind:** proposed-technique
**Origin:** atlas-privesc-part2
**Would relate to:** T-017, T-023
**Source units:** unit 9, unit 10, unit 11, unit 12, unit 13, unit 14, unit 15, unit 16, unit 37, unit 38, unit 39

SEC670 devotes multiple units (9–16) to Windows services as a privilege-escalation surface: SCM interaction via OpenSCManager, service enumeration via EnumServicesStatus and QueryServiceStatus, unquoted-service-path LPE, weak service permissions, and CVE-2019-1322 (which the material references as an example service-configuration LPE). The vault has no card covering service enumeration as an offensive capability. This would merit its own T-NNN card distinct from T-017 persistence because the operational purpose is privilege escalation rather than persistence, and the technique surface (ImagePath enumeration, BINARY_PATH_NAME inspection, service-descriptor SDDL analysis) is a discrete tradecraft area.

### Note 2: Service-Based Local Privilege Escalation
- **id**: `lgtm:service-based-lpe-proposed-technique`
- **origin**: atlas-privesc-part3
- **source_units**: ['unit 11', 'unit 15', 'unit 16', 'unit 17', 'unit 18']
- **would_relate_to**: ['T-017', 'T-020']
- **tags**: ['scm', 'services', 'lpe', 'unquoted-path', 'weak-permissions', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-privesc-part3
**Would relate to:** T-017, T-020
**Source units:** unit 11, unit 15, unit 16, unit 17, unit 18

SEC670 and CRTO both cover service enumeration (OpenSCManager, EnumServicesStatus, QueryServiceStatus), weak binary permissions (Get-Acl on service paths), and unquoted path LPE. This is distinct from the persistence suite — the operational purpose is one-shot elevation rather than persistence. A dedicated T-NNN for service LPE tradecraft would document the enumeration, ACL inspection, and replacement workflow the vault currently lacks.

---

## Your Task

Produce the technique card for **T-044** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-044` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017', 'T-020', 'T-023'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:proposed-technique-service-lpe-enumeration', 'lgtm:service-based-lpe-proposed-technique']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.