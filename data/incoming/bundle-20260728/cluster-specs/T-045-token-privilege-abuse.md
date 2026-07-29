# Cluster Spec — T-045: Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-045`
- **Canonical name**: Token Privilege Abuse: SeDebugPrivilege and Privilege Manipulation
- **Proposed category**: `privesc`
- **Proposed tier**: `A`
- **Priority**: medium — Singleton, covers coherent privilege-abuse family, broader than token theft, distinct from UAC bypass.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-016', 'T-023']

## Consolidated Description (from clustering)

Token privilege abuse via AdjustTokenPrivileges to enable privileges in current token (SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeImpersonatePrivilege). SeDebugPrivilege enables OpenProcess with high-privilege access; SeBackup/SeRestore bypass ACL checks; SeImpersonate enables token stealing. Integrated tradecraft covering privilege escalation via both OS-granted and privilege rights.

## Member LGTM Notes (1)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Token Privilege Abuse as Standalone Technique
- **id**: `lgtm:token-privilege-abuse-proposed-technique`
- **origin**: atlas-privesc-part3
- **source_units**: ['unit 5', 'unit 6', 'unit 13', 'unit 14', 'unit 28', 'unit 32', 'unit 34', 'unit 35', 'unit 40']
- **would_relate_to**: ['T-016', 'T-023']
- **tags**: ['privilege-abuse', 'token', 'sedebug', 'sebackup', 'serestore', 'lpe', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-privesc-part3
**Would relate to:** T-016, T-023
**Source units:** unit 5, unit 6, unit 13, unit 14, unit 28, unit 32, unit 34, unit 35, unit 40

SEC670 covers AdjustTokenPrivileges, SeDebugPrivilege, SE_BACKUP_NAME/SE_RESTORE_NAME ACL bypass, and token stealing as a coherent privilege-abuse tradecraft block. The vault references SeDebugPrivilege implicitly through T-016 handle operations but has no dedicated card for privilege token manipulation as a distinct capability — the AdjustTokenPrivileges + SeDebugPrivilege + token-stealing chain is reusable across escalation scenarios independent of injection or evasion.

---

## Your Task

Produce the technique card for **T-045** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-045` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-016', 'T-023'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:token-privilege-abuse-proposed-technique']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.