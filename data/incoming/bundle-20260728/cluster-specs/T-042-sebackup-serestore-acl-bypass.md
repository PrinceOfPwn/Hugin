# Cluster Spec — T-042: SeBackupPrivilege / SeRestorePrivilege: ACL Bypass for File Access

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-042`
- **Canonical name**: SeBackupPrivilege / SeRestorePrivilege: ACL Bypass for File Access
- **Proposed category**: `privesc`
- **Proposed tier**: `S`
- **Priority**: high — Novel capability, new territory for vault, critical for post-exploitation file access.
- **would_relate_to** (existing T-NNN to cross-reference): []

## Consolidated Description (from clustering)

SeBackupPrivilege and SeRestorePrivilege are special Windows privileges that bypass file DACL checks entirely, granting unrestricted read (Backup) or write (Restore) access. Any process with these privileges can access NTFS objects regardless of security descriptor. Operationally distinct from ACL manipulation; privilege-based bypasses. Often granted to backup operators, admins, or SYSTEM services; critical for sensitive file access (SAM, NTDS, DPAPI keys).

## Member LGTM Notes (1)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: SeBackupPrivilege / SeRestorePrivilege ACL Bypass
- **id**: `lgtm:proposed-acl-bypass-privilege-card`
- **origin**: atlas-privesc-part1
- **source_units**: ['unit 5', 'unit 12', 'unit 20', 'unit 37', 'unit 38']
- **would_relate_to**: []
- **tags**: ['acl-bypass', 'privilege', 'file-system', 'lpe', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-privesc-part1
**Would relate to:** (new territory)
**Source units:** unit 5, unit 12, unit 20, unit 37, unit 38

SEC670 explicitly calls out SeBackupPrivilege and SeRestorePrivilege as the two privileges that bypass the standard ACL check entirely — granted complete read or write access regardless of the file's DACL. The vault does not currently cover file-ACL bypass as a standalone technique. This would merit its own T-NNN card because it is a distinct operational primitive (read SAM/SYSTEM registry hives from disk, read restricted user files, write to ACL-protected locations) used in the post-exploitation phase rather than the injection phase.

---

## Your Task

Produce the technique card for **T-042** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-042` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = [] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:proposed-acl-bypass-privilege-card']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.