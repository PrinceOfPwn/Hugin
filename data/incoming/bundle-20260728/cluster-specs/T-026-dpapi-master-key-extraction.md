# Cluster Spec — T-026: DPAPI Master Key Extraction for Credential Decryption

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-026`
- **Canonical name**: DPAPI Master Key Extraction for Credential Decryption
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: medium — Singleton, focused credential-harvesting primitive, clear operational value.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-023']

## Consolidated Description (from clustering)

DPAPI master key extraction for credential harvesting: locate user's master key in %APPDATA%\Microsoft\Protect\<SID>, decrypt using LogonUser/CryptUnprotectData or offline tools, use master key to decrypt user credential caches (Chrome login database, Credential Manager vault). Master key encrypted with user's logon password or system DPAPI key. Prerequisite for accessing browser and OS credential stores; operationally critical.

## Member LGTM Notes (1)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: DPAPI Master Key Extraction as Credential Sub-Technique
- **id**: `lgtm:dpapi-master-key-extraction`
- **origin**: atlas-post-exploit-part9
- **source_units**: ['unit 20', 'unit 21']
- **would_relate_to**: ['T-023']
- **tags**: ['dpapi', 'master-key', 'credentials', 'chrome', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part9
**Would relate to:** T-023
**Source units:** unit 20, unit 21

CRTO and SEC670 both surface DPAPI as the cryptographic substrate protecting Chrome and Credential Manager secrets. T-023 covers credential harvest broadly but does not document the DPAPI master key access step (locating %APPDATA%\Microsoft\Protect\<SID>, decrypting the master key with the user's logon password or DPAPI domain backup key) as a distinct sub-technique. This deserves explicit graph presence because it is the rate-limiting step for offline credential decryption.

---

## Your Task

Produce the technique card for **T-026** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-026` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-023'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:dpapi-master-key-extraction']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.