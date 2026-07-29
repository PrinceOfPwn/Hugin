# Cluster Spec — T-047: Cross-Session Process Injection via WTS Enumeration

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-047`
- **Canonical name**: Cross-Session Process Injection via WTS Enumeration
- **Proposed category**: `process-injection`
- **Proposed tier**: `A`
- **Priority**: medium — 3 member notes, distinct targeting criterion from core injection methods.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-013', 'T-007', 'T-015', 'T-023']

## Consolidated Description (from clustering)

Cross-session process injection via WTSEnumerateProcessesEx for identifying processes across multiple logon sessions. Operators enumerate session IDs and target high-value processes in other sessions (e.g., SYSTEM session from user session). Distinct operational variant from in-session injection; requires knowledge of session enumeration and cross-session process accessibility.

## Member LGTM Notes (3)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Cross-Session Process Injection via WTS Target Selection
- **id**: `lgtm:cross-session-injection-primitive`
- **origin**: atlas-binary-analysis-part2
- **source_units**: ['unit 30', 'unit 31']
- **would_relate_to**: ['T-013', 'T-007']
- **tags**: ['cross-session', 'wts', 'terminal-services', 'injection', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part2
**Would relate to:** T-013, T-007
**Source units:** unit 30, unit 31

SEC670 frames WTSEnumProcessSessions as the path to identifying cross-session process injection opportunities. The vault's T-013 (Remaining Injection Methods) catalogues injection primitives but does not specifically address cross-session targeting — the operational constraint that the target runs in a Terminal Services session other than the caller's, requiring SeChangeNotifyPrivilege / session-boundary traversal. This is a distinct operational tradecraft area worth surfacing as either a T-013 sub-technique or a new card.

### Note 2: Cross-Session Process Injection as Standalone Primitive
- **id**: `lgtm:cross-session-injection-as-distinct-primitive`
- **origin**: atlas-exploit-dev-part7
- **source_units**: ['unit 36']
- **would_relate_to**: ['T-013', 'T-023']
- **tags**: ['wts', 'cross-session', 'injection-primitive', 'session-targeting']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part7
**Would relate to:** T-013, T-023
**Source units:** unit 36

SEC670 explicitly calls out cross-session process injection via WTSEnumerateProcessesEx as a distinct operational capability enabled by session-aware enumeration. The vault's T-013 documents injection methods but does not currently frame cross-session targeting as a primitive in its own right. A future card could document the WTSEnumerateProcessesEx → session-ID filter → cross-session OpenProcess sequence alongside considerations for session-0 service injection and terminal-service session targeting.

### Note 3: Cross-Session Process Injection
- **id**: `lgtm:cross-session-injection-variant`
- **origin**: atlas-post-exploit-part9
- **source_units**: ['unit 35']
- **would_relate_to**: ['T-007', 'T-013', 'T-015']
- **tags**: ['cross-session', 'injection', 'wts', 'session-id', 'token']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part9
**Would relate to:** T-007, T-013, T-015
**Source units:** unit 35

SEC670's WTSEnumerateProcessesEx coverage explicitly names cross-session process injection as a distinct variant — injecting into a process running in a different user's logon session. The vault's T-007 methods do not distinguish in-session from cross-session injection, and the token/handle requirements for cross-session operation differ. A dedicated card or T-013 entry would surface this operational distinction.

---

## Your Task

Produce the technique card for **T-047** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-047` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-013', 'T-007', 'T-015', 'T-023'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:cross-session-injection-primitive', 'lgtm:cross-session-injection-as-distinct-primitive', 'lgtm:cross-session-injection-variant']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.