# Cluster Spec — T-048: Custom Shell Loader as Distinct from Generic Injection

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-048`
- **Canonical name**: Custom Shell Loader as Distinct from Generic Injection
- **Proposed category**: `process-injection`
- **Proposed tier**: `B`
- **Priority**: medium — Singleton, distinct from injection methods per SANS Lab structure, clear operational separation.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-007', 'T-022']

## Consolidated Description (from clustering)

Custom shell construction as distinct from process injection technique selection. Labs CustomShell, The Loader, and ShadowCraft indicate custom shell construction is treated as separate offensive capability. Involves developing standalone shellcode-based shell infrastructure (interactive session management, I/O handling, command execution).

## Member LGTM Notes (1)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Custom Shell Loader as Distinct from Generic Injection
- **id**: `lgtm:customshell-shellcode-loader-card`
- **origin**: atlas-labs-part2
- **source_units**: ['unit 4', 'unit 5', 'unit 7', 'unit 8']
- **would_relate_to**: ['T-007', 'T-022']
- **tags**: ['shell', 'loader', 'implant-architecture', 'coverage-gap', 'sec670']

**Kind:** proposed-technique
**Origin:** atlas-labs-part2
**Would relate to:** T-007, T-022
**Source units:** unit 4, unit 5, unit 7, unit 8

SEC670 Lab 4.7 'CustomShell' pairs with Lab 5.1 'The Loader' and Lab 5.5 'ShadowCraft' to indicate that custom shell construction is treated as its own offensive capability — distinct from the injection method catalog in T-007. The vault's T-007 card enumerates 14 injection methods but does not document the shell/implant scaffolding layer (command dispatch, error handling, transport abstraction) as a separate concern.

---

## Your Task

Produce the technique card for **T-048** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-048` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-007', 'T-022'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:customshell-shellcode-loader-card']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.