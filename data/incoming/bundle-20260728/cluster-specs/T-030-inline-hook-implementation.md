# Cluster Spec — T-030: Inline Hook Implementation: Red-Team Hooking Mechanics

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-030`
- **Canonical name**: Inline Hook Implementation: Red-Team Hooking Mechanics
- **Proposed category**: `edr-evasion`
- **Proposed tier**: `B`
- **Priority**: medium — Singleton, foundational for API interception, enables post-exploitation capabilities.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-016']

## Consolidated Description (from clustering)

Red-team inline hook implementation covering byte-patching of prologue code, trampoline construction, and x64 hook stubs. Hooks intercept function calls for logging, credential theft, or behavior manipulation. Distinct from EDR-side hook interception; red-team hooks can be placed on any DLL or API. Requires knowledge of prologue, stub construction, and memory protection.

## Member LGTM Notes (1)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Inline Hook Implementation (Red-Team-Side Hooking)
- **id**: `lgtm:inline-hook-implementation-side`
- **origin**: atlas-exploit-dev-part12
- **source_units**: ['unit 1', 'unit 8', 'unit 9', 'unit 10', 'unit 11']
- **would_relate_to**: ['T-016']
- **tags**: ['inline-hook', 'trampoline', 'hook-implementation', 'red-team-side']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part12
**Would relate to:** T-016
**Source units:** unit 1, unit 8, unit 9, unit 10, unit 11

Units 1, 8-11 cover inline hooking from the implementer's perspective — how to patch bytes, construct trampolines to avoid infinite loops, and structure x64 hooks with mov rax/jmp rax. The vault's T-016 documents EDR-side hooks as something to bypass but does not document implant-side hooking (e.g., hooking NtQuerySystemInformation to hide processes, hooking ETW functions to muffle telemetry from within the implant itself). This is a distinct tradecraft capability that would merit its own card or a dedicated subsection in T-016.

---

## Your Task

Produce the technique card for **T-030** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-030` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-016'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:inline-hook-implementation-side']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.