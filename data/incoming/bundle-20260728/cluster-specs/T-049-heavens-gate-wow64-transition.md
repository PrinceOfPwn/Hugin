# Cluster Spec — T-049: Heaven's Gate: 32-to-64-Bit Syscall Transition

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-049`
- **Canonical name**: Heaven's Gate: 32-to-64-Bit Syscall Transition
- **Proposed category**: `syscalls`
- **Proposed tier**: `A`
- **Priority**: high — 3 member notes, novel architecture bypass (32-bit implant issuing 64-bit syscalls), fills gap in T-001-T-006.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-001', 'T-002', 'T-004', 'T-006']

## Consolidated Description (from clustering)

Heaven's Gate is a 32-bit-to-64-bit transition mechanism Wow64 processes use to issue native 64-bit syscalls. Entry via segment 0x33 jump through ntdll.Wow64Transition to wow64cpu.dll, then to 64-bit ntdll syscall stub. Allows 32-bit implants to bypass 32-bit ntdll hooks entirely while executing kernel-mode operations in 64-bit context.

## Member LGTM Notes (3)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Heaven's Gate (WOW64 32→64 Bit Syscall Bridge)
- **id**: `lgtm:heavens-gate-wow64-syscall-bridge`
- **origin**: atlas-binary-analysis-part1
- **source_units**: ['unit 7']
- **would_relate_to**: ['T-001', 'T-002', 'T-004']
- **tags**: ['heavens-gate', 'wow64', 'syscall', 'cross-bitness', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part1
**Would relate to:** T-001, T-002, T-004
**Source units:** unit 7

Unit 7 references the Heaven's Gate technique for 32-bit processes transitioning to 64-bit code space via ntdll.dll offset. The vault's syscall dispatch cards (T-001 RecycledGate, T-002 Hells/Halo/Tartarus, T-003 VEH Gate, T-006 Phantom Stubs) all assume 64-bit execution. Heaven's Gate would merit a distinct T-NNN card or a coverage note on the existing dispatch cards: it is a deployment-context technique (32-bit payload) that fundamentally changes which ntdll syscall stubs are visible and hookable.

### Note 2: Heaven's Gate / Wow64 Cross-Architecture Syscalls
- **id**: `lgtm:heavens-gate-wow64-syscalls`
- **origin**: atlas-exploit-dev-part12
- **source_units**: ['unit 6', 'unit 7']
- **would_relate_to**: ['T-001', 'T-002', 'T-006']
- **tags**: ['wow64', "heaven's-gate", 'x86', 'syscall', 'hook-evasion']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part12
**Would relate to:** T-001, T-002, T-006
**Source units:** unit 6, unit 7

SEC670 units 6-7 cover Heaven's Gate — the 32-bit-to-64-bit transition mechanism Wow64 processes use to issue syscalls. This is a distinct operational capability: a 32-bit implant can issue 64-bit syscalls to bypass 32-bit ntdll hooks entirely. The vault's T-001, T-002, T-006 are all documented for x64 only; a Wow64 cross-arch syscall card would cover the segment-selector far jump, the dual ntdll.dll mapping in Wow64 processes, and the implications for hook evasion in 32-bit contexts.

### Note 3: Heaven's Gate WoW64 Transition as a Standalone Technique
- **id**: `lgtm:heavens-gate-wow64-bypass-as-standalone-technique`
- **origin**: atlas-exploit-dev-part3
- **source_units**: ['unit 26']
- **would_relate_to**: ['T-002', 'T-016']
- **tags**: ['heavens-gate', 'wow64', 'bitness-evasion', 'syscall', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part3
**Would relate to:** T-002, T-016
**Source units:** unit 26

Unit 26 explains the Heaven's Gate 32-to-64-bit syscall transition in detail — the segment 0x33 jump through ntdll.Wow64Transition to wow64cpu.dll, then to the 64-bit ntdll syscall stub. The vault's T-002 covers SSN resolution but does not document the bitness-transition evasion itself, which defeats 32-bit-only EDR hooking. Heaven's Gate (and its modern WoW64-subsystem-less descendants) deserves a discrete technique card because it is an evasion layer applied on top of any SSN resolution method.

---

## Your Task

Produce the technique card for **T-049** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-049` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-001', 'T-002', 'T-004', 'T-006'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:heavens-gate-wow64-syscall-bridge', 'lgtm:heavens-gate-wow64-syscalls', 'lgtm:heavens-gate-wow64-bypass-as-standalone-technique']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.