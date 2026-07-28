# Cluster Spec — T-039: On-Disk Binary Patching for Persistence and Evasion

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-039`
- **Canonical name**: On-Disk Binary Patching for Persistence and Evasion
- **Proposed category**: `persistence`
- **Proposed tier**: `B`
- **Priority**: medium — 3 member notes, persistent (survives reboot), distinct from ImagePath-based service persistence.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017', 'T-006', 'T-021']

## Consolidated Description (from clustering)

Binary patching persistence via on-disk PE file modification: code-cave shellcode insertion, import-table patching, resource-section modification. Survives reboot (unlike in-memory unhooking); can target system DLLs. Persistence through modification of application logic at rest; evasion through modification of signature-scan targets.

## Member LGTM Notes (3)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Binary Patching of Compiled PE Files
- **id**: `lgtm:proposed-binary-patching-technique`
- **origin**: atlas-exploit-dev-part22
- **source_units**: ['unit 17']
- **would_relate_to**: ['T-006', 'T-021']
- **tags**: ['binary-patching', 'code-cave', 'pe-modification', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part22
**Would relate to:** T-006, T-021
**Source units:** unit 17

SEC670 introduces binary patching as a distinct module with stated objectives and benefits. The vault does not have a technique card covering on-disk PE binary modification (code-cave shellcode insertion, import-table patching, resource-section modification). T-021 covers obfuscation and shellcode encoding, T-006 covers MEM_IMAGE-backed phantom stubs, but neither covers modification of an existing signed PE for stealth execution. A dedicated card would document the trade, signed-binary cave availability, and detection via signature mismatch.

### Note 2: Binary Patching as a Persistence Mechanism
- **id**: `lgtm:proposed-technique-binary-patching-persistence`
- **origin**: atlas-methodology-part8
- **source_units**: ['unit 16', 'unit 17', 'unit 18', 'unit 19', 'unit 20', 'unit 22']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'binary-patching', 'disk-modification', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-methodology-part8
**Would relate to:** T-017
**Source units:** unit 16, unit 17, unit 18, unit 19, unit 20, unit 22

SEC670 Section 4 (units 16-22) lists Binary Patching as a distinct persistence topic alongside Registry Keys, Services, IFEO, and WMI Event Subscriptions. The vault does not have a technique card covering in-place modification of binary files on disk to insert persistent execution hooks — a technique distinct from module stomping (which operates in memory) and from proxy DLL planting (which adds new files rather than modifying existing ones). This deserves its own coverage either as a new T-NNN or as an explicit sub-technique of T-017.

### Note 3: On-Disk Patching of System DLLs for Persistent AV Bypass
- **id**: `lgtm:on-disk-patching-system-dlls`
- **origin**: atlas-post-exploit-part11
- **source_units**: ['unit 19']
- **would_relate_to**: ['T-016']
- **tags**: ['on-disk-patching', 'ntdll', 'integrity', 'persistence', 'cascading-risk']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part11
**Would relate to:** T-016
**Source units:** unit 19

SEC670 raises on-disk patching of system binaries (potentially including Ntdll.dll and signature-scanning binaries) as a persistence mechanism that survives reboot unlike in-memory unhooking. T-016 documents NTDLL .text restoration (in-memory unhooking) but does not document the on-disk equivalent. The technique has documented cascading risks (system instability, faster detection by file integrity monitoring, harder to undo) that distinguish it operationally from the in-memory variant.

---

## Your Task

Produce the technique card for **T-039** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-039` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017', 'T-006', 'T-021'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:proposed-binary-patching-technique', 'lgtm:proposed-technique-binary-patching-persistence', 'lgtm:on-disk-patching-system-dlls']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.