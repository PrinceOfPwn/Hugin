# Cluster Spec — T-034: IFEO GlobalFlag and SilentProcessExit Registry Persistence

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-034`
- **Canonical name**: IFEO GlobalFlag and SilentProcessExit Registry Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — 8 member notes (strong cross-source signal), two distinct persistence triggers, clear operational value.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017']

## Consolidated Description (from clustering)

IFEO persistence via Debugger key (redirects launches to malicious binary) and GlobalFlag/SilentProcessExit (executes recovery command on exit). Registry-resident under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary>. Admin/SYSTEM required; survives reboot.

## Member LGTM Notes (8)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: IFEO GlobalFlag and Silent Process Exit as Persistence Primitives
- **id**: `lgtm:ifeo-silent-process-exit-persistence`
- **origin**: atlas-edr-evasion-part2
- **source_units**: ['unit 7', 'unit 8', 'unit 9', 'unit 10', 'unit 11', 'unit 12', 'unit 13', 'unit 14']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'ifeo', 'globalflag', 'silent-process-exit', 'gflags', 'proposed']

**Kind:** proposed-technique
**Origin:** atlas-edr-evasion-part2
**Would relate to:** T-017
**Source units:** unit 7, unit 8, unit 9, unit 10, unit 11, unit 12, unit 13, unit 14

SEC670 devotes multiple units to IFEO GlobalFlag and Silent Process Exit as abuse targets. The vault's T-017 persistence suite does not document IFEO as a layer. These primitives are gated on Admin/SYSTEM and produce per-process triggers distinct from COM hijack and schtask. Worth a dedicated card or a T-017 extension documenting programmatic setup via the IFEO registry subtree.

### Note 2: Image File Execution Options (IFEO) Debugger Persistence
- **id**: `lgtm:ifeo-debugger-persistence`
- **origin**: atlas-methodology-part4
- **source_units**: ['unit 9', 'unit 13', 'unit 14', 'unit 15', 'unit 16']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'ifeo', 'registry', 'debugger', 'accessibility-binary', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-methodology-part4
**Would relate to:** T-017
**Source units:** unit 9, unit 13, unit 14, unit 15, unit 16

SEC670 Section 4 dedicates two labs (4.2 Sauron, 4.3 IFEOPersisto) to IFEO-based persistence. The vault's T-017 Five-Layer Persistence card documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include IFEO. IFEO is a distinct persistence vector operating through the HKLM Image File Execution Options registry key, redirecting target executable launch to an attacker-specified Debugger binary. The mechanism is reusable across accessibility binary hijacks (sethc, utilman), security tool redirects, and arbitrary target hijack.

### Note 3: Image File Execution Options Persistence
- **id**: `lgtm:proposed-ifeo-persistence`
- **origin**: atlas-misc-part1
- **source_units**: ['unit 2', 'unit 28']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'ifeo', 'registry', 'debugger-hijack', 'proposed']

**Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 2, unit 28

SEC670 dedicates Lab 4.2 (Sauron IFEO) and Lab 4.3 (IFEOPersisto) to IFEO persistence with two variants documented: 'process start' (debugger redirect on launch) and 'silent.exe'. The vault's T-017 does not document IFEO. IFEO persistence is distinct enough — uses Debugger/GlobalFlag registry values rather than COM hijack or schtask — to merit its own T-NNN card.

### Note 4: Image File Execution Options Persistence as a Distinct Technique Card
- **id**: `lgtm:ifeo-persistence-card`
- **origin**: atlas-post-exploit-part7
- **source_units**: ['unit 9', 'unit 10', 'unit 11', 'unit 12', 'unit 13', 'unit 14', 'unit 15', 'unit 16', 'unit 17', 'unit 18', 'unit 19', 'unit 20', 'unit 21', 'unit 22', 'unit 23', 'unit 24', 'unit 25', 'unit 26', 'unit 27', 'unit 28', 'unit 29', 'unit 30', 'unit 31', 'unit 32', 'unit 33', 'unit 34', 'unit 35']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'ifeo', 'debugger', 'silent-process-exit', 'globalflag', 'registry', 'proposed-technique', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part7
**Would relate to:** T-017
**Source units:** unit 9, unit 10, unit 11, unit 12, unit 13, unit 14, unit 15, unit 16, unit 17, unit 18, unit 19, unit 20, unit 21, unit 22, unit 23, unit 24, unit 25, unit 26, unit 27, unit 28, unit 29, unit 30, unit 31, unit 32, unit 33, unit 34, unit 35

SEC670 covers IFEO persistence across two variants (Debugger for process start, SilentProcessExit for process exit) with substantial depth: registry key paths, GlobalFlag value 512, ReportingMode/MonitorProcess structure, gflags.exe usage, Win32 Registry API implementation, target process selection rationale (userinit.exe for boot-early execution), and Admin/SYSTEM permission requirements. The vault's T-017 does not include IFEO. This would merit its own T-NNN card given the two distinct trigger mechanisms (process start vs process exit) and the operational tradecraft around target selection.

### Note 5: IFEO Persistence (Debugger + SilentProcessExit)
- **id**: `lgtm:proposed-ifeo-persistence-suite`
- **origin**: atlas-post-exploit-part15
- **source_units**: ['unit 8', 'unit 9', 'unit 10', 'unit 11', 'unit 12', 'unit 13', 'unit 14', 'unit 15']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'ifeo', 'debugger', 'silentprocessexit', 'registry', 'event-driven']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part15
**Would relate to:** T-017
**Source units:** unit 8, unit 9, unit 10, unit 11, unit 12, unit 13, unit 14, unit 15

SEC670 Lab 4.3 (IFEOPersisto) covers IFEO persistence in two distinct variants: the Debugger key (triggered by target process start) and the SilentProcessExit key (triggered by target process exit). The vault's T-017 does not include either. These merit a dedicated card because they are registry-only (no binary staging on disk beyond the payload itself), event-driven (no scheduler), and survive reboot. The two variants have distinct trigger conditions and detection signatures.

### Note 6: IFEO / SilentProcessExit Registry Persistence
- **id**: `lgtm:ifeo-silentprocessexit-persistence-card`
- **origin**: atlas-post-exploit-part12
- **source_units**: ['unit 31', 'unit 32', 'unit 35', 'unit 38', 'unit 39']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'ifeo', 'silentprocessexit', 'registry', 'globalflag', 'coverage-gap', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part12
**Would relate to:** T-017
**Source units:** unit 31, unit 32, unit 35, unit 38, unit 39

SEC670 units 31–40 detail both IFEO Debugger-value persistence and SilentProcessExit MonitorProcess persistence, including the GlobalFlag=512 → ReportingMode=1 → MonitorProcess=<path> registry sequence. The vault's T-017 card does not include IFEO or SilentProcessExit as layers — these are operationally distinct because they trigger on victim process launch/exit events rather than time or boot, making them useful for targeted persistence on specific monitored processes.

### Note 7: SilentProcessExit Registry Trigger Persistence
- **id**: `lgtm:silentprocessexit-trigger-persistence`
- **origin**: atlas-labs-part1
- **source_units**: ['unit 36']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'silentprocessexit', 'registry', 'process-termination', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-labs-part1
**Would relate to:** T-017
**Source units:** unit 36

Unit 36 references SilentProcessExit as a registry key that can watch for process termination. The same key is abuseable as a persistence mechanism by configuring ReportingMode and MonitorProcess values to relaunch an implant when a sacrificial process exits. The vault does not currently document this capability, and it sits at the intersection of T-017 (persistence) and process-lifecycle monitoring.

### Note 8: Silent Process Exit via GlobalFlag Persistence
- **id**: `lgtm:proposed-silent-process-exit-persistence`
- **origin**: atlas-misc-part1
- **source_units**: ['unit 11', 'unit 12', 'unit 22', 'unit 23', 'unit 27']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'silent-process-exit', 'globalflag', 'gflags', 'exit-trigger', 'proposed']

**Kind:** proposed-technique
**Origin:** atlas-misc-part1
**Would relate to:** T-017
**Source units:** unit 11, unit 12, unit 22, unit 23, unit 27

SEC670 covers Silent Process Exit configured via Gflags.exe / GlobalFlag registry key as a process-exit-triggered persistence mechanism distinct from boot-time or launch-time persistence. Units 11, 12, 22, 23, 27 document the configuration via GflagsX GUI tool. The vault has no card for exit-triggered persistence primitives. Would relate to T-017 as an additional persistence layer with a different trigger condition.

---

## Your Task

Produce the technique card for **T-034** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-034` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:ifeo-silent-process-exit-persistence', 'lgtm:ifeo-debugger-persistence', 'lgtm:proposed-ifeo-persistence', 'lgtm:ifeo-persistence-card', 'lgtm:proposed-ifeo-persistence-suite', 'lgtm:ifeo-silentprocessexit-persistence-card', 'lgtm:silentprocessexit-trigger-persistence', 'lgtm:proposed-silent-process-exit-persistence']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.