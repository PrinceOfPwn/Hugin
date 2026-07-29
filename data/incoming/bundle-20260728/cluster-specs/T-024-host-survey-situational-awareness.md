# Cluster Spec — T-024: Host Survey and Situational Awareness: Unified Reconnaissance

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-024`
- **Canonical name**: Host Survey and Situational Awareness: Unified Reconnaissance
- **Proposed category**: `discovery`
- **Proposed tier**: `A`
- **Priority**: high — 5 member notes, explicit SEC670 Book 2 module, foundational post-exploitation reconnaissance.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-023', 'T-020', 'T-016', 'T-022', 'T-007']

## Consolidated Description (from clustering)

Unified host survey encompassing OS version/build, service pack/patch status, process enumeration (WTSEnumerateProcessesEx, NtQuerySystemInformation), installed software discovery, services and scheduled tasks, network adapters and IP configuration, registry hive structure, user account enumeration across four domains (network adapters, registry, processes, services) with documented operational trade-offs. Aggregates tactical reconnaissance data for target assessment and technique selection.

## Member LGTM Notes (5)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Host Survey Script as a Unified Recon Capability
- **id**: `lgtm:host-survey-script-primitive`
- **origin**: atlas-recon-part1
- **source_units**: ['unit 19', 'unit 20', 'unit 21']
- **would_relate_to**: ['T-023', 'T-020', 'T-022', 'T-007']
- **tags**: ['recon', 'survey', 'tradecraft', 'operational-decision', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-recon-part1
**Would relate to:** T-023, T-020, T-022, T-007
**Source units:** unit 19, unit 20, unit 21

SEC670 dedicates an entire Section 2 to the host survey — a unified operational primitive that aggregates OS version, patch status, process list, installed software, services/tasks, NIC state, and registry state into a single survey output. The vault currently distributes these capabilities across T-023 (Client Capabilities: recon, sysinfo), T-020 (Kaguya LOtL + EDR detection), and T-022 (network recon), with no explicit technique card documenting the survey as a coordinated first-phase action. A dedicated card would capture the SEC670 sequence and the operational-decision handoff to evasion and injection technique selection.

### Note 2: Dedicated Recon & Survey Technique Card
- **id**: `lgtm:proposed-recon-survey-card`
- **origin**: atlas-recon-part2
- **source_units**: ['unit 1', 'unit 4', 'unit 8', 'unit 15', 'unit 20', 'unit 27', 'unit 40']
- **would_relate_to**: ['T-023', 'T-020', 'T-016']
- **tags**: ['recon', 'survey', 'api-catalog', 'coverage-expansion']

**Kind:** proposed-technique
**Origin:** atlas-recon-part2
**Would relate to:** T-023, T-020, T-016
**Source units:** unit 1, unit 4, unit 8, unit 15, unit 20, unit 27, unit 40

SEC670 dedicates an entire course section to Windows survey APIs: process enumeration (WTSEnumerateProcessesEx, NtQuerySystemInformation, CreateToolhelp32Snapshot), installed-software discovery via Program Files directory walks, user/group enumeration (lmaccess.h NetAPI family), services/tasks enumeration via SCM, NIC/network enumeration via the IP Helper family, and registry survey. The vault's T-023 captures recon as a client capability but does not document the API catalog at the depth SEC670 demonstrates. A dedicated card would document the Win32 API surface, the per-API detection signature, and the recon-to-evasion decision flow.

### Note 3: Host Survey and Situational Awareness as a Standalone Technique
- **id**: `lgtm:proposed-host-survey-card`
- **origin**: atlas-recon-part4
- **source_units**: ['unit 7', 'unit 9', 'unit 14', 'unit 25', 'unit 26', 'unit 29', 'unit 38']
- **would_relate_to**: ['T-023', 'T-016', 'T-017', 'T-020']
- **tags**: ['recon', 'survey', 'coverage-gap', 'technique-proposal']

**Kind:** proposed-technique
**Origin:** atlas-recon-part4
**Would relate to:** T-023, T-016, T-017, T-020
**Source units:** unit 7, unit 9, unit 14, unit 25, unit 26, unit 29, unit 38

SEC670 dedicates an entire Book (Book 2, 'Getting to Know Your Target') to host survey: OS info, hotfixes/SPs, process enum, services, network adapters, registry hives, and user enumeration. The vault folds this into T-023 Client Capabilities under recon/sysinfo but does not elevate the survey process itself to a technique card. A dedicated survey T-NNN would let operators compose recon steps against a coherent capability rather than treating each enumeration API as an isolated T-023 sub-item, and would surface the explicit dependency: survey output gates evasion, persistence, and exploit technique selection.

### Note 4: Host Survey Recon as a Standalone Technique Card
- **id**: `lgtm:proposed-host-survey-recon-card`
- **origin**: atlas-recon-part5
- **source_units**: ['unit 1', 'unit 2', 'unit 3', 'unit 8', 'unit 11', 'unit 21', 'unit 35']
- **would_relate_to**: ['T-023', 'T-016', 'T-020']
- **tags**: ['recon', 'host-survey', 'tradecraft', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-recon-part5
**Would relate to:** T-023, T-016, T-020
**Source units:** unit 1, unit 2, unit 3, unit 8, unit 11, unit 21, unit 35

SEC670 devotes an entire book (Section 2) to host surveying: OS info, service packs, process enumeration across four API families, installed software directory walks, user enumeration, services and tasks, network info, and registry info. The vault folds recon into T-023 Client Capabilities as one capability among many, but the operational weight SEC670 places on survey-first tradecraft (gating payload selection, aborting on research-VM detection, targeting Domain Admins) suggests a dedicated T-NNN card for host-survey recon would surface tradecraft the vault currently under-documents.

### Note 5: Recon Enumeration API Surface as a Standalone Technique
- **id**: `lgtm:recon-enumeration-api-surface`
- **origin**: atlas-recon-part7
- **source_units**: ['unit 1', 'unit 2', 'unit 5', 'unit 12', 'unit 13', 'unit 16', 'unit 17']
- **would_relate_to**: ['T-023', 'T-007', 'T-017']
- **tags**: ['recon', 'enumeration', 'api-surface', 'proposed-card']

**Kind:** proposed-technique
**Origin:** atlas-recon-part7
**Would relate to:** T-023, T-007, T-017
**Source units:** unit 1, unit 2, unit 5, unit 12, unit 13, unit 16, unit 17

SEC670 dedicates an entire module to enumerating targets across four domains (network adapters, registry, processes, services) using specific Win32/NT/WTS APIs with operational trade-offs (snapshot lag, hookability, remote-vs-local). T-023 covers 'recon' at a coarse granularity but does not document the API-surface decisions an operator makes when assembling recon tradecraft. A dedicated recon-enumeration card documenting the three process-enumeration APIs, the network-adapter API ladder (GetAdapterAddresses > GetNumberOfInterfaces > GetIpStatistics), the SYSTEM_INFO fields an implant relies on, and the SDDL inspection flow would give the vault operator-grade coverage of pre-injection target selection.

---

## Your Task

Produce the technique card for **T-024** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-024` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-023', 'T-020', 'T-016', 'T-022', 'T-007'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:host-survey-script-primitive', 'lgtm:proposed-recon-survey-card', 'lgtm:proposed-host-survey-card', 'lgtm:proposed-host-survey-recon-card', 'lgtm:recon-enumeration-api-surface']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.