# Cluster Spec — T-035: Port Monitor (AddMonitor) Persistence via Print Spooler

You are generating a HUGIN technique card. This spec is your primary directive.

## Assigned Card Metadata

- **T-NNN ID**: `T-035`
- **Canonical name**: Port Monitor (AddMonitor) Persistence via Print Spooler
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — 5 member notes, SYSTEM-context persistence, distinct print-spooler vector not covered in T-017.
- **would_relate_to** (existing T-NNN to cross-reference): ['T-017']

## Consolidated Description (from clustering)

Port Monitor persistence via AddMonitor API and _MONITORINFO_2 structure. Malicious port monitor DLL loaded into spoolsv.exe with SYSTEM privileges on every spooler start. Survives reboot; distinct from service-based persistence and other T-017 layers.

## Member LGTM Notes (6)

Each note below was independently surfaced by the atlas synthesis pass. Read them all — technical details vary across notes.

### Note 1: Port Monitor (AddMonitor / Print Spooler) Persistence
- **id**: `lgtm:port-monitor-print-spooler-persistence`
- **origin**: atlas-binary-analysis-part5
- **source_units**: ['unit 18']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'port-monitor', 'print-spooler', 'system', 'addmonitor']

**Kind:** proposed-technique
**Origin:** atlas-binary-analysis-part5
**Would relate to:** T-017
**Source units:** unit 18

SEC670 unit 18 documents the AddMonitor API and _MONITORINFO_2 structure for installing a local port monitor. A malicious port monitor DLL loaded by the spooler service executes in SYSTEM context and is enumerated at every spooler restart. The vault's T-017 persistence suite currently enumerates COM hijack, NTFS EA, scheduled task, TLS callback, and PhantomPersist layers but does not include print monitor / port monitor persistence as a distinct layer. This deserves its own card or its own entry in the T-017 layer catalog because the trigger (spooler service) and the persistence context (SYSTEM) differ from the existing layers.

### Note 2: Port Monitor Print Spooler Persistence
- **id**: `lgtm:proposed-port-monitor-persistence`
- **origin**: atlas-exploit-dev-part22
- **source_units**: ['unit 19', 'unit 20']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'port-monitor', 'spooler', 'system', 'coverage-gap']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part22
**Would relate to:** T-017
**Source units:** unit 19, unit 20

SEC670 dedicates a module to Port Monitor source code as a SYSTEM-context persistence tradecraft. T-017's persistence suite documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include the print spooler Port Monitor vector. This would merit its own entry or a sub-technique under T-017 because it operates in spoolsv.exe (SYSTEM), uses a different installation primitive (registry + spooler restart), and has distinct Sysmon detection characteristics.

### Note 3: Port Monitor DLL as a Standalone Persistence Technique
- **id**: `lgtm:proposed-port-monitor-persistence-card`
- **origin**: atlas-exploit-dev-part24
- **source_units**: ['unit 25']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'port-monitor', 'print-spooler', 'system', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part24
**Would relate to:** T-017
**Source units:** unit 25

SEC670 dedicates a source code review module (Unit 25) to implementing a Port Monitor DLL for Print Spooler persistence. The vault's T-017 Five-Layer Persistence card covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — but does not surface Port Monitor as a distinct SYSTEM-privilege, reboot-persistent primitive. Given Stuxnet used this exact mechanism and the spooler runs at SYSTEM with auto-restart semantics, it warrants standalone coverage with detection surface and cleanup tradeoffs.

### Note 4: AddMonitor Port Monitor Persistence as a Standalone T-NNN
- **id**: `lgtm:port-monitor-addmonitor-persistence`
- **origin**: atlas-exploit-dev-part4
- **source_units**: ['unit 31']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'port-monitor', 'addmonitor', 'print-spooler', 'system']

**Kind:** proposed-technique
**Origin:** atlas-exploit-dev-part4
**Would relate to:** T-017
**Source units:** unit 31

SEC670 documents AddMonitor with MONITOR_INFO_2 as a persistence mechanism that loads an attacker DLL into spoolsv.exe (SYSTEM context) on every print spooler start. The vault's T-017 Five-Layer Persistence covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include print spooler / port monitor persistence. This is a distinct primitive with its own detection surface (Sysmon Event 7 on spoolsv.exe loading a non-driver-store DLL) and reboot survival in a SYSTEM process — it would merit a dedicated card or an explicit extension to T-017.

### Note 5: AddMonitor Port Monitor Persistence
- **id**: `lgtm:port-monitor-persistence`
- **origin**: atlas-labs-part1
- **source_units**: ['unit 35']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'port-monitor', 'spooler', 'addmonitor', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-labs-part1
**Would relate to:** T-017
**Source units:** unit 35

Unit 35 explicitly identifies AddMonitor (vs. CreateNewMonitor or AddNewMonitor) as the correct API to install a port monitor. Port monitor persistence survives reboot inside spoolsv.exe and is a recognized tradecraft distinct from T-017's persistence layers, which target userland and boot-time triggers rather than service-hosted monitor DLLs. The vault has no card covering spooler-based persistence and would benefit from one.

### Note 6: Print Spooler Port Monitor Persistence
- **id**: `lgtm:port-monitor-persistence-card`
- **origin**: atlas-post-exploit-part12
- **source_units**: ['unit 24', 'unit 25', 'unit 26', 'unit 28', 'unit 29']
- **would_relate_to**: ['T-017']
- **tags**: ['persistence', 'port-monitor', 'spoolsv', 'print-spooler', 'coverage-gap', 'proposed-technique']

**Kind:** proposed-technique
**Origin:** atlas-post-exploit-part12
**Would relate to:** T-017
**Source units:** unit 24, unit 25, unit 26, unit 28, unit 29

SEC670 units 24–29 cover the Print Spooler port monitor persistence vector in depth — registering a malicious DLL as a port monitor under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors to gain spoolsv.exe-hosted execution at service startup. The vault has no technique card covering spoolsv.exe-hosted persistence or the broader Print Spooler abuse surface, which has historical weight (PrintNightmare lineage).

---

## Your Task

Produce the technique card for **T-035** following the system prompt's Output template exactly.

Sequence:
1. Use `id: T-035` in the YAML frontmatter — this is the assigned ID, do not change it.
2. Use the canonical name and category above as strong defaults (you may adjust if the atlas material clearly supports a different choice — explain in the Why It Matters section if you do).
3. Cross-reference the T-NNN cards in `would_relate_to` = ['T-017'] in your Related Techniques section.
4. If matching Rust source files are included, verify each actually implements this technique before referencing it. False attribution corrupts the source_file frontmatter — better to say 'no current implementation' than to attribute wrongly.
5. Include the exact member_notes list in the frontmatter:
   `member_notes: ['lgtm:port-monitor-print-spooler-persistence', 'lgtm:proposed-port-monitor-persistence', 'lgtm:proposed-port-monitor-persistence-card', 'lgtm:port-monitor-addmonitor-persistence', 'lgtm:port-monitor-persistence', 'lgtm:port-monitor-persistence-card']`

Follow all rules in the system prompt: no fanboy language, no ratings, no suggestions/variant sections, material is authority, exact section structure, minimum 800 words body.