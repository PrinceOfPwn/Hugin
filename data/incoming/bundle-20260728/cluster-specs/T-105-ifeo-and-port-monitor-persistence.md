# Cluster Spec — T-105: IFEO Debugger and Port Monitor DLL Persistence

- **T-NNN ID**: `T-105`
- **Canonical name**: IFEO Debugger and Port Monitor DLL Persistence
- **Proposed category**: `persistence`
- **Proposed tier**: `A`
- **Priority**: high — 4 member notes from independent batches, named techniques with public tooling and lab exercises
- **would_relate_to**: ['T-017']

## Consolidated Description

SEC670's Section 4 persistence curriculum covers two registry-driven autostart mechanisms absent from T-017: Image File Execution Options (IFEO) Debugger value and Port Monitor DLLs. IFEO persistence writes HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>\Debugger to redirect process launch into an attacker binary (Lab 4.3 'IFEOPersist'). Port Monitor persistence installs a DLL via the AddMonitor() API into HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver, which the Print Spooler service loads at spooler initialization. Both are file-less, event-driven persistence vectors triggered by legitimate system events (process launch, spooler restart) rather than scheduled timers. Multiple SEC670 modules independently converge on these as standalone techniques distinct from Run keys or COM hijack.


## Member LGTM Notes (4)

### Note 1: T-017 Persistence Suite Missing IFEO, Port Monitor, and WMI Event Subscription Layers
- id: `lgtm:coverage-gap-persistence-layer-ifoe-portmon-wmi`
- origin: atlas-methodology-part8
- would_relate_to: ['T-017']
- tags: ['persistence', 'ifeo', 'port-monitor', 'wmi', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part8
**Would relate to:** T-017
**Source units:** unit 16, unit 17, unit 18, unit 19, unit 20, unit 22, unit 24

SEC670 Section 4 (units 15-24) covers a persistence curriculum that includes In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Services Revisited, Port Monitors, IFEO, and WMI Event Subscriptions. The vault's T-017 Five-Layer Persistence card documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — but does not surface IFEO, Port Monitor, or WMI Event Subscription as persistence layers. These are well-established Windows persistence techniques with distinct registry and WMI-namespace footprints and would strengthen the persistence card's coverage.

### Note 2: IFEO and Port Monitor Persistence Techniques
- id: `lgtm:ifoe-and-port-monitor-persistence-coverage`
- origin: atlas-methodology-part9
- would_relate_to: ['T-017']
- tags: ['persistence', 'ifeo', 'port-monitor', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-methodology-part9
**Would relate to:** T-017
**Source units:** unit 20, unit 21, unit 22, unit 24, unit 25, unit 26, unit 28, unit 29, unit 30

SEC670 Section 4 explicitly covers IFEO Debugger persistence (Lab 4.3 'IFEOPersist') and Port Monitors as persistence vectors. Neither appears by name in the T-017 persistence suite enumeration. These are canonical, well-documented Windows persistence primitives that the vault's persistence card would benefit from explicitly cataloging — particularly since each has distinct Sysmon telemetry (IFEO Debugger registry write; Port Monitor DLL load by spoolsv.exe).

### Note 3: IFEO and Port Monitor Persistence Coverage Gap
- id: `lgtm:ifeo-and-port-monitor-coverage`
- origin: atlas-post-exploit-part1
- would_relate_to: ['T-017']
- tags: ['persistence', 'ifeo', 'port-monitor', 'coverage-gap']

**Kind:** coverage-gap
**Origin:** atlas-post-exploit-part1
**Would relate to:** T-017
**Source units:** unit 13, unit 34, unit 35

SEC670 covers IFEO Debugger value persistence (targeting userinit.exe and similar boot processes) and print-spooler port-monitor DLL persistence as standalone techniques. T-017 lists COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include IFEO or port monitors. Both are well-documented in MITRE ATT&CK T1546.012 and T1547.001 and have distinctive registry-write detection signatures. The vault under-covers the persistence-surface breadth that operators actually choose among.

### Note 4: Persistence Layer Cross-Source Convergence
- id: `lgtm:persistence-layer-cross-source-convergence`
- origin: atlas-post-exploit-part12
- would_relate_to: ['T-017']
- tags: ['persistence', 'convergence', 'tradecraft', 'coverage']

**Kind:** cross-source-convergence
**Origin:** atlas-post-exploit-part12
**Would relate to:** T-017
**Source units:** unit 1, unit 24, unit 31, unit 39

Multiple SEC670 modules (services, port monitors, IFEO, in-memory execution) converge on the same operational pattern as the vault's T-017 persistence suite — install a stealthy autostart primitive gated by Admin/SYSTEM that survives reboot. This convergence indicates the persistence surface extends well beyond the five T-017 layers and warrants either an expanded card or a sibling-card structure grouping persistence vectors by trigger type (boot / logon / process-event / scheduled).

---
Use `id: T-105`, canonical name above, and `member_notes: ['lgtm:coverage-gap-persistence-layer-ifoe-portmon-wmi', 'lgtm:ifoe-and-port-monitor-persistence-coverage', 'lgtm:ifeo-and-port-monitor-coverage', 'lgtm:persistence-layer-cross-source-convergence']`.
Cross-reference `would_relate_to`: ['T-017'] in Related Techniques.
Verify any Rust source files actually implement this technique before attributing.