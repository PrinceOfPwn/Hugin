## Synthesis Summary

This batch of 37 units from SANS SEC670 (Books 1–5) is dominated by navigational content — course roadmaps, table-of-contents pages, and review-question slides — with limited substantive technical depth. The on-theme signal that does surface maps to four HUGIN technique areas: **T-016 (EDR Evasion Suite)** via Section 5 topics (custom loaders, NTDLL unhooking, AMSI bypass, AV/EDR bypass), **T-017 (Five-Layer Persistence)** via Section 4 persistence mechanisms (IFEO, Port Monitors, WMI Event Subscriptions, services, registry keys), **T-012 / T-013 (Early Cascade / Early Bird APC injection)** via the APC injection lab introduction, and **T-023 (Client Capabilities)** via Section 2 recon topics (WTSEnum, CreateToolhelp, OS info, process enumeration). Unit 3 surfaces PE-sieve as a defensive tool that detects injected implants, which is detection-relevant to the broader T-007 injection family. The training material fills a knowledge gap mostly at the topic-area level — naming which persistence and evasion tradecraft categories SEC670 teaches — rather than at the implementation-internals level the vault's source-code-reading audience typically needs. Roughly 30 of 37 units are administrative/navigational duplicates (Section 4 and Section 5 course roadmaps repeat across multiple units); no units were skipped as off-theme, but the substantive contribution density is low.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "concept-custom-loader"
    target: "concept-ntdll-unhooking"
    type: chains_to
    rationale: "SEC670 Section 5 roadmap sequences custom loader development (Lab 5.1) before unhooking hooks (Lab 5.2), implying the loader is the host for the unhooking routine."
  - source: "concept-ntdll-unhooking"
    target: T-016
    type: concept_link
    rationale: "Unhooking Hooks is listed as a Section 5 module; T-016 includes NTDLL .text restoration as a documented evasion technique."
  - source: "concept-amsi-bypass"
    target: T-016
    type: concept_link
    rationale: "Lab 5.4 'AMSI No More' corresponds to the AMSI bypass entry in T-016's evasion suite."
  - source: "concept-pe-sieve"
    target: T-007
    type: detects
    rationale: "Unit 3 explicitly identifies PE-sieve as a tool for detecting injected implants, which directly observes the process-injection techniques cataloged under T-007."
  - source: "concept-pe-sieve"
    target: T-008
    type: detects
    rationale: "PE-sieve's injected-implant detection scope applies to threadless injection as well, where foreign code is staged in a hijacked export region."
  - source: "concept-wmi-event-subscription"
    target: T-017
    type: concept_link
    rationale: "WMI Event Subscriptions appear in the SEC670 Section 4 persistence roadmap; T-017's persistence suite covers multiple persistence layers and WMI Event Subscription is a canonical Windows persistence vector that belongs in that space."
  - source: "concept-ifeo-persistence"
    target: T-017
    type: concept_link
    rationale: "IFEO (Image File Execution Options) is explicitly listed as a Section 4 persistence lab (IFEOPersist); maps to T-017 persistence suite."
  - source: "concept-apc-injection"
    target: T-012
    type: alternative_to
    rationale: "Unit 18 introduces an APC injection lab; Early Cascade (T-012) is a pre-LdrInitializeThunk APC injection variant that falls under the APC injection family."
```

### Concept Nodes

```yaml
concepts:
  - id: "windows-dispatcher-quantum"
    name: "Windows Dispatcher and Thread Quantum"
    category: os-internal
    description: "The Windows dispatcher is a preemptive, priority-based scheduler. Threads are assigned priorities and run for a fixed number of clock cycles called a quantum. A higher-priority thread leaving its waiting state and becoming ready preempts any lower-priority thread currently in its quantum. Thread state transitions between Running, Ready, and Waiting govern when user-mode APCs can be delivered, since APCs require the target thread to enter an alertable wait state."
    relevant_to: [T-012, T-013]
    tags: [scheduler, thread-state, apc, windows-internals, dispatcher]

  - id: "ethread-kernel-object-residency"
    name: "Thread Object Residency in System (Kernel) Space"
    category: windows-structure
    description: "Newly created thread objects reside in system (kernel) space, not user space or the process handle table. The ETHREAD/KTHREAD structures are kernel objects managed by the executive. User-mode code interacts with them only through opaque handles returned by NtCreateThreadEx. This residency underpins why thread hijacking, APC queuing, and thread-context manipulation all require NT syscalls and cannot be performed via Win32 userland APIs alone."
    relevant_to: [T-012, T-013, T-007]
    tags: [ethread, kthread, kernel-object, thread, windows-internals]

  - id: "concept-pe-sieve"
    name: "PE-sieve Memory Scanner"
    category: defense-mechanism
    description: "PE-sieve is an open-source memory scanner that detects injected implants by walking process memory and comparing in-memory module contents against their on-disk counterparts. It flags modified .text sections, unbacked executable regions, and replaced module content. The tool operates from user mode by default and is therefore subject to the same handle-access constraints as EDR userland scanners."
    relevant_to: [T-007, T-008, T-013]
    tags: [memory-scan, detection, pe-sieve, unbacked, injection-detection]

  - id: "concept-wmi-event-subscription"
    name: "WMI Event Subscription Persistence"
    category: attack-pattern
    description: "WMI Event Subscriptions are a persistence mechanism that combines an EventFilter (a query describing the triggering condition), an EventConsumer (an action to take — typically CommandLineEventConsumer or ActiveScriptEventConsumer), and a FilterToConsumerBinding linking them. The subscription executes asynchronously when the filter condition is met, with no requirement for an interactive logon. SEC670 lists this as a Section 4 persistence lab."
    relevant_to: [T-017]
    tags: [persistence, wmi, event-subscription, attack-pattern]

  - id: "concept-ifeo-persistence"
    name: "Image File Execution Options Persistence"
    category: attack-pattern
    description: "Image File Execution Options (IFEO) is a registry subtree under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options that supports a Debugger value. When a process matching the IFEO subkey name is launched, the debugger value is executed instead, allowing an attacker to redirect execution to a malicious payload on every invocation of the targeted binary. SEC670 documents this as Lab 4.3 'IFEOPersist'."
    relevant_to: [T-017]
    tags: [persistence, ifeo, registry, attack-pattern]

  - id: "concept-port-monitor-persistence"
    name: "Port Monitor Persistence"
    category: attack-pattern
    description: "Port Monitors are print spooler components registered under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors. A malicious DLL registered as a Port Monitor is loaded by the print spooler service (spoolsv.exe), which runs as SYSTEM, on service start. The technique persists across reboots and runs in a privileged context. SEC670 lists Port Monitors as a Section 4 persistence topic."
    relevant_to: [T-017]
    tags: [persistence, port-monitor, print-spooler, system-privilege]

  - id: "concept-ntdll-unhooking"
    name: "NTDLL Unhooking (SEC670 framing)"
    category: attack-pattern
    description: "SEC670's Section 5 lab 'UnhookTheHook' frames NTDLL unhooking as restoring the ntdll.dll .text section to a clean state to defeat userland API hooks placed by AV/EDR. The course positions this as a prerequisite evasion step before additional AV/EDR bypass techniques are layered on."
    relevant_to: [T-016]
    tags: [ntdll-unhook, evasion, edr-bypass]

  - id: "concept-amsi-bypass"
    name: "AMSI Bypass (SEC670 framing)"
    category: attack-pattern
    description: "SEC670's Section 5 lab 'AMSI No More' covers bypassing the Anti-Malware Scan Interface. AMSI is a Windows service interface that allows registered AV products to scan script content from PowerShell, VBA, and similar script engines. Bypass approaches typically target amsi.dll in the script host process."
    relevant_to: [T-016]
    tags: [amsi, evasion, script-bypass]

  - id: "concept-custom-loader"
    name: "Custom Loader Development"
    category: attack-pattern
    description: "SEC670's Section 5 opens with custom loader development (Lab 5.1: The Loader) as the foundation for staging shellcode, applying evasion, and establishing C2. The loader is positioned as the host component that integrates subsequent evasion modules (unhooking, AMSI bypass) before the implant calls home."
    relevant_to: [T-016, T-013]
    tags: [loader, dropper, tradecraft, staging]

  - id: "concept-wtsenum-proctoolhelp-recon"
    name: "WTSEnumProcesses and CreateToolhelp32Snapshot Recon"
    category: attack-pattern
    description: "WTSEnumProcesses enumerates processes on a WTS session (including other sessions on the same host) and returns per-process SID information. CreateToolhelp32Snapshot takes a snapshot of process, thread, heap, and module state. SEC670 Section 2 covers both as primary recon primitives for implant situational awareness — enumerating processes to identify targets for injection, defense-relevant processes, and adversary tooling already in the environment."
    relevant_to: [T-023]
    tags: [recon, process-enumeration, wtsenum, createtoolhelp32snapshot]

  - id: "concept-windows-update-agent-recon"
    name: "Windows Update Agent API for Patch Recon"
    category: attack-pattern
    description: "The Windows Update Agent (WUA) API exposes interfaces (notably IWindowsUpdateAgent) that can enumerate installed hotfixes and service packs. SEC670 identifies WUA as the API family used to query hotfixes, used by implants to determine patch level and infer whether specific privilege-escalation or kernel-exploit paths are viable on a target."
    relevant_to: [T-023]
    tags: [recon, hotfix, patch-level, wua]
```

### Detection Insights

```yaml
detection:
  - indicator: "PE-sieve flagged modified module .text section or unbacked executable region"
    source: memory-scan
    confidence: high
    relevant_to: [T-007, T-008, T-013]
    description: "PE-sieve walks process memory and identifies regions where in-memory module content diverges from the on-disk PE file (module stomping, function stomping, .text patches) and regions with execute permissions that have no on-disk file backing (VadS nodes). Output is per-process and per-region, naming the suspicious module or describing the unbacked allocation. Run as a periodic host scan, typically user-mode."
    bypassed_by: "Mapping shellcode as a SEC_IMAGE section backed by a real file path (module overloading with a legitimate file) produces a VAD node that PE-sieve's unbacked-region heuristic does not flag. Stack-spoofed and module-stomped payloads still produce .text divergence that PE-sieve catches unless the on-disk file is also modified to match."

  - indicator: "WMI Event Subscription registered (__EventFilter, __EventConsumer, __FilterToConsumerBinding)"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon EID 19 (WmiEventFilter), EID 20 (WmiEventConsumer), and EID 21 (WmiEventConsumerToFilter) log the registration of WMI event subscription components with their queries, consumer types, and binding relationships. The events appear in the Microsoft-Windows-Sysmon/Operational channel. A persistent implant using WMI Event Subscription will generate one event of each type at registration time."
    bypassed_by: "not discussed — SEC670 Section 4 only lists WMI Event Subscriptions as a topic in the roadmap without covering evasion of the corresponding Sysmon telemetry."

  - indicator: "IFEO Debugger value under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<binary>"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon EID 12 (RegistryEvent value set) or EID 13 (RegistryEvent value set on a specific key) captures creation of a Debugger value under an IFEO subkey. The event includes the registry path, value name, and the data (the payload path or command line)."
    bypassed_by: "not discussed"

  - indicator: "Port Monitor registered under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\<name> with a Driver value pointing to a DLL"
    source: sysmon
    confidence: medium
    relevant_to: [T-017]
    description: "Sysmon EID 12/13 registry events capture the addition of a Port Monitor subkey and its Driver value. A subsequent Sysmon EID 7 (Image loaded) event captures spoolsv.exe loading the named DLL at service start. Correlating the registry write with a subsequent load by spoolsv.exe is a high-signal indicator."
    bypassed_by: "not discussed"

  - indicator: "AMSI content scan flagged as malicious in Microsoft-AntiMalware-Engine log"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-016]
    description: "When AMSI is intact and a registered AV engine is present, script content passed through PowerShell, VBScript, JavaScript, or Office macros is scanned and results appear in the AMSI ETW provider (Microsoft-AntiMalware-ScanInterface, GUID {61CCAE71-8A6A-4A3A-9C10-1F0A20F7B735}) and the AV product's scan result log. The event contains a content hash and the verdict."
    bypassed_by: "Patching amsi.dll in-memory in the script host process before AMSI is queried, or running the payload through a host that does not initialize AMSI. SEC670's 'AMSI No More' lab covers bypass approaches."

sigma_ideas:
  - title: "WMI Event Subscription Persistence"
    logsource: sysmon
    condition_summary: "Sysmon EID 19, 20, or 21 with EventType WmiFilter, WmiConsumer, or WmiConsumerToFilter — particularly where ConsumerType is CommandLineEventConsumer or ActiveScriptEventConsumer"
  - title: "IFEO Debugger Persistence"
    logsource: sysmon
    condition_summary: "Sysmon EID 13 where TargetObject contains 'Image File Execution Options' and ends with '\\Debugger'"
  - title: "Malicious Port Monitor DLL"
    logsource: sysmon
    condition_summary: "Sysmon EID 12 where TargetObject startswith 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors' AND EventID 7 where Image is 'spoolsv.exe' and ImageLoaded is not a known printer driver"
  - title: "PE-sieve Detection of Unbacked Executable"
    logsource: memory-scan
    condition_summary: "PE-sieve scan result reporting unbacked executable region or replaced module .text content in a process that is not a known debugging or hooking tool"
```

### Operational Chains

```yaml
chains:
  - name: "SEC670 Section 5 Implant Build-Out Chain"
    description: "Custom loader hosts evasion modules before calling home; the canonical SEC670 Section 5 operational sequence."
    steps:
      - technique: "concept-custom-loader"
        role: "Stage and execute the implant payload from a custom loader that integrates the evasion stack"
      - technique: T-016
        role: "Restore ntdll.dll .text to clean state (UnhookTheHook) to defeat userland API hooks"
      - technique: T-016
        role: "Bypass AMSI to permit script-based payload components or LOLBin invocation"
      - technique: "calling-home"
        role: "Establish outbound C2 channel (Lab 5.3 'No Caller ID' covers call-home tradecraft)"
    notes: "SEC670 Section 5 roadmap explicitly sequences these labs in order: Loader (5.1) → UnhookTheHook (5.2) → No Caller ID (5.3) → AMSI No More (5.4) → ShadowCraft (5.5). The course does not specify which evasion modules must be present before calling home; the ordering is pedagogical."

  - name: "SEC670 Section 4 Persistence Chain"
    description: "Section 4 enumerates multiple independent persistence vectors; they are alternatives rather than a strict sequence."
    steps:
      - technique: T-017
        role: "Persistence Service (Lab 4.1) — service registration for boot-time execution"
      - technique: T-017
        role: "Sauron (Lab 4.2) — binary patching based persistence"
      - technique: T-017
        role: "IFEOPersist (Lab 4.3) — Image File Execution Options Debugger persistence"
      - technique: T-017
        role: "Port Monitors — print spooler DLL load persistence"
      - technique: T-017
        role: "WMI Event Subscriptions — event-driven persistence"
    notes: "Material presents these as a menu of persistence techniques rather than a chain. The roadmap does not specify prerequisites or inter-technique dependencies. Stacking multiple is operational choice, not a required sequence."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "wmi-event-subscription-persistence-card"
    title: "WMI Event Subscription Persistence as Standalone Card"
    kind: proposed-technique
    description: "SEC670 Section 4 dedicates a persistence module to WMI Event Subscriptions (EventFilter + EventConsumer + FilterToConsumerBinding). T-017 currently covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not list WMI Event Subscription as a documented persistence layer. WMI Event Subscription is operationally distinct from these — it requires WMI namespace write access, has unique detection surface (Sysmon EID 19/20/21), and supports event-triggered execution rather than boot/logon-triggered. Deserves standalone treatment within or alongside T-017."
    would_relate_to: [T-017]
    source_units: ["unit 19", "unit 20", "unit 21"]
    tags: [persistence, wmi, event-subscription, coverage-gap]

  - id: "ifoe-and-port-monitor-persistence-coverage"
    title: "IFEO and Port Monitor Persistence Techniques"
    kind: coverage-gap
    description: "SEC670 Section 4 explicitly covers IFEO Debugger persistence (Lab 4.3 'IFEOPersist') and Port Monitors as persistence vectors. Neither appears by name in the T-017 persistence suite enumeration. These are canonical, well-documented Windows persistence primitives that the vault's persistence card would benefit from explicitly cataloging — particularly since each has distinct Sysmon telemetry (IFEO Debugger registry write; Port Monitor DLL load by spoolsv.exe)."
    would_relate_to: [T-017]
    source_units: ["unit 20", "unit 21", "unit 22", "unit 24", "unit 25", "unit 26", "unit 28", "unit 29", "unit 30"]
    tags: [persistence, ifeo, port-monitor, coverage-gap]

  - id: "custom-loader-development-tradecraft"
    title: "Custom Loader Development as a Tradecraft Area"
    kind: coverage-gap
    description: "SEC670 Section 5 opens with 'Custom Loaders' as a dedicated module, treating loader development as a discipline distinct from evasion or C2. The vault's dark_crystal crate contains loader infrastructure (src/loader/mod.rs, src/transport.rs, src/runner.rs multi-phase runner) but does not have a dedicated technique card for the loader construct itself — T-022 (architecture) is the closest reference. A loader-focused card would document staging, payload acquisition (embedded vs remote), phase sequencing, and integration points for evasion modules."
    would_relate_to: [T-016, T-013]
    source_units: ["unit 32", "unit 34", "unit 35", "unit 36", "unit 37"]
    tags: [loader, dropper, tradecraft, coverage-gap]

  - id: "pe-sieve-as-detection-reference"
    title: "PE-sieve as Defensive Reference Tool"
    kind: coverage-gap
    description: "SEC670 Unit 3 names PE-sieve as a community-driven defensive tool for detecting injected implants. The vault currently documents detection from the EDR perspective (ETW-TI, kernel callbacks, userland hooks) but does not reference standalone open-source scanners that operators and defenders run independently of EDR. A detection concept node for PE-sieve is added here; a future LGTM consideration is whether the vault's detection sections should systematically cross-reference open-source scanner capabilities alongside EDR telemetry."
    would_relate_to: [T-007, T-008, T-013]
    source_units: ["unit 3"]
    tags: [detection, pe-sieve, memory-scan, coverage-gap]

  - id: "section4-roadmap-content-redundancy"
    title: "Section 4 Roadmap Duplication in Source Material"
    kind: cross-source-convergence
    description: "Units 20–30 are near-identical repetitions of the SEC670 Section 4 course roadmap slide (In Memory Execution, Binary Patching, Registry Keys, Services, Port Monitors, IFEO, WMI Event Subscriptions). This indicates the roadmap slide is reused as a section opener across multiple lectures but carries no additional content per repetition. Graph ingestion of future SEC670 batches should treat duplicate roadmap slides as a single contribution rather than 10 separate data points."
    would_relate_to: []
    source_units: ["unit 20", "unit 21", "unit 22", "unit 23", "unit 24", "unit 26", "unit 28", "unit 29", "unit 30"]
    tags: [meta, redundancy, roadmap, sec670]
```