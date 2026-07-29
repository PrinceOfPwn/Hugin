## Synthesis Summary

This batch maps sparsely to the HUGIN vault. The substantive technical content clusters around three areas: WMI infrastructure (CIM class hierarchy, WQL query semantics, intrinsic vs extrinsic events, WMI event subscriptions as persistence), Windows security descriptor manipulation (SDDL strings, ACE types, NULL SID S-1-0-0 usage), and host-recon API enumeration (OpenProcess, WTSEnumerateProcessesEx, NtQuerySystemInformation for process info; WUA for hotfix enumeration). These connect to T-017 (Five-Layer Persistence — as a coverage gap, since the vault's persistence layers omit WMI event subscriptions, IFEO, port monitors, services, and registry Run keys), T-023 (Client Capabilities — recon primitives), and T-016 (EDR Evasion — security descriptor manipulation concepts). The remaining ~30 units are course roadmaps, table-of-contents pages, module objectives, and module summaries that do not contain extractable technical content; they were read but yielded no graph contributions. The gap this material fills is the operator's "why" behind WMI-based persistence and SDDL ACE construction, which the vault's source code alone does not surface.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "wmi-event-subscription-persistence"
    target: T-017
    type: alternative_to
    rationale: "SEC670 documents WMI event subscriptions (event filter + consumer + binding) as a persistence layer; the vault's T-017 covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but omits WMI subscriptions, making these alternative persistence vectors in the same operational role."
  - source: "ifeo-image-file-execution-options"
    target: T-017
    type: alternative_to
    rationale: "SEC670's Section 4 roadmap lists IFEO (Image File Execution Options) as a persistence module with a dedicated lab (IFEOPersist); the vault's T-017 persistence suite does not currently cover IFEO, making it an alternative persistence mechanism not yet represented."
  - source: "wql-event-query"
    target: "wmi-event-subscription-persistence"
    type: enables
    rationale: "WQL event queries (e.g., SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process') are the trigger mechanism for WMI event subscription persistence; without WQL event query semantics the subscription has no firing condition."
  - source: "sddl-null-sid-ace"
    target: T-016
    type: concept_link
    rationale: "The SDDL example granting GA (GENERIC_ALL) to S-1-0-0 (NULL SID) demonstrates security descriptor loosening that relates to the vault's T-016 handle blocking and access manipulation evasion surface; both deal with who can obtain handles to the implant process."
  - source: "wua-hotfix-enumeration"
    target: T-023
    type: enables
    rationale: "Windows Update Agent (WUA) APIs enable hotfix and patch enumeration — a recon primitive that supports the T-023 client capability of system information collection by exposing patch level gaps."
  - source: "process-enumeration-api-triad"
    target: T-023
    type: enables
    rationale: "SEC670's unit review identifies OpenProcess(), WTSEnumerateProcessesEx(), and NtQuerySystemInformation() as the API triad for obtaining process information from a PID — the foundational recon primitive feeding T-023 process discovery and injection target selection."
```

### Concept Nodes

```yaml
concepts:
  - id: "cim-class-hierarchy"
    name: "Common Information Model (CIM) Class Hierarchy"
    category: os-internal
    description: "WMI uses the industry-standard Common Information Model to represent managed objects in an object-oriented schema. CIM defines three tiers: Core (universal, technology-agnostic primitives), Common (commonly applicable system, process, and device abstractions like Win32_Process), and Extended (vendor- or technology-specific extensions). Understanding the tier hierarchy clarifies which WMI classes are guaranteed across Windows versions and which are vendor-specific."
    relevant_to: [T-017, T-023]
    tags: [wmi, cim, windows-internals, recon, persistence]

  - id: "wql-query-types"
    name: "WQL Data, Event, and Schema Queries"
    category: os-internal
    description: "Windows Query Language supports three query classes. Data queries (e.g., SELECT * FROM Win32_NTLogEvent WHERE logfile='System' AND EventCode='4625') retrieve instances. Event queries subscribe to instance lifecycle changes via __InstanceCreationEvent / __InstanceDeletionEvent with a WITHIN polling interval. Schema queries (SELECT * FROM meta_class WHERE __this ISA 'Win32_Process') enumerate class definitions rather than instances. Intrinsic events require explicit polling intervals while extrinsic events fire from provider callbacks."
    relevant_to: [T-017, T-023]
    tags: [wmi, wql, event-subscription, polling, windows-internals]

  - id: "wmi-intrinsic-vs-extrinsic-events"
    name: "WMI Intrinsic vs Extrinsic Event Model"
    category: os-internal
    description: "Intrinsic WMI events are synthesized by the WMI infrastructure from instance changes (creation, modification, deletion) in a CIM repository and must be polled at a defined WITHIN interval — the consumer does not receive them unless it actively queries. Extrinsic events are raised by event providers directly (e.g., Win32_ProcessStartTrace), require no polling interval, and deliver near-real-time. Persistence consumers using intrinsic events incur polling overhead and a maximum delay equal to the WITHIN interval."
    relevant_to: [T-017]
    tags: [wmi, event-subscription, persistence, polling, windows-internals]

  - id: "wmi-event-subscription-persistence"
    name: "WMI Event Subscription Persistence"
    category: attack-pattern
    description: "WMI permanent event subscriptions achieve persistence by binding an __EventFilter (a WQL trigger condition) to an __EventConsumer (typically CommandLineEventConsumer or ActiveScriptEventConsumer) via a __FilterToConsumerBinding instance. All three are stored in the CIM repository and survive reboots. The subscription fires asynchronously whenever the filter condition is satisfied, executing the consumer payload without an attacker-controlled process needing to remain resident."
    relevant_to: [T-017]
    tags: [persistence, wmi, event-subscription, fileless, boot-survival]

  - id: "ifeo-image-file-execution-options"
    name: "Image File Execution Options (IFEO) Persistence"
    category: attack-pattern
    description: "IFEO registry entries under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target>.exe allow an attacker to register a Debugger value that is invoked in place of (or in addition to) the target executable. When the system launches the target binary, the debugger path is executed instead, providing a fileless, reboot-surviving persistence trigger tied to legitimate binary launches."
    relevant_to: [T-017]
    tags: [persistence, registry, ifeo, boot-survival, fileless]

  - id: "sddl-null-sid-ace"
    name: "SDDL ACE Granting to NULL SID (S-1-0-0)"
    category: attack-pattern
    description: "The SDDL string 'O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)' encodes a DACL with a single ACCESS_ALLOWED_ACE_TYPE entry granting READ_CONTROL | WRITE_DAC | WRITE_OWNER | GENERIC_ALL to the NULL well-known SID (S-1-0-0). Granting rights to NULL SID effectively permits access to subjects with no authenticated identity — a known technique for loosening security descriptors on services, named pipes, or kernel objects to permit anonymous or low-privilege access."
    relevant_to: [T-016]
    tags: [sddl, security-descriptor, null-sid, ace, privilege-escalation, evasion]

  - id: "wua-hotfix-enumeration"
    name: "Windows Update Agent (WUA) Hotfix Enumeration"
    category: os-internal
    description: "The Windows Update Agent API family is the documented method for querying installed hotfixes, also known as Quick Fix Engineering (QFE) updates. SEC670 identifies WUA as the correct API family for hotfix enumeration (vs. LUA or FUA), used by offensive operators to enumerate patch level and identify missing security updates for vulnerability selection."
    relevant_to: [T-023]
    tags: [recon, hotfix, qfe, wua, patch-enumeration, vulnerability-assessment]

  - id: "process-enumeration-api-triad"
    name: "Process Enumeration API Triad"
    category: os-internal
    description: "Three Win32/NT APIs provide process information from a PID: OpenProcess() returns a handle used for subsequent queries; WTSEnumerateProcessesEx() enumerates all processes in a session with extended info in a single call; NtQuerySystemInformation() with SystemProcessInformation returns a flat buffer of all EPROCESS-linked process records from the kernel. The trade-offs are handle-based access vs. snapshot enumeration vs. native NT buffer walk."
    relevant_to: [T-023, T-007]
    tags: [recon, process-enumeration, openprocess, wts, nt-query-system-information, windows-internals]

  - id: "windows-hotfix-qfe"
    name: "Windows Hotfix / Quick Fix Engineering Updates"
    category: os-internal
    description: "Windows Hotfixes, also referred to as Quick Fix Engineering (QFE) updates, are Microsoft's mechanism for applying critical fixes to deployed software. They are enumerated via the WUA API family and appear in WMI as Win32_QuickFixEngineering instances. Operators enumerate QFE state to identify missing patches and select viable privilege-escalation or LPE primitives."
    relevant_to: [T-023]
    tags: [hotfix, qfe, patching, recon, vulnerability-assessment]
```

### Detection Insights

```yaml
detection:
  - indicator: "Creation of __EventFilter, __EventConsumer, or __FilterToConsumerBinding in the CIM repository"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon EID 19 (WmiEventFilter), EID 20 (WmiEventConsumer), and EID 21 (WmiEventConsumerToFilter binding) fire when an attacker creates the three components of a WMI permanent event subscription. The events include the filter query (EventNamespace + Query), consumer type (CommandLineEventConsumer / ActiveScriptEventConsumer), and binding link."
    bypassed_by: "not discussed"

  - indicator: "CommandLineEventConsumer with suspicious command or script text"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon EID 20 surfaces the ConsumerBindingName and the consumer payload text. CommandLineEventConsumer entries with cmd.exe /c, powershell.exe, or scriptable ActiveScriptEventConsumer registrations are high-confidence persistence indicators."
    bypassed_by: "not discussed"

  - indicator: "IFEO Debugger value under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-017]
    description: "Registry modification events on the IFEO key (typically monitored via Sysmon EID 12/13) — specifically the addition of a Debugger value to a target executable's IFEO subkey — indicate persistence by image hijack. The value's data is the attacker payload path."
    bypassed_by: "not discussed"

  - indicator: "SDDL string containing S-1-0-0 (NULL SID) with GENERIC_ALL or WRITE_DAC access mask"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-016]
    description: "Security descriptor modification events (Sysmon EID 4 or registry SetSecurityDescriptor operations on services / named pipes) that include S-1-0-0 in the DACL with GA, WD, or WO flags indicate a security descriptor loosening to permit anonymous access. The string form 'A;;GA;;;S-1-0-0' or the expanded 'A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0' is the high-signal pattern."
    bypassed_by: "not discussed"

  - indicator: "WMI permanent subscription polling activity (high-frequency __InstanceCreationEvent queries)"
    source: behavioral
    confidence: low
    relevant_to: [T-017]
    description: "Intrinsic event subscriptions with short WITHIN intervals (≤ 5 seconds) generate recurring WMI provider host (wmiprvse.exe) query activity. Behavioral baselining of WMI namespace query rates can surface low-frequency but anomalous polling patterns tied to attacker subscriptions."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "WMI Permanent Event Subscription Created"
    logsource: sysmon
    condition_summary: "Sysmon EID 19 OR EID 20 OR EID 21 — creation of __EventFilter, __EventConsumer, or __FilterToConsumerBinding in any WMI namespace"
  - title: "IFEO Debugger Value Added"
    logsource: sysmon
    condition_summary: "Sysmon EID 13 — Registry value set under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\* with value name 'Debugger'"
  - title: "SDDL with NULL SID Grant"
    logsource: windows-security
    condition_summary: "Security descriptor modification event where the new SDDL string contains 'S-1-0-0' paired with access mask flags GA, WD, or WO"
```

### Operational Chains

```yaml
chains:
  - name: "WMI Permanent Event Subscription Persistence"
    description: "Establish reboot-surviving, fileless persistence via WMI event subscription binding"
    steps:
      - technique: "wmi-event-subscription-persistence"
        role: "Create __EventFilter with a WQL trigger condition (e.g., __InstanceCreationEvent for a target process, or a timed event)"
      - technique: "wmi-event-subscription-persistence"
        role: "Create __EventConsumer (CommandLineEventConsumer or ActiveScriptEventConsumer) with the payload to execute"
      - technique: "wmi-event-subscription-persistence"
        role: "Create __FilterToConsumerBinding linking the filter to the consumer in the CIM repository"
    notes: "SEC670 lists WMI Event Subscriptions as a Section 4 persistence topic. The material does not detail timing constraints or consumer payload constraints. Subscription survives reboot because all three objects are stored in the CIM repository, not in the attacker process."

  - name: "IFEO Image Hijack Persistence"
    description: "Trigger payload execution whenever a legitimate target binary is launched"
    steps:
      - technique: "ifeo-image-file-execution-options"
        role: "Create or modify HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target>.exe with a Debugger value pointing to the attacker payload"
      - technique: T-017
        role: "Coordinate with other persistence layers in T-017 for resilience against single-layer removal"
    notes: "SEC670 dedicates Lab 4.3 (IFEOPersist) to this technique. The material lists IFEO as a peer persistence vector to registry Run keys, services, port monitors, and WMI event subscriptions. The vault's T-017 does not currently cover IFEO; this chain represents a coverage gap."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "wmi-event-subscription-persistence-gap"
    title: "WMI Event Subscription Persistence Not in Vault"
    kind: coverage-gap
    description: "SEC670 dedicates a Section 4 module to WMI Event Subscriptions as a persistence vector with the canonical filter/consumer/binding triad. The vault's T-017 (Five-Layer Persistence) covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but omits WMI permanent event subscriptions entirely. This is a major offensive persistence technique with strong detection surface (Sysmon 19/20/21) that the vault should represent."
    would_relate_to: [T-017]
    source_units: ["unit 5", "unit 6", "unit 8", "unit 9", "unit 10"]
    tags: [persistence, wmi, event-subscription, coverage-gap, fileless]

  - id: "ifeo-persistence-gap"
    title: "Image File Execution Options (IFEO) Persistence Not in Vault"
    kind: coverage-gap
    description: "SEC670 covers IFEO persistence with a dedicated lab (Lab 4.3: IFEOPersist) and lists IFEO alongside services, port monitors, and WMI event subscriptions as a peer persistence mechanism. The vault's T-017 suite does not include IFEO Debugger value hijacking. IFEO persistence is high-value because it is registry-only (fileless), reboot-surviving, and triggers on legitimate binary launches rather than time-based scheduling."
    would_relate_to: [T-017]
    source_units: ["unit 5", "unit 6", "unit 8", "unit 10"]
    tags: [persistence, ifeo, registry, coverage-gap, fileless]

  - id: "port-monitor-persistence-gap"
    title: "Port Monitor Persistence Not in Vault"
    kind: coverage-gap
    description: "SEC670 lists Port Monitors as a Section 4 persistence topic alongside services, IFEO, and WMI. Port monitor persistence installs a DLL under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors that is loaded by the spoolsv.exe service at startup, surviving reboot and running in a privileged context. The vault's T-017 does not cover port monitors."
    would_relate_to: [T-017]
    source_units: ["unit 5", "unit 6", "unit 8"]
    tags: [persistence, port-monitor, spoolsv, coverage-gap, dll]

  - id: "services-persistence-gap"
    title: "Windows Service Persistence Not in Vault"
    kind: coverage-gap
    description: "SEC670 covers 'Services Revisited' and Lab 4.1 (PersistentService) as a primary persistence vector. The vault's T-017 suite does not include classic service-based persistence (svc.exe binary on disk + SCM registration with auto-start). Given that services remain one of the most common real-world persistence vectors, this is a notable gap versus the existing schtask layer in T-017."
    would_relate_to: [T-017]
    source_units: ["unit 5", "unit 6", "unit 8", "unit 10"]
    tags: [persistence, services, scm, coverage-gap]

  - id: "registry-run-keys-persistence-gap"
    title: "Registry Run Keys Persistence Not in Vault"
    kind: coverage-gap
    description: "SEC670 lists 'Registry Keys' as the opening Section 4 persistence module. The vault's T-017 covers registry-adjacent persistence (NTFS EA, COM hijack) but does not include Run/RunOnce keys, Winlogon shell, Userinit, or the classic registry persistence vectors. These remain among the most common persistence techniques encountered in real engagements and warrant coverage parity with the schtask layer."
    would_relate_to: [T-017]
    source_units: ["unit 5", "unit 6", "unit 8", "unit 9", "unit 10"]
    tags: [persistence, registry, run-keys, coverage-gap]

  - id: "sddl-security-descriptor-manipulation"
    title: "Security Descriptor Manipulation via SDDL"
    kind: proposed-technique
    description: "SEC670's SDDL Example #1 walks through constructing a security descriptor that grants GENERIC_ALL to the NULL SID (S-1-0-0), demonstrating the primitive of loosening object DACLs to permit anonymous access. The vault's T-016 covers handle blocking (restricting access to the implant) but does not cover the inverse primitive: loosening security descriptors on services, named pipes, or kernel objects to permit low-privilege access. This is a distinct offensive capability that would merit its own treatment under the EDR Evasion suite."
    would_relate_to: [T-016]
    source_units: ["unit 7"]
    tags: [sddl, security-descriptor, null-sid, ace, proposed-technique]

  - id: "sparse-methodology-batch"
    title: "Methodology Batch Contains Mostly Course Meta-Content"
    kind: coverage-gap
    description: "Approximately 30 of the 40 units in this batch are course roadmaps, table-of-contents pages, module objectives, and module summaries that do not contain extractable technical content. The substantive technical material clusters in units 1, 2, 3 (WMI/CIM/WQL), unit 7 (SDDL), unit 22 (WUA), and unit 31 (process enumeration APIs). Future batches from the same source should prioritize deeper module excerpts over roadmap slides to yield denser graph contributions."
    would_relate_to: []
    source_units: ["unit 4", "unit 11", "unit 12", "unit 13", "unit 14", "unit 15", "unit 16", "unit 17", "unit 18", "unit 19", "unit 20", "unit 21", "unit 23", "unit 24", "unit 25", "unit 26", "unit 27", "unit 28", "unit 29", "unit 30", "unit 32", "unit 33", "unit 34", "unit 35", "unit 36", "unit 37", "unit 38", "unit 39", "unit 40"]
    tags: [meta-content, sparse-batch, methodology, coverage-gap]
```