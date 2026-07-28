## Synthesis Summary

This batch consists primarily of SANS SEC670 and CRTO course roadmap, table-of-contents, and module-summary slides with sparse technical depth. Material that maps to existing HUGIN techniques surfaces only through topic listings: process injection primitives (T-007, T-013), EDR-evasion concepts including AMSI bypass and NTDLL unhooking (T-016), persistence mechanisms including IFEO, port monitors, and WMI event subscriptions (T-017), UAC bypass research (T-021), and C2 networking concepts (T-022). The training material fills the gap of operational sequencing and tradecraft framing — specifically how SEC670 sequences custom loader development, unhooking, AV/EDR bypass, and C2 callback establishment as a single training arc — but provides no API-level or Windows-internals depth in this batch. The CRTO units (30-33) cover engagement planning logistics and are off-theme for the vault. No units were skipped outright because the on-theme technical references, although sparse, are valid graph contributions; the depth of each contribution reflects the shallow nature of the source slides.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "classic-dll-injection"
    target: T-007
    type: enables
    rationale: "Unit 9 states foundational DLL injection 'puts down the foundation so it can be built upon later in the course when we go over reflective DLL injection', establishing that basic injection enables more advanced reflective variants."

  - source: "ntdll-unhooking"
    target: T-016
    type: concept_link
    rationale: "Units 27 and 28 list 'UnhookTheHook' as a lab under the Bypassing AV/EDR module, placing ntdll .text restoration as a constituent technique of the broader EDR evasion suite."

  - source: "amsi-bypass"
    target: T-016
    type: concept_link
    rationale: "Units 27 and 28 list 'AMSI No More' as a lab under the Bypassing AV/EDR module, positioning AMSI bypass as a constituent capability of T-016."

  - source: "custom-loader"
    target: "ntdll-unhooking"
    type: chains_to
    rationale: "The SEC670 Section 5 roadmap (units 27, 28, 29) sequences Custom Loaders (Lab 5.1) before Unhooking Hooks (Lab 5.2), implying the loader is the foundation on which unhooking is then applied."

  - source: "ntdll-unhooking"
    target: "av-edr-bypass"
    type: chains_to
    rationale: "The SEC670 Section 5 roadmap sequences Unhooking Hooks (Lab 5.2) before Bypassing AV/EDR (Lab 5.3), implying unhooking is a prerequisite step for broader evasion work in the operational arc."

  - source: "ifeo-persistence"
    target: T-017
    type: alternative_to
    rationale: "Units 16, 17, 18, 19, 20, 22, and 24 list IFEO alongside registry keys, services, port monitors, and WMI Event Subscriptions as Section 4 persistence topics, positioning IFEO as an alternative persistence layer to the COM hijack, NTFS EA, schtask, and TLS callback layers currently documented in T-017."
```

### Concept Nodes

```yaml
concepts:
  - id: "thread-quantum-running-state"
    name: "Thread Quantum Slice and Running State"
    category: os-internal
    description: "A thread executing during its allocated quantum slice is in the Running state, distinct from Waiting (blocked on a dispatcher object) and Ready (eligible to run but not currently scheduled). The quantum is the time allowance the scheduler grants before preempting the thread for another Ready thread of equal priority. This state distinction matters for injection techniques that target suspended or waiting threads, because a thread in Running state has an actively executing context that cannot be safely modified without synchronization."
    relevant_to: [T-008, T-013]
    tags: [thread-state, scheduling, windows-internals, quantum, dispatcher]

  - id: "anonymous-pipes-windows-ipc"
    name: "Anonymous Pipes (Windows IPC)"
    category: os-internal
    description: "Anonymous pipes are a one-way, local-only interprocess communication mechanism with lower overhead than named pipes. Because they cannot span process boundaries on remote machines and lack the kernel namespace registration of named pipes, they are less observable via Sysmon Event ID 17/18 (PipeEvent) and are sometimes used for parent-child implant communication where stealth is preferred over flexibility. They require an inheritable handle to be passed to the child at creation time."
    relevant_to: [T-022]
    tags: [ipc, pipes, covert-channel, windows-internals]

  - id: "sal-source-annotation-language"
    name: "SAL (Source-code Annotation Language)"
    category: os-internal
    description: "SAL is Microsoft's source-code annotation language used in Windows headers to express contract semantics between callers and callees: _In_, _Out_, _Inout_, _In_opt_, _Outptr_, _Ret_*, and buffer-size annotations like _In_reads_(count). The annotations drive static analysis tools (PREfast, /analyze) and document pointer ownership, nullability, and length contracts. Offensive tooling developers reading Windows SDK headers encounter SAL on every NT API prototype, and ignoring the annotations leads to incorrect buffer sizing or wrong pointer levels when constructing FFI bindings in Rust."
    relevant_to: []
    tags: [sal, windows-api, ffi, annotations, orphan]

  - id: "ifeo-persistence"
    name: "Image File Execution Options Persistence"
    category: attack-pattern
    description: "Image File Execution Options is a registry-based persistence mechanism under HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target.exe> where setting the Debugger value to an attacker-controlled path causes any launch of target.exe to invoke the attacker binary instead with the original command line appended. SEC670 lists IFEO alongside registry keys, services, port monitors, and WMI Event Subscriptions as a Section 4 persistence topic. The technique is detectable via registry monitoring on the IFEO key tree and is privilege-gated to HKLM write access."
    relevant_to: [T-017]
    tags: [persistence, registry, ifeo, image-hijack]

  - id: "port-monitor-persistence"
    name: "Port Monitor Persistence"
    category: attack-pattern
    description: "A port monitor is a DLL loaded by the print spooler service (spoolsv.exe) into a SYSTEM-privileged process. Registering a port monitor via AddMonitor or by writing directly to HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors causes spoolsv.exe to load the attacker DLL on service start, yielding persistent SYSTEM-code execution. SEC670 lists Port Monitors as a Section 4 persistence topic. The technique requires local administrator privileges to install the monitor and is detectable by monitoring for new entries under the Print\\Monitors registry key and for unexpected DLL loads by spoolsv.exe."
    relevant_to: [T-017]
    tags: [persistence, port-monitor, print-spooler, system-privilege]

  - id: "wmi-event-subscription-persistence"
    name: "WMI Event Subscription Persistence"
    category: attack-pattern
    description: "WMI event subscriptions persist attacker code execution through three WMI objects: an event filter (trigger condition such as startup, interval timer, or process creation), an event consumer (the action — ActiveScriptEventConsumer for script, CommandLineEventConsumer for binary), and a binding between them. All three are stored in the root\\subscription WMI namespace and survive reboots. SEC670 lists WMI Event Subscriptions as a Section 4 persistence topic. Detection requires querying the root\\subscription namespace for __EventFilter, __EventConsumer, and __FilterToConsumerBinding instances or monitoring Sysmon Event ID 21 (WmiEventFilter) and 22 (WmiEventConsumer) and 19 (WmiFilterToConsumerBinding)."
    relevant_to: [T-017]
    tags: [persistence, wmi, event-subscription, system-privilege]

  - id: "reflective-dll-injection"
    name: "Reflective DLL Injection"
    category: attack-pattern
    description: "Reflective DLL injection is a technique in which a DLL is loaded into a target process without using the standard Windows loader (LoadLibrary) by manually mapping the PE file: allocating memory, copying sections, resolving imports, processing relocations, and invoking DllMain from the entry point. SEC670 frames it as an advanced technique built upon foundational DLL injection. The technique avoids creating a module entry in the PEB loader list (unless explicitly linked), reducing detection by tools that enumerate loaded modules, but produces an unbacked executable private memory region detectable by memory scanners."
    relevant_to: [T-007, T-013]
    tags: [injection, reflective, pe-loading, peb-avoidance]

  - id: "extrinsic-vs-intrinsic-events"
    name: "Extrinsic vs Intrinsic Event Polling"
    category: os-internal
    description: "Extrinsic events are externally triggered and require the implant to poll at some interval to detect them — examples include file drops, registry changes, or external process creation. Intrinsic events are driven by the implant's own execution state and can be handled synchronously. SEC670 poses both as event classes that must be polled at some interval, which frames the operational trade-off: tighter polling improves responsiveness but increases the implant's CPU footprint and detection surface; looser polling reduces footprint but risks missing transient signals like short-lived child processes or rapidly deleted staging files."
    relevant_to: []
    tags: [event-polling, operational-trade-off, polling-interval, orphan]
```

### Detection Insights

```yaml
detection:
  - indicator: "New entry under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors with a custom DLL path"
    source: windows-security-log
    confidence: high
    relevant_to: [T-017]
    description: "Port monitor persistence requires registering a monitor DLL under the Print\\Monitors registry key. Sysmon Event ID 12 (RegistryEvent) or 13 (RegistryValueSet) on the Print\\Monitors subtree with a value not matching the standard Windows monitor DLLs (usbmon.dll, localmon.dll, tcpmon.dll, etc.) indicates port monitor persistence. The corresponding spoolsv.exe load of the unknown DLL appears in Sysmon Event ID 7 (ImageLoad) with the spoolsv.exe as the Image and the unknown DLL as ImageLoaded."
    bypassed_by: "not discussed"

  - indicator: "WMI __EventFilter, __EventConsumer, and __FilterToConsumerBinding instances in root\\subscription namespace"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon Event IDs 19 (WmiFilter), 20 (WmiConsumer), and 21 (WmiFilterToConsumerBinding) surface WMI persistence. A binding of a startup-triggered filter to a CommandLineEventConsumer or ActiveScriptEventConsumer is a high-confidence persistence indicator. Querying Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding also reveals the relationship. Legitimate WMI subscriptions in enterprise environments are rare, so most bindings warrant investigation."
    bypassed_by: "not discussed"

  - indicator: "Debugger value under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<exe>"
    source: windows-security-log
    confidence: high
    relevant_to: [T-017]
    description: "IFEO persistence sets the Debugger registry value under the target executable's IFEO key to redirect execution. Sysmon Event ID 12/13 on the Image File Execution Options subtree, particularly the Debugger value, indicates IFEO tampering. A Debugger value pointing to an unsigned or non-standard binary path is high-confidence. The EventData will include the target executable name and the attacker-controlled Debugger path."
    bypassed_by: "not discussed"

  - indicator: "Unbacked private executable memory region with no PEB module entry"
    source: memory-scan
    confidence: medium
    relevant_to: [T-007, T-013]
    description: "Reflective DLL injection produces a private executable memory allocation (VadS node, MEM_PRIVATE, PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ) with no corresponding entry in the PEB loader list and no file backing. Memory scanners (pe-sieve, Moneta) flag such regions as 'unbacked executable' or 'floating code'. The presence of a valid PE header in the region further increases the heuristic confidence."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Suspicious Port Monitor Registration"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 12 or 13 where TargetObject contains 'Print\\\\Monitors' and the new value data is a DLL path not matching known Microsoft monitor DLLs"
  - title: "WMI Event Subscription Persistence"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 19, 20, or 21 in root\\subscription namespace with a CommandLineEventConsumer or ActiveScriptEventConsumer consumer type"
  - title: "IFEO Debugger Persistence"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 13 where TargetObject contains 'Image File Execution Options' and the value name is 'Debugger'"
```

### Operational Chains

```yaml
chains:
  - name: "SEC670 Section 5 Implant Enhancement Arc"
    description: "The course roadmap in units 27, 28, and 29 sequences the steps of building an evasion-capable implant from loader through C2 callback."
    steps:
      - technique: "custom-loader"
        role: "Build a custom shellcode/PE loader that does not rely on the standard Windows loader, establishing the execution foundation."
      - technique: T-016
        role: "Restore ntdll .text section (UnhookTheHook, Lab 5.2) to remove EDR userland hooks placed in ntdll."
      - technique: T-016
        role: "Apply broader AV/EDR bypass tradecraft including AMSI patching (AMSI No More, Lab 5.4) and additional evasion primitives."
      - technique: T-022
        role: "Establish C2 callback channel ('Calling Home', Lab 5.3: No Caller ID) so the implant can reach the redirector or listening post."
    notes: "Material does not specify sequencing constraints beyond the roadmap order; timing between steps and environmental prerequisites are not discussed."

  - name: "Reflective DLL Injection Progression"
    description: "Unit 9 describes a foundational DLL injection lab followed by a more advanced reflective DLL injection technique in a later module."
    steps:
      - technique: "classic-dll-injection"
        role: "Inject a DLL into a target process via standard CreateRemoteThread + LoadLibrary pattern, establishing foundational injection mechanics."
      - technique: "reflective-dll-injection"
        role: "Manually map the PE without invoking the Windows loader, bypassing LoadLibrary-based detection and avoiding PEB loader list entries."
    notes: "The material states only that the foundational lab 'puts down the foundation' for the reflective variant; specific module numbers and prerequisites are not provided in this batch."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "coverage-gap-persistence-layer-ifoe-portmon-wmi"
    title: "T-017 Persistence Suite Missing IFEO, Port Monitor, and WMI Event Subscription Layers"
    kind: coverage-gap
    description: "SEC670 Section 4 (units 15-24) covers a persistence curriculum that includes In Memory Execution, Dropping to Disk, Binary Patching, Registry Keys, Services Revisited, Port Monitors, IFEO, and WMI Event Subscriptions. The vault's T-017 Five-Layer Persistence card documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — but does not surface IFEO, Port Monitor, or WMI Event Subscription as persistence layers. These are well-established Windows persistence techniques with distinct registry and WMI-namespace footprints and would strengthen the persistence card's coverage."
    would_relate_to: [T-017]
    source_units: ["unit 16", "unit 17", "unit 18", "unit 19", "unit 20", "unit 22", "unit 24"]
    tags: [persistence, ifeo, port-monitor, wmi, coverage-gap]

  - id: "proposed-technique-binary-patching-persistence"
    title: "Binary Patching as a Persistence Mechanism"
    kind: proposed-technique
    description: "SEC670 Section 4 (units 16-22) lists Binary Patching as a distinct persistence topic alongside Registry Keys, Services, IFEO, and WMI Event Subscriptions. The vault does not have a technique card covering in-place modification of binary files on disk to insert persistent execution hooks — a technique distinct from module stomping (which operates in memory) and from proxy DLL planting (which adds new files rather than modifying existing ones). This deserves its own coverage either as a new T-NNN or as an explicit sub-technique of T-017."
    would_relate_to: [T-017]
    source_units: ["unit 16", "unit 17", "unit 18", "unit 19", "unit 20", "unit 22"]
    tags: [persistence, binary-patching, disk-modification, proposed-technique]

  - id: "cross-source-convergence-custom-loader-to-callback-arc"
    title: "Loader → Unhook → AV/EDR Bypass → C2 Callback Tradecraft Sequence"
    kind: cross-source-convergence
    description: "SEC670 Section 5 (units 27, 28, 29) sequences custom loader development, ntdll unhooking, AV/EDR bypass, AMSI patching, and C2 callback establishment as a single training arc. This sequencing mirrors the dark_crystal crate's phase runner structure (T-022 architecture overview) and the evasion chain builder in the xptool. The convergence across SEC670 and the vault architecture indicates a strong tradecraft consensus on the operational order of these primitives — loader first, then in-process evasion, then callback — that the vault could surface explicitly as a canonical chain rather than leaving it implicit in the phase runner."
    would_relate_to: [T-016, T-022]
    source_units: ["unit 27", "unit 28", "unit 29"]
    tags: [tradecraft-sequence, cross-source-convergence, loader, evasion, c2]
```