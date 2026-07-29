## Synthesis Summary

This batch maps primarily to T-007 (Pool Party/thread pool manipulation), T-012 (Early Cascade APC), T-013 (Early Bird APC and remaining injection methods), T-017 (NTFS EA persistence), and T-023 (client recon capabilities). The material comes from SANS SEC670 Section 2-3 content covering Windows internals fundamentals: thread definition and `AddressOfEntryPoint`, the Windows dispatcher's preemptive priority-based scheduling with quantum-based CPU allocation, the Asynchronous Procedure Call (APC) mechanism and its dependence on alertable wait states, the svchost.exe shared-vs-isolated service hosting model, NTFS directory entry tables, and the `RegQueryInfoKey`/`RegNotifyChangeKeyValue` registry APIs. The gap this fills versus reading source code alone is the OS-level rationale for why APC-based injection primitives require an alertable wait to drain the user-mode APC queue, why thread priority and quantum mechanics matter when targeting thread pools, and why the svchost hosting model affects target selection for injection. Roughly 28 of 40 units are off-theme course administrative content (roadmaps, module summaries, "future of tools" meta-discussions, section intros, lab listings) and were skipped; the remaining 12 units produce the contributions below.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: T-012
    target: apc-alertable-wait
    type: requires
    rationale: "Early Cascade queues an APC before LdrInitializeThunk; the APC only dispatches when the target thread enters an alertable wait state, per the SEC670 APC injection unit explaining that APC objects are queued and executed only when the thread enters an alertable state."

  - source: T-013
    target: apc-alertable-wait
    type: requires
    rationale: "Early Bird APC injection (T-013) depends on the same APC dispatch mechanism — SEC670 states APCs are placed into a thread's queue and executed when that thread enters an alertable state, making the wait state a hard prerequisite."

  - source: T-007
    target: windows-thread-scheduling
    type: requires
    rationale: "Pool Party thread pool manipulation operates within the Windows dispatcher's preemptive priority-based scheduling model; SEC670 explains that thread quantum, priority preemption, and dispatcher events govern which threads actually execute queued work items."

  - source: regnotifychangekeyvalue-watchdog
    target: T-017
    type: detects
    rationale: "SEC670's Registry Watch Dogs unit documents RegNotifyChangeKeyValue as a mechanism to be notified when specific registry changes happen — this is the exact detection primitive that observes COM hijack and schtask persistence entries written by T-017."

  - source: T-007
    target: svchost-service-hosting
    type: concept_link
    rationale: "SEC670's Windows Services unit distinguishes shared services (multiple services sharing address space in svchost.exe) from isolated services; injection target selection in T-007 implicitly depends on whether the chosen host process shares its address space with other services."

  - source: T-023
    target: regqueryinfokey-enumeration
    type: requires
    rationale: "SEC670 documents RegQueryInfoKey as the API used to gather detailed info about a registry key including subkeys and value sizes; T-023 recon capabilities enumerate registry information as part of host profiling, requiring this API."

  - source: T-017
    target: ntfs-directory-entry-table
    type: concept_link
    rationale: "SEC670's NTFS Directory Entries unit describes the directory table that tracks files and child directories with hard links; T-017's NTFS EA persistence writes EA streams into this same file system object model."
```

### Concept Nodes

```yaml
concepts:
  - id: "windows-thread-scheduling"
    name: "Windows Dispatcher Thread Scheduling"
    category: os-internal
    description: "Windows uses a preemptive, priority-based dispatcher. Threads are selected for execution but may never actually run because a higher-priority thread preempts them. Each thread runs for a quantum measured in clock cycles. When a high-priority thread leaves its waiting state and becomes ready, it preempts any currently-running lower-priority thread in its quantum. Server and endpoint configurations use different default quantum values."
    relevant_to: [T-007, T-013]
    tags: [thread-scheduling, dispatcher, quantum, priority, preemption, windows-internals]

  - id: "apc-alertable-wait"
    name: "APC Alertable Wait State"
    category: os-internal
    description: "An Asynchronous Procedure Call (APC) is a mechanism that allows an I/O operation to complete later, providing asynchronous execution. APC objects are placed into a thread's queue and execute only when the thread enters an alertable waiting state. A thread that never enters an alertable wait will not drain its user-mode APC queue, causing queued APCs (including injection payloads) to remain pending without error."
    relevant_to: [T-007, T-012, T-013]
    tags: [apc, injection, thread-state, async-io, windows-internals]

  - id: "svchost-service-hosting"
    name: "svchost.exe Shared vs Isolated Service Hosting"
    category: os-internal
    description: "Windows services are special processes with no GUI and no direct user interaction. A shared service hosts multiple services sharing address space within a single svchost.exe process; if one crashes, they all crash. An isolated service is hosted in svchost.exe without sharing its address space with other services. The hosting model determines blast radius and affects which services can be safely targeted for process injection."
    relevant_to: [T-007, T-013]
    tags: [services, svchost, process-model, injection-target, windows-internals]

  - id: "ntfs-directory-entry-table"
    name: "NTFS Directory Entry Table"
    category: windows-structure
    description: "NTFS tracks directories and child directories in a directory tree. Each directory has a table holding entries with the names of files contained in that directory. The directory entry table, combined with hard links, forms the structural basis for NTFS file system navigation. APIs include CreateDirectory, CreateDirectoryEx, and CreateDirectoryTransacted."
    relevant_to: [T-017]
    tags: [ntfs, directory, file-system, windows-internals, persistence]

  - id: "regqueryinfokey-enumeration"
    name: "RegQueryInfoKey Registry Enumeration API"
    category: os-internal
    description: "RegQueryInfoKey (declared in Winreg.h, returns LSTATUS) retrieves detailed information about a registry key: class string, number of subkeys (lpcSubKeys), number of values (lpcValues), max subkey name length (lpcbMaxSubKeyLen), max value name length (lpcbMaxValueNameLen), and max value data size (lpcbMaxValueLen). Used to enumerate registry structure before walking subkeys and values."
    relevant_to: [T-023]
    tags: [registry, enumeration, recon, api, windows-internals]

  - id: "regnotifychangekeyvalue-watchdog"
    name: "RegNotifyChangeKeyValue Registry Watchdog"
    category: defense-mechanism
    description: "RegNotifyChangeKeyValue (declared in Winreg.h, returns LSTATUS) is used to be notified when specific changes happen to a registry key. Parameters include hKey (must have REG_NOTIFY access mask), bWatchSubtree (Boolean for recursive watch), dwNotifyFilter (which change types trigger notification), hEvent (optional event handle), and fAsynchronous (Boolean for async vs sync notification). Functions as a sentry for registry persistence writes."
    relevant_to: [T-017]
    tags: [registry, detection, watchdog, persistence, defense-mechanism]

  - id: "thread-entrypoint-initial"
    name: "Process Initial Thread and AddressOfEntryPoint"
    category: os-internal
    description: "A thread is an entity within a process that can be scheduled for execution — the smallest unit of execution tied to a process. Every process has at least one initial thread that kicks off image code execution at the image's AddressOfEntryPoint. This initial thread and its entry point form the foundation of process startup that injection techniques such as Early Cascade (T-012) intercept before LdrInitializeThunk."
    relevant_to: [T-007, T-012, T-013]
    tags: [thread, entrypoint, process-startup, ldr-initialize-thunk, windows-internals]
```

### Detection Insights

```yaml
detection:
  - indicator: "Registry value write to persistence-related keys (Run keys, Image File Execution Options, schtask entries, COM hijack paths)"
    source: behavioral
    confidence: medium
    relevant_to: [T-017]
    description: "SEC670 documents RegNotifyChangeKeyValue as the primitive defenders use to be notified when specific changes happen to a registry key. A defender registers a watchdog on persistence-relevant hKey paths with bWatchSubtree=TRUE and dwNotifyFilter covering REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET; any T-017 write to COM hijack or schtask persistence locations triggers the notification."
    bypassed_by: "not discussed"

  - indicator: "Process hosting model mismatch — DLL loaded into shared svchost instance"
    source: behavioral
    confidence: low
    relevant_to: [T-007]
    description: "SEC670's Windows Services unit notes that shared services in svchost.exe share address space and that if one crashes they all crash. Defenders baseline the expected DLL set per svchost group; a T-007 thread pool manipulation payload loaded into a shared svchost group appears as an unexpected module in a service host that other co-tenant services depend on."
    bypassed_by: "not discussed"

  - indicator: "Thread quantum preemption observed on injected worker thread"
    source: behavioral
    confidence: low
    relevant_to: [T-007]
    description: "SEC670's Thread Scheduling unit documents that the Windows dispatcher preempts running threads based on priority and quantum. Thread pool worker threads hijacked by Pool Party execute injected work during their quantum; a thread observed running non-standard code during dispatcher-allocated quantum, particularly with priority changes, is anomalous."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Registry Watchdog Notification on Persistence Keys"
    logsource: windows-security
    condition_summary: "RegNotifyChangeKeyValue-based watchdog fires on writes to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, HKLM\\Software\\Classes\\CLSID (COM hijack), and HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Taskcache"
```

### Operational Chains

```yaml
chains:
  - name: "APC Injection Requiring Alertable Wait Trigger"
    description: "SEC670 sequence for asynchronous APC-based injection that depends on the target thread entering an alertable state"
    steps:
      - technique: T-013
        role: "Queue the APC carrying the payload onto the target thread's APC queue (Early Bird or WaitingThread variant)"
      - technique: "apc-alertable-wait"
        role: "Trigger an alertable wait state (SleepEx, WaitForSingleObjectEx with ALERTABLE) so the queued APC drains and executes the payload"
    notes: "SEC670 explicitly states APC objects are queued and execute only when the thread enters an alertable state; without the alertable wait trigger, the queued injection silently fails without error."

  - name: "Registry Recon for Persistence Targeting"
    description: "SEC670 Section 2 sequence for using registry enumeration to plan T-017 persistence placement"
    steps:
      - technique: T-023
        role: "Reconnaissance phase: enumerate registry structure to identify candidate persistence locations"
      - technique: "regqueryinfokey-enumeration"
        role: "Use RegQueryInfoKey to gather subkey count, value count, and max value sizes to plan the walk"
      - technique: T-017
        role: "Write persistence entry to the enumerated COM hijack, schtask, or registry Run key location"
    notes: "SEC670's Section 2 curriculum explicitly pairs registry information gathering with persistence decision-making in later sections; the order is recon then place."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "registry-watchdog-detection-primitive"
    title: "Registry Watchdog Detection via RegNotifyChangeKeyValue"
    kind: coverage-gap
    description: "SEC670 documents RegNotifyChangeKeyValue as a defensive primitive for receiving notifications on registry key changes, with parameters for subkey recursion, filter masks, and asynchronous vs synchronous delivery. The vault's T-017 persistence card documents registry-writing techniques but does not document this detection primitive on the receiving side. Worth surfacing as cross-cutting metadata on T-017 so operators understand what telemetry a defender with this API gets."
    would_relate_to: [T-017]
    source_units: ["unit 24"]
    tags: [registry, detection, watchdog, defense-primitive, coverage-gap]

  - id: "windows-dispatcher-quantum-model"
    title: "Windows Dispatcher Quantum and Priority Model as Foundation Knowledge"
    kind: coverage-gap
    description: "SEC670 devotes multiple units to the Windows dispatcher's preemptive priority-based scheduling, quantum allocation in clock cycles, and preemption events. The vault's thread-pool and APC techniques (T-007, T-012, T-013) operate inside this model but do not document the scheduler's behavior as background context. A concept-anchored explanation of why a queued APC may be delayed by priority preemption would help operators reason about timing."
    would_relate_to: [T-007, T-012, T-013]
    source_units: ["unit 35", "unit 36", "unit 37"]
    tags: [dispatcher, scheduling, quantum, priority, coverage-gap, windows-internals]

  - id: "svchost-hosting-model-target-selection"
    title: "svchost Shared vs Isolated Service Hosting as Injection Target Selection Criterion"
    kind: proposed-technique
    description: "SEC670 distinguishes shared services (multiple services in one svchost, share address space, shared crash fate) from isolated services (dedicated svchost). This distinction is operationally relevant when selecting a process injection host: targeting a shared svchost group risks destabilizing unrelated co-tenant services. The vault does not have a technique card or selection criterion for choosing injection targets based on service hosting model. Would merit either a new technique card or selection metadata on T-007."
    would_relate_to: [T-007, T-013]
    source_units: ["unit 19"]
    tags: [svchost, services, target-selection, injection, proposed-technique]
```