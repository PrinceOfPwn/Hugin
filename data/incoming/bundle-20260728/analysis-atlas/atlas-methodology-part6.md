## Synthesis Summary

This batch consists of 40 units sourced from SANS SEC670 course materials (Books 1-4) covering course roadmaps, tables of contents, module summaries, and review questions, with a small subset of substantive technical content on Windows internals. The substantive units map loosely to T-002 (Hell's/Halo's/Tartarus Gate), T-004 (PEB Walker), T-007 (Pool Party and related injection methods), T-012 (Early Cascade), T-013 (Remaining Injection Methods including APC/Early Bird), T-014 (NtCreateUserProcess), and T-016 (EDR Evasion Suite). The material that does carry technical weight covers the Ntdll/Kernel32/Kernelbase/User32 system DLL hierarchy (Unit 13), thread state transitions (Unit 31), preemptive priority-based thread scheduling (Unit 32), the internal NtCreateThreadEx → PspCreateThread creation flow with suspended-then-resumed semantics (Units 33-34), APC queue dispatch during thread quantum (Unit 37), and the SECURITY_ATTRIBUTES / Create* API family securable object model (Unit 39). The gap this material fills is the OS-internals layer beneath the vault's Rust implementations — the "why" behind syscall dispatch living in ntdll, why thread creation starts suspended (relevant to Early Bird and Early Cascade APC injection), and why APC injection depends on the thread entering a quantum with a drainable APC queue. The majority of units (approximately 30 of 40) are administrative navigation pages with no extractable tradecraft content.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "windows-system-dll-hierarchy"
    target: "T-002"
    type: concept_link
    rationale: "Unit 13 establishes ntdll as the gateway to kernel land and identifies kernel32/kernelbase as re-exporting ntdll functions, which is the OS-level rationale behind SSN resolution cascades that locate syscall stubs inside ntdll's .text section."

  - source: "windows-system-dll-hierarchy"
    target: "T-004"
    type: concept_link
    rationale: "Unit 13 states ntdll, kernel32, and kernelbase are practically always mapped and that the OS handles ntdll mapping — the PEB walker technique traverses the loader module list to locate exactly these DLLs without resolver APIs."

  - source: "thread-creation-internals"
    target: "T-007"
    type: enables
    rationale: "Units 33 and 34 document that newly created threads begin suspended before being scheduled — this suspended initial state is what thread hijack and thread-pool injection variants exploit to stage payload context before the thread executes."

  - source: "apc-queue-thread-execution"
    target: "T-012"
    type: enables
    rationale: "Unit 37 identifies the APC queue as the mechanism threads use to process routines during their quantum, which is the OS primitive that Early Cascade APC injection depends on for pre-LdrInitializeThunk delivery."

  - source: "thread-states-windows"
    target: "T-013"
    type: concept_link
    rationale: "Unit 31 documents the Ready/Running/Waiting thread state triad that WaitingThread hijack and other thread-state-dependent injection variants in T-013 target by selecting threads in specific scheduler states."

  - source: "windows-system-dll-hierarchy"
    target: "T-016"
    type: concept_link
    rationale: "Unit 13 mentions a technique for bypassing user-mode hooks by unloading system DLLs, which connects to the ntdll unhooking evasion tradecraft in T-016."
```

### Concept Nodes

```yaml
concepts:
  - id: "windows-system-dll-hierarchy"
    name: "System DLL Hierarchy: Ntdll, Kernel32, Kernelbase, User32"
    category: os-internal
    description: "Several system DLLs are mapped into nearly every process. Ntdll is the only one strictly required and is mapped by the OS. Ntdll exports functions acting as the gateway to kernel land. Kernel32 re-exports a large number of ntdll functions, with some exports consisting of nothing but jumps or forwarders to ntdll. User32 holds GUI component functions. The material notes that user-mode hooks placed in these DLLs can be bypassed by unloading the system DLLs."
    relevant_to: [T-002, T-004, T-016]
    tags: [dll, ntdll, kernel32, kernelbase, user32, syscall, hook-bypass]

  - id: "thread-states-windows"
    name: "Windows Thread States: Ready, Running, Waiting"
    category: os-internal
    description: "Windows tracks threads in three primary states: Ready (eligible to run but not currently dispatched), Running (currently executing on a logical processor), and Waiting (blocked on a dispatcher object such as an event, semaphore, or alertable wait). Thread-state-dependent injection techniques select threads in Waiting state because their context is stable and their resume semantics are predictable."
    relevant_to: [T-007, T-013]
    tags: [thread-state, scheduling, injection, windows-internals]

  - id: "thread-scheduling-preemptive-priority"
    name: "Preemptive Priority-Based Thread Scheduling"
    category: os-internal
    description: "The Windows dispatcher selects threads for execution under a preemptive, priority-based scheduling model. Higher-priority threads preempt lower-priority ones. This affects injection timing because a hijacked or APC-targeted thread's quantum arrival depends on its priority and the dispatcher's selection, not on a deterministic call from the implant."
    relevant_to: [T-007, T-012, T-013]
    tags: [scheduler, dispatcher, priority, thread-state]

  - id: "thread-creation-internals"
    name: "Thread Creation Internal Flow: NtCreateThreadEx → PspCreateThread"
    category: os-internal
    description: "Thread creation converts parameters into flags, adds the client ID and TEB address to an attribute list, determines whether the thread is local or remote, then calls NtCreateThreadEx which initializes user-mode thread context and invokes PspCreateThread. The thread is created initially suspended and later resumed so the dispatcher can schedule it. This suspended initial state is the window during which APC injection payloads are queued before the thread runs."
    relevant_to: [T-007, T-012, T-013, T-014]
    tags: [thread-creation, ntcreatethreadex, pspcreatethread, suspended-thread, apc-injection]

  - id: "apc-queue-thread-execution"
    name: "APC Queue as Routine Dispatch Mechanism"
    category: os-internal
    description: "Threads process routines queued to their APC queue when they enter their quantum. The APC queue is the mechanism that allows kernel and user-mode code to schedule routine execution on a target thread without direct invocation. APC injection techniques exploit this by queuing payload-bearing APCs to threads that will drain the queue during an upcoming quantum or alertable wait."
    relevant_to: [T-012, T-013]
    tags: [apc, apc-queue, thread-quantum, alertable-wait, injection]

  - id: "securable-objects-security-descriptor"
    name: "Securable Objects and SECURITY_ATTRIBUTES"
    category: os-internal
    description: "Securable objects in Windows carry a corresponding security descriptor. The Create* family of Win32 APIs (CreateProcess, CreateThread, CreateFile, CreateRegistryKey, etc.) accept a pointer to a SECURITY_ATTRIBUTES structure that controls access. Handles returned from these APIs are gated by the security descriptor and the handle table. Process injection and handle-blocking evasion techniques interact with this model when opening remote process handles or denying external handle access."
    relevant_to: [T-014, T-016]
    tags: [securable-object, security-descriptor, security-attributes, handle-table, create-api]

  - id: "anonymous-vs-named-pipes-ipc"
    name: "Anonymous and Named Pipes for IPC"
    category: os-internal
    description: "Pipes are one of several interprocess communication methods on Windows. Anonymous pipes are local only, one-way, and have less overhead than named pipes. Named pipes support bidirectional and cross-host communication. Implant tradecraft uses pipes for C2 channel multiplexing, localhost relay between staged components, and impersonation token theft via named pipe security descriptors."
    relevant_to: []
    tags: [ipc, pipes, anonymous-pipe, named-pipe, orphan, windows-internals]
```

### Detection Insights

```yaml
detection:
  - indicator: "User-mode hook bypass via system DLL unload or reload"
    source: behavioral
    confidence: low
    relevant_to: [T-016]
    description: "Unit 13 mentions unloading system DLLs as a technique for bypassing user-mode hooks. A defender-visible behavioral indicator is a process invoking NtUnmapViewOfSection or equivalent on ntdll/kernel32/kernelbase outside of known loader activity, followed by a fresh section map that restores the DLL. This pattern is uncommon in benign process behavior."
    bypassed_by: "not discussed"

  - indicator: "Newly created thread in suspended state targeted by APC"
    source: behavioral
    confidence: medium
    relevant_to: [T-012, T-013]
    description: "Units 33 and 34 establish that newly created threads begin suspended before resume. Early Bird and Early Cascade injection queue APCs to a thread in this suspended window. A behavioral indicator is a sequence of CreateThread (CREATE_SUSPENDED) followed by NtQueueApcThread or NtQueueApcThreadEx on the same TID prior to ResumeThread."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Suspended Thread Creation Immediately Followed by APC Queue"
    logsource: etw
    condition_summary: "Sequence within one process: NtCreateThreadEx with CREATE_SUSPENDED flag followed by NtQueueApcThread targeting the same TID before thread resume event"
```

### Operational Chains

```yaml
chains:
  - name: "OS-Internal Thread Creation Sequence (descriptive, not operational)"
    description: "Units 33-34 document the OS-internal sequence of thread creation, included here because it underpins suspended-thread injection variants."
    steps:
      - technique: "parameter conversion to flags"
        role: "CreateThread parameters converted to internal flags"
      - technique: "attribute list construction"
        role: "Client ID and TEB address added to thread attribute list"
      - technique: "local-vs-remote dispatch"
        role: "Determine whether thread is created in local or remote process"
      - technique: "NtCreateThreadEx + PspCreateThread"
        role: "Initialize user-mode thread context and call PspCreateThread"
      - technique: "suspended-then-resumed"
        role: "Thread initially suspended; resumed later for scheduler dispatch"
    notes: "This is an OS-internal sequence documented in SEC670, not a red team operational chain. No multi-step tradecraft chain is described in this batch."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "sec670-thread-creation-internals-coverage"
    title: "SEC670 Thread Creation Internals as Cross-Reference for Injection Cards"
    kind: cross-source-convergence
    description: "SEC670 Books 1 and 3 document the NtCreateThreadEx → PspCreateThread creation flow with suspended-then-resumed semantics and the APC-queue dispatch mechanism during thread quantum. This converges with the suspended-thread window that Early Cascade (T-012), Early Bird, and APC injection (T-013) exploit. The vault's injection cards would benefit from explicit cross-references to this OS-level flow so implementers understand why CREATE_SUSPENDED is the load-bearing flag."
    would_relate_to: [T-007, T-012, T-013, T-014]
    source_units: ["unit 33", "unit 34", "unit 37"]
    tags: [thread-creation, apc, suspended-thread, injection, cross-source]

  - id: "sec670-methodology-batch-sparse-content"
    title: "SEC670 Methodology Batch — Predominantly Navigation Content"
    kind: coverage-gap
    description: "Approximately 30 of 40 units in this batch are course roadmaps, tables of contents, module summaries, review questions, and administrative setup slides. The extractable tradecraft is concentrated in a handful of units covering system DLL hierarchy, thread internals, IPC pipes, and securable objects. Subsequent batches from SEC670 Books covering injection labs (ClassicDLLInjection, APCInjection, ThreadHijacker), persistence (Die Another Day), and the Enhancing Your Implant shellcode/evasion/C2 module are likely to carry denser, more graphable content."
    would_relate_to: []
    source_units: ["unit 1", "unit 2", "unit 3", "unit 5", "unit 6", "unit 9", "unit 10", "unit 11", "unit 12", "unit 16", "unit 17", "unit 21", "unit 28", "unit 29", "unit 30", "unit 35", "unit 36", "unit 38", "unit 40"]
    tags: [batch-composition, sparse-material, coverage-gap, sec670]
```