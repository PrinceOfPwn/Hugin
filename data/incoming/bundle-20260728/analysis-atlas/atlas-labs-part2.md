## Synthesis Summary

This batch maps loosely to T-007 (process injection, via "The Loader" lab covering local and cross-process shellcode execution), T-017 (persistence, via the NotInService/InitToWinit/OhMyWMI/CustomShell labs), T-019/T-022 (networking, via the "No Caller ID" HTTP C2 lab), T-020/T-021 (evasion/obfuscation, via the "ShadowCraft" lab), and T-023 (client capabilities, via the implied WMI execution in "OhMyWMI"). The material also surfaces a TokenThief token-theft lab that has no direct vault equivalent. The batch is overwhelmingly thin: every unit is a table-of-contents entry, a slide caption, or a quiz question referring operators to an external eWorkbook, so the technical depth required for substantive concept nodes is largely absent. What the material does establish is the SANS SEC670 curriculum sequencing (loader → token theft → persistence mechanisms → HTTP C2 → evasion hardening) and confirms token theft, service-based persistence, and WMI execution as on-theme areas where the vault's coverage is partial. No units were skipped as off-theme; all eight are on-topic but informationally sparse.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "ms-dos-pe-stub"
    target: T-007
    type: concept_link
    rationale: "The SEC670 unit-review quiz on the MS-DOS header byte sequence relates to PE parsing, which T-007's pe.rs and multiple injection labs depend on for header walking and section parsing."

  - source: "token-theft-lab"
    target: T-023
    type: concept_link
    rationale: "The TokenThief lab operates in the credential-harvest and lateral-movement space that T-023 partially covers (lsass_dump, wmi_exec), but token impersonation itself is not implemented in the vault."
```

### Concept Nodes

```yaml
concepts:
  - id: "ms-dos-pe-stub"
    name: "MS-DOS Header and DOS Stub"
    category: windows-structure
    description: "The MS-DOS header (MZ) at the start of every PE file is followed by the DOS stub. The unit review quiz identifies the byte following the MS-DOS header as 0x90, which corresponds to the first instruction of the DOS stub program that typically prints 'This program cannot be run in DOS mode.'"
    relevant_to: [T-007]
    tags: [pe-format, dos-header, pe-parsing, sec670]

  - id: "thread-scheduling-quantum"
    name: "Thread Scheduling Quantum"
    category: os-internal
    description: "The default thread scheduling quantum on Windows Server editions is the subject of an SEC601/SEC670 unit review question with options of 2, 8, and 12 clock cycles. The quantum governs how long a thread runs before the scheduler preempts it, which is relevant to APC draining behavior, thread-hijack timing windows, and sleep-obfuscation frame windows."
    relevant_to: [T-005, T-007, T-012]
    tags: [scheduler, thread-state, quantum, windows-internals]

  - id: "token-theft-lab"
    name: "Token Theft / Impersonation Lab"
    category: attack-pattern
    description: "SEC670 Lab 3.5 'TokenThief' covers stealing and reusing Windows access tokens for privilege escalation and lateral movement. The vault currently has no dedicated technique card for token impersonation, theft, or MakeToken-equivalent tradecraft despite its central role in red team operations."
    relevant_to: []
    tags: [orphan, token-impersonation, privilege-escalation, lateral-movement, sec670]
```

### Detection Insights

```yaml
# Material does not discuss detection indicators, ETW providers, Sysmon event IDs, or memory scanner heuristics. All eight units are TOC/quiz/slide-reference entries that defer to an external eWorkbook. No detection content can be honestly extracted from this batch.
```

### Operational Chains

```yaml
chains:
  - name: "SEC670 Implant Development Curriculum Arc"
    description: "The SANS SEC670 lab sequence implied by this batch establishes a curriculum arc from loader development through persistence to evasion hardening."
    steps:
      - technique: T-007
        role: "Lab 5.1 'The Loader' establishes local and cross-process shellcode execution as the foundational implant primitive"
      - technique: "token-theft"
        role: "Lab 3.5 'TokenThief' adds privilege escalation and lateral-movement capability via stolen token reuse"
      - technique: T-017
        role: "Labs 4.4-4.7 (NotInService, InitToWinit, OhMyWMI, CustomShell) establish persistence using services, WinInit, WMI, and custom shell mechanisms"
      - technique: T-022
        role: "Lab 5.3 'No Caller ID' implements HTTP C2 communications using HTTP libraries"
      - technique: T-020
        role: "Lab 5.5 'ShadowCraft' combines the basic shell with evasion features and error checking as a hardening phase"
    notes: "The chain reflects curriculum ordering rather than a per-operation sequence. Each lab defers to an external eWorkbook for implementation specifics, so operational constraints (timing, prerequisites, environmental conditions) are not surfaced in this batch."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "token-impersonation-theft-card"
    title: "Token Theft and Impersonation as a Standalone Technique Card"
    kind: proposed-technique
    description: "SEC670 Lab 3.5 'TokenThief' dedicates an entire lab to token theft and impersonation, indicating it is a distinct, teachable offensive capability. The vault currently distributes token-related logic implicitly across T-023 client capabilities (lsass_dump, wmi_exec) but has no card documenting the MakeToken/ImpersonateLoggedOnUser/DuplicateTokenEx primitive family or its operational use for lateral movement and privilege escalation."
    would_relate_to: [T-023, T-017]
    source_units: ["unit 1"]
    tags: [token-impersonation, privilege-escalation, lateral-movement, sec670, coverage-gap]

  - id: "service-based-persistence-gap"
    title: "Service-Based Persistence Coverage Gap in T-017"
    kind: coverage-gap
    description: "SEC670 Lab 4.4 'NotInService' and Lab 4.5 'InitToWinit' target service and WinInit-based persistence mechanisms. T-017 documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not cover service-image-path manipulation, service trigger configuration, or WinInit/RunOnce-style persistence. The vault's persistence card under-covers the service-vector space."
    would_relate_to: [T-017]
    source_units: ["unit 4", "unit 5"]
    tags: [persistence, service, wininit, coverage-gap, sec670]

  - id: "wmi-execution-coverage-gap"
    title: "WMI Execution and Lateral Movement Card"
    kind: coverage-gap
    description: "SEC670 Lab 4.6 'OhMyWMI' covers WMI as an execution and lateral-movement vector. The vault has a wmi_exec.rs implementation mapped to T-023 but does not surface WMI tradecraft (event subscription persistence, Win32_Process::Create lateral movement, WMI repository abuse) as a documented technique area. A dedicated sub-card or technique would surface this operator-relevant capability."
    would_relate_to: [T-023, T-017]
    source_units: ["unit 4", "unit 5"]
    tags: [wmi, lateral-movement, coverage-gap, sec670]

  - id: "customshell-shellcode-loader-card"
    title: "Custom Shell Loader as Distinct from Generic Injection"
    kind: proposed-technique
    description: "SEC670 Lab 4.7 'CustomShell' pairs with Lab 5.1 'The Loader' and Lab 5.5 'ShadowCraft' to indicate that custom shell construction is treated as its own offensive capability — distinct from the injection method catalog in T-007. The vault's T-007 card enumerates 14 injection methods but does not document the shell/implant scaffolding layer (command dispatch, error handling, transport abstraction) as a separate concern."
    would_relate_to: [T-007, T-022]
    source_units: ["unit 4", "unit 5", "unit 7", "unit 8"]
    tags: [shell, loader, implant-architecture, coverage-gap, sec670]
```